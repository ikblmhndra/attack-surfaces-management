"""
ASM Platform — Findings API Endpoints
Full-featured findings management with filtering, bulk ops, and risk acceptance.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import (
    RequireRole, get_current_user, get_db, get_workspace_id,
)
from app.core.redis_client import cache
from app.db.models.models import Asset, Finding, Organization, ScanFinding, User
from app.services.audit_service import audit_log

log = structlog.get_logger()
router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])
require_admin   = RequireRole(["owner", "admin"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Schemas ───────────────────────────────────────────────────

class FindingUpdateRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


class FalsePositiveRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=2000)


class RiskAcceptRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=2000)
    until: Optional[datetime] = None  # Expiry for risk acceptance


class BulkActionRequest(BaseModel):
    finding_ids: List[UUID] = Field(..., min_items=1, max_items=500)
    action: str  # mark_false_positive, accept_risk, reopen
    reason: Optional[str] = None


# ── List / Search ─────────────────────────────────────────────

@router.get("")
async def list_findings(
    org_id: Optional[UUID] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None, description="open,resolved,false_positive,accepted"),
    category: Optional[str] = Query(None),
    asset_id: Optional[UUID] = Query(None),
    template_id: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    has_cve: Optional[bool] = Query(None),
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("severity"),
    sort_dir: str = Query("asc"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings with rich filtering. Supports workspace-level and org-level queries."""

    # Build base query scoped to workspace
    query = select(Finding).where(
        Finding.workspace_id == workspace_id,
        Finding.deleted_at.is_(None),
    )

    # ── Filters ───────────────────────────────────────────────
    if org_id:
        query = query.where(Finding.org_id == org_id)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if severity:
        sevs = [s.strip() for s in severity.split(",")]
        query = query.where(Finding.severity.in_(sevs))
    if status:
        statuses = [s.strip() for s in status.split(",")]
        query = query.where(Finding.status.in_(statuses))
    else:
        query = query.where(Finding.status == "open")  # Default: open only
    if category:
        query = query.where(Finding.category == category)
    if template_id:
        query = query.where(Finding.template_id == template_id)
    if cve_id:
        query = query.where(Finding.cve_ids.any(cve_id))
    if has_cve is True:
        query = query.where(Finding.cve_ids != [])
    elif has_cve is False:
        query = query.where(or_(Finding.cve_ids == [], Finding.cve_ids.is_(None)))
    if min_cvss is not None:
        query = query.where(Finding.cvss_score >= min_cvss)
    if search:
        search_term = f"%{search}%"
        query = query.where(
            or_(
                Finding.title.ilike(search_term),
                Finding.description.ilike(search_term),
                Finding.affected_url.ilike(search_term),
                Finding.template_id.ilike(search_term),
            )
        )

    # ── Count ─────────────────────────────────────────────────
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # ── Severity counts for stats bar ─────────────────────────
    sev_counts_q = (
        select(Finding.severity, func.count(Finding.id).label("cnt"))
        .where(Finding.workspace_id == workspace_id, Finding.deleted_at.is_(None))
    )
    if org_id:
        sev_counts_q = sev_counts_q.where(Finding.org_id == org_id)
    if status:
        sev_counts_q = sev_counts_q.where(Finding.status.in_([s.strip() for s in status.split(",")]))
    else:
        sev_counts_q = sev_counts_q.where(Finding.status == "open")

    sev_counts_q = sev_counts_q.group_by(Finding.severity)
    sev_rows = (await db.execute(sev_counts_q)).all()
    severity_counts = {row.severity: row.cnt for row in sev_rows}

    # ── Sort ──────────────────────────────────────────────────
    sort_map = {
        "severity": Finding.severity,
        "title": Finding.title,
        "first_seen": Finding.first_seen,
        "last_seen": Finding.last_seen,
        "cvss_score": Finding.cvss_score,
        "status": Finding.status,
        "category": Finding.category,
    }
    sort_col = sort_map.get(sort_by, Finding.severity)
    if sort_by == "severity":
        # Custom severity ordering
        from sqlalchemy import case
        sort_col = case(
            {sev: i for i, sev in enumerate(["critical", "high", "medium", "low", "info"])},
            value=Finding.severity,
            else_=99,
        )
    query = query.order_by(sort_col.asc() if sort_dir == "asc" else sort_col.desc())

    # ── Paginate ──────────────────────────────────────────────
    query = query.offset((page - 1) * page_size).limit(page_size)
    findings = (await db.execute(query)).scalars().all()

    return {
        "items": [_finding_to_dict(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
    }


@router.get("/{finding_id}")
async def get_finding(
    finding_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed finding information including evidence and history."""
    finding = await _get_finding_or_404(db, finding_id, workspace_id)

    # Load asset info
    asset = None
    if finding.asset_id:
        asset_result = await db.execute(
            select(Asset).where(Asset.id == finding.asset_id)
        )
        asset = asset_result.scalar_one_or_none()

    # Load scan history for this finding
    scan_history = (await db.execute(
        select(ScanFinding).where(
            ScanFinding.finding_id == finding_id
        ).order_by(ScanFinding.created_at.desc()).limit(10)
    )).scalars().all()

    result = _finding_to_dict(finding, include_evidence=True)
    result["asset"] = {
        "id": str(asset.id),
        "type": asset.asset_type,
        "value": asset.value,
        "criticality": asset.criticality,
    } if asset else None
    result["scan_history"] = [
        {
            "scan_id": str(sh.scan_id),
            "change_type": sh.change_type,
            "detected_at": sh.created_at.isoformat(),
        }
        for sh in scan_history
    ]

    return result


@router.put("/{finding_id}")
async def update_finding(
    finding_id: UUID,
    request: FindingUpdateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update finding metadata (status, severity, notes)."""
    finding = await _get_finding_or_404(db, finding_id, workspace_id)

    changes = {}
    for field, value in request.model_dump(exclude_none=True).items():
        if hasattr(finding, field) and getattr(finding, field) != value:
            changes[field] = {"old": getattr(finding, field), "new": value}
            setattr(finding, field, value)

    if "status" in changes and changes["status"]["new"] == "resolved":
        finding.resolved_at = datetime.now(timezone.utc)

    await db.commit()

    bg.add_task(audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="finding.update",
        resource_type="finding",
        resource_id=str(finding_id),
        changes=changes,
    )

    return {"id": str(finding_id), "message": "Finding updated"}


@router.post("/{finding_id}/false-positive")
async def mark_false_positive(
    finding_id: UUID,
    request: FalsePositiveRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Mark a finding as false positive."""
    finding = await _get_finding_or_404(db, finding_id, workspace_id)

    if finding.status == "false_positive":
        raise HTTPException(status_code=400, detail="Finding is already marked as false positive")

    finding.is_false_positive = True
    finding.false_positive_reason = request.reason
    finding.status = "false_positive"
    finding.resolved_at = datetime.now(timezone.utc)
    await db.commit()

    bg.add_task(audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="finding.false_positive",
        resource_type="finding",
        resource_id=str(finding_id),
        changes={"reason": request.reason},
    )

    # Invalidate org score cache
    await cache.delete(f"org_score:{finding.org_id}")

    return {"id": str(finding_id), "status": "false_positive", "message": "Finding marked as false positive"}


@router.post("/{finding_id}/accept-risk")
async def accept_risk(
    finding_id: UUID,
    request: RiskAcceptRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Accept risk for a finding (excludes from score until expiry)."""
    finding = await _get_finding_or_404(db, finding_id, workspace_id)

    finding.is_risk_accepted = True
    finding.risk_acceptance_reason = request.reason
    finding.risk_accepted_by = current_user.id
    finding.risk_accepted_until = request.until or (datetime.now(timezone.utc) + timedelta(days=90))
    finding.status = "accepted"
    await db.commit()

    bg.add_task(audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="finding.accept_risk",
        resource_type="finding",
        resource_id=str(finding_id),
        changes={"reason": request.reason, "until": str(request.until)},
    )

    await cache.delete(f"org_score:{finding.org_id}")

    return {
        "id": str(finding_id),
        "status": "accepted",
        "accepted_until": finding.risk_accepted_until.isoformat(),
    }


@router.post("/{finding_id}/reopen")
async def reopen_finding(
    finding_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Reopen a resolved or false-positive finding."""
    finding = await _get_finding_or_404(db, finding_id, workspace_id)

    if finding.status == "open":
        raise HTTPException(status_code=400, detail="Finding is already open")

    finding.status = "open"
    finding.is_false_positive = False
    finding.is_risk_accepted = False
    finding.resolved_at = None
    finding.risk_acceptance_reason = None
    await db.commit()

    bg.add_task(audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="finding.reopen",
        resource_type="finding",
        resource_id=str(finding_id),
    )

    return {"id": str(finding_id), "status": "open"}


@router.post("/bulk-action")
async def bulk_action(
    request: BulkActionRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Perform bulk actions on multiple findings."""
    finding_ids = [str(fid) for fid in request.finding_ids]

    # Verify all findings belong to this workspace
    count = (await db.execute(
        select(func.count(Finding.id)).where(
            Finding.id.in_(finding_ids),
            Finding.workspace_id == workspace_id,
        )
    )).scalar_one()

    if count != len(finding_ids):
        raise HTTPException(status_code=403, detail="Some findings not found or access denied")

    now = datetime.now(timezone.utc)
    updated = 0

    if request.action == "mark_false_positive":
        result = await db.execute(
            update(Finding).where(Finding.id.in_(finding_ids)).values(
                status="false_positive",
                is_false_positive=True,
                false_positive_reason=request.reason or "Bulk marked",
                resolved_at=now,
            ).returning(Finding.id)
        )
        updated = len(result.fetchall())

    elif request.action == "accept_risk":
        result = await db.execute(
            update(Finding).where(Finding.id.in_(finding_ids)).values(
                status="accepted",
                is_risk_accepted=True,
                risk_acceptance_reason=request.reason or "Bulk accepted",
                risk_accepted_by=current_user.id,
                risk_accepted_until=now + timedelta(days=90),
            ).returning(Finding.id)
        )
        updated = len(result.fetchall())

    elif request.action == "reopen":
        result = await db.execute(
            update(Finding).where(Finding.id.in_(finding_ids)).values(
                status="open",
                is_false_positive=False,
                is_risk_accepted=False,
                resolved_at=None,
            ).returning(Finding.id)
        )
        updated = len(result.fetchall())

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")

    await db.commit()

    bg.add_task(audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action=f"finding.bulk_{request.action}",
        resource_type="finding",
        resource_id="bulk",
        changes={"count": updated, "ids": finding_ids[:10]},
    )

    return {"updated": updated, "action": request.action}


@router.get("/stats/by-category")
async def findings_by_category(
    org_id: Optional[UUID] = Query(None),
    days: int = Query(30, ge=1, le=365),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate findings by category for dashboard charts."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    query = (
        select(
            Finding.category,
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .where(
            Finding.workspace_id == workspace_id,
            Finding.status == "open",
            Finding.deleted_at.is_(None),
            Finding.first_seen >= since,
        )
    )
    if org_id:
        query = query.where(Finding.org_id == org_id)

    query = query.group_by(Finding.category, Finding.severity)
    rows = (await db.execute(query)).all()

    # Reshape for chart consumption
    by_category: dict = {}
    for row in rows:
        if row.category not in by_category:
            by_category[row.category] = {
                "category": row.category,
                "total": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            }
        by_category[row.category][row.severity] = row.count
        by_category[row.category]["total"] += row.count

    return {
        "categories": sorted(by_category.values(), key=lambda x: -x["total"]),
        "period_days": days,
    }


@router.get("/stats/trend")
async def findings_trend(
    org_id: Optional[UUID] = Query(None),
    days: int = Query(30, ge=7, le=365),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Daily new findings trend for timeline chart."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    query = (
        select(
            func.date_trunc("day", Finding.first_seen).label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        )
        .where(
            Finding.workspace_id == workspace_id,
            Finding.deleted_at.is_(None),
            Finding.first_seen >= since,
        )
    )
    if org_id:
        query = query.where(Finding.org_id == org_id)

    query = query.group_by(
        func.date_trunc("day", Finding.first_seen),
        Finding.severity,
    ).order_by(func.date_trunc("day", Finding.first_seen))

    rows = (await db.execute(query)).all()

    return {
        "trend": [
            {
                "date": row.date.isoformat(),
                "severity": row.severity,
                "count": row.count,
            }
            for row in rows
        ],
        "period_days": days,
    }


# ── Export ──────────────────────────────────────────────────

@router.get("/export")
async def export_findings(
    org_id: Optional[UUID] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    format: str = Query("csv", regex="^(csv|json)$"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse
    import csv, io

    query = select(Finding).where(Finding.workspace_id == workspace_id, Finding.deleted_at.is_(None))
    if org_id: query = query.where(Finding.org_id == org_id)
    if severity: query = query.where(Finding.severity == severity)
    if status: query = query.where(Finding.status == status)
    if category: query = query.where(Finding.category == category)
    findings = (await db.execute(query.order_by(Finding.last_seen.desc()).limit(10000))).scalars().all()

    if format == "json":
        return [_finding_to_dict(f) for f in findings]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "org_id", "title", "severity", "category", "status", "source", "cve_ids", "cvss_score", "affected_url", "first_seen", "last_seen"])
    for f in findings:
        writer.writerow([str(f.id), str(f.org_id), f.title, f.severity, f.category, f.status, f.source, ";".join(f.cve_ids or []), f.cvss_score, f.affected_url, f.first_seen.isoformat() if f.first_seen else "", f.last_seen.isoformat() if f.last_seen else ""])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=findings.csv"})


# ── Helpers ───────────────────────────────────────────────────

async def _get_finding_or_404(
    db: AsyncSession,
    finding_id: UUID,
    workspace_id: UUID,
) -> Finding:
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.workspace_id == workspace_id,
            Finding.deleted_at.is_(None),
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


def _finding_to_dict(finding: Finding, include_evidence: bool = False) -> dict:
    d = {
        "id": str(finding.id),
        "org_id": str(finding.org_id),
        "asset_id": str(finding.asset_id) if finding.asset_id else None,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.category,
        "subcategory": finding.subcategory,
        "status": finding.status,
        "source": finding.source,
        "template_id": finding.template_id,
        "template_url": finding.template_url,
        "scanner": finding.scanner,
        "cve_ids": finding.cve_ids or [],
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cwe_ids": finding.cwe_ids or [],
        "affected_url": finding.affected_url,
        "remediation": finding.remediation,
        "references": finding.references or [],
        "is_false_positive": finding.is_false_positive,
        "false_positive_reason": finding.false_positive_reason,
        "is_risk_accepted": finding.is_risk_accepted,
        "risk_acceptance_reason": finding.risk_acceptance_reason,
        "risk_accepted_until": finding.risk_accepted_until.isoformat() if finding.risk_accepted_until else None,
        "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
        "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }

    if include_evidence:
        d["evidence"] = finding.evidence
        d["request_raw"] = finding.request_raw
        d["response_raw"] = finding.response_raw
        d["proof"] = finding.proof

    return d

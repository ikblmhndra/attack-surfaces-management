import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from uuid import UUID
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, Scan, Organization, ScanPhaseRun, ScanTargetSelection
from app.services.scan_profiles import apply_scan_profile, normalize_scan_profile
from app.services.scan_progress import merge_runtime_phase_status
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once
from sqlalchemy import select, update, func, or_, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])


class ManualScanRequest(BaseModel):
    org_id: UUID
    targets: List[str]
    config: dict = Field(default_factory=dict)
    vuln_depth: str = "default"
    scan_profile: Optional[str] = None

    @field_validator("vuln_depth")
    @classmethod
    def validate_vuln_depth(cls, value: str) -> str:
        allowed = {"critical", "default", "full", "endpoint"}
        if value not in allowed:
            raise ValueError(f"vuln_depth must be one of: {', '.join(sorted(allowed))}")
        return value

    @field_validator("scan_profile")
    @classmethod
    def validate_scan_profile(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = normalize_scan_profile(value)
        if not normalized:
            raise ValueError("scan_profile must be one of: safe, default, deep_authorized")
        return normalized

@router.get("")
async def list_scans(org_id: Optional[UUID] = Query(None), status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1), page_size: int = Query(20),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(Scan).where(Scan.workspace_id == workspace_id)
    if org_id: query = query.where(Scan.org_id == org_id)
    if status: query = query.where(Scan.status == status)
    if search:
        term = f"%{search}%"
        query = query.where(or_(
            cast(Scan.id, String).ilike(term),
            Scan.scan_type.ilike(term),
            Scan.status.ilike(term),
            Scan.error_message.ilike(term),
        ))
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    scans = (await db.execute(query.order_by(Scan.created_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    return {"items": [await _scan_to_dict(s) for s in scans], "total": total}

@router.get("/{scan_id}")
async def get_scan(scan_id: UUID, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    scan = result.scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    return await _scan_to_dict(scan, detailed=True, db=db)


async def _scan_to_dict(scan: Scan, detailed: bool = False, db: AsyncSession | None = None) -> dict:
    phase_status = await merge_runtime_phase_status(str(scan.id), scan.phase_status or {})
    config = scan.config or {}
    data = {
        "id": str(scan.id),
        "org_id": str(scan.org_id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "modules": scan.modules or [],
        "scan_profile": config.get("scan_profile"),
        "progress_pct": scan.progress_pct,
        "phase_status": phase_status,
        "total_tasks": scan.total_tasks,
        "completed_tasks": scan.completed_tasks,
        "failed_tasks": scan.failed_tasks,
        "error_count": scan.error_count,
        "assets_found": scan.assets_found,
        "findings_found": scan.findings_found,
        "new_assets": scan.new_assets,
        "new_findings": scan.new_findings,
        "error_message": scan.error_message,
        "duration_seconds": scan.duration_seconds,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at": scan.created_at.isoformat(),
    }
    if detailed and db is not None:
        data["config"] = config
        data["phase_runs"] = await _scan_phase_runs(db, scan)
        selections = await _scan_target_selections(db, scan)
        data["target_summary"] = _target_summary(selections)
        data["target_selections"] = selections[:500]
        data["why_no_findings"] = _why_no_findings(data)
    return data


async def _scan_phase_runs(db: AsyncSession, scan: Scan) -> list[dict]:
    rows = (await db.execute(
        select(ScanPhaseRun)
        .where(ScanPhaseRun.scan_id == scan.id, ScanPhaseRun.workspace_id == scan.workspace_id)
        .order_by(ScanPhaseRun.started_at.nulls_last(), ScanPhaseRun.created_at)
    )).scalars().all()
    return [
        {
            "phase": row.phase,
            "status": row.status,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "duration_seconds": row.duration_seconds,
            "expected_tasks": row.expected_tasks,
            "completed_tasks": row.completed_tasks,
            "failed_tasks": row.failed_tasks,
            "targets_total": row.targets_total,
            "targets_selected": row.targets_selected,
            "targets_skipped": row.targets_skipped,
            "errors": row.errors,
            "warnings": row.warnings,
            "summary": row.summary or {},
        }
        for row in rows
    ]


async def _scan_target_selections(db: AsyncSession, scan: Scan) -> list[dict]:
    rows = (await db.execute(
        select(ScanTargetSelection)
        .where(ScanTargetSelection.scan_id == scan.id, ScanTargetSelection.workspace_id == scan.workspace_id)
        .order_by(ScanTargetSelection.phase, ScanTargetSelection.selected.desc(), ScanTargetSelection.score.desc().nulls_last())
        .limit(1000)
    )).scalars().all()
    return [
        {
            "id": str(row.id),
            "asset_id": str(row.asset_id) if row.asset_id else None,
            "target": row.target,
            "target_type": row.target_type,
            "phase": row.phase,
            "profile": row.profile,
            "selected": row.selected,
            "score": row.score,
            "reasons": row.reasons or [],
            "skip_reason": row.skip_reason,
            "metadata": row.metadata_ or {},
            "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(),
        }
        for row in rows
    ]


def _target_summary(selections: list[dict]) -> dict:
    by_phase: dict[str, Counter] = defaultdict(Counter)
    by_type: Counter = Counter()
    selected = 0
    skipped = 0
    for row in selections:
        phase = row.get("phase") or "unknown"
        if row.get("selected"):
            selected += 1
            by_phase[phase]["selected"] += 1
        else:
            skipped += 1
            by_phase[phase]["skipped"] += 1
        by_type[row.get("target_type") or "unknown"] += 1
    return {
        "total": len(selections),
        "selected": selected,
        "skipped": skipped,
        "by_phase": {phase: dict(counts) for phase, counts in by_phase.items()},
        "by_type": dict(by_type),
    }


def _why_no_findings(scan_data: dict) -> list[dict]:
    if scan_data.get("findings_found", 0) > 0:
        return []
    phase_status = scan_data.get("phase_status") or {}
    target_summary = scan_data.get("target_summary") or {}
    reasons = []
    targeting = phase_status.get("targeting") or {}
    nuclei = phase_status.get("nuclei") or {}
    crawl = phase_status.get("crawl") or {}

    if not targeting.get("web_standard") and not targeting.get("web_limited"):
        reasons.append({
            "code": "no_web_targets",
            "label": "No web targets selected",
            "detail": "Discovery did not select live standard or limited web targets for nuclei.",
        })
    if crawl.get("endpoints") and not crawl.get("selected_for_nuclei"):
        reasons.append({
            "code": "no_endpoint_targets",
            "label": "No endpoint targets selected",
            "detail": "Crawler persisted endpoints, but none met the endpoint nuclei scoring threshold.",
        })
    if nuclei.get("expected_batches") and nuclei.get("completed_batches", 0) < nuclei.get("expected_batches", 0):
        reasons.append({
            "code": "nuclei_incomplete",
            "label": "Nuclei still running",
            "detail": f"{nuclei.get('completed_batches', 0)}/{nuclei.get('expected_batches')} nuclei batches are complete.",
        })
    if target_summary.get("total") == 0:
        reasons.append({
            "code": "no_target_records",
            "label": "No durable target records",
            "detail": "This scan has no persisted target selections yet. It may have started before observability tracking was enabled.",
        })
    if scan_data.get("status") == "failed" and scan_data.get("error_message"):
        reasons.append({
            "code": "scan_failed",
            "label": "Scan failed",
            "detail": scan_data["error_message"],
        })
    return reasons

@router.post("/manual", status_code=201)
async def manual_scan(
    request: ManualScanRequest,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Run nuclei directly against user-provided targets, bypassing discovery pipeline."""
    if not request.targets:
        raise HTTPException(400, "At least one target is required")

    org_exists = await db.execute(
        select(Organization.id).where(
            Organization.id == request.org_id,
            Organization.workspace_id == workspace_id,
            Organization.deleted_at.is_(None),
        )
    )
    if not org_exists.scalar_one_or_none():
        raise HTTPException(404, "Organization not found")

    scan_id = str(uuid.uuid4())
    scan_config = apply_scan_profile(
        {
            "targets": request.targets,
            "vuln_depth": request.vuln_depth,
            **request.config,
            **({"scan_profile": request.scan_profile} if request.scan_profile else {}),
        },
        "manual_nuclei",
    )

    db.add(
        Scan(
            id=scan_id,
            org_id=request.org_id,
            workspace_id=workspace_id,
            created_by=current_user.id,
            scan_type="manual_nuclei",
            status="queued",
            modules=["nuclei"],
            config=scan_config,
            phase_status={"nuclei": {"status": "queued"}},
            total_tasks=1,
        )
    )
    db.add(
        create_queue_event(
            routing_key="scan.nuclei",
            payload={
                "scan_id": scan_id,
                "org_id": str(request.org_id),
                "workspace_id": str(workspace_id),
                "targets": request.targets,
                "config": scan_config,
            },
            headers={
                "coordinator": {
                    "scan_id": scan_id,
                    "nuclei_expected": 1,
                    "screenshot_done": True,
                }
            },
            aggregate_type="scan",
            aggregate_id=scan_id,
        )
    )
    await db.commit()

    try:
        await dispatch_pending_outbox_once(limit=5)
    except Exception as e:
        await db.execute(update(Scan).where(Scan.id == scan_id).values(status="failed", error_message=str(e)))
        await db.commit()
        raise HTTPException(500, f"Failed to queue scan: {str(e)}")

    return {"scan_id": scan_id, "status": "queued", "message": f"Nuclei scan queued against {len(request.targets)} target(s)"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: UUID, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    scan = result.scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    if scan.status not in ("pending", "running", "queued"):
        raise HTTPException(400, f"Cannot cancel scan in state: {scan.status}")
    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Scan cancellation requested"}

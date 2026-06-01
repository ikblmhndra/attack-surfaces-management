"""
ASM Platform — Organizations API Endpoints
Full CRUD for organization management and scan orchestration.
"""
from typing import List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import (
    RequireRole,
    get_current_user,
    get_db,
    get_workspace_id,
)
from app.db.models.models import Asset, Finding, Organization, RiskScore, Scan, ScanTemplate, User
from app.services.audit_service import audit_log
from app.services.scan_service import ScanService

log = structlog.get_logger()
router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])
require_admin = RequireRole(["owner", "admin"])


# ── Schemas ───────────────────────────────────────────────────

class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    domains: List[str] = Field(default_factory=list)
    root_domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    asns: List[str] = Field(default_factory=list)
    company_name: Optional[str] = None
    industry: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    criticality: int = Field(default=3, ge=1, le=5)
    environment: str = Field(default="production")
    auto_scan_enabled: bool = True


class OrgUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    domains: Optional[List[str]] = None
    root_domains: Optional[List[str]] = None
    ip_ranges: Optional[List[str]] = None
    asns: Optional[List[str]] = None
    company_name: Optional[str] = None
    industry: Optional[str] = None
    tags: Optional[List[str]] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    environment: Optional[str] = None
    is_monitoring_active: Optional[bool] = None
    auto_scan_enabled: Optional[bool] = None


class ScanRequest(BaseModel):
    scan_type: str = Field(default="full")  # full, discovery, vuln, quick
    modules: List[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    template_id: Optional[str] = None  # Optional scan template reference

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, value: str) -> str:
        allowed = {"full", "quick", "discovery", "vuln"}
        if value not in allowed:
            raise ValueError(f"scan_type must be one of: {', '.join(sorted(allowed))}")
        return value

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, value: List[str]) -> List[str]:
        allowed = {"discovery", "port", "nuclei", "screenshot"}
        invalid = sorted(set(value) - allowed)
        if invalid:
            raise ValueError(f"unsupported scan module(s): {', '.join(invalid)}")
        return value


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    domains: List[str]
    root_domains: List[str]
    ip_ranges: List[str]
    asns: List[str]
    company_name: Optional[str]
    industry: Optional[str]
    tags: List[str]
    criticality: int
    environment: str
    total_assets: int
    total_findings: int
    is_monitoring_active: bool
    auto_scan_enabled: bool
    last_scan_at: Optional[str]
    current_score: Optional[dict]
    created_at: str
    updated_at: str


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int


# ── Endpoints ─────────────────────────────────────────────────

@router.get("", response_model=PaginatedResponse)
async def list_organizations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = Query(default=None),
    industry: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    tags: Optional[str] = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc"),
    workspace_id: UUID = Depends(get_workspace_id),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all organizations in the workspace with filtering and pagination."""
    query = select(Organization).where(
        Organization.workspace_id == workspace_id,
        Organization.deleted_at.is_(None),
    )

    if search:
        query = query.where(
            Organization.name.ilike(f"%{search}%") |
            Organization.company_name.ilike(f"%{search}%")
        )
    if industry:
        query = query.where(Organization.industry == industry)
    if environment:
        query = query.where(Organization.environment == environment)
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]
        query = query.where(Organization.tags.overlap(tag_list))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Sort
    sort_col = getattr(Organization, sort_by, Organization.created_at)
    if sort_dir == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    orgs = result.scalars().all()

    # Enrich with latest scores
    items = []
    for org in orgs:
        score_q = select(RiskScore).where(
            RiskScore.org_id == org.id
        ).order_by(RiskScore.computed_at.desc()).limit(1)
        score_result = await db.execute(score_q)
        latest_score = score_result.scalar_one_or_none()

        items.append({
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "description": org.description,
            "domains": org.domains or [],
            "root_domains": org.root_domains or [],
            "ip_ranges": org.ip_ranges or [],
            "asns": org.asns or [],
            "company_name": org.company_name,
            "industry": org.industry,
            "tags": org.tags or [],
            "criticality": org.criticality,
            "environment": org.environment,
            "total_assets": org.total_assets,
            "total_findings": org.total_findings,
            "is_monitoring_active": org.is_monitoring_active,
            "auto_scan_enabled": org.auto_scan_enabled,
            "last_scan_at": org.last_scan_at.isoformat() if org.last_scan_at else None,
            "current_score": {
                "overall": latest_score.overall_score,
                "grade": latest_score.grade,
                "critical": latest_score.critical_count,
                "high": latest_score.high_count,
                "medium": latest_score.medium_count,
                "computed_at": latest_score.computed_at.isoformat(),
            } if latest_score else None,
            "created_at": org.created_at.isoformat(),
            "updated_at": org.updated_at.isoformat(),
        })

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, (total + page_size - 1) // page_size),
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_organization(
    request: OrgCreateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization target."""
    import re, secrets

    slug = re.sub(r"[^\w\s-]", "", request.name.lower())
    slug = re.sub(r"[\s_-]+", "-", slug).strip("-")[:90] + "-" + secrets.token_hex(3)

    # Check name uniqueness within workspace
    existing = await db.execute(
        select(Organization).where(
            Organization.workspace_id == workspace_id,
            Organization.name == request.name,
            Organization.deleted_at.is_(None),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization with this name already exists",
        )

    org = Organization(
        workspace_id=workspace_id,
        name=request.name,
        slug=slug,
        description=request.description,
        domains=request.domains,
        root_domains=request.root_domains,
        ip_ranges=request.ip_ranges,
        asns=request.asns,
        company_name=request.company_name,
        industry=request.industry,
        tags=request.tags,
        criticality=request.criticality,
        environment=request.environment,
        auto_scan_enabled=request.auto_scan_enabled,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)

    log.info("org_created", org_id=str(org.id), workspace_id=str(workspace_id))

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="org.create",
        resource_type="organization",
        resource_id=str(org.id),
        changes={"name": org.name},
    )

    return {"id": str(org.id), "name": org.name, "slug": org.slug}


@router.get("/{org_id}")
async def get_organization(
    org_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization details with current risk score."""
    org = await _get_org_or_404(db, org_id, workspace_id)

    # Latest score
    score_q = select(RiskScore).where(RiskScore.org_id == org_id).order_by(
        RiskScore.computed_at.desc()
    ).limit(1)
    latest_score = (await db.execute(score_q)).scalar_one_or_none()

    # Stats
    asset_count = (await db.execute(
        select(func.count(Asset.id)).where(
            Asset.org_id == org_id,
            Asset.deleted_at.is_(None),
        )
    )).scalar_one()

    finding_count = (await db.execute(
        select(func.count(Finding.id)).where(
            Finding.org_id == org_id,
            Finding.status == "open",
            Finding.deleted_at.is_(None),
        )
    )).scalar_one()

    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "description": org.description,
        "domains": org.domains or [],
        "root_domains": org.root_domains or [],
        "ip_ranges": org.ip_ranges or [],
        "asns": org.asns or [],
        "company_name": org.company_name,
        "industry": org.industry,
        "tags": org.tags or [],
        "labels": org.labels or {},
        "criticality": org.criticality,
        "environment": org.environment,
        "total_assets": asset_count,
        "total_findings": finding_count,
        "is_monitoring_active": org.is_monitoring_active,
        "auto_scan_enabled": org.auto_scan_enabled,
        "last_scan_at": org.last_scan_at.isoformat() if org.last_scan_at else None,
        "risk_score": {
            "overall": latest_score.overall_score,
            "grade": latest_score.grade,
            "category_scores": latest_score.score_breakdown,
            "critical": latest_score.critical_count,
            "high": latest_score.high_count,
            "medium": latest_score.medium_count,
            "low": latest_score.low_count,
            "info": latest_score.info_count,
            "computed_at": latest_score.computed_at.isoformat(),
            "score_factors": latest_score.score_factors,
        } if latest_score else None,
        "created_at": org.created_at.isoformat(),
        "updated_at": org.updated_at.isoformat(),
    }


@router.put("/{org_id}")
async def update_organization(
    org_id: UUID,
    request: OrgUpdateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update organization details."""
    org = await _get_org_or_404(db, org_id, workspace_id)

    changes = {}
    for field, value in request.model_dump(exclude_none=True).items():
        if hasattr(org, field) and getattr(org, field) != value:
            changes[field] = {"old": getattr(org, field), "new": value}
            setattr(org, field, value)

    await db.commit()
    await db.refresh(org)

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="org.update",
        resource_type="organization",
        resource_id=str(org_id),
        changes=changes,
    )

    return {"id": str(org.id), "message": "Organization updated successfully"}


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: UUID,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Soft delete an organization."""
    from datetime import datetime, timezone
    org = await _get_org_or_404(db, org_id, workspace_id)
    org.deleted_at = datetime.now(timezone.utc)
    await db.commit()

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="org.delete",
        resource_type="organization",
        resource_id=str(org_id),
    )


@router.post("/{org_id}/scans", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    org_id: UUID,
    request: ScanRequest,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a new security scan for the organization."""
    org = await _get_org_or_404(db, org_id, workspace_id)

    # Check concurrent scan limit
    active_scans = (await db.execute(
        select(func.count(Scan.id)).where(
            Scan.org_id == org_id,
            Scan.status.in_(["queued", "pending", "running"]),
        )
    )).scalar_one()

    if active_scans >= 3:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Maximum concurrent scans (3) reached. Please wait for active scans to complete.",
        )

    # Resolve template if provided
    modules = request.modules
    config = request.config
    scan_type = request.scan_type
    if request.template_id:
        result = await db.execute(
            select(ScanTemplate).where(
                ScanTemplate.id == request.template_id,
                ScanTemplate.workspace_id == workspace_id,
                ScanTemplate.is_active == True,
            )
        )
        tmpl = result.scalar_one_or_none()
        if tmpl:
            if not modules:
                modules = tmpl.modules
            config = {**tmpl.config, **config}
            config["severities"] = config.get("severities", tmpl.severities)
            config["template_name"] = tmpl.name
            scan_type = tmpl.scan_type

    scan_service = ScanService(db)
    scan = await scan_service.create_and_queue(
        org_id=org_id,
        workspace_id=workspace_id,
        created_by=current_user.id,
        scan_type=scan_type,
        modules=modules,
        config=config,
        org=org,
    )

    log.info("scan_triggered", scan_id=str(scan.id), org_id=str(org_id), type=request.scan_type)

    return {
        "scan_id": str(scan.id),
        "status": "queued",
        "scan_type": scan.scan_type,
        "message": "Scan queued successfully. Check /api/v1/scans/{scan_id} for status.",
    }


@router.get("/{org_id}/scans")
async def list_org_scans(
    org_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scans for an organization."""
    await _get_org_or_404(db, org_id, workspace_id)

    query = select(Scan).where(Scan.org_id == org_id).order_by(Scan.created_at.desc())
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    scans = (await db.execute(query.offset((page - 1) * page_size).limit(page_size))).scalars().all()

    return {
        "items": [_scan_to_dict(s) for s in scans],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{org_id}/score-history")
async def get_score_history(
    org_id: UUID,
    days: int = Query(default=90, ge=7, le=365),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get risk score history for trend visualization."""
    from datetime import datetime, timedelta, timezone
    await _get_org_or_404(db, org_id, workspace_id)

    since = datetime.now(timezone.utc) - timedelta(days=days)
    scores = (await db.execute(
        select(RiskScore)
        .where(RiskScore.org_id == org_id, RiskScore.computed_at >= since)
        .order_by(RiskScore.computed_at.asc())
    )).scalars().all()

    return {
        "org_id": str(org_id),
        "days": days,
        "history": [
            {
                "date": s.computed_at.isoformat(),
                "overall_score": s.overall_score,
                "grade": s.grade,
                "categories": s.score_breakdown,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
            }
            for s in scores
        ],
    }


@router.get("/{org_id}/timeline")
async def get_attack_surface_timeline(
    org_id: UUID,
    days: int = Query(default=30, ge=1, le=365),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get asset/finding timeline for change tracking."""
    from datetime import datetime, timedelta, timezone
    await _get_org_or_404(db, org_id, workspace_id)

    since = datetime.now(timezone.utc) - timedelta(days=days)

    # New assets over time
    new_assets = (await db.execute(
        select(
            func.date_trunc("day", Asset.first_seen).label("date"),
            func.count(Asset.id).label("count"),
        ).where(
            Asset.org_id == org_id,
            Asset.first_seen >= since,
        ).group_by(func.date_trunc("day", Asset.first_seen))
        .order_by(func.date_trunc("day", Asset.first_seen))
    )).all()

    # New findings over time
    new_findings = (await db.execute(
        select(
            func.date_trunc("day", Finding.first_seen).label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        ).where(
            Finding.org_id == org_id,
            Finding.first_seen >= since,
        ).group_by(
            func.date_trunc("day", Finding.first_seen),
            Finding.severity,
        ).order_by(func.date_trunc("day", Finding.first_seen))
    )).all()

    return {
        "new_assets": [{"date": r.date.isoformat(), "count": r.count} for r in new_assets],
        "new_findings": [
            {"date": r.date.isoformat(), "severity": r.severity, "count": r.count}
            for r in new_findings
        ],
    }


# ── Helpers ───────────────────────────────────────────────────

async def _get_org_or_404(db: AsyncSession, org_id: UUID, workspace_id: UUID) -> Organization:
    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.workspace_id == workspace_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


def _scan_to_dict(scan: Scan) -> dict:
    return {
        "id": str(scan.id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "modules": scan.modules or [],
        "progress_pct": scan.progress_pct,
        "assets_found": scan.assets_found,
        "findings_found": scan.findings_found,
        "new_assets": scan.new_assets,
        "new_findings": scan.new_findings,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "error_message": scan.error_message,
        "created_at": scan.created_at.isoformat(),
    }

"""
ASM Platform — Organizations API Endpoints
Full CRUD for organization management and scan orchestration.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import (
    RequireRole,
    get_current_user,
    get_db,
    get_workspace_id,
)
from app.db.models.models import (
    Asset, AssetRelationship, Finding, Organization, RiskScore, Scan, ScanTemplate,
    Subdomain, Technology, User,
)
from app.services.audit_service import audit_log
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once
from app.services.scan_progress import merge_runtime_phase_status
from app.services.scan_profiles import normalize_scan_profile
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
    scan_policy: Dict[str, Any] = Field(default_factory=dict)
    scope_allow_patterns: List[str] = Field(default_factory=list)
    scope_deny_patterns: List[str] = Field(default_factory=list)


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
    scan_policy: Optional[Dict[str, Any]] = None
    scope_allow_patterns: Optional[List[str]] = None
    scope_deny_patterns: Optional[List[str]] = None


class ScanRequest(BaseModel):
    scan_type: str = Field(default="full")  # full, discovery, vuln, quick
    modules: List[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    scan_profile: Optional[str] = None
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
        allowed = {"discovery", "port", "crawl", "nuclei", "scanner", "screenshot", "enrich"}
        invalid = sorted(set(value) - allowed)
        if invalid:
            raise ValueError(f"unsupported scan module(s): {', '.join(invalid)}")
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


class NucleiAssetScanRequest(BaseModel):
    scan_profile: str = Field(default="deep_authorized")
    include_hosts: bool = True
    include_endpoints: bool = True
    include_limited: bool = True
    max_hosts: int = Field(default=200, ge=1, le=500)
    max_endpoints: int = Field(default=50, ge=0, le=500)
    config: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("scan_profile")
    @classmethod
    def validate_scan_profile(cls, value: str) -> str:
        normalized = normalize_scan_profile(value)
        if not normalized:
            raise ValueError("scan_profile must be one of: safe, default, deep_authorized")
        return normalized


class AssetValidationRequest(BaseModel):
    asset_ids: List[str] = Field(default_factory=list)
    limit: int = Field(default=200, ge=1, le=1000)
    stale_hours: Optional[int] = Field(default=None, ge=1, le=720)


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
    scan_policy: Dict[str, Any]
    scope_allow_patterns: List[str]
    scope_deny_patterns: List[str]
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
            "scan_policy": org.scan_policy or {},
            "scope_allow_patterns": org.scope_allow_patterns or [],
            "scope_deny_patterns": org.scope_deny_patterns or [],
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
        scan_policy=request.scan_policy,
        scope_allow_patterns=request.scope_allow_patterns,
        scope_deny_patterns=request.scope_deny_patterns,
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
        "scan_policy": org.scan_policy or {},
        "scope_allow_patterns": org.scope_allow_patterns or [],
        "scope_deny_patterns": org.scope_deny_patterns or [],
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
    config = dict(request.config)
    if request.scan_profile:
        config["scan_profile"] = request.scan_profile
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


@router.post("/{org_id}/scans/nuclei-assets", status_code=status.HTTP_201_CREATED)
async def trigger_nuclei_asset_scan(
    org_id: UUID,
    request: NucleiAssetScanRequest,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Run nuclei directly against existing discovered assets and crawled endpoints."""
    await _get_org_or_404(db, org_id, workspace_id)

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

    scan_service = ScanService(db)
    try:
        scan = await scan_service.create_nuclei_asset_scan(
            org_id=org_id,
            workspace_id=workspace_id,
            created_by=current_user.id,
            config=request.config,
            scan_profile=request.scan_profile,
            include_hosts=request.include_hosts,
            include_endpoints=request.include_endpoints,
            include_limited=request.include_limited,
            max_hosts=request.max_hosts,
            max_endpoints=request.max_endpoints,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target_counts = (scan.config or {}).get("target_counts") or {}
    return {
        "scan_id": str(scan.id),
        "status": "queued",
        "scan_type": scan.scan_type,
        "target_counts": target_counts,
        "message": (
            f"Nuclei asset scan queued against {target_counts.get('hosts', 0)} host target(s) "
            f"and {target_counts.get('endpoints', 0)} endpoint target(s)."
        ),
    }


@router.post("/{org_id}/assets/validate", status_code=status.HTTP_202_ACCEPTED)
async def queue_asset_validation(
    org_id: UUID,
    request: AssetValidationRequest,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Queue ownership/scope revalidation for existing assets."""
    await _get_org_or_404(db, org_id, workspace_id)
    payload = {
        "org_id": str(org_id),
        "workspace_id": str(workspace_id),
        "asset_ids": request.asset_ids,
        "limit": request.limit,
    }
    if request.stale_hours:
        payload["stale_hours"] = request.stale_hours

    event = create_queue_event(
        routing_key="asset.validate",
        payload=payload,
        priority=4,
        aggregate_type="organization",
        aggregate_id=str(org_id),
    )
    db.add(event)
    await db.commit()

    try:
        await dispatch_pending_outbox_once(limit=5)
    except Exception as exc:
        log.warning("asset_validation_outbox_dispatch_deferred", org_id=str(org_id), error=str(exc))

    return {
        "status": "queued",
        "routing_key": "asset.validate",
        "asset_count": len(request.asset_ids),
        "limit": request.limit,
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
        "items": [await _scan_to_dict(s) for s in scans],
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
                "score_version": s.score_version,
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

    asset_day = func.date_trunc(text("'day'"), Asset.first_seen)
    finding_day = func.date_trunc(text("'day'"), Finding.first_seen)

    # New assets over time
    new_assets = (await db.execute(
        select(
            asset_day.label("date"),
            func.count(Asset.id).label("count"),
        ).where(
            Asset.org_id == org_id,
            Asset.first_seen >= since,
        ).group_by(asset_day)
        .order_by(asset_day)
    )).all()

    # New findings over time
    new_findings = (await db.execute(
        select(
            finding_day.label("date"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        ).where(
            Finding.org_id == org_id,
            Finding.first_seen >= since,
        ).group_by(
            finding_day,
            Finding.severity,
        ).order_by(finding_day)
    )).all()

    return {
        "new_assets": [{"date": r.date.isoformat(), "count": r.count} for r in new_assets],
        "new_findings": [
            {"date": r.date.isoformat(), "severity": r.severity, "count": r.count}
            for r in new_findings
        ],
    }


@router.get("/{org_id}/attack-surface-graph")
async def get_attack_surface_graph(
    org_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Org-wide attack-surface graph. Real `AssetRelationship` edges
    (resolves_to, shares_infrastructure) plus presentation-only Technology/
    Finding nodes -- neither Technology nor Finding is an asset-backed
    entity, so they can't be genuine AssetRelationship rows; they're built
    directly here instead, same as the frontend previously built them
    client-side."""
    await _get_org_or_404(db, org_id, workspace_id)

    # IP assets are touched far less often than subdomains (a port scan runs
    # once; DNS/HTTP rechecks on subdomains run constantly), so sorted by
    # last_seen desc they'd fall outside a single page's window -- fetched
    # separately and merged, same fix the frontend already needed before
    # this endpoint existed.
    subdomain_assets = (await db.execute(
        select(Asset).where(Asset.org_id == org_id, Asset.status == "active", Asset.deleted_at.is_(None))
        .order_by(Asset.last_seen.desc()).limit(200)
    )).scalars().all()
    ip_assets = (await db.execute(
        select(Asset).where(
            Asset.org_id == org_id, Asset.asset_type == "ip",
            Asset.status == "active", Asset.deleted_at.is_(None),
        ).order_by(Asset.last_seen.desc()).limit(200)
    )).scalars().all()

    assets_by_id: Dict[UUID, Asset] = {}
    for asset in [*subdomain_assets, *ip_assets]:
        assets_by_id[asset.id] = asset
    asset_ids = list(assets_by_id.keys())

    nodes: List[Dict[str, Any]] = [
        {
            "id": str(asset.id),
            "label": asset.value,
            "type": "ip" if asset.asset_type == "ip" else "domain",
            "data": {"criticality": asset.criticality, "status": asset.status},
        }
        for asset in assets_by_id.values()
    ]
    edges: List[Dict[str, Any]] = []

    if asset_ids:
        rel_rows = (await db.execute(
            select(AssetRelationship).where(
                or_(
                    AssetRelationship.source_asset_id.in_(asset_ids),
                    AssetRelationship.target_asset_id.in_(asset_ids),
                )
            )
        )).scalars().all()
        for rel in rel_rows:
            # Only keep edges where both ends are actually in this graph --
            # a relationship can reach outside the 200-asset window above.
            if rel.source_asset_id not in assets_by_id or rel.target_asset_id not in assets_by_id:
                continue
            edges.append({
                "id": str(rel.id),
                "source": str(rel.source_asset_id),
                "target": str(rel.target_asset_id),
                "label": rel.relationship_type,
                "type": rel.relationship_type,
            })

        tech_rows = (await db.execute(
            select(Technology).where(Technology.asset_id.in_(asset_ids))
        )).scalars().all()
        # Keyed by technology name (case-insensitive), not per (name, asset) --
        # "Apache HTTP Server" running on 30 assets is one shared node with 30
        # edges fanning in, not 30 separate nodes (confirmed real data: this
        # was the single largest contributor to graph-density noise).
        tech_nodes: Dict[str, Dict[str, Any]] = {}
        for tech in tech_rows:
            tech_key = tech.name.strip().lower()
            tech_node_id = f"tech-{tech_key}"
            entry = tech_nodes.setdefault(tech_node_id, {"label": tech.name, "count": 0})
            entry["count"] += 1
            edges.append({
                "id": f"tech-edge-{tech_node_id}-{tech.asset_id}",
                "source": str(tech.asset_id),
                "target": tech_node_id,
                "label": "runs",
                "type": "runs",
            })
        nodes.extend(
            {"id": tid, "label": v["label"], "type": "tech", "data": {"asset_count": v["count"]}}
            for tid, v in tech_nodes.items()
        )

        # Critical/high only, matching the frontend's pre-existing filter --
        # avoids clutter from the far larger set of medium/low/info findings.
        finding_rows = (await db.execute(
            select(Finding).where(
                Finding.asset_id.in_(asset_ids),
                Finding.status == "open",
                Finding.severity.in_(["critical", "high"]),
            ).limit(100)
        )).scalars().all()
        for finding in finding_rows:
            finding_node_id = f"finding-{finding.id}"
            nodes.append({
                "id": finding_node_id,
                "label": finding.title[:30],
                "type": "finding",
                "severity": finding.severity,
                "data": {
                    "severity": finding.severity,
                    "category": finding.category,
                    "cve_ids": finding.cve_ids or [],
                },
            })
            edges.append({
                "id": f"finding-edge-{finding_node_id}",
                "source": str(finding.asset_id),
                "target": finding_node_id,
                "label": "has",
                "type": "has_finding",
            })

    return {"nodes": nodes, "edges": edges}


@router.get("/{org_id}/network-clusters")
async def get_network_clusters(
    org_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Group subdomains by shared IP -- a real shared-hosting/blast-radius
    signal, replacing the node-link graph as the primary Attack Surface view
    (kept as a secondary 'Graph' tab, unmodified). Only hosts with at least
    one resolved IP are considered -- an unresolved host has no network
    position to cluster by (same scope boundary as the discovery-noise
    tuning work)."""
    await _get_org_or_404(db, org_id, workspace_id)

    rows = (await db.execute(
        select(Asset, Subdomain)
        .join(Subdomain, Subdomain.asset_id == Asset.id)
        .where(
            Asset.org_id == org_id,
            Asset.status == "active",
            Asset.deleted_at.is_(None),
            func.array_length(Subdomain.ip_addresses, 1) > 0,
        )
    )).all()

    hosts_by_id: Dict[UUID, Dict[str, Any]] = {}
    ips_by_asset: Dict[UUID, List[str]] = {}
    assets_by_ip: Dict[str, List[UUID]] = {}
    for asset, subdomain in rows:
        hosts_by_id[asset.id] = {
            "id": str(asset.id), "value": asset.value, "http_status": subdomain.http_status,
        }
        ips = list(dict.fromkeys(subdomain.ip_addresses or []))
        ips_by_asset[asset.id] = ips
        for ip in ips:
            assets_by_ip.setdefault(ip, []).append(asset.id)

    clustered_ids: set = set()
    cluster_groups: List[tuple] = []
    for ip, asset_ids in assets_by_ip.items():
        unique_ids = sorted(set(asset_ids), key=str)
        if len(unique_ids) >= 2:
            cluster_groups.append((ip, unique_ids))
            clustered_ids.update(unique_ids)

    standalone_ids = [aid for aid in hosts_by_id if aid not in clustered_ids]

    severity_rank = case(
        {sev: i for i, sev in enumerate(["critical", "high", "medium", "low", "info"])},
        value=Finding.severity, else_=99,
    )

    async def _severity_counts_and_top(asset_ids: List[UUID], top_n: int = 0):
        if not asset_ids:
            return {}, []
        counts_rows = (await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.asset_id.in_(asset_ids), Finding.status == "open", Finding.deleted_at.is_(None))
            .group_by(Finding.severity)
        )).all()
        counts = {sev: n for sev, n in counts_rows}
        top = []
        if top_n:
            top_rows = (await db.execute(
                select(Finding)
                .where(Finding.asset_id.in_(asset_ids), Finding.status == "open", Finding.deleted_at.is_(None))
                .order_by(severity_rank, Finding.last_seen.desc())
                .limit(top_n)
            )).scalars().all()
            asset_value_by_id = {aid: hosts_by_id[aid]["value"] for aid in asset_ids if aid in hosts_by_id}
            top = [
                {
                    "id": str(f.id), "title": f.title, "severity": f.severity,
                    "affected_host": asset_value_by_id.get(f.asset_id, ""),
                }
                for f in top_rows
            ]
        return counts, top

    clusters = []
    for ip, asset_ids in cluster_groups:
        tech_rows = (await db.execute(
            select(Technology.name).where(Technology.asset_id.in_(asset_ids)).distinct()
        )).scalars().all()
        severity_counts, top_findings = await _severity_counts_and_top(asset_ids, top_n=5)
        clusters.append({
            "ip": ip,
            "hosts": [hosts_by_id[aid] for aid in asset_ids],
            "host_count": len(asset_ids),
            "technologies": sorted(tech_rows),
            "severity_counts": severity_counts,
            "top_findings": top_findings,
        })
    clusters.sort(key=lambda c: c["host_count"], reverse=True)

    standalone_severity_by_asset: Dict[UUID, Dict[str, int]] = {}
    if standalone_ids:
        standalone_counts_rows = (await db.execute(
            select(Finding.asset_id, Finding.severity, func.count(Finding.id))
            .where(Finding.asset_id.in_(standalone_ids), Finding.status == "open", Finding.deleted_at.is_(None))
            .group_by(Finding.asset_id, Finding.severity)
        )).all()
        for aid, sev, n in standalone_counts_rows:
            standalone_severity_by_asset.setdefault(aid, {})[sev] = n

    standalone = [
        {
            **hosts_by_id[aid],
            "ip": (ips_by_asset.get(aid) or [None])[0],
            "severity_counts": standalone_severity_by_asset.get(aid, {}),
        }
        for aid in standalone_ids
    ]

    total_ips = (await db.execute(
        select(func.count(Asset.id)).where(
            Asset.org_id == org_id, Asset.asset_type == "ip",
            Asset.status == "active", Asset.deleted_at.is_(None),
        )
    )).scalar_one()

    return {
        "clusters": clusters,
        "standalone": standalone,
        "summary": {
            "clusters_found": len(clusters),
            "hosts_clustered": len(clustered_ids),
            "standalone_hosts": len(standalone_ids),
            "total_ips": total_ips,
        },
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


async def _scan_to_dict(scan: Scan) -> dict:
    phase_status = await merge_runtime_phase_status(str(scan.id), scan.phase_status or {})
    config = scan.config or {}
    return {
        "id": str(scan.id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "modules": scan.modules or [],
        "scan_profile": config.get("scan_profile"),
        "phase_status": phase_status,
        "progress_pct": scan.progress_pct,
        "total_tasks": scan.total_tasks,
        "completed_tasks": scan.completed_tasks,
        "failed_tasks": scan.failed_tasks,
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

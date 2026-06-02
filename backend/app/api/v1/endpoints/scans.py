import uuid
from datetime import datetime, timezone
from uuid import UUID
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, Scan, Organization
from app.services.scan_profiles import apply_scan_profile, normalize_scan_profile
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
    return {"items": [{"id": str(s.id), "org_id": str(s.org_id), "scan_type": s.scan_type,
                       "status": s.status, "progress_pct": s.progress_pct,
                       "assets_found": s.assets_found, "findings_found": s.findings_found,
                       "phase_status": s.phase_status or {},
                       "error_message": s.error_message,
                       "started_at": s.started_at.isoformat() if s.started_at else None,
                       "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                       "created_at": s.created_at.isoformat()} for s in scans], "total": total}

@router.get("/{scan_id}")
async def get_scan(scan_id: UUID, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    scan = result.scalar_one_or_none()
    if not scan: raise HTTPException(404, "Scan not found")
    return {"id": str(scan.id), "org_id": str(scan.org_id), "scan_type": scan.scan_type,
            "status": scan.status, "modules": scan.modules, "progress_pct": scan.progress_pct,
            "phase_status": scan.phase_status or {},
            "total_tasks": scan.total_tasks, "completed_tasks": scan.completed_tasks,
            "assets_found": scan.assets_found, "findings_found": scan.findings_found,
            "error_message": scan.error_message,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "created_at": scan.created_at.isoformat()}

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

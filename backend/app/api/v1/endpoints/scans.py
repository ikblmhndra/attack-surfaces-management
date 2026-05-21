import uuid
from uuid import UUID
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel

from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, Scan
from sqlalchemy import select, update, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])


class ManualScanRequest(BaseModel):
    org_id: str
    targets: List[str]
    config: dict = {}
    vuln_depth: str = "default"

@router.get("")
async def list_scans(org_id: Optional[UUID] = Query(None), status: Optional[str] = Query(None),
    page: int = Query(1), page_size: int = Query(20),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(Scan).where(Scan.workspace_id == workspace_id)
    if org_id: query = query.where(Scan.org_id == org_id)
    if status: query = query.where(Scan.status == status)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    scans = (await db.execute(query.order_by(Scan.created_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    return {"items": [{"id": str(s.id), "org_id": str(s.org_id), "scan_type": s.scan_type,
                       "status": s.status, "progress_pct": s.progress_pct,
                       "assets_found": s.assets_found, "findings_found": s.findings_found,
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
            "total_tasks": scan.total_tasks, "completed_tasks": scan.completed_tasks,
            "assets_found": scan.assets_found, "findings_found": scan.findings_found,
            "error_message": scan.error_message,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None}

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

    from app.core.queue_client import QueueClient

    scan_id = str(uuid.uuid4())

    await db.execute(
        pg_insert(Scan.__table__).values(
            id=scan_id,
            org_id=request.org_id,
            workspace_id=workspace_id,
            created_by=current_user.id,
            scan_type="manual_nuclei",
            status="pending",
            modules=["nuclei"],
            config={"targets": request.targets, "vuln_depth": request.vuln_depth, **request.config},
            total_tasks=1,
        )
    )
    await db.commit()

    try:
        queue = QueueClient()
        await queue.connect()

        # Publish directly to nuclei queue
        await queue.publish(
            routing_key="scan.nuclei",
            message={
                "scan_id": scan_id,
                "org_id": request.org_id,
                "workspace_id": str(workspace_id),
                "targets": request.targets,
                "config": {
                    "vuln_depth": request.vuln_depth,
                    "severities": ["critical", "high", "medium", "low"],
                    **request.config,
                },
            },
        )
        await queue.close()

        # Set up Redis coordinator: mark screenshot done so terminal check passes
        import redis.asyncio as aioredis
        import os
        r = aioredis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
        await r.incr(f"scan:{scan_id}:nuclei_expected")
        await r.setex(f"scan:{scan_id}:screenshot_done", 86400, 1)
        await r.expire(f"scan:{scan_id}:nuclei_expected", 86400)
        await r.aclose()

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
    await db.commit()
    return {"message": "Scan cancellation requested"}

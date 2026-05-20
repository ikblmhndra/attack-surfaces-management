from fastapi import APIRouter, Depends, Query, HTTPException
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db
from app.db.models.models import User, Scan
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

router = APIRouter()

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

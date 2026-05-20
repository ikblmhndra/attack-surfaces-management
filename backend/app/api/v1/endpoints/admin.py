from fastapi import APIRouter, Depends, Query
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, AuditLog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
from datetime import datetime, timedelta, timezone

router = APIRouter()

@router.get("/users")
async def list_users(workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User).where(User.workspace_id == workspace_id))).scalars().all()
    return {"items": [{"id": str(u.id), "email": u.email, "full_name": u.full_name,
                       "role": u.role, "is_active": u.is_active, "mfa_enabled": u.mfa_enabled} for u in users]}

@router.get("/audit-logs")
async def list_audit_logs(page: int = Query(1), page_size: int = Query(50),
    days: int = Query(30), workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = select(AuditLog).where(AuditLog.workspace_id == workspace_id, AuditLog.created_at >= since)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    logs = (await db.execute(query.order_by(AuditLog.created_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    return {"items": [{"id": str(l.id), "action": l.action, "resource_type": l.resource_type,
                       "ip_address": l.ip_address, "created_at": l.created_at.isoformat()} for l in logs], "total": total}

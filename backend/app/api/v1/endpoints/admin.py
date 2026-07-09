from fastapi import APIRouter, Depends, HTTPException, Query
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, AuditLog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from datetime import datetime, timedelta, timezone

router = APIRouter()

VALID_ROLES = {"owner", "admin", "analyst", "viewer"}

class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

@router.get("/users")
async def list_users(workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User).where(User.workspace_id == workspace_id))).scalars().all()
    return {"items": [{"id": str(u.id), "email": u.email, "full_name": u.full_name,
                       "role": u.role, "is_active": u.is_active, "mfa_enabled": u.mfa_enabled} for u in users]}

@router.put("/users/{user_id}")
async def update_user(user_id: UUID, request: UserUpdate,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == user_id, User.workspace_id == workspace_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    if request.role is not None:
        if request.role not in VALID_ROLES:
            raise HTTPException(400, f"Invalid role — must be one of {sorted(VALID_ROLES)}")
        user.role = request.role
    if request.is_active is not None:
        user.is_active = request.is_active
    await db.commit()
    return {"id": str(user.id), "email": user.email, "role": user.role, "is_active": user.is_active}

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

from fastapi import APIRouter, Depends, HTTPException, Query
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, Notification, NotificationRule
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, List
from uuid import UUID

router = APIRouter()

class NotificationRuleCreate(BaseModel):
    name: str; event_types: List[str]; channels: List[str]
    min_severity: str = "high"; config: dict = {}

class NotificationRuleUpdate(BaseModel):
    name: Optional[str] = None
    event_types: Optional[List[str]] = None
    channels: Optional[List[str]] = None
    min_severity: Optional[str] = None
    config: Optional[dict] = None
    is_active: Optional[bool] = None

@router.get("")
async def list_notifications(is_read: Optional[bool] = Query(None), page: int = Query(1),
    page_size: int = Query(20), workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    query = select(Notification).where(Notification.workspace_id == workspace_id)
    if is_read is not None: query = query.where(Notification.is_read == is_read)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    notifs = (await db.execute(query.order_by(Notification.created_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    return {"items": [{"id": str(n.id), "event_type": n.event_type, "severity": n.severity,
                       "title": n.title, "message": n.message, "is_read": n.is_read,
                       "created_at": n.created_at.isoformat()} for n in notifs], "total": total}

@router.post("/mark-all-read")
async def mark_all_read(workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(update(Notification).where(Notification.workspace_id == workspace_id, Notification.is_read == False).values(is_read=True))
    await db.commit(); return {"message": "All marked as read"}

@router.get("/rules")
async def list_rules(workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rules = (await db.execute(select(NotificationRule).where(NotificationRule.workspace_id == workspace_id))).scalars().all()
    return {"items": [{"id": str(r.id), "name": r.name, "channels": r.channels, "is_active": r.is_active} for r in rules]}

@router.post("/rules", status_code=201)
async def create_rule(request: NotificationRuleCreate, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    rule = NotificationRule(workspace_id=workspace_id, **request.model_dump())
    db.add(rule); await db.commit(); return {"id": str(rule.id)}

@router.put("/rules/{rule_id}")
async def update_rule(rule_id: UUID, request: NotificationRuleUpdate,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(NotificationRule).where(NotificationRule.id == rule_id, NotificationRule.workspace_id == workspace_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Notification rule not found")
    for key, value in request.model_dump(exclude_unset=True).items():
        setattr(rule, key, value)
    await db.commit()
    return {"id": str(rule.id)}

@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: UUID, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin"])), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(NotificationRule).where(NotificationRule.id == rule_id, NotificationRule.workspace_id == workspace_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Notification rule not found")
    await db.delete(rule)
    await db.commit()

@router.patch("/{notification_id}/read")
async def mark_notification_read(notification_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import update as sql_update
    result = await db.execute(
        sql_update(Notification).where(
            Notification.id == notification_id,
            Notification.workspace_id == workspace_id
        ).values(is_read=True)
    )
    await db.commit()
    if result.rowcount == 0:
        from fastapi import HTTPException
        raise HTTPException(404, "Notification not found")
    return {"message": "Marked as read"}

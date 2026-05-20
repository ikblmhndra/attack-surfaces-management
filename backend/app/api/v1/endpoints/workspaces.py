from fastapi import APIRouter, Depends
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, Workspace
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

router = APIRouter()

@router.get("")
async def get_workspace(
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = result.scalar_one_or_none()
    if not ws:
        from fastapi import HTTPException
        raise HTTPException(404, "Workspace not found")
    return {"id": str(ws.id), "name": ws.name, "slug": ws.slug,
            "plan": ws.plan, "is_active": ws.is_active,
            "max_organizations": ws.max_organizations, "created_at": ws.created_at.isoformat()}

@router.get("/members")
async def list_members(
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.db.models.models import User as UserModel
    result = await db.execute(
        select(UserModel).where(UserModel.workspace_id == workspace_id, UserModel.is_active == True)
    )
    users = result.scalars().all()
    return {"items": [{"id": str(u.id), "email": u.email, "full_name": u.full_name, "role": u.role} for u in users]}

@router.post("/invite")
async def invite_member(workspace_id: UUID = Depends(get_workspace_id),
                        current_user: User = Depends(RequireRole(["owner", "admin"]))):
    return {"message": "Invitation sent"}

@router.put("")
async def update_workspace(
    data: dict,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    from fastapi import HTTPException
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    ws = result.scalar_one_or_none()
    if not ws:
        raise HTTPException(404, "Workspace not found")
    if "name" in data:
        ws.name = data["name"]
    settings = dict(ws.settings) if ws.settings else {}
    for key in ("scan_interval_hours", "max_concurrent_scans", "auto_resolve_findings", "session_timeout", "auto_scan_enabled"):
        if key in data:
            settings[key] = data[key]
    ws.settings = settings
    await db.commit()
    return {"id": str(ws.id), "name": ws.name, "slug": ws.slug,
            "plan": ws.plan, "is_active": ws.is_active,
            "max_organizations": ws.max_organizations, "created_at": ws.created_at.isoformat()}

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, field_validator
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.core.config import settings
from app.db.models.models import User, Workspace
from app.services.audit_service import audit_log
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

router = APIRouter()

# Invitable roles -- "owner" is reserved for the account that created the
# workspace at registration, never granted through an invite.
INVITABLE_ROLES = {"admin", "analyst", "viewer"}
INVITE_TOKEN_EXPIRE_DAYS = 7


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        if value not in INVITABLE_ROLES:
            raise ValueError(f"role must be one of: {', '.join(sorted(INVITABLE_ROLES))}")
        return value

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
async def invite_member(
    request: InviteMemberRequest,
    req: Request,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    """Generate a signed, stateless invite token for this workspace -- same
    pattern as auth.py's forgot-password/reset-password tokens (jose JWT,
    `type` discriminator, no DB row, no migration needed). Not single-use or
    revocable, matching the same simplicity level as that existing pattern --
    anyone holding the link can join at the granted role until it expires.

    Delivery is deliberately the caller's problem, not this endpoint's: no
    SMTP is assumed to be configured. The token/link is returned directly in
    the response for an owner/admin to share however they like.
    """
    from jose import jwt

    invite_payload = {
        "wid": str(workspace_id),
        "role": request.role,
        "invited_email": request.email.lower(),
        "type": "workspace_invite",
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(days=INVITE_TOKEN_EXPIRE_DAYS)).timestamp()),
        "jti": secrets.token_hex(16),
    }
    invite_token = jwt.encode(invite_payload, settings.SECRET_KEY, algorithm="HS256")

    bg.add_task(
        audit_log,
        workspace_id=str(workspace_id),
        user_id=str(current_user.id),
        action="workspace.invite.create",
        resource_type="workspace",
        resource_id=str(workspace_id),
        changes={"invited_email": request.email.lower(), "role": request.role},
        ip_address=req.client.host if req.client else None,
    )

    return {
        "invite_token": invite_token,
        "invite_path": f"/auth/register?invite_token={invite_token}",
        "role": request.role,
        "expires_in_days": INVITE_TOKEN_EXPIRE_DAYS,
    }

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

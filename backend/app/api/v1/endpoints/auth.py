"""
ASM Platform — Authentication Endpoints
JWT-based auth with refresh tokens and MFA support.
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pyotp
import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_db
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
    hash_token,
)
from app.db.models.models import User, Workspace
from app.services.audit_service import audit_log
from app.services.user_service import UserService

log = structlog.get_logger()
router = APIRouter()

# A self-serve registration always creates a brand-new workspace (never
# joins an existing one -- see register() below), so product selection is a
# natural one-time choice made right here, not a per-user setting layered on
# top later. See Workspace.enabled_products.
PRODUCTS = {"asm", "bounty"}


# ── Schemas ───────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    workspace_name: str
    enabled_products: List[str] = Field(default_factory=lambda: ["asm"])
    invite_token: Optional[str] = None

    class Config:
        min_anystr_length = 1

    def validate_password(self) -> "RegisterRequest":
        if len(self.password) < 12:
            raise ValueError("Password must be at least 12 characters")
        return self

    @field_validator("enabled_products")
    @classmethod
    def validate_enabled_products(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("Choose at least one product: asm, bounty")
        invalid = set(value) - PRODUCTS
        if invalid:
            raise ValueError(f"Unknown product(s): {', '.join(sorted(invalid))}. Must be one of: {', '.join(sorted(PRODUCTS))}")
        return sorted(set(value))


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    workspace_id: str
    role: str
    enabled_products: List[str] = Field(default_factory=lambda: ["asm"])


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAEnableResponse(BaseModel):
    secret: str
    qr_uri: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    code: str
    secret: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# ── Endpoints ─────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
    bg: BackgroundTasks = BackgroundTasks(),
):
    """Register a new user. Joins an existing workspace if a valid
    invite_token is supplied (see workspaces.py::invite_member); otherwise
    always creates a brand-new workspace, same as before."""
    user_service = UserService(db)

    # Check if email already exists
    existing = await user_service.get_by_email(request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    invited_workspace = None
    invited_role = "owner"
    if request.invite_token:
        from jose import JWTError, jwt
        try:
            invite_payload = jwt.decode(request.invite_token, settings.SECRET_KEY, algorithms=["HS256"])
        except JWTError:
            raise HTTPException(status_code=400, detail="Invalid or expired invite token")
        if invite_payload.get("type") != "workspace_invite":
            raise HTTPException(status_code=400, detail="Invalid invite token")
        result = await db.execute(
            select(Workspace).where(Workspace.id == invite_payload["wid"], Workspace.is_active == True)
        )
        invited_workspace = result.scalar_one_or_none()
        if not invited_workspace:
            raise HTTPException(status_code=400, detail="Invite token's workspace no longer exists")
        invited_role = invite_payload["role"]

    if invited_workspace:
        # Joining an existing workspace -- product entitlement and workspace
        # identity come from the invite, not from this request (a request
        # here can't be trusted to self-assign products/workspace).
        workspace = invited_workspace
    else:
        # No invite -- create workspace + owner user, same as always.
        workspace = Workspace(
            name=request.workspace_name,
            slug=_slugify(request.workspace_name),
            enabled_products=request.enabled_products,
        )
        db.add(workspace)
        await db.flush()

    user = User(
        workspace_id=workspace.id,
        email=request.email.lower(),
        password_hash=get_password_hash(request.password),
        full_name=request.full_name,
        role=invited_role,
        is_verified=False,
        last_login=datetime.now(timezone.utc),
        last_login_ip=_get_client_ip(req),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    log.info("user_registered", user_id=str(user.id), email=user.email, via_invite=bool(invited_workspace))

    # Generate tokens
    access_token = create_access_token(
        subject=str(user.id),
        workspace_id=str(workspace.id),
        role=user.role,
        extra_claims={"products": workspace.enabled_products},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    # Store refresh token hash
    user.refresh_token_hash = hash_token(refresh_token)
    user.refresh_token_expires = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    await db.commit()

    bg.add_task(
        audit_log,
        workspace_id=str(workspace.id),
        user_id=str(user.id),
        action="user.register.via_invite" if invited_workspace else "user.register",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=_get_client_ip(req),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=str(user.id),
        workspace_id=str(workspace.id),
        role=user.role,
        enabled_products=workspace.enabled_products,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
    bg: BackgroundTasks = BackgroundTasks(),
):
    """Authenticate user and return JWT tokens."""
    user_service = UserService(db)
    user = await user_service.get_by_email(request.email.lower())

    if not user or not verify_password(request.password, user.password_hash):
        log.warning("login_failed", email=request.email, ip=_get_client_ip(req))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # MFA check
    if user.mfa_enabled:
        if not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_428_PRECONDITION_REQUIRED,
                detail="MFA code required",
                headers={"X-MFA-Required": "true"},
            )
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(request.mfa_code, valid_window=1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )

    enabled_products = (await db.execute(
        select(Workspace.enabled_products).where(Workspace.id == user.workspace_id)
    )).scalar_one_or_none() or ["asm"]

    # Generate tokens
    access_token = create_access_token(
        subject=str(user.id),
        workspace_id=str(user.workspace_id),
        role=user.role,
        extra_claims={"products": enabled_products},
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    # Update user
    user.last_login = datetime.now(timezone.utc)
    user.last_login_ip = _get_client_ip(req)
    user.refresh_token_hash = hash_token(refresh_token)
    user.refresh_token_expires = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    await db.commit()

    log.info("user_login", user_id=str(user.id), ip=_get_client_ip(req))

    bg.add_task(
        audit_log,
        workspace_id=str(user.workspace_id),
        user_id=str(user.id),
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=_get_client_ip(req),
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=str(user.id),
        workspace_id=str(user.workspace_id),
        role=user.role,
        enabled_products=enabled_products,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a valid refresh token for new token pair."""
    payload = verify_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_by_id(payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Verify stored token hash
    if not user.refresh_token_hash or user.refresh_token_hash != hash_token(request.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    if user.refresh_token_expires and user.refresh_token_expires < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    enabled_products = (await db.execute(
        select(Workspace.enabled_products).where(Workspace.id == user.workspace_id)
    )).scalar_one_or_none() or ["asm"]

    # Issue new token pair (rotation)
    access_token = create_access_token(
        subject=str(user.id),
        workspace_id=str(user.workspace_id),
        role=user.role,
        extra_claims={"products": enabled_products},
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    user.refresh_token_hash = hash_token(new_refresh_token)
    user.refresh_token_expires = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=str(user.id),
        workspace_id=str(user.workspace_id),
        role=user.role,
        enabled_products=enabled_products,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invalidate the current user's refresh token."""
    current_user.refresh_token_hash = None
    current_user.refresh_token_expires = None
    await db.commit()
    log.info("user_logout", user_id=str(current_user.id))


@router.post("/mfa/setup", response_model=MFAEnableResponse)
async def mfa_setup(
    current_user: User = Depends(get_current_user),
):
    """Generate TOTP secret for MFA setup. Does not enable MFA until verified."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="ASM Platform",
    )
    backup_codes = [secrets.token_hex(6).upper() for _ in range(8)]

    return MFAEnableResponse(
        secret=secret,
        qr_uri=qr_uri,
        backup_codes=backup_codes,
    )


@router.post("/mfa/enable", status_code=status.HTTP_200_OK)
async def mfa_enable(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enable MFA after verifying the provided TOTP code."""
    totp = pyotp.TOTP(request.secret)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Please try again.",
        )

    current_user.mfa_enabled = True
    current_user.mfa_secret = request.secret
    await db.commit()

    log.info("mfa_enabled", user_id=str(current_user.id))
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable", status_code=status.HTTP_200_OK)
async def mfa_disable(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA after verifying current TOTP code."""
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.commit()

    log.info("mfa_disabled", user_id=str(current_user.id))
    return {"message": "MFA disabled successfully"}


@router.get("/me")
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current authenticated user profile."""
    enabled_products = (await db.execute(
        select(Workspace.enabled_products).where(Workspace.id == current_user.workspace_id)
    )).scalar_one_or_none() or ["asm"]
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "workspace_id": str(current_user.workspace_id),
        "enabled_products": enabled_products,
        "mfa_enabled": current_user.mfa_enabled,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat(),
    }


@router.put("/me")
async def update_me(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile."""
    if "full_name" in data:
        current_user.full_name = data["full_name"]
    await db.commit()
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "workspace_id": str(current_user.workspace_id),
        "mfa_enabled": current_user.mfa_enabled,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "created_at": current_user.created_at.isoformat(),
    }


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user's password."""
    if not verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if len(request.new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 12 characters",
        )
    current_user.password_hash = get_password_hash(request.new_password)
    current_user.refresh_token_hash = None
    current_user.refresh_token_expires = None
    await db.commit()
    log.info("password_changed", user_id=str(current_user.id))
    return {"message": "Password changed successfully"}


@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
):
    """Request a password reset email."""
    from app.core.security import verify_token
    from app.services.user_service import UserService
    user_service = UserService(db)
    user = await user_service.get_by_email(request.email.lower())
    if user:
        reset_payload = {
            "sub": str(user.id),
            "type": "password_reset",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "jti": secrets.token_hex(16),
        }
        from jose import jwt
        reset_token = jwt.encode(reset_payload, settings.SECRET_KEY, algorithm="HS256")
        log.info("password_reset_requested", user_id=str(user.id), reset_token=reset_token[:20])
    return {"message": "If the email exists, a reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Reset password using a reset token."""
    from jose import JWTError, jwt
    from app.services.user_service import UserService
    try:
        payload = jwt.decode(request.token, settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    if payload.get("type") != "password_reset":
        raise HTTPException(status_code=400, detail="Invalid reset token")
    user_service = UserService(db)
    user = await user_service.get_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if len(request.new_password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    user.password_hash = get_password_hash(request.new_password)
    user.refresh_token_hash = None
    user.refresh_token_expires = None
    await db.commit()
    log.info("password_reset_completed", user_id=str(user.id))
    return {"message": "Password reset successfully"}


# ── Helpers ───────────────────────────────────────────────────

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _slugify(name: str) -> str:
    import re
    slug = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[\s_-]+", "-", slug).strip("-")
    return slug[:100] + "-" + secrets.token_hex(4)

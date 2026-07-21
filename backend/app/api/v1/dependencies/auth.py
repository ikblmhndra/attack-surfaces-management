"""
ASM Platform — Auth Dependencies
FastAPI dependencies for JWT/API key auth and RBAC enforcement.
"""
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session as get_db
from app.core.security import verify_token, verify_api_key, hash_token
from app.db.models.models import APIKey, User, Workspace

log = structlog.get_logger()

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Token extraction ──────────────────────────────────────────

async def get_token_payload(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Extract and validate auth token from either:
    - Bearer JWT token (Authorization header)
    - API key (X-API-Key header)

    Returns decoded token payload dict.
    """
    # ── Try Bearer JWT first ──────────────────────────────────
    if bearer and bearer.credentials:
        payload = verify_token(bearer.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )
        return payload

    # ── Try API key ───────────────────────────────────────────
    if api_key:
        # Look up by prefix (first 12 chars)
        key_prefix = api_key[:12]
        result = await db.execute(
            select(APIKey).where(
                APIKey.key_prefix == key_prefix,
                APIKey.is_active == True,
            )
        )
        key_record = result.scalar_one_or_none()

        if not key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        # Verify hash
        if not verify_api_key(api_key, key_record.key_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        # Check expiry
        if key_record.expires_at and key_record.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )

        # Update last used (non-blocking)
        key_record.last_used_at = datetime.now(timezone.utc)
        key_record.usage_count += 1
        try:
            await db.commit()
        except Exception:
            pass

        # Fetch user for API key
        user_result = await db.execute(
            select(User).where(User.id == key_record.user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key owner not found or disabled",
            )

        return {
            "sub": str(user.id),
            "wid": str(key_record.workspace_id),
            "role": user.role,
            "type": "api_key",
            "scopes": key_record.scopes or [],
        }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Current user dependency ───────────────────────────────────

async def get_current_user(
    payload: dict = Depends(get_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the authenticated user from the token payload."""
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject",
        )

    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account disabled",
        )

    return user


# ── Workspace ID extraction ───────────────────────────────────

async def get_workspace_id(
    payload: dict = Depends(get_token_payload),
) -> UUID:
    """Extract workspace ID from token for row-level scoping."""
    workspace_id = payload.get("wid")
    if not workspace_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No workspace context in token",
        )
    try:
        return UUID(workspace_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid workspace ID in token",
        )


# ── RBAC enforcement ──────────────────────────────────────────

class RequireRole:
    """
    Dependency factory for role-based access control.

    Usage:
        require_admin = RequireRole(["owner", "admin"])

        @router.delete("/{id}")
        async def delete(user: User = Depends(require_admin)):
            ...
    """

    ROLE_HIERARCHY = {
        "owner": 4,
        "admin": 3,
        "analyst": 2,
        "viewer": 1,
    }

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(
        self,
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in self.allowed_roles:
            log.warning(
                "rbac_denied",
                user_id=str(current_user.id),
                user_role=current_user.role,
                required_roles=self.allowed_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {' or '.join(self.allowed_roles)}",
            )
        return current_user


class RequireMinRole:
    """
    Dependency factory for minimum role level enforcement.
    Owner > Admin > Analyst > Viewer
    """

    ROLE_HIERARCHY = {
        "owner": 4,
        "admin": 3,
        "analyst": 2,
        "viewer": 1,
    }

    def __init__(self, min_role: str):
        self.min_level = self.ROLE_HIERARCHY.get(min_role, 0)

    def __call__(
        self,
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_level = self.ROLE_HIERARCHY.get(current_user.role, 0)
        if user_level < self.min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user


# Pre-built role dependencies
require_viewer  = RequireMinRole("viewer")
require_analyst = RequireMinRole("analyst")
require_admin   = RequireMinRole("admin")
require_owner   = RequireRole(["owner"])


# ── Product entitlement enforcement ───────────────────────────

class RequireProduct:
    """
    Dependency factory for per-workspace product entitlement (ASM vs Bug
    Bounty vs both -- chosen once at registration, see
    Workspace.enabled_products). Complements RBAC (role), doesn't replace
    it: a workspace not entitled to a product gets 403 regardless of the
    requesting user's own role within it. Meant for router-level wiring
    (`include_router(..., dependencies=[Depends(require_bounty_product)])`)
    so an entire product's endpoint surface is gated in one place rather
    than every individual endpoint.

    A JWT bearer token carries its workspace's product list as a claim (set
    at register/login/refresh -- see auth.py) so the common path costs no
    extra query. An API key token doesn't carry that claim (it's long-
    lived, so trusting a claim embedded at issue time would go stale if the
    workspace's entitlement changes later) -- falls back to a fresh DB
    lookup in that case.

    Usage:
        require_bounty_product = RequireProduct("bounty")

        api_router.include_router(bounty.router, dependencies=[Depends(require_bounty_product)])
    """

    def __init__(self, product: str):
        self.product = product

    async def __call__(
        self,
        payload: dict = Depends(get_token_payload),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        products = payload.get("products")
        if products is None:
            result = await db.execute(
                select(Workspace.enabled_products).where(Workspace.id == payload.get("wid"))
            )
            products = result.scalar_one_or_none() or []
        if self.product not in products:
            log.warning(
                "product_access_denied",
                workspace_id=payload.get("wid"),
                required_product=self.product,
                enabled_products=products,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This workspace isn't enabled for '{self.product}'. Enabled: {', '.join(products) or 'none'}",
            )
        return payload


require_asm_product = RequireProduct("asm")
require_bounty_product = RequireProduct("bounty")


# ── Workspace isolation check ─────────────────────────────────

async def verify_workspace_access(
    resource_workspace_id: str,
    current_workspace_id: UUID,
) -> None:
    """
    Verify a resource belongs to the current workspace.
    Raises 403 if workspace mismatch detected.
    """
    if str(resource_workspace_id) != str(current_workspace_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: resource belongs to another workspace",
        )


# ── Scope check for API keys ──────────────────────────────────

def require_scope(scope: str):
    """Check that an API key has the required scope."""
    async def _check(payload: dict = Depends(get_token_payload)) -> dict:
        if payload.get("type") == "api_key":
            scopes = payload.get("scopes", [])
            if scope not in scopes and "*" not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing required scope: {scope}",
                )
        return payload
    return _check


# ── Rate limiting dependency ──────────────────────────────────

class RateLimiter:
    """
    Redis-backed rate limiter using sliding window algorithm.
    """

    def __init__(self, requests: int = 100, window_seconds: int = 60):
        self.requests = requests
        self.window = window_seconds

    async def __call__(
        self,
        request: Request,
        payload: dict = Depends(get_token_payload),
    ) -> None:
        from app.core.redis_client import redis_client
        from app.core.security import get_rate_limit_key

        identifier = payload.get("sub", request.client.host if request.client else "anon")
        key = get_rate_limit_key(identifier, request.url.path)

        try:
            current = await redis_client.incr(key)
            if current == 1:
                await redis_client.expire(key, self.window)

            if current > self.requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={
                        "Retry-After": str(self.window),
                        "X-RateLimit-Limit": str(self.requests),
                        "X-RateLimit-Remaining": "0",
                    },
                )
        except HTTPException:
            raise
        except Exception as e:
            log.warning("rate_limit_check_failed", error=str(e))
            # Fail open on Redis errors

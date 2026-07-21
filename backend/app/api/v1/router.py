"""
ASM Platform — API v1 Router
Aggregates all endpoint routers.
"""
from fastapi import APIRouter, Depends

from app.api.v1.dependencies.auth import require_asm_product, require_bounty_product
from app.api.v1.endpoints import (
    auth,
    workspaces,
    organizations,
    assets,
    scans,
    findings,
    scores,
    search,
    notifications,
    reports,
    admin,
    keys,
    websocket,
    intel,
    screenshots,
    templates,
    bounty,
)

api_router = APIRouter()

# Cross-cutting / account-level -- never product-gated: auth has to work
# before any product is even known, and workspaces/notifications/admin/keys/
# websocket/search all serve every workspace regardless of which product(s)
# it's entitled to (e.g. a bounty-only workspace still configures its own
# notification channels through the same NotificationRule rows an asm
# workspace would).
api_router.include_router(auth.router,          prefix="/auth",          tags=["Authentication"])
api_router.include_router(workspaces.router,    prefix="/workspaces",    tags=["Workspaces"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(admin.router,         prefix="/admin",         tags=["Admin"])
api_router.include_router(keys.router,          prefix="/keys",          tags=["API Keys"])
api_router.include_router(websocket.router,     prefix="/ws",            tags=["WebSocket"])
api_router.include_router(search.router,        prefix="/search",        tags=["Search"])

# ASM-specific -- gated on Workspace.enabled_products containing "asm".
_asm = [Depends(require_asm_product)]
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"], dependencies=_asm)
api_router.include_router(assets.router,        prefix="/assets",        tags=["Assets"],         dependencies=_asm)
api_router.include_router(scans.router,         prefix="/scans",         tags=["Scans"],          dependencies=_asm)
api_router.include_router(findings.router,      prefix="/findings",      tags=["Findings"],       dependencies=_asm)
api_router.include_router(scores.router,        prefix="/scores",        tags=["Risk Scores"],    dependencies=_asm)
api_router.include_router(intel.router,         prefix="/intel",         tags=["Threat Intelligence"], dependencies=_asm)
api_router.include_router(reports.router,       prefix="/reports",       tags=["Reports"],        dependencies=_asm)
api_router.include_router(screenshots.router,   prefix="/screenshots",   tags=["Screenshots"],    dependencies=_asm)
api_router.include_router(templates.router,     prefix="/templates",     tags=["Scan Templates"], dependencies=_asm)

# Bug Bounty -- gated on Workspace.enabled_products containing "bounty".
api_router.include_router(bounty.router,        prefix="/bounty",        tags=["Bug Bounty"], dependencies=[Depends(require_bounty_product)])

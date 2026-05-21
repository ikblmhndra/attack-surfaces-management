"""
ASM Platform — API v1 Router
Aggregates all endpoint routers.
"""
from fastapi import APIRouter

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
)

api_router = APIRouter()

api_router.include_router(auth.router,          prefix="/auth",          tags=["Authentication"])
api_router.include_router(workspaces.router,    prefix="/workspaces",    tags=["Workspaces"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(assets.router,        prefix="/assets",        tags=["Assets"])
api_router.include_router(scans.router,         prefix="/scans",         tags=["Scans"])
api_router.include_router(findings.router,      prefix="/findings",      tags=["Findings"])
api_router.include_router(scores.router,        prefix="/scores",        tags=["Risk Scores"])
api_router.include_router(intel.router,         prefix="/intel",         tags=["Threat Intelligence"])
api_router.include_router(search.router,        prefix="/search",        tags=["Search"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(reports.router,       prefix="/reports",       tags=["Reports"])
api_router.include_router(admin.router,         prefix="/admin",         tags=["Admin"])
api_router.include_router(keys.router,          prefix="/keys",          tags=["API Keys"])
api_router.include_router(screenshots.router,   prefix="/screenshots",   tags=["Screenshots"])
api_router.include_router(websocket.router,     prefix="/ws",            tags=["WebSocket"])
api_router.include_router(templates.router,    prefix="/templates",     tags=["Scan Templates"])

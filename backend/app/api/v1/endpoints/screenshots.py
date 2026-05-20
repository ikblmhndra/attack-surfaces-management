"""
ASM Platform — Screenshots API
Global screenshot gallery with pagination, org filter, and search.
"""
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_db, get_workspace_id
from app.db.models.models import Asset, Screenshot, User

log = structlog.get_logger()

router = APIRouter()


@router.get("")
async def list_screenshots(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    org_id: UUID | None = Query(None),
    search: str | None = Query(None),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    base_q = (
        select(Screenshot, Asset.value)
        .join(Asset, Screenshot.asset_id == Asset.id)
        .where(Asset.workspace_id == workspace_id, Asset.deleted_at.is_(None))
    )

    if org_id:
        base_q = base_q.where(Screenshot.org_id == org_id)

    if search:
        base_q = base_q.where(Asset.value.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(base_q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    base_q = base_q.order_by(Screenshot.captured_at.desc())
    base_q = base_q.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(base_q)).all()

    items = [
        {
            "id": str(s.id),
            "url": f"/storage/screenshots/{s.storage_path}",
            "thumbnail_url": f"/storage/screenshots/{s.thumbnail_path}" if s.thumbnail_path else None,
            "captured_at": s.captured_at.isoformat(),
            "http_status": s.http_status,
            "file_size": s.file_size,
            "is_current": s.is_current,
            "asset_value": asset_value,
        }
        for s, asset_value in rows
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
    }

from fastapi import APIRouter, Depends, Query
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db
from app.db.models.models import User, ThreatIntel, Asset
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

router = APIRouter()

@router.get("")
async def list_intel(org_id: Optional[UUID] = Query(None), is_malicious: Optional[bool] = Query(None),
    page: int = Query(1), page_size: int = Query(50),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    query = select(ThreatIntel).join(Asset, Asset.id == ThreatIntel.asset_id).where(Asset.workspace_id == workspace_id)
    if org_id: query = query.where(ThreatIntel.org_id == org_id)
    if is_malicious is not None: query = query.where(ThreatIntel.is_malicious == is_malicious)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    items = (await db.execute(query.order_by(ThreatIntel.enriched_at.desc()).offset((page-1)*page_size).limit(page_size))).scalars().all()
    return {"items": [{"id": str(i.id), "source": i.source, "is_malicious": i.is_malicious,
                       "risk_score": i.risk_score, "tags": i.tags,
                       "enriched_at": i.enriched_at.isoformat()} for i in items], "total": total}

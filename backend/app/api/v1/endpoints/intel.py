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
    query = select(ThreatIntel, Asset.value).join(Asset, Asset.id == ThreatIntel.asset_id).where(Asset.workspace_id == workspace_id)
    if org_id: query = query.where(ThreatIntel.org_id == org_id)
    if is_malicious is not None: query = query.where(ThreatIntel.is_malicious == is_malicious)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (await db.execute(query.order_by(ThreatIntel.enriched_at.desc()).offset((page-1)*page_size).limit(page_size))).all()
    # `data` is the rich JSONB payload (asn/isp/bgp_prefix/cloud_provider/is_cdn/is_hosting for the
    # no-key network_baseline source) — previously omitted here, leaving the frontend with only
    # risk_score/tags/categories, which the no-key enrichment path never populates (see CLAUDE.md).
    return {"items": [{"id": str(i.id), "asset_id": str(i.asset_id), "asset_value": value,
                       "source": i.source, "indicator_type": i.indicator_type,
                       "is_malicious": i.is_malicious, "risk_score": i.risk_score,
                       "tags": i.tags, "categories": i.categories, "data": i.data,
                       "enriched_at": i.enriched_at.isoformat()} for i, value in rows], "total": total}

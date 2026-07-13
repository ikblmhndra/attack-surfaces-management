from fastapi import APIRouter, Depends, Query
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db
from app.db.models.models import User, RiskScore
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta, timezone

router = APIRouter()

@router.get("")
async def list_scores(org_id: Optional[UUID] = Query(None),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(RiskScore).where(RiskScore.workspace_id == workspace_id)
    if org_id:
        query = query.where(RiskScore.org_id == org_id)
    query = query.order_by(RiskScore.computed_at.desc()).limit(50)
    scores = (await db.execute(query)).scalars().all()
    return {"items": [{"id": str(s.id), "org_id": str(s.org_id), "overall_score": s.overall_score,
                       "grade": s.grade, "critical": s.critical_count, "high": s.high_count,
                       "medium": s.medium_count, "low": s.low_count, "info": s.info_count,
                       "total_findings": s.total_findings,
                       "total_assets": s.total_assets, "computed_at": s.computed_at.isoformat()} for s in scores]}

@router.get("/history")
async def score_history(org_id: Optional[UUID] = Query(None), days: int = Query(90),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = select(RiskScore).where(RiskScore.workspace_id == workspace_id, RiskScore.computed_at >= since)
    if org_id:
        query = query.where(RiskScore.org_id == org_id)
    scores = (await db.execute(query.order_by(RiskScore.computed_at.asc()))).scalars().all()
    return {"history": [{"date": s.computed_at.isoformat(), "score": s.overall_score, "grade": s.grade, "org_id": str(s.org_id), "score_version": s.score_version} for s in scores]}

@router.get("/breakdown")
async def score_breakdown(org_id: UUID = Query(...),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RiskScore).where(RiskScore.org_id == org_id, RiskScore.workspace_id == workspace_id).order_by(RiskScore.computed_at.desc()).limit(1))
    score = result.scalar_one_or_none()
    if not score:
        from fastapi import HTTPException; raise HTTPException(404, "No score computed yet")
    return {"breakdown": score.score_breakdown, "factors": score.score_factors, "overall": score.overall_score, "grade": score.grade}

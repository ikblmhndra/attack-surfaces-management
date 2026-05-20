from fastapi import APIRouter, Depends, HTTPException
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db
from app.db.models.models import User, APIKey
from app.core.security import generate_api_key
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID
from datetime import datetime

router = APIRouter()

class APIKeyCreate(BaseModel):
    name: str; scopes: List[str] = ["read"]; expires_at: Optional[datetime] = None

@router.get("")
async def list_keys(workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    keys = (await db.execute(select(APIKey).where(APIKey.workspace_id == workspace_id, APIKey.is_active == True))).scalars().all()
    return {"items": [{"id": str(k.id), "name": k.name, "key_prefix": k.key_prefix,
                       "scopes": k.scopes, "usage_count": k.usage_count} for k in keys]}

@router.post("", status_code=201)
async def create_key(request: APIKeyCreate, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    raw_key, key_hash, key_prefix = generate_api_key()
    key = APIKey(workspace_id=workspace_id, user_id=current_user.id, name=request.name,
                 key_hash=key_hash, key_prefix=key_prefix, scopes=request.scopes, expires_at=request.expires_at)
    db.add(key); await db.commit()
    return {"id": str(key.id), "key": raw_key, "message": "Save this key — it will not be shown again"}

@router.delete("/{key_id}", status_code=204)
async def delete_key(key_id: UUID, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.workspace_id == workspace_id))
    key = result.scalar_one_or_none()
    if not key: raise HTTPException(404, "API key not found")
    key.is_active = False; await db.commit()

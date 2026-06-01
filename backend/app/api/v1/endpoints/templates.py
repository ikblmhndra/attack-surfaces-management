from fastapi import APIRouter, Depends, HTTPException
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import User, ScanTemplate
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID

router = APIRouter()

class ScanTemplateCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scan_type: str = "full"
    modules: List[str] = ["discovery", "dns", "probe", "port", "crawl", "nuclei", "screenshot", "enrich"]
    config: dict = {}
    severities: List[str] = ["critical", "high", "medium", "low"]
    tags: List[str] = []
    is_default: bool = False

class ScanTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scan_type: Optional[str] = None
    modules: Optional[List[str]] = None
    config: Optional[dict] = None
    severities: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None

@router.get("")
async def list_templates(
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(ScanTemplate).where(ScanTemplate.workspace_id == workspace_id)
    templates = (await db.execute(query.order_by(ScanTemplate.is_default.desc(), ScanTemplate.name))).scalars().all()
    return {
        "items": [{
            "id": str(t.id),
            "name": t.name,
            "description": t.description,
            "scan_type": t.scan_type,
            "modules": t.modules,
            "severities": t.severities,
            "tags": t.tags,
            "is_active": t.is_active,
            "is_default": t.is_default,
            "created_at": t.created_at.isoformat(),
        } for t in templates],
    }

@router.post("", status_code=201)
async def create_template(
    request: ScanTemplateCreate,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner", "admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    if request.is_default:
        await db.execute(
            update(ScanTemplate).where(
                ScanTemplate.workspace_id == workspace_id,
                ScanTemplate.is_default == True,
            ).values(is_default=False)
        )
    tmpl = ScanTemplate(
        workspace_id=workspace_id,
        created_by=current_user.id,
        **request.model_dump(),
    )
    db.add(tmpl)
    await db.commit()
    return {"id": str(tmpl.id)}

@router.get("/{template_id}")
async def get_template(
    template_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.workspace_id == workspace_id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Template not found")
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "scan_type": t.scan_type,
        "modules": t.modules,
        "config": t.config,
        "severities": t.severities,
        "tags": t.tags,
        "is_active": t.is_active,
        "is_default": t.is_default,
        "created_at": t.created_at.isoformat(),
        "updated_at": t.updated_at.isoformat(),
    }

@router.patch("/{template_id}")
async def update_template(
    template_id: UUID,
    request: ScanTemplateUpdate,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner", "admin", "analyst"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.workspace_id == workspace_id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Template not found")
    update_data = request.model_dump(exclude_unset=True)
    if update_data.get("is_default"):
        await db.execute(
            update(ScanTemplate).where(
                ScanTemplate.workspace_id == workspace_id,
                ScanTemplate.is_default == True,
                ScanTemplate.id != template_id,
            ).values(is_default=False)
        )
    for key, value in update_data.items():
        setattr(t, key, value)
    await db.commit()
    return {"message": "Template updated"}

@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner", "admin"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.workspace_id == workspace_id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Template not found")
    await db.delete(t)
    await db.commit()

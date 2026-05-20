from fastapi import APIRouter, Depends
from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, RequireRole
from app.db.models.models import User
from pydantic import BaseModel
from uuid import UUID

router = APIRouter()

class ReportRequest(BaseModel):
    org_id: str; report_type: str = "executive"; format: str = "pdf"

@router.post("/generate", status_code=202)
async def generate_report(request: ReportRequest, workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(RequireRole(["owner","admin","analyst"]))):
    return {"report_id": "pending", "status": "queued", "estimated_seconds": 30}

from typing import Any, Dict, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import Organization, Report, User
from app.services import report_service

log = structlog.get_logger()
router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])

class ReportGenerateRequest(BaseModel):
    org_id: str
    report_type: str = "executive"
    format: str = "pdf"
    date_range_days: int = 30
    include_charts: bool = True
    include_evidence: bool = True

@router.post("/generate", status_code=202)
async def generate_report(
    request: ReportGenerateRequest,
    bg: BackgroundTasks,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    org = await db.execute(
        select(Organization).where(Organization.id == request.org_id, Organization.workspace_id == workspace_id)
    )
    org = org.scalar_one_or_none()
    if not org:
        raise HTTPException(404, "Organization not found")

    report = Report(
        org_id=request.org_id,
        workspace_id=workspace_id,
        created_by=current_user.id,
        report_type=request.report_type,
        format=request.format,
        status="pending",
        title=f"{request.report_type.title()} Report — {org.name}",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    bg.add_task(
        report_service.generate_report,
        str(report.id),
        request.org_id,
        str(workspace_id),
        request.report_type,
        request.format,
        request.date_range_days,
        request.include_charts,
        request.include_evidence,
    )

    return {
        "report_id": str(report.id),
        "status": "queued",
        "message": "Report generation started. Check /api/v1/reports/{report_id} for status.",
    }

@router.get("")
async def list_reports(
    org_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(Report).where(Report.workspace_id == workspace_id)
    if org_id:
        query = query.where(Report.org_id == org_id)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    reports = (await db.execute(
        query.order_by(Report.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return {
        "items": [{
            "id": str(r.id),
            "org_id": str(r.org_id),
            "report_type": r.report_type,
            "format": r.format,
            "title": r.title,
            "status": r.status,
            "stats": r.stats,
            "download_url": f"/api/v1/reports/{r.id}/download" if r.status == "completed" else None,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "created_at": r.created_at.isoformat(),
        } for r in reports],
        "total": total,
    }

@router.get("/{report_id}")
async def get_report(
    report_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.workspace_id == workspace_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")
    return {
        "id": str(report.id),
        "org_id": str(report.org_id),
        "report_type": report.report_type,
        "format": report.format,
        "title": report.title,
        "status": report.status,
        "summary": report.summary,
        "data": report.data,
        "stats": report.stats,
        "download_url": f"/api/v1/reports/{report.id}/download" if report.status == "completed" else None,
        "generated_at": report.generated_at.isoformat() if report.generated_at else None,
        "error_message": report.error_message,
        "created_at": report.created_at.isoformat(),
    }

@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse, JSONResponse
    import csv
    import io

    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.workspace_id == workspace_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")
    if report.status != "completed":
        raise HTTPException(400, "Report is not yet generated")

    data: Dict[str, Any] = report.data or {}
    filename_slug = str(report.id)[:8]

    if report.format == "pdf":
        if not report.file_path:
            raise HTTPException(500, "Report PDF is missing its stored file")
        from app.core.config import settings
        from app.core.minio_client import get_minio
        import asyncio

        bucket, key = settings.MINIO_BUCKET_REPORTS, str(report.file_path)

        def _fetch() -> bytes:
            obj = get_minio().get_object(bucket, key)
            try:
                return obj.read()
            finally:
                obj.close()
                obj.release_conn()

        loop = asyncio.get_running_loop()
        pdf_bytes = await loop.run_in_executor(None, _fetch)
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{filename_slug}.pdf"},
        )

    if report.format == "json":
        return JSONResponse(content=data, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report_{filename_slug}.json"})

    if report.format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        if data.get("findings"):
            writer.writerow(["title", "severity", "category", "status", "cve_ids", "cvss_score", "affected_url", "first_seen", "last_seen"])
            for f in data["findings"]:
                writer.writerow([f.get("title"), f.get("severity"), f.get("category"), f.get("status"), ";".join(f.get("cve_ids", [])), f.get("cvss_score"), f.get("affected_url"), f.get("first_seen"), f.get("last_seen")])
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=report_{filename_slug}.csv"})

    return report.data

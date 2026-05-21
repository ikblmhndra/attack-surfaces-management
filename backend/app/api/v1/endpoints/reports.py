import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_workspace_id, get_db, RequireRole
from app.db.models.models import Asset, Finding, Organization, Report, Scan, User

log = structlog.get_logger()
router = APIRouter()

require_analyst = RequireRole(["owner", "admin", "analyst"])

class ReportGenerateRequest(BaseModel):
    org_id: str
    report_type: str = "executive"
    format: str = "json"

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

    bg.add_task(_generate_report_data, str(report.id), request.org_id, str(workspace_id), request.report_type, request.format)

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
    import csv, io

    result = await db.execute(
        select(Report).where(Report.id == report_id, Report.workspace_id == workspace_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")
    if report.status != "completed":
        raise HTTPException(400, "Report is not yet generated")

    data = report.data or {}
    if report.format == "json":
        return JSONResponse(content=data, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=report_{report_id[:8]}.json"})

    if report.format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        if data.get("findings"):
            writer.writerow(["title", "severity", "category", "status", "cve_ids", "cvss_score", "affected_url", "first_seen", "last_seen"])
            for f in data["findings"]:
                writer.writerow([f.get("title"), f.get("severity"), f.get("category"), f.get("status"), ";".join(f.get("cve_ids", [])), f.get("cvss_score"), f.get("affected_url"), f.get("first_seen"), f.get("last_seen")])
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=report_{report_id[:8]}.csv"})

    return report.data


async def _generate_report_data(report_id: str, org_id: str, workspace_id: str, report_type: str, format: str):
    """Generate report data in background task."""
    from app.core.database import AsyncSessionLocal as session_factory

    async with session_factory() as db:
        report = await db.get(Report, report_id)
        if not report:
            return

        try:
            report.status = "generating"
            await db.commit()

            now = datetime.now(timezone.utc)

            # Gather data
            total_assets = (await db.execute(
                select(func.count(Asset.id)).where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
            )).scalar_one()

            total_findings = (await db.execute(
                select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.deleted_at.is_(None), Finding.status == "open")
            )).scalar_one()

            critical = (await db.execute(
                select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.severity == "critical", Finding.status == "open", Finding.deleted_at.is_(None))
            )).scalar_one()

            high = (await db.execute(
                select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.severity == "high", Finding.status == "open", Finding.deleted_at.is_(None))
            )).scalar_one()

            by_category = (await db.execute(
                select(Finding.category, func.count(Finding.id))
                .where(Finding.org_id == org_id, Finding.status == "open", Finding.deleted_at.is_(None))
                .group_by(Finding.category)
                .order_by(func.count(Finding.id).desc())
                .limit(10)
            )).all()

            # Findings detail
            findings_rows = (await db.execute(
                select(Finding)
                .where(Finding.org_id == org_id, Finding.status == "open", Finding.deleted_at.is_(None))
                .order_by(Finding.last_seen.desc())
                .limit(500)
            )).scalars().all()

            # Recent scans
            recent_scans = (await db.execute(
                select(Scan)
                .where(Scan.org_id == org_id)
                .order_by(Scan.created_at.desc())
                .limit(10)
            )).scalars().all()

            asset_types = (await db.execute(
                select(Asset.asset_type, func.count(Asset.id))
                .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
                .group_by(Asset.asset_type)
            )).all()

            report_data = {
                "report_type": report_type,
                "generated_at": now.isoformat(),
                "organization_id": org_id,
                "summary": {
                    "total_assets": total_assets,
                    "total_findings": total_findings,
                    "critical": critical,
                    "high": high,
                    "medium": (await db.execute(select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.severity == "medium", Finding.status == "open", Finding.deleted_at.is_(None)))).scalar_one(),
                    "low": (await db.execute(select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.severity == "low", Finding.status == "open", Finding.deleted_at.is_(None)))).scalar_one(),
                },
                "asset_types": {at: count for at, count in asset_types},
                "findings_by_category": {cat: count for cat, count in by_category},
                "findings": [{
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "status": f.status,
                    "cve_ids": f.cve_ids or [],
                    "cvss_score": f.cvss_score,
                    "affected_url": f.affected_url,
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                    "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                } for f in findings_rows],
                "recent_scans": [{
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "progress_pct": s.progress_pct,
                    "assets_found": s.assets_found,
                    "findings_found": s.findings_found,
                    "created_at": s.created_at.isoformat(),
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                } for s in recent_scans],
            }

            summary_text = (
                f"Security assessment for organization {org_id[:8]}... "
                f"Found {total_assets} assets and {total_findings} open findings "
                f"({critical} critical, {high} high)."
            )

            report.data = report_data
            report.summary = summary_text
            report.stats = report_data["summary"]
            report.status = "completed"
            report.generated_at = now

            await db.commit()
            log.info("report_generated", report_id=report_id, org_id=org_id)

        except Exception as e:
            report.status = "failed"
            report.error_message = str(e)
            await db.commit()
            log.error("report_generation_failed", report_id=report_id, error=str(e))

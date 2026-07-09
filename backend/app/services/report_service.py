"""
ASM Platform — Report Generation Service
Builds the report data payload (executive/technical) and, for PDF requests,
renders it through Jinja2 + WeasyPrint and uploads the result to MinIO.
"""
import asyncio
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select

from app.db.models.models import Asset, Finding, Organization, Report, RiskScore, Scan, Workspace

log = structlog.get_logger()

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)

# report_type values that get the same "full detail" treatment as `technical`.
# `compliance` and `custom` don't have real framework-mapping / section-picker
# support yet, so they alias to technical rather than fabricating content.
DETAILED_REPORT_TYPES = {"technical", "compliance", "custom"}

EVIDENCE_FIELDS = ("evidence", "request_raw", "response_raw", "proof", "affected_url")


def _date_cutoff(days: int, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return now - timedelta(days=max(0, days))


def _strip_evidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of a finding dict with raw evidence fields removed."""
    return {k: v for k, v in finding.items() if k not in EVIDENCE_FIELDS}


def _finding_to_dict(f: Finding, include_evidence: bool) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "status": f.status,
        "cve_ids": f.cve_ids or [],
        "cvss_score": f.cvss_score,
        "affected_url": f.affected_url,
        "evidence": (f.evidence or "")[:500] or None,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
    }
    return data if include_evidence else _strip_evidence(data)


def build_report_summary_text(report_type: str, total_assets: int, total_findings: int, critical: int, high: int, org_id: str) -> str:
    label = "Executive" if report_type == "executive" else "Technical"
    return (
        f"{label} security assessment for organization {org_id[:8]}... "
        f"Found {total_assets} assets and {total_findings} open findings "
        f"({critical} critical, {high} high)."
    )


async def _fetch_latest_risk_score(db, org_id: str, workspace_id: str) -> Optional[Dict[str, Any]]:
    result = await db.execute(
        select(RiskScore)
        .where(RiskScore.org_id == org_id, RiskScore.workspace_id == workspace_id)
        .order_by(RiskScore.computed_at.desc())
        .limit(1)
    )
    score = result.scalar_one_or_none()
    if not score:
        return None
    return {
        "overall_score": score.overall_score,
        "grade": score.grade,
        "computed_at": score.computed_at.isoformat(),
        "categories": {
            "network_security": score.network_security_score,
            "dns_health": score.dns_health_score,
            "web_security": score.web_security_score,
            "tls_security": score.tls_security_score,
            "exposure_mgmt": score.exposure_mgmt_score,
            "patch_hygiene": score.patch_hygiene_score,
            "info_leakage": score.info_leakage_score,
            "reputation": score.reputation_score,
            "misconfiguration": score.misconfiguration_score,
        },
    }


async def _build_report_data(
    db,
    org: Organization,
    report_type: str,
    date_range_days: int,
    include_evidence: bool,
) -> Dict[str, Any]:
    org_id = str(org.id)
    workspace_id = str(org.workspace_id)
    now = datetime.now(timezone.utc)
    cutoff = _date_cutoff(date_range_days, now)
    detailed = report_type in DETAILED_REPORT_TYPES

    total_assets = (await db.execute(
        select(func.count(Asset.id)).where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
    )).scalar_one()

    total_findings = (await db.execute(
        select(func.count(Finding.id)).where(Finding.org_id == org_id, Finding.deleted_at.is_(None), Finding.status == "open")
    )).scalar_one()

    severity_counts = {}
    for sev in ("critical", "high", "medium", "low"):
        severity_counts[sev] = (await db.execute(
            select(func.count(Finding.id)).where(
                Finding.org_id == org_id, Finding.severity == sev, Finding.status == "open", Finding.deleted_at.is_(None)
            )
        )).scalar_one()

    by_category = (await db.execute(
        select(Finding.category, func.count(Finding.id))
        .where(Finding.org_id == org_id, Finding.status == "open", Finding.deleted_at.is_(None))
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
    )).all()

    asset_types = (await db.execute(
        select(Asset.asset_type, func.count(Asset.id))
        .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
        .group_by(Asset.asset_type)
    )).all()

    risk_score = await _fetch_latest_risk_score(db, org_id, workspace_id)

    # None (not []) signals "section omitted" for executive reports, vs. an empty
    # list meaning "detailed report, nothing in this window" — the PDF template
    # and API consumers both rely on that distinction to decide whether to render
    # the findings/scans sections at all.
    findings: Optional[List[Dict[str, Any]]] = None
    recent_scans: Optional[List[Dict[str, Any]]] = None

    if detailed:
        findings_rows = (await db.execute(
            select(Finding)
            .where(
                Finding.org_id == org_id,
                Finding.status == "open",
                Finding.deleted_at.is_(None),
                Finding.last_seen >= cutoff,
            )
            .order_by(Finding.last_seen.desc())
            .limit(500)
        )).scalars().all()
        findings = [_finding_to_dict(f, include_evidence) for f in findings_rows]

        recent_scans_rows = (await db.execute(
            select(Scan)
            .where(Scan.org_id == org_id, Scan.created_at >= cutoff)
            .order_by(Scan.created_at.desc())
            .limit(10)
        )).scalars().all()
        recent_scans = [{
            "scan_type": s.scan_type,
            "status": s.status,
            "progress_pct": s.progress_pct,
            "assets_found": s.assets_found,
            "findings_found": s.findings_found,
            "created_at": s.created_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        } for s in recent_scans_rows]

    return {
        "report_type": report_type,
        "generated_at": now.isoformat(),
        "organization_id": org_id,
        "organization_name": org.name,
        "date_range_days": date_range_days,
        "risk_score": risk_score,
        "summary": {
            "total_assets": total_assets,
            "total_findings": total_findings,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        },
        "asset_types": {at: count for at, count in asset_types},
        "findings_by_category": {cat: count for cat, count in by_category},
        "findings": findings,
        "recent_scans": recent_scans,
    }


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
}


def _build_chart_data(report_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Precompute bar widths (0-100) so the template does no arithmetic."""
    summary = report_data["summary"]
    severity_bars = []
    max_sev = max(summary["critical"], summary["high"], summary["medium"], summary["low"], 1)
    for sev in ("critical", "high", "medium", "low"):
        count = summary[sev]
        severity_bars.append({
            "label": sev.capitalize(),
            "count": count,
            "pct": round(100 * count / max_sev, 1),
            "color": SEVERITY_COLORS[sev],
        })

    by_category = report_data.get("findings_by_category") or {}
    max_cat = max(by_category.values(), default=1) or 1
    category_bars = [
        {"label": cat, "count": count, "pct": round(100 * count / max_cat, 1)}
        for cat, count in by_category.items()
    ]

    return {"severity": severity_bars, "category": category_bars}


async def _render_pdf(report_data: Dict[str, Any], workspace_name: str, include_charts: bool) -> bytes:
    def _render() -> bytes:
        from weasyprint import HTML

        template = _jinja_env.get_template("report_pdf.html")
        html_str = template.render(
            r=report_data,
            workspace_name=workspace_name,
            include_charts=include_charts,
            charts=_build_chart_data(report_data) if include_charts else None,
        )
        return HTML(string=html_str).write_pdf()

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _render)


async def _upload_pdf(pdf_bytes: bytes, workspace_id: str, report_id: str) -> str:
    from app.core.config import settings
    from app.core.minio_client import get_minio

    key = f"{workspace_id}/{report_id}.pdf"

    def _upload():
        get_minio().put_object(
            settings.MINIO_BUCKET_REPORTS,
            key,
            io.BytesIO(pdf_bytes),
            length=len(pdf_bytes),
            content_type="application/pdf",
        )

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _upload)
    return key


async def generate_report(
    report_id: str,
    org_id: str,
    workspace_id: str,
    report_type: str,
    format: str,
    date_range_days: int = 30,
    include_charts: bool = True,
    include_evidence: bool = True,
) -> None:
    """Generate a report's data (and PDF artifact, if requested) in the background."""
    from app.core.database import AsyncSessionLocal as session_factory

    async with session_factory() as db:
        report = await db.get(Report, report_id)
        if not report:
            return

        try:
            report.status = "generating"
            await db.commit()

            org = (await db.execute(
                select(Organization).where(Organization.id == org_id)
            )).scalar_one_or_none()
            if not org:
                raise ValueError(f"organization {org_id} not found")

            report_data = await _build_report_data(db, org, report_type, date_range_days, include_evidence)

            summary = report_data["summary"]
            summary_text = build_report_summary_text(
                report_type, summary["total_assets"], summary["total_findings"],
                summary["critical"], summary["high"], org_id,
            )

            report.data = report_data
            report.summary = summary_text
            report.stats = summary

            if format == "pdf":
                workspace_name = (await db.execute(
                    select(Workspace.name).where(Workspace.id == workspace_id)
                )).scalar_one_or_none() or ""
                pdf_bytes = await _render_pdf(report_data, workspace_name, include_charts)
                report.file_path = await _upload_pdf(pdf_bytes, workspace_id, report_id)

            report.status = "completed"
            report.generated_at = datetime.now(timezone.utc)
            await db.commit()
            log.info("report_generated", report_id=report_id, org_id=org_id, format=format, report_type=report_type)

        except Exception as e:
            report.status = "failed"
            report.error_message = str(e)
            await db.commit()
            log.error("report_generation_failed", report_id=report_id, error=str(e), exc_info=True)

"""
ASM Platform — Assets API Endpoints
Asset inventory management with filtering, relationships, and technology tracking.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies.auth import get_current_user, get_db, get_workspace_id, RequireRole
from app.db.models.models import (
    Asset, AssetRelationship, Finding, IPAddress, Port,
    Screenshot, Subdomain, Technology, ThreatIntel, User,
)

log = structlog.get_logger()
router = APIRouter()
require_analyst = RequireRole(["owner", "admin", "analyst"])


# ── Asset List ─────────────────────────────────────────────────

@router.get("")
async def list_assets(
    org_id: Optional[UUID] = Query(None),
    asset_type: Optional[str] = Query(None, description="subdomain,ip,cidr,url"),
    status: Optional[str] = Query(None, description="active,inactive"),
    search: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    has_findings: Optional[bool] = Query(None),
    technology: Optional[str] = Query(None),
    cdn_only: Optional[bool] = Query(None),
    cloud_provider: Optional[str] = Query(None),
    criticality: Optional[int] = Query(None, ge=1, le=5),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("last_seen"),
    sort_dir: str = Query("desc"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all assets with advanced filtering."""
    query = select(Asset).where(
        Asset.workspace_id == workspace_id,
        Asset.deleted_at.is_(None),
    )

    if org_id:
        query = query.where(Asset.org_id == org_id)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if status:
        query = query.where(Asset.status == status)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    if tags:
        tag_list = [t.strip() for t in tags.split(",")]
        query = query.where(Asset.tags.overlap(tag_list))
    if search:
        query = query.where(Asset.value.ilike(f"%{search}%"))
    if has_findings is True:
        query = query.where(
            select(Finding.id).where(
                Finding.asset_id == Asset.id,
                Finding.status == "open",
            ).exists()
        )
    elif has_findings is False:
        query = query.where(
            ~select(Finding.id).where(
                Finding.asset_id == Asset.id,
                Finding.status == "open",
            ).exists()
        )

    # Technology filter (via Subdomain join)
    if technology:
        tech_subq = select(Subdomain.asset_id).where(
            Subdomain.technologies.any(technology)
        ).scalar_subquery()
        query = query.where(Asset.id.in_(tech_subq))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Sort
    sort_map = {
        "value": Asset.value,
        "last_seen": Asset.last_seen,
        "first_seen": Asset.first_seen,
        "criticality": Asset.criticality,
        "asset_type": Asset.asset_type,
    }
    sort_col = sort_map.get(sort_by, Asset.last_seen)
    query = query.order_by(sort_col.desc() if sort_dir == "desc" else sort_col.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    assets = (await db.execute(query)).scalars().all()

    # Enrich with subdomain details in bulk
    asset_ids = [a.id for a in assets]
    subdomains_map = {}
    if asset_ids:
        subs = (await db.execute(
            select(Subdomain).where(Subdomain.asset_id.in_(asset_ids))
        )).scalars().all()
        subdomains_map = {s.asset_id: s for s in subs}

    ips_map = {}
    ip_assets = (await db.execute(
        select(IPAddress).where(IPAddress.asset_id.in_(asset_ids))
    )).scalars().all()
    ips_map = {ip.asset_id: ip for ip in ip_assets}

    # Finding counts per asset
    finding_counts_q = (
        select(Finding.asset_id, func.count(Finding.id).label("cnt"))
        .where(Finding.asset_id.in_(asset_ids), Finding.status == "open", Finding.deleted_at.is_(None))
        .group_by(Finding.asset_id)
    )
    finding_counts = {row.asset_id: row.cnt for row in (await db.execute(finding_counts_q)).all()}

    items = []
    for asset in assets:
        sub = subdomains_map.get(asset.id)
        ip = ips_map.get(asset.id)
        item = _asset_to_dict(asset, sub, ip)
        item["open_findings"] = finding_counts.get(asset.id, 0)
        items.append(item)

    # Asset type distribution
    type_counts_q = (
        select(Asset.asset_type, func.count(Asset.id).label("cnt"))
        .where(Asset.workspace_id == workspace_id, Asset.deleted_at.is_(None))
    )
    if org_id:
        type_counts_q = type_counts_q.where(Asset.org_id == org_id)
    type_counts_q = type_counts_q.group_by(Asset.asset_type)
    type_counts = {row.asset_type: row.cnt for row in (await db.execute(type_counts_q)).all()}

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "type_counts": type_counts,
    }


@router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get full asset details including subdomain, IP, technologies, ports."""
    asset = await _get_asset_or_404(db, asset_id, workspace_id)

    sub = (await db.execute(
        select(Subdomain).where(Subdomain.asset_id == asset_id)
    )).scalar_one_or_none()

    ip = (await db.execute(
        select(IPAddress).where(IPAddress.asset_id == asset_id)
    )).scalar_one_or_none()

    ports = []
    if ip:
        ports = (await db.execute(
            select(Port).where(Port.ip_id == ip.id).order_by(Port.port_number)
        )).scalars().all()

    technologies = (await db.execute(
        select(Technology).where(Technology.asset_id == asset_id)
        .order_by(Technology.confidence.desc())
    )).scalars().all()

    open_findings = (await db.execute(
        select(Finding)
        .where(Finding.asset_id == asset_id, Finding.status == "open", Finding.deleted_at.is_(None))
        .order_by(Finding.severity)
        .limit(20)
    )).scalars().all()

    latest_screenshot = (await db.execute(
        select(Screenshot)
        .where(Screenshot.asset_id == asset_id, Screenshot.is_current == True)
        .order_by(Screenshot.captured_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    threat_intel = (await db.execute(
        select(ThreatIntel).where(ThreatIntel.asset_id == asset_id)
        .order_by(ThreatIntel.enriched_at.desc())
    )).scalars().all()

    result = _asset_to_dict(asset, sub, ip, detailed=True)
    result.update({
        "ports": [_port_to_dict(p) for p in ports],
        "technologies": [_tech_to_dict(t) for t in technologies],
        "open_findings": [_finding_summary(f) for f in open_findings],
        "screenshot": {
            "url": f"/storage/screenshots/{latest_screenshot.storage_path}",
            "thumbnail_url": f"/storage/screenshots/{latest_screenshot.thumbnail_path}" if latest_screenshot.thumbnail_path else None,
            "captured_at": latest_screenshot.captured_at.isoformat(),
            "http_status": latest_screenshot.http_status,
        } if latest_screenshot else None,
        "threat_intel": [_intel_to_dict(ti) for ti in threat_intel],
    })

    return result


@router.get("/{asset_id}/findings")
async def get_asset_findings(
    asset_id: UUID,
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all findings for a specific asset."""
    await _get_asset_or_404(db, asset_id, workspace_id)

    query = select(Finding).where(
        Finding.asset_id == asset_id,
        Finding.deleted_at.is_(None),
    )
    if status:
        query = query.where(Finding.status == status)
    else:
        query = query.where(Finding.status == "open")
    if severity:
        query = query.where(Finding.severity.in_([s.strip() for s in severity.split(",")]))

    findings = (await db.execute(query.order_by(Finding.severity))).scalars().all()
    return {"items": [_finding_summary(f) for f in findings], "total": len(findings)}


@router.get("/{asset_id}/screenshots")
async def get_asset_screenshots(
    asset_id: UUID,
    limit: int = Query(10, ge=1, le=50),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get screenshot history for an asset."""
    await _get_asset_or_404(db, asset_id, workspace_id)

    screenshots = (await db.execute(
        select(Screenshot)
        .where(Screenshot.asset_id == asset_id)
        .order_by(Screenshot.captured_at.desc())
        .limit(limit)
    )).scalars().all()

    return {
        "items": [
            {
                "id": str(s.id),
                "url": f"/storage/screenshots/{s.storage_path}",
                "thumbnail_url": f"/storage/screenshots/{s.thumbnail_path}" if s.thumbnail_path else None,
                "captured_at": s.captured_at.isoformat(),
                "http_status": s.http_status,
                "file_size": s.file_size,
                "is_current": s.is_current,
            }
            for s in screenshots
        ]
    }


@router.get("/{asset_id}/technologies")
async def get_asset_technologies(
    asset_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get detected technologies for an asset."""
    await _get_asset_or_404(db, asset_id, workspace_id)

    techs = (await db.execute(
        select(Technology)
        .where(Technology.asset_id == asset_id)
        .order_by(Technology.confidence.desc())
    )).scalars().all()

    return {"items": [_tech_to_dict(t) for t in techs]}


@router.get("/{asset_id}/intel")
async def get_asset_intel(
    asset_id: UUID,
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get threat intelligence enrichment data for an asset."""
    await _get_asset_or_404(db, asset_id, workspace_id)

    intel = (await db.execute(
        select(ThreatIntel)
        .where(ThreatIntel.asset_id == asset_id)
        .order_by(ThreatIntel.enriched_at.desc())
    )).scalars().all()

    return {"items": [_intel_to_dict(ti) for ti in intel]}


@router.get("/{asset_id}/relationships")
async def get_asset_relationships(
    asset_id: UUID,
    depth: int = Query(2, ge=1, le=3),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the asset relationship graph for visualization."""
    await _get_asset_or_404(db, asset_id, workspace_id)

    nodes = {}
    edges = []
    visited = set()

    async def fetch_related(aid: UUID, current_depth: int):
        if aid in visited or current_depth > depth:
            return
        visited.add(aid)

        asset_result = await db.execute(select(Asset).where(Asset.id == aid))
        asset = asset_result.scalar_one_or_none()
        if not asset:
            return

        nodes[str(aid)] = {
            "id": str(aid),
            "label": asset.value[:40],
            "type": asset.asset_type,
            "data": {"criticality": asset.criticality, "status": asset.status},
        }

        rels = (await db.execute(
            select(AssetRelationship).where(
                or_(
                    AssetRelationship.source_asset_id == aid,
                    AssetRelationship.target_asset_id == aid,
                )
            )
        )).scalars().all()

        for rel in rels:
            edge_id = str(rel.id)
            if edge_id not in [e["id"] for e in edges]:
                edges.append({
                    "id": edge_id,
                    "source": str(rel.source_asset_id),
                    "target": str(rel.target_asset_id),
                    "label": rel.relationship_type,
                    "type": rel.relationship_type,
                })

            next_id = rel.target_asset_id if rel.source_asset_id == aid else rel.source_asset_id
            await fetch_related(next_id, current_depth + 1)

    await fetch_related(asset_id, 1)

    return {"nodes": list(nodes.values()), "edges": edges}


# ── Stats ──────────────────────────────────────────────────────

@router.get("/stats/by-type")
async def assets_by_type(
    org_id: Optional[UUID] = Query(None),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Asset distribution by type for dashboard chart."""
    query = (
        select(Asset.asset_type, func.count(Asset.id).label("count"))
        .where(Asset.workspace_id == workspace_id, Asset.deleted_at.is_(None), Asset.status == "active")
    )
    if org_id:
        query = query.where(Asset.org_id == org_id)
    query = query.group_by(Asset.asset_type)
    rows = (await db.execute(query)).all()
    return {"distribution": [{"type": r.asset_type, "count": r.count} for r in rows]}


@router.get("/stats/new-over-time")
async def assets_new_over_time(
    org_id: Optional[UUID] = Query(None),
    days: int = Query(30, ge=7, le=365),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Daily new asset discovery trend."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = (
        select(
            func.date_trunc("day", Asset.first_seen).label("date"),
            Asset.asset_type,
            func.count(Asset.id).label("count"),
        )
        .where(
            Asset.workspace_id == workspace_id,
            Asset.deleted_at.is_(None),
            Asset.first_seen >= since,
        )
    )
    if org_id:
        query = query.where(Asset.org_id == org_id)
    query = query.group_by(func.date_trunc("day", Asset.first_seen), Asset.asset_type)
    query = query.order_by(func.date_trunc("day", Asset.first_seen))
    rows = (await db.execute(query)).all()

    return {
        "trend": [{"date": r.date.isoformat(), "type": r.asset_type, "count": r.count} for r in rows],
        "period_days": days,
    }


# ── Helpers ───────────────────────────────────────────────────

async def _get_asset_or_404(db, asset_id, workspace_id):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.workspace_id == workspace_id, Asset.deleted_at.is_(None))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


def _asset_to_dict(asset, sub=None, ip=None, detailed=False) -> dict:
    d = {
        "id": str(asset.id),
        "org_id": str(asset.org_id),
        "asset_type": asset.asset_type,
        "value": asset.value,
        "status": asset.status,
        "tags": asset.tags or [],
        "criticality": asset.criticality,
        "environment": asset.environment,
        "discovery_method": asset.discovery_method,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }
    if sub:
        d["subdomain"] = {
            "fqdn": sub.fqdn,
            "root_domain": sub.root_domain,
            "ip_addresses": sub.ip_addresses or [],
            "http_status": sub.http_status,
            "https_status": sub.https_status,
            "title": sub.http_title,
            "server": sub.http_server,
            "technologies": sub.technologies or [],
            "cdn_provider": sub.cdn_provider,
            "waf_detected": sub.waf_detected,
            "tls_expiry": sub.tls_expiry.isoformat() if sub.tls_expiry else None,
            "tls_issuer": sub.tls_issuer,
            "tls_version": sub.tls_version,
            "last_probed": sub.last_probed.isoformat() if sub.last_probed else None,
        }
        if detailed:
            d["subdomain"]["dns_records"] = sub.dns_records or {}
            d["subdomain"]["security_headers"] = sub.security_headers or {}
            d["subdomain"]["redirect_chain"] = sub.redirect_chain or []
            d["subdomain"]["tls_info"] = sub.tls_info
    if ip:
        d["ip"] = {
            "ip": ip.ip,
            "version": ip.version,
            "asn": ip.asn,
            "asn_org": ip.asn_org,
            "country_code": ip.country_code,
            "country_name": ip.country_name,
            "city": ip.city,
            "isp": ip.isp,
            "cloud_provider": ip.cloud_provider,
            "cloud_region": ip.cloud_region,
            "is_cdn": ip.is_cdn,
            "is_hosting": ip.is_hosting,
            "is_vpn": ip.is_vpn,
            "is_tor": ip.is_tor,
            "latitude": ip.latitude,
            "longitude": ip.longitude,
            "open_ports_count": ip.open_ports_count,
        }
    return d


def _port_to_dict(port) -> dict:
    return {
        "port": port.port_number,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service_name,
        "version": port.service_version,
        "banner": port.banner[:200] if port.banner else None,
        "first_seen": port.first_seen.isoformat(),
        "last_seen": port.last_seen.isoformat(),
    }


def _tech_to_dict(tech) -> dict:
    return {
        "id": str(tech.id),
        "name": tech.name,
        "version": tech.version,
        "category": tech.category,
        "confidence": tech.confidence,
        "first_detected": tech.first_detected.isoformat(),
    }


def _finding_summary(f) -> dict:
    return {
        "id": str(f.id),
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "status": f.status,
        "template_id": f.template_id,
        "cve_ids": f.cve_ids or [],
        "cvss_score": f.cvss_score,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
    }


# ── Export ──────────────────────────────────────────────────

@router.get("/export")
async def export_assets(
    org_id: Optional[UUID] = Query(None),
    asset_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    format: str = Query("csv", regex="^(csv|json)$"),
    workspace_id: UUID = Depends(get_workspace_id),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse
    import csv, io

    query = select(Asset).where(Asset.workspace_id == workspace_id)
    if org_id: query = query.where(Asset.org_id == org_id)
    if asset_type: query = query.where(Asset.asset_type == asset_type)
    if status: query = query.where(Asset.status == status)
    assets = (await db.execute(query.order_by(Asset.last_seen.desc()).limit(10000))).scalars().all()

    if format == "json":
        return [{
            "id": str(a.id), "org_id": str(a.org_id), "asset_type": a.asset_type,
            "value": a.value, "status": a.status, "tags": a.tags or [],
            "criticality": a.criticality, "discovery_method": a.discovery_method,
            "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
        } for a in assets]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "org_id", "asset_type", "value", "status", "tags", "criticality", "discovery_method", "first_seen", "last_seen"])
    for a in assets:
        writer.writerow([str(a.id), str(a.org_id), a.asset_type, a.value, a.status, ";".join(a.tags or []), a.criticality, a.discovery_method, a.first_seen.isoformat(), a.last_seen.isoformat()])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=assets.csv"})


def _intel_to_dict(ti) -> dict:
    return {
        "id": str(ti.id),
        "source": ti.source,
        "risk_score": ti.risk_score,
        "is_malicious": ti.is_malicious,
        "tags": ti.tags or [],
        "categories": ti.categories or [],
        "enriched_at": ti.enriched_at.isoformat(),
        "expires_at": ti.expires_at.isoformat() if ti.expires_at else None,
        "data": ti.data,
    }

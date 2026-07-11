"""Shared helpers for Milestone 5 scanner-family workers."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.db import get_session
from workers.db_models import Asset, Finding, Scan, ScanFinding, Subdomain
from workers.queue_client import QueueClient
from workers.scan_phase import update_scan_phase


def clean_text(value: Any, limit: int = 5000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    value = "".join(ch if ch in {"\n", "\r", "\t"} or ord(ch) >= 32 else " " for ch in value)
    return value[:limit]


def clean_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {clean_text(k, 500): clean_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_json(v) for v in value]
    if isinstance(value, str):
        return clean_text(value, 10000)
    return value


def host_from_target(target: str) -> str:
    target = str(target or "").strip()
    parsed = urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target.split("/")[0].split(":")[0]
    return host.strip("[]").lower()


def finding_fingerprint(org_id: str, scanner: str, check_id: str, target: str) -> str:
    return hashlib.sha256(f"{org_id}:{scanner}:{check_id}:{target}".encode()).hexdigest()


def status_preserving_conflict_updates(now: datetime) -> Dict[str, Any]:
    """SET-clause fragments for a Finding upsert on rediscovery.

    A rediscovered finding must not clobber an analyst's false-positive call or an
    active risk-acceptance — every finding-persistence path used to hardcode
    `status: "open"` on every upsert, silently undoing triage on the very next scan
    that re-matched the same fingerprint. A `resolved` finding (or one whose risk
    acceptance has lapsed) reappearing is a real regression and should reopen.
    """
    t = Finding.__table__.c
    accepted_active = and_(
        t.status == "accepted",
        t.is_risk_accepted.is_(True),
        or_(t.risk_accepted_until.is_(None), t.risk_accepted_until > now),
    )
    preserved = or_(t.status == "false_positive", accepted_active)
    return {
        "last_seen": now,
        "status": case((preserved, t.status), else_="open"),
        "is_risk_accepted": case((preserved, t.is_risk_accepted), else_=False),
        "resolved_at": case((preserved, t.resolved_at), else_=None),
    }


def content_refresh_updates(stmt, fields: Iterable[str]) -> Dict[str, Any]:
    """SET-clause fragments that refresh a Finding's mutable *content* on
    rediscovery, sourced from the attempted-insert row (`stmt.excluded`).

    status_preserving_conflict_updates() only protects triage fields
    (status/is_risk_accepted/resolved_at) — every other column was left
    completely untouched on conflict, freezing severity/proof/cve_ids/evidence/
    etc. at whatever they were the first time a finding was ever seen. In
    practice this meant a rediscovered finding kept stale confidence/EPSS/KEV
    data forever (see CHANGELOG.md) even though a fresh scan re-parsed
    genuinely current values for it. Only pass field names that are actually
    present in the caller's own `.values()` call — `stmt.excluded.<col>`
    resolves to that column's table default (not "leave unchanged") for any
    column the INSERT didn't explicitly set.
    """
    return {field: getattr(stmt.excluded, field) for field in fields}


def make_finding(
    *,
    org_id: str,
    workspace_id: str,
    scanner: str,
    check_id: str,
    target: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    proof: Optional[Dict[str, Any]] = None,
    remediation: str = "",
    references: Optional[List[str]] = None,
    subcategory: Optional[str] = None,
    cve_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "org_id": org_id,
        "workspace_id": workspace_id,
        "scanner": scanner,
        "source": scanner,
        "template_id": check_id,
        "title": clean_text(title, 500),
        "severity": severity,
        "category": category,
        "subcategory": subcategory,
        "description": clean_text(description, 5000),
        "affected_url": clean_text(target, 1000),
        "evidence": clean_text(evidence, 5000),
        "proof": clean_json(proof or {}),
        "remediation": clean_text(remediation, 5000),
        "references": [clean_text(ref, 1000) for ref in (references or [])[:20]],
        "cve_ids": [clean_text(cve_id, 100) for cve_id in (cve_ids or [])[:10]],
        "fingerprint": finding_fingerprint(org_id, scanner, check_id, target),
    }


async def find_asset_for_target(db, org_id: str, target: str):
    host = host_from_target(target)
    values = [target, host]
    if target.startswith(("http://", "https://")):
        values.append(target.rstrip("/"))
    result = await db.execute(
        select(Asset)
        .outerjoin(Subdomain, Subdomain.asset_id == Asset.id)
        .where(
            Asset.org_id == org_id,
            or_(
                Asset.value.in_(list(dict.fromkeys(v for v in values if v))),
                Subdomain.fqdn == host,
            ),
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def persist_findings(db, scan_id: str, findings: Iterable[Dict[str, Any]]) -> List[str]:
    now = datetime.now(timezone.utc)
    persisted_ids: List[str] = []

    for finding in findings:
        asset = await find_asset_for_target(db, finding["org_id"], finding["affected_url"])
        if not asset:
            continue
        values = {
            "org_id": finding["org_id"],
            "workspace_id": finding["workspace_id"],
            "asset_id": asset.id,
            "title": finding["title"],
            "description": finding["description"],
            "fingerprint": finding["fingerprint"],
            "severity": finding["severity"],
            "category": finding["category"],
            "subcategory": finding.get("subcategory"),
            "status": "open",
            "source": finding["source"],
            "template_id": finding.get("template_id"),
            "scanner": finding.get("scanner"),
            # Was hardcoded to [] regardless of what make_finding() actually
            # produced — never mattered before since no coverage_worker.py
            # check ever set cve_ids (only nuclei_worker.py's own, separate
            # persistence path populated it). version_cve_intel-based findings
            # are the first non-nuclei source that needs this populated (so
            # M14's EPSS/KEV lookup and cve_id-based filtering apply to them
            # too), so read it from the finding dict like every other field.
            "cve_ids": finding.get("cve_ids") or [],
            "cwe_ids": [],
            "affected_url": finding.get("affected_url"),
            "evidence": finding.get("evidence"),
            "proof": finding.get("proof") or {},
            "remediation": finding.get("remediation"),
            "references": finding.get("references") or [],
            "last_seen": now,
        }
        stmt = pg_insert(Finding.__table__).values(**values, first_seen=now)
        stmt = stmt.on_conflict_do_update(
            index_elements=["fingerprint", "org_id"],
            set_={
                **status_preserving_conflict_updates(now),
                **content_refresh_updates(stmt, [
                    "title", "description", "severity", "category", "subcategory",
                    "affected_url", "evidence", "proof", "remediation", "references",
                ]),
            },
        ).returning(Finding.__table__.c.id, Finding.__table__.c.first_seen)
        row = (await db.execute(stmt)).fetchone()
        if not row:
            continue
        finding_id = row[0]
        is_new = row[1] and (now - row[1]).total_seconds() < 5
        link = await db.execute(
            pg_insert(ScanFinding.__table__).values(
                scan_id=scan_id,
                finding_id=finding_id,
                change_type="new" if is_new else "recurring",
            ).on_conflict_do_nothing(
                constraint="uq_scan_findings_scan_finding",
            ).returning(ScanFinding.__table__.c.finding_id)
        )
        if link.fetchone():
            persisted_ids.append(str(finding_id))

    total = (await db.execute(
        select(func.count(ScanFinding.finding_id)).where(ScanFinding.scan_id == scan_id)
    )).scalar_one()
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(
            findings_found=total,
            progress_pct=func.greatest(Scan.progress_pct, 75),
        )
    )
    await db.commit()
    return persisted_ids


async def mark_worker_task_complete(db, scan_id: str, progress_floor: int = 75) -> None:
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(
            completed_tasks=Scan.completed_tasks + 1,
            progress_pct=func.greatest(Scan.progress_pct, progress_floor),
        )
    )
    await db.commit()


async def publish_scanner_completion(scan_id: str, org_id: str, workspace_id: str) -> None:
    from workers.task_coordinator import TaskCoordinator

    queue = QueueClient()
    await queue.connect()
    coord = TaskCoordinator()
    await coord.incr_scanner_done(scan_id)

    counts = await coord.get_counts(scan_id)
    expected = max(counts.get("scanner_expected", 0), 0)
    done = max(counts.get("scanner_done", 0), 0)
    scanner_status = "completed" if expected and done >= expected else "running"
    async with get_session() as db:
        await update_scan_phase(
            db,
            scan_id,
            "scanner",
            scanner_status,
            expected_batches=expected,
            completed_batches=done,
            remaining_batches=max(expected - done, 0),
        )

    await queue.publish(
        routing_key="correlation.process",
        message={"scan_id": scan_id, "org_id": org_id, "workspace_id": workspace_id},
    )
    if await coord.mark_terminal_if_all_done(scan_id):
        await queue.publish(
            routing_key="correlation.process",
            message={
                "scan_id": scan_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
                "is_terminal": True,
            },
        )
        await coord.cleanup(scan_id)
    await coord.close()
    await queue.close()


async def complete_phase_with_findings(
    *,
    scan_id: str,
    org_id: str,
    workspace_id: str,
    phase: str,
    targets_total: int,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> int:
    async with get_session() as db:
        persisted = await persist_findings(db, scan_id, findings)
        await mark_worker_task_complete(db, scan_id)
        await update_scan_phase(
            db,
            scan_id,
            phase,
            "completed",
            targets_total=targets_total,
            findings=len(persisted),
            **summary,
        )
    await publish_scanner_completion(scan_id, org_id, workspace_id)
    return len(persisted)

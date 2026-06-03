"""Durable scan observability helpers for workers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.db_models import Scan, ScanTargetSelection


def _merge_target_selection(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge duplicate target-selection rows that share the DB conflict key."""
    existing["selected"] = bool(existing.get("selected")) or bool(incoming.get("selected"))

    if incoming.get("asset_id") and not existing.get("asset_id"):
        existing["asset_id"] = incoming["asset_id"]

    incoming_score = incoming.get("score")
    if incoming_score is not None:
        current_score = existing.get("score")
        if current_score is None or incoming_score > current_score:
            existing["score"] = incoming_score

    reasons = []
    seen_reasons = set()
    for reason in [*existing.get("reasons", []), *incoming.get("reasons", [])]:
        if reason and reason not in seen_reasons:
            seen_reasons.add(reason)
            reasons.append(reason)
    existing["reasons"] = reasons

    if existing["selected"]:
        existing["skip_reason"] = None
    elif incoming.get("skip_reason"):
        existing["skip_reason"] = incoming["skip_reason"]

    metadata = dict(existing.get("metadata") or {})
    metadata.update(incoming.get("metadata") or {})
    existing["metadata"] = metadata


async def record_target_selections(
    db,
    *,
    scan_id: str,
    phase: str,
    targets: Iterable[dict[str, Any]],
) -> int:
    """Upsert selected/skipped target records for scan detail and coverage UI."""
    rows_by_key: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    scan = None
    now = datetime.now(timezone.utc)

    for item in targets:
        target = str(item.get("target") or "").strip()
        if not target:
            continue
        if scan is None:
            result = await db.execute(select(Scan).where(Scan.id == scan_id).limit(1))
            scan = result.scalar_one_or_none()
            if not scan:
                return 0
        row = {
            "id": uuid.uuid4(),
            "scan_id": scan.id,
            "org_id": scan.org_id,
            "workspace_id": scan.workspace_id,
            "asset_id": item.get("asset_id"),
            "target": target[:2000],
            "target_type": item.get("target_type") or "unknown",
            "phase": phase,
            "profile": item.get("profile") or "",
            "selected": bool(item.get("selected", True)),
            "score": item.get("score"),
            "reasons": item.get("reasons") or [],
            "skip_reason": item.get("skip_reason"),
            "metadata": item.get("metadata") or {},
            "updated_at": now,
        }
        key = (str(scan.id), phase, row["target"], row["target_type"], row["profile"])
        existing = rows_by_key.get(key)
        if existing:
            _merge_target_selection(existing, row)
        else:
            rows_by_key[key] = row

    rows = list(rows_by_key.values())
    if not rows:
        return 0

    stmt = pg_insert(ScanTargetSelection.__table__).values(rows)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_scan_target_selection",
        set_={
            "asset_id": stmt.excluded.asset_id,
            "selected": stmt.excluded.selected,
            "score": stmt.excluded.score,
            "reasons": stmt.excluded.reasons,
            "skip_reason": stmt.excluded.skip_reason,
            "metadata": stmt.excluded.metadata,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    await db.execute(stmt)
    await db.commit()
    return len(rows)

"""Durable scan observability helpers for workers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.db_models import Scan, ScanTargetSelection


async def record_target_selections(
    db,
    *,
    scan_id: str,
    phase: str,
    targets: Iterable[dict[str, Any]],
) -> int:
    """Upsert selected/skipped target records for scan detail and coverage UI."""
    rows = []
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
        rows.append({
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
        })

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

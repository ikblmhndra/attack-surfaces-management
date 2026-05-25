"""
Shared scan lifecycle helpers for worker processes.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Integer, cast, select, update, func

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
ACTIVE_STATUSES = {"queued", "pending", "running"}


async def _publish_scan_event(
    workspace_id: str,
    org_id: str,
    scan_id: str,
    status: str,
    progress_pct: float,
    message: str = "",
) -> None:
    try:
        import json
        import os
        from datetime import datetime, timezone

        import redis.asyncio as aioredis

        redis = aioredis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379/0"),
            decode_responses=True,
        )
        await redis.publish(
            f"asm:events:{workspace_id}",
            json.dumps({
                "type": "scan.progress",
                "data": {
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "status": status,
                    "progress_pct": progress_pct,
                    "message": message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }),
        )
        await redis.aclose()
    except Exception:
        pass


async def get_scan_status(db, scan_id: str) -> Optional[str]:
    from workers.db_models import Scan

    result = await db.execute(select(Scan.status).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def should_process_scan(db, scan_id: str) -> bool:
    status = await get_scan_status(db, scan_id)
    return status in ACTIVE_STATUSES


async def mark_scan_running(db, scan_id: str, progress_floor: int = 10) -> bool:
    from workers.db_models import Scan

    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_(list(ACTIVE_STATUSES)))
        .values(
            status="running",
            started_at=func.coalesce(Scan.started_at, datetime.now(timezone.utc)),
            progress_pct=func.greatest(Scan.progress_pct, progress_floor),
        )
        .returning(Scan.id, Scan.workspace_id, Scan.org_id, Scan.progress_pct)
    )
    await db.commit()
    row = result.fetchone()
    if row:
        await _publish_scan_event(str(row.workspace_id), str(row.org_id), scan_id, "running", float(row.progress_pct or progress_floor))
    return row is not None


async def mark_scan_failed(db, scan_id: str, error_message: str) -> None:
    from workers.db_models import Scan

    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.notin_(list(TERMINAL_STATUSES)))
        .values(
            status="failed",
            failed_tasks=Scan.failed_tasks + 1,
            error_count=Scan.error_count + 1,
            error_message=error_message[:4000],
            completed_at=datetime.now(timezone.utc),
        )
        .returning(Scan.workspace_id, Scan.org_id, Scan.progress_pct)
    )
    await db.commit()
    row = result.fetchone()
    if row:
        await _publish_scan_event(str(row.workspace_id), str(row.org_id), scan_id, "failed", float(row.progress_pct or 0), error_message[:500])


async def mark_scan_completed(db, scan_id: str) -> bool:
    from workers.db_models import Scan

    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_(list(ACTIVE_STATUSES)))
        .values(
            status="completed",
            progress_pct=100,
            completed_tasks=Scan.total_tasks,
            completed_at=now,
            duration_seconds=cast(func.extract("epoch", now - Scan.started_at), Integer),
        )
        .returning(Scan.id, Scan.workspace_id, Scan.org_id)
    )
    await db.commit()
    row = result.fetchone()
    if row:
        await _publish_scan_event(str(row.workspace_id), str(row.org_id), scan_id, "completed", 100, "Scan completed")
    return row is not None

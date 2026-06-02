"""
Shared scan phase-status updates.
"""
from datetime import datetime, timezone
from typing import Any


async def update_scan_phase(db, scan_id: str, phase: str, status: str, **fields: Any) -> None:
    from sqlalchemy import select
    from workers.db_models import Scan

    result = await db.execute(select(Scan).where(Scan.id == scan_id).limit(1))
    scan = result.scalar_one_or_none()
    if not scan:
        return

    now = datetime.now(timezone.utc).isoformat()
    phases = dict(scan.phase_status or {})
    current = dict(phases.get(phase) or {})
    current.update({key: value for key, value in fields.items() if value is not None})
    current["status"] = status
    if status == "running" and not current.get("started_at"):
        current["started_at"] = now
    if status in {"completed", "failed", "skipped"}:
        current["completed_at"] = now
    phases[phase] = current
    scan.phase_status = phases
    await db.commit()

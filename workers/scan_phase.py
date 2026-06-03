"""
Shared scan phase-status updates.
"""
from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy import func


async def update_scan_phase(db, scan_id: str, phase: str, status: str, **fields: Any) -> None:
    from sqlalchemy import select
    from workers.db_models import Scan, ScanPhaseRun

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

    summary = {key: value for key, value in current.items() if key not in {"status", "started_at", "completed_at"}}
    started_at = _parse_iso_datetime(current.get("started_at"))
    completed_at = _parse_iso_datetime(current.get("completed_at"))
    duration_seconds = None
    if started_at and completed_at:
        duration_seconds = max(0, int((completed_at - started_at).total_seconds()))

    values = {
        "id": uuid.uuid4(),
        "scan_id": scan.id,
        "org_id": scan.org_id,
        "workspace_id": scan.workspace_id,
        "phase": phase,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "expected_tasks": int(current.get("expected_batches") or current.get("expected_tasks") or 0),
        "completed_tasks": int(current.get("completed_batches") or current.get("completed_tasks") or 0),
        "failed_tasks": int(current.get("failed_tasks") or 0),
        "targets_total": int(current.get("targets_total") or 0),
        "targets_selected": int(current.get("targets_selected") or current.get("selected_for_nuclei") or 0),
        "targets_skipped": int(current.get("targets_skipped") or 0),
        "errors": int(current.get("errors") or 0),
        "warnings": int(current.get("warnings") or 0),
        "summary": summary,
        "updated_at": datetime.now(timezone.utc),
    }
    stmt = pg_insert(ScanPhaseRun.__table__).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_scan_phase_runs_scan_phase",
        set_={
            "status": values["status"],
            "started_at": func.coalesce(ScanPhaseRun.started_at, values["started_at"]),
            "completed_at": values["completed_at"],
            "duration_seconds": values["duration_seconds"],
            "expected_tasks": values["expected_tasks"],
            "completed_tasks": values["completed_tasks"],
            "failed_tasks": values["failed_tasks"],
            "targets_total": values["targets_total"],
            "targets_selected": values["targets_selected"],
            "targets_skipped": values["targets_skipped"],
            "errors": values["errors"],
            "warnings": values["warnings"],
            "summary": values["summary"],
            "updated_at": values["updated_at"],
        },
    )
    await db.execute(stmt)
    await db.commit()


def _parse_iso_datetime(value: Any):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None

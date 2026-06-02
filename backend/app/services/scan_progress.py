"""Runtime scan progress helpers backed by Redis coordinator counters."""
from __future__ import annotations

from typing import Any

from app.core.redis_client import get_redis


COUNTER_KEYS = {
    "nuclei_expected": "nuclei_expected",
    "nuclei_done": "nuclei_done",
    "nuclei_targets_scanned": "nuclei_targets_scanned",
    "nuclei_findings_found": "nuclei_findings_found",
    "port_expected": "port_expected",
    "port_done": "port_done",
    "crawl_expected": "crawl_expected",
    "crawl_done": "crawl_done",
    "enrich_expected": "enrich_expected",
    "enrich_done": "enrich_done",
    "screenshot_done": "screenshot_done",
}


async def get_scan_runtime_counts(scan_id: str) -> dict[str, int]:
    keys = [f"scan:{scan_id}:{suffix}" for suffix in COUNTER_KEYS.values()]
    try:
        values = await get_redis().mget(keys)
    except Exception:
        return {}
    return {name: int(value or 0) for name, value in zip(COUNTER_KEYS, values)}


async def merge_runtime_phase_status(scan_id: str, phase_status: dict[str, Any] | None) -> dict[str, Any]:
    phases = dict(phase_status or {})
    counts = await get_scan_runtime_counts(scan_id)
    if not counts:
        return phases

    for phase in ("port", "crawl", "enrich"):
        expected = counts.get(f"{phase}_expected", 0)
        done = counts.get(f"{phase}_done", 0)
        if not expected and not done:
            continue
        current = dict(phases.get(phase) or {})
        current.update({
            "expected_batches": expected,
            "completed_batches": done,
            "remaining_batches": max(expected - done, 0),
        })
        if expected and done >= expected and current.get("status") not in {"failed", "skipped"}:
            current["status"] = "completed"
        elif current.get("status") not in {"completed", "failed", "skipped"}:
            current["status"] = "running"
        phases[phase] = current

    nuclei_expected = counts.get("nuclei_expected", 0)
    nuclei_done = counts.get("nuclei_done", 0)
    if nuclei_expected or nuclei_done:
        current = dict(phases.get("nuclei") or {})
        current.update({
            "expected_batches": nuclei_expected,
            "completed_batches": nuclei_done,
            "remaining_batches": max(nuclei_expected - nuclei_done, 0),
            "targets_scanned": counts.get("nuclei_targets_scanned", 0),
            "findings": counts.get("nuclei_findings_found", current.get("findings", 0)),
        })
        if nuclei_expected and nuclei_done >= nuclei_expected and current.get("status") not in {"failed", "skipped"}:
            current["status"] = "completed"
        elif current.get("status") not in {"completed", "failed", "skipped"}:
            current["status"] = "running"
        phases["nuclei"] = current

    if counts.get("screenshot_done"):
        current = dict(phases.get("screenshot") or {})
        if current.get("status") not in {"failed", "skipped"}:
            current["status"] = "completed"
        phases["screenshot"] = current

    return phases

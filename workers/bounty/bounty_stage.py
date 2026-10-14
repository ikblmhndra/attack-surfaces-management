"""
ASM Platform — Bug Bounty pipeline: per-stage run-status tracking.

Writes each stage's live status into BountyProgram.stage_status (JSONB) so the
UI can show queued / running / completed / skipped / failed per phase and spot
a stuck run. Uses a targeted jsonb_set on a single stage key so two stages
running concurrently never clobber each other's status (a plain
read-modify-write of the whole column would). See CHANGELOG.md.

BountyStageWorker wraps process() so every bounty worker gets running→
completed/failed bookkeeping for free — subclasses implement run_stage() and
return a small summary dict (or {"skipped": reason}).
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy import func, or_, select, text, type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.db_models import BountyProgram, ExploitAttempt
from workers.queue_client import QueueClient

log = structlog.get_logger()

VALID_STAGES = {"recon", "probe", "vulnscan", "exploit", "report"}

# Full-auto chain order. A stage publishes the next one when it completes and
# the message carries auto_chain=true. `report` is terminal (no entry). The
# chain only ever advances on a *completed* stage -- a skip or failure ends it,
# and a paused program breaks it too (the next worker skips as inactive).
NEXT_STAGE = {
    "recon": "probe",
    "probe": "vulnscan",
    "vulnscan": "exploit",
    "exploit": "report",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_window_bound(raw: Any) -> Optional[datetime]:
    try:
        bound = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return bound if bound.tzinfo else bound.replace(tzinfo=timezone.utc)


def _within_testing_window(roe: Dict[str, Any]) -> bool:
    """True if now falls within rules_of_engagement.testing_window_start/end
    (ISO 8601 timestamps, either/both optional). Absence of a bound means
    unrestricted on that side -- same opt-in, conservative-by-default pattern
    as every other rules_of_engagement field (sqlmap_level, exploit_modules,
    ...): a program that never set a window is never restricted by one. An
    unparseable bound is logged and treated as not set, rather than either
    silently allowing everything or blocking a whole engagement over a
    config typo."""
    now = datetime.now(timezone.utc)
    for key, ok in (("testing_window_start", lambda t: now >= t), ("testing_window_end", lambda t: now <= t)):
        raw = roe.get(key)
        if not raw:
            continue
        bound = _parse_window_bound(raw)
        if bound is None:
            log.warning("bounty_testing_window_unparseable", key=key, value=raw)
            continue
        if not ok(bound):
            return False
    return True


async def _publish_next_stage(stage: str, program_id: str, workspace_id: Optional[str]) -> None:
    """In an auto run, hand off to the next stage. Marks the next stage
    'queued' immediately so the UI reflects the hand-off, then publishes it
    (carrying auto_chain forward) via the same QueueClient the ASM pipeline
    uses to chain its own stages."""
    next_stage = NEXT_STAGE.get(stage)
    if not next_stage:
        return
    await set_stage_status(program_id, next_stage, {"status": "queued", "queued_at": _now()})
    client = QueueClient()
    try:
        await client.connect()
        await client.publish(
            f"bounty.{next_stage}",
            {"program_id": program_id, "workspace_id": workspace_id, "auto_chain": True},
            priority=4,
        )
    finally:
        await client.close()


async def set_stage_status(program_id: str, stage: str, payload: Dict[str, Any]) -> None:
    """Merge `payload` into BountyProgram.stage_status[stage] atomically.

    `stage` is always an internal enum value (never user input), so embedding
    it in the jsonb path text is safe.
    """
    if stage not in VALID_STAGES:
        return
    payload = {**payload, "updated_at": _now()}
    stmt = (
        update(BountyProgram)
        .where(BountyProgram.id == program_id)
        .values(
            stage_status=func.jsonb_set(
                func.coalesce(BountyProgram.stage_status, text("'{}'::jsonb")),
                text(f"'{{{stage}}}'"),
                # type_coerce (not cast(json.dumps(...))) so the JSONB bind
                # json-encodes exactly once -- double-encoding stored the value
                # as a JSON *string* instead of an object.
                type_coerce(payload, JSONB),
                True,
            )
        )
    )
    async with get_session() as db:
        await db.execute(stmt)
        await db.commit()


async def set_interactsh_session_data(program_id: str, session_yaml: str) -> None:
    """Persist interactsh-client's session-file content into
    rules_of_engagement.interactsh_session_data so the SAME OOB domain gets
    reused on the next exploit run instead of a fresh random one every time
    (see interactsh_session.py's module docstring for why this exists).
    Single hardcoded key, not a generic "set any RoE field" helper -- keeps
    this safe to embed directly in the jsonb path text the same way
    set_stage_status embeds `stage` (an internal, non-user-controlled value).
    """
    stmt = (
        update(BountyProgram)
        .where(BountyProgram.id == program_id)
        .values(
            rules_of_engagement=func.jsonb_set(
                func.coalesce(BountyProgram.rules_of_engagement, text("'{}'::jsonb")),
                text("'{interactsh_session_data}'"),
                type_coerce(session_yaml, JSONB),
                True,
            )
        )
    )
    async with get_session() as db:
        await db.execute(stmt)
        await db.commit()


async def persist_deduped_attempts(db: AsyncSession, attempts: List[Dict[str, Any]]) -> int:
    """Insert new ExploitAttempt rows, or bump last_seen_at/occurrence_count on
    an existing row for the same (program_id, target_id, module, technique,
    evidence URL) instead of inserting a duplicate -- a program tested
    repeatedly over its life used to grow one new row per re-run for the same
    already-known finding forever. Matches whichever evidence key the finding
    used for its URL (target_url/url/matched_at -- different modules use
    different keys), same fallback order bounty_report.py::_dedup_findings
    already uses for its own *display*-layer dedup, so both layers agree on
    what "the same finding" means.

    Deliberately never touches `triage_status` on an existing match -- only
    the report/findings PATCH endpoint does. A human marking something
    false_positive/duplicate/wont_fix is never silently reverted just because
    the same technicality reproduces on a later run; last_seen_at/
    occurrence_count still update so the record honestly reflects it's still
    being detected, in case a human wants to re-open it.

    Caller still owns the transaction (commits after calling this), matching
    every other persist site's existing pattern.
    """
    now = datetime.now(timezone.utc)
    persisted = 0
    for attempt in attempts:
        evidence = attempt.get("evidence") or {}
        target_url = evidence.get("target_url") or evidence.get("url") or evidence.get("matched_at")
        existing = None
        if target_url:
            existing = (await db.execute(
                select(ExploitAttempt).where(
                    ExploitAttempt.program_id == attempt["program_id"],
                    ExploitAttempt.target_id == attempt["target_id"],
                    ExploitAttempt.module == attempt["module"],
                    ExploitAttempt.technique == attempt.get("technique"),
                    or_(
                        ExploitAttempt.evidence["target_url"].astext == target_url,
                        ExploitAttempt.evidence["url"].astext == target_url,
                        ExploitAttempt.evidence["matched_at"].astext == target_url,
                    ),
                ).order_by(ExploitAttempt.executed_at.desc()).limit(1)
            )).scalar_one_or_none()
        if existing is not None:
            existing.last_seen_at = now
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            existing.evidence = attempt.get("evidence")
            existing.severity = attempt.get("severity", existing.severity)
            existing.status = attempt.get("status", existing.status)
        else:
            db.add(ExploitAttempt(**attempt))
        persisted += 1
    return persisted


class BountyStageWorker(BaseWorker):
    """Base for bounty pipeline workers. Subclasses set STAGE and implement
    run_stage(message) -> summary dict. This wraps it with stage-status
    bookkeeping so any unhandled error still surfaces as 'failed' in the UI
    (and still propagates for BaseWorker's retry/DLQ)."""

    STAGE: str = ""

    async def process(self, message: Dict[str, Any]) -> None:
        program_id = message.get("program_id")
        if not program_id:
            log.warning("bounty_stage_missing_program_id", worker=self.worker_type)
            return

        async with get_session() as db:
            roe = (await db.execute(
                select(BountyProgram.rules_of_engagement).where(BountyProgram.id == program_id)
            )).scalar_one_or_none() or {}
        if not _within_testing_window(roe):
            log.info("bounty_stage_outside_testing_window", stage=self.STAGE, program_id=program_id)
            now = _now()
            await set_stage_status(program_id, self.STAGE, {
                "status": "skipped", "reason": "outside_testing_window",
                "started_at": now, "finished_at": now,
            })
            return

        started = _now()
        await set_stage_status(program_id, self.STAGE, {"status": "running", "started_at": started})

        try:
            summary = await self.run_stage(message) or {}
        except Exception as exc:
            await set_stage_status(program_id, self.STAGE, {
                "status": "failed",
                "started_at": started,
                "finished_at": _now(),
                "error": str(exc)[:500],
            })
            raise

        skipped = summary.get("skipped")
        await set_stage_status(program_id, self.STAGE, {
            "status": "skipped" if skipped else "completed",
            "started_at": started,
            "finished_at": _now(),
            "reason": skipped if isinstance(skipped, str) else None,
            "summary": {k: v for k, v in summary.items() if k != "skipped"},
        })

        # Full-auto hand-off: only advance on a real completion, and only when
        # the run was started in auto mode. A skip/failure ends the chain.
        if not skipped and message.get("auto_chain"):
            try:
                await _publish_next_stage(self.STAGE, program_id, message.get("workspace_id"))
            except Exception as exc:
                log.warning("bounty_chain_publish_failed", stage=self.STAGE, program_id=program_id, error=str(exc)[:200])

    async def run_stage(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Do the stage's work; return a small summary dict (or
        {"skipped": "<reason>"} to record a skip). Implemented by subclasses."""
        raise NotImplementedError

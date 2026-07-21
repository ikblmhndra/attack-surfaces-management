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
from typing import Any, Dict, Optional

import structlog
from sqlalchemy import func, text, type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.db_models import BountyProgram
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

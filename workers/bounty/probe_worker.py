"""
ASM Platform — Bug Bounty Probe Worker
Module 5: live-host probing (httpx) against explicitly human-approved
BountyTarget rows only -- never BountyAsset (unreviewed recon suggestions).
Re-validates scope inside the worker itself before touching anything, same
as every later pipeline stage. See CHANGELOG.md for the design rationale.
"""
import asyncio
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import structlog
from sqlalchemy import select

from app.services.bounty_scope import is_target_in_scope
from workers.bounty.bounty_stage import BountyStageWorker
from workers.bounty.detect import run_wafw00f
from workers.bounty.tools import run_httpx

# WAF fingerprinting spawns a wafw00f subprocess per host (~seconds each), so
# only the first N alive targets get checked -- a bound, not a scope limit.
MAX_WAF_CHECKS = 15
from workers.db import get_session
from workers.db_models import BountyProgram, BountyTarget

log = structlog.get_logger()


class BountyProbeWorker(BountyStageWorker):
    QUEUE = "bounty.probe"
    STAGE = "probe"
    CONCURRENCY = int(os.getenv("BOUNTY_PROBE_CONCURRENCY", "2"))

    async def run_stage(self, message: Dict[str, Any]):
        program_id = message["program_id"]

        async with get_session() as db:
            program = (await db.execute(
                select(BountyProgram).where(BountyProgram.id == program_id)
            )).scalar_one_or_none()

            if not program:
                log.warning("bounty_probe_program_missing", program_id=program_id)
                return {"skipped": "program_missing"}
            if program.status != "active":
                log.info("bounty_probe_skipped_inactive", program_id=program_id, status=program.status)
                return {"skipped": "program_not_active"}

            targets = (await db.execute(
                select(BountyTarget).where(BountyTarget.program_id == program.id)
            )).scalars().all()

        scope_rules = program.scope_rules or []
        roe = program.rules_of_engagement or {}
        # A bug bounty program's required identifying header (e.g. Bugcrowd's
        # X-Request-Purpose) must reach every request, including this stage's
        # httpx liveness probe -- it's often the very first traffic the
        # pipeline sends, so it needs to be identifiable from the start too.
        extra_headers: Dict[str, str] = dict(roe.get("custom_headers") or {})
        in_scope_targets: List[BountyTarget] = []
        for target in targets:
            if is_target_in_scope(target.value, scope_rules):
                in_scope_targets.append(target)
            else:
                # Scope can change after a target was approved (rules edited
                # later) -- never probe something that's fallen out of scope.
                log.warning("bounty_probe_target_out_of_scope_skipped", program_id=program_id, target=target.value)

        if not in_scope_targets:
            log.info("bounty_probe_no_in_scope_targets", program_id=program_id)
            return {"skipped": "no_in_scope_targets"}

        log.info("bounty_probe_started", program_id=program_id, targets=len(in_scope_targets))

        with tempfile.TemporaryDirectory(prefix="asm-bounty-probe-") as tmpdir_raw:
            tmpdir = Path(tmpdir_raw)
            probe_values = [t.value for t in in_scope_targets]
            alive = await run_httpx(probe_values, tmpdir, extra_headers=extra_headers)

        # WAF fingerprint the alive targets (bounded). Keyed by target value.
        waf_by_value: Dict[str, Any] = {}
        alive_values = [t.value for t in in_scope_targets if alive.get(t.value)]
        for value in alive_values[:MAX_WAF_CHECKS]:
            probe_url = (alive.get(value) or {}).get("url") or value
            waf = await run_wafw00f(probe_url)
            if waf and waf.get("detected"):
                waf_by_value[value] = waf

        now = datetime.now(timezone.utc)
        async with get_session() as db:
            alive_count = 0
            waf_count = 0
            for target in in_scope_targets:
                result = alive.get(target.value)
                row = (await db.execute(
                    select(BountyTarget).where(BountyTarget.id == target.id)
                )).scalar_one_or_none()
                if not row:
                    continue
                row.last_probed_at = now
                row.is_alive = result is not None
                meta = dict(result) if result else None
                if meta is not None and target.value in waf_by_value:
                    meta["waf"] = waf_by_value[target.value]
                    waf_count += 1
                row.probe_metadata = meta
                if result is not None:
                    alive_count += 1
            await db.commit()

        log.info("bounty_probe_completed", program_id=program_id, probed=len(in_scope_targets), alive=alive_count, waf=waf_count)
        return {"probed": len(in_scope_targets), "alive": alive_count, "waf_detected": waf_count}


if __name__ == "__main__":
    worker = BountyProbeWorker()
    asyncio.run(worker.run())

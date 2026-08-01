"""
ASM Platform — Bug Bounty Report Worker
Module 13: turn confirmed ExploitAttempt findings into submission-ready
BountyReport drafts (Markdown). Purely internal (reads findings, writes
reports -- no external interaction), but still gated on an active, existing
program for consistency with every other stage. Reports are drafts a human
reviews and edits before submitting to HackerOne/Bugcrowd. See CHANGELOG.md.
"""
import asyncio
import os
from typing import Any, Dict, List

import structlog
from sqlalchemy import select

from app.services.bounty_report_templates import build_report
from workers.bounty.bounty_stage import BountyStageWorker
from workers.db import get_session
from workers.db_models import BountyProgram, BountyReport, BountyTarget, ExploitAttempt

log = structlog.get_logger()

# Which finding statuses get a draft. Confirmed only by default -- a program
# can opt into inconclusive candidates (idor/ssrf) via rules_of_engagement.
DEFAULT_REPORTABLE_STATUSES = ["confirmed"]


class BountyReportWorker(BountyStageWorker):
    QUEUE = "bounty.report"
    STAGE = "report"
    CONCURRENCY = int(os.getenv("BOUNTY_REPORT_CONCURRENCY", "2"))

    async def run_stage(self, message: Dict[str, Any]):
        program_id = message["program_id"]

        async with get_session() as db:
            program = (await db.execute(
                select(BountyProgram).where(BountyProgram.id == program_id)
            )).scalar_one_or_none()
            if not program:
                log.warning("bounty_report_program_missing", program_id=program_id)
                return {"skipped": "program_missing"}
            if program.status != "active":
                log.info("bounty_report_skipped_inactive", program_id=program_id, status=program.status)
                return {"skipped": "program_not_active"}

            roe = program.rules_of_engagement or {}
            statuses = roe.get("reportable_statuses") or DEFAULT_REPORTABLE_STATUSES

            attempts = (await db.execute(
                select(ExploitAttempt).where(
                    ExploitAttempt.program_id == program.id,
                    ExploitAttempt.status.in_(statuses),
                    ExploitAttempt.triage_status.is_(None),
                )
            )).scalars().all()

            target_values = {
                t.id: t.value
                for t in (await db.execute(
                    select(BountyTarget).where(BountyTarget.program_id == program.id)
                )).scalars().all()
            }

            # Skip findings already covered by an existing report (idempotent
            # re-runs). finding_ids is an array column; collect the flat set.
            existing_reports = (await db.execute(
                select(BountyReport).where(BountyReport.program_id == program.id)
            )).scalars().all()
            already_reported = {
                str(fid)
                for report in existing_reports
                for fid in (report.finding_ids or [])
            }

            created = 0
            for attempt in attempts:
                if str(attempt.id) in already_reported:
                    continue
                draft = build_report(
                    {
                        "module": attempt.module,
                        "technique": attempt.technique,
                        "severity": attempt.severity,
                        "status": attempt.status,
                        "evidence": attempt.evidence or {},
                    },
                    target_value=target_values.get(attempt.target_id, "unknown target"),
                    program_name=program.name,
                )
                db.add(BountyReport(
                    program_id=program.id,
                    finding_ids=[attempt.id],
                    title=draft["title"],
                    summary=draft["summary"],
                    steps_to_reproduce=draft["steps_to_reproduce"],
                    impact=draft["impact"],
                    remediation=draft["remediation"],
                    status="draft",
                    format="markdown",
                    created_by=None,
                ))
                created += 1

            await db.commit()

        log.info("bounty_report_completed", program_id=program_id, reports_created=created)
        return {"reports_created": created}


if __name__ == "__main__":
    worker = BountyReportWorker()
    asyncio.run(worker.run())

"""
ASM Platform — One-off Backfill: Finding.cvss_score for version_cve_correlation findings

`workers/scanner/coverage_worker.py::_scan_version_cve` (Milestone 21) always knew the matched
CVE's cvss_score and stashed it in `proof->>'cvss_score'`, but never passed it to
`make_finding()` as a real column value (make_finding() had no cvss_score parameter at all
until Stage 2 of the risk-engine redesign added one). This left every version_cve_correlation
finding's `Finding.cvss_score` NULL, so risk_engine.py's existing CVSS-blending code
(compute_severity_penalty's `if cvss is not None: ...` branch) never fired for them.

Reuses data already sitting in `proof` — no CIRCL re-fetch needed. Idempotent and safe to
re-run: only touches rows where `cvss_score IS NULL AND proof->>'cvss_score' IS NOT NULL`.

Usage (inside a worker container):
    python -m workers.scripts.backfill_version_cve_cvss --dry-run
    python -m workers.scripts.backfill_version_cve_cvss
    python -m workers.scripts.backfill_version_cve_cvss --org-id <uuid>  # limit to one org
"""
from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from workers.db import get_session
from workers.db_models import Finding


async def _run(dry_run: bool, org_id: str | None) -> None:
    async with get_session() as db:
        query = select(Finding).where(
            Finding.scanner == "version_cve_correlation",
            Finding.cvss_score.is_(None),
            Finding.proof["cvss_score"].astext.is_not(None),
        )
        if org_id:
            query = query.where(Finding.org_id == org_id)

        findings = (await db.execute(query)).scalars().all()
        if not findings:
            print("No stuck-at-null cvss_score findings found matching criteria.")
            return

        updated = 0
        for finding in findings:
            raw = (finding.proof or {}).get("cvss_score")
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
            print(
                f"{'[dry-run] ' if dry_run else ''}finding={finding.id} org={finding.org_id} "
                f"template={finding.template_id}: cvss_score None -> {score}"
            )
            if not dry_run:
                finding.cvss_score = score
                updated += 1

        if not dry_run:
            await db.commit()

        print(f"\n{'Would update' if dry_run else 'Updated'} {updated if not dry_run else len(findings)} finding(s).")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print planned changes without writing them.")
    parser.add_argument("--org-id", default=None, help="Limit backfill to a single organization UUID.")
    args = parser.parse_args()

    asyncio.run(_run(dry_run=args.dry_run, org_id=args.org_id))


if __name__ == "__main__":
    main()

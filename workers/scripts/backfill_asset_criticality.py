"""
ASM Platform — One-off Backfill: Asset.criticality

Assigns an inferred criticality to the pre-existing asset population that was
stuck at the schema default of 3 before workers/asset_criticality.py existed
(new assets get this at creation time via discovery_worker.py::_persist_assets;
this script is only for the assets that predate that wiring).

Idempotent and safe to re-run: only touches assets where
`criticality == 3 AND labels->>'criticality_source' IS NULL`, so a manually-set
value (PATCH /assets/{id}, stamps labels.criticality_source="manual") or a
previous backfill run (stamps "backfill") is never overwritten.

Usage (inside a worker container, e.g. `docker compose exec worker-discovery`):
    python -m workers.scripts.backfill_asset_criticality --dry-run
    python -m workers.scripts.backfill_asset_criticality
    python -m workers.scripts.backfill_asset_criticality --org-id <uuid>  # limit to one org
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter

from sqlalchemy import select

from workers.asset_criticality import infer_asset_criticality
from workers.db import get_session
from workers.db_models import Asset, Organization


async def _run(dry_run: bool, org_id: str | None) -> None:
    async with get_session() as db:
        query = select(Asset).where(
            Asset.criticality == 3,
            Asset.labels["criticality_source"].astext.is_(None),
            Asset.deleted_at.is_(None),
        )
        if org_id:
            query = query.where(Asset.org_id == org_id)

        assets = (await db.execute(query)).scalars().all()
        if not assets:
            print("No stuck-at-3 assets found matching criteria.")
            return

        org_ids = {a.org_id for a in assets}
        orgs = (
            await db.execute(select(Organization).where(Organization.id.in_(org_ids)))
        ).scalars().all()
        org_by_id = {o.id: o for o in orgs}

        reason_counts: Counter = Counter()
        updated = 0

        for asset in assets:
            org = org_by_id.get(asset.org_id)
            org_criticality = org.criticality if org else None
            root_domains = set(org.root_domains or []) if org else set()

            criticality, reason = infer_asset_criticality(
                asset.value,
                is_root_domain=asset.value in root_domains,
                org_criticality=org_criticality,
            )
            reason_counts[reason] += 1

            print(
                f"{'[dry-run] ' if dry_run else ''}{asset.value} "
                f"(org={asset.org_id}, type={asset.asset_type}): 3 -> {criticality} ({reason})"
            )

            if not dry_run:
                asset.criticality = criticality
                asset.labels = {**(asset.labels or {}), "criticality_source": "backfill", "criticality_reason": reason}
                updated += 1

        if not dry_run:
            await db.commit()

        print(f"\n{'Would update' if dry_run else 'Updated'} {len(assets)} asset(s).")
        for reason, count in reason_counts.most_common():
            print(f"  {reason}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print planned changes without writing them.")
    parser.add_argument("--org-id", default=None, help="Limit backfill to a single organization UUID.")
    args = parser.parse_args()

    asyncio.run(_run(dry_run=args.dry_run, org_id=args.org_id))


if __name__ == "__main__":
    main()

"""
ASM Platform — Correlation Engine Worker
Merges duplicate assets, builds relationships, detects changes,
indexes to OpenSearch, and triggers risk recomputation.
"""
import asyncio
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog
from opensearchpy import AsyncOpenSearch
from sqlalchemy import select, update, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_completed, should_process_scan

log = structlog.get_logger()


class CorrelationWorker(BaseWorker):
    """
    Correlation engine: processes scan results to:
    1. Deduplicate and merge duplicate assets
    2. Build asset relationship graph (domain→IP→port→service→tech→vuln)
    3. Detect new/removed/changed assets (diff against previous scan)
    4. Index assets and findings to OpenSearch
    5. Compute attack surface statistics
    6. Trigger risk engine
    7. Trigger notifications for changes
    """

    QUEUE = "correlation.process"
    CONCURRENCY = 2

    def __init__(self):
        super().__init__()
        self.opensearch: Optional[AsyncOpenSearch] = None

    async def setup(self):
        import os
        self.opensearch = AsyncOpenSearch(
            hosts=[{
                "host": os.getenv("OPENSEARCH_HOST", "opensearch"),
                "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
            }],
            use_ssl=False,
            verify_certs=False,
        )
        await self._ensure_indices()

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        is_terminal = message.get("is_terminal", False)

        log.info("correlation_started", scan_id=scan_id, org_id=org_id)

        deduplicated = 0
        relationships: List[Dict] = []

        async with get_session() as db:
            if not await should_process_scan(db, scan_id):
                log.info("correlation_skipped_inactive_scan", scan_id=scan_id)
                return
            await update_scan_phase(db, scan_id, "correlation", "running", is_terminal=is_terminal)

            # Dedupe/relationship-rebuild/org-stats/OpenSearch-index are full,
            # org-wide recomputes, not incremental — every fan-out phase
            # (nuclei per batch, crawl, port, enrich, scanner-family) publishes
            # its own intermediate correlation.process message, so running
            # this unconditionally meant repeating full-org work ~40-50x per
            # scan. The primary findings list doesn't depend on any of it
            # (nuclei/scanner workers write findings straight to Postgres,
            # independent of correlation) — only the relationship graph, the
            # /search OpenSearch index, and denormalized org stats do, and
            # nothing was watching those update live mid-scan. Deferring all
            # of it to the terminal message cuts ~40x redundant work per scan
            # for a cost nobody could actually see.
            if is_terminal:
                # ── Step 1: Asset Deduplication ───────────────
                deduplicated = await self._deduplicate_assets(db, org_id)

                # ── Step 2: Build Relationships ───────────────
                relationships = await self._build_relationships(db, org_id)
                await self._persist_relationships(db, relationships)

                # ── Step 3: Update Org Statistics ─────────────
                await self._update_org_stats(db, org_id)

                # ── Step 4: Index to OpenSearch ───────────────
                await self._index_to_opensearch(db, org_id, workspace_id)

                # ── Step 5: Mark scan as complete ─────────────
                await self._complete_scan(db, scan_id)

        if is_terminal:
            # ── Step 6: Change Detection (full scan diff) ────
            async with get_session() as db:
                changes = await self._detect_changes(db, org_id, scan_id)

            # ── Step 7: Queue Risk Engine ─────────────────────
            await self._queue_risk_computation(scan_id, org_id, workspace_id)

            # ── Step 8: Queue Notifications for Changes ───────
            if changes:
                await self._queue_change_notifications(scan_id, org_id, workspace_id, changes)

            async with get_session() as db:
                await update_scan_phase(
                    db,
                    scan_id,
                    "correlation",
                    "completed",
                    is_terminal=True,
                    deduplicated=deduplicated,
                    relationships=len(relationships),
                    changes=len(changes),
                    risk_queued=True,
                    notifications_queued=len(changes),
                )

            log.info("correlation_completed", scan_id=scan_id, changes=len(changes))
        else:
            async with get_session() as db:
                await update_scan_phase(
                    db,
                    scan_id,
                    "correlation",
                    "running",
                    is_terminal=False,
                )
            log.info("correlation_intermediate", scan_id=scan_id)

    # ── Asset Deduplication ───────────────────────────────────

    async def _deduplicate_assets(self, db: AsyncSession, org_id: str) -> int:
        """
        Find and merge duplicate assets:
        - Same value, same type → keep newest, merge metadata
        - IP appears as both subdomain resolution and direct IP → link
        """
        from workers.db_models import Asset

        # Find assets with identical value and type (shouldn't exist due to unique constraint,
        # but handles edge cases from concurrent workers)
        dupes_q = (
            select(Asset.value, Asset.asset_type, func.count(Asset.id).label("cnt"))
            .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
            .group_by(Asset.value, Asset.asset_type)
            .having(func.count(Asset.id) > 1)
        )
        dupes = (await db.execute(dupes_q)).all()

        merged = 0
        for value, asset_type, cnt in dupes:
            assets_q = (
                select(Asset)
                .where(
                    Asset.org_id == org_id,
                    Asset.value == value,
                    Asset.asset_type == asset_type,
                )
                .order_by(Asset.first_seen.asc())
            )
            assets = (await db.execute(assets_q)).scalars().all()

            if len(assets) < 2:
                continue

            # Keep the first (oldest), soft delete the rest
            primary = assets[0]
            now = datetime.now(timezone.utc)
            for dup in assets[1:]:
                # Merge last_seen
                if dup.last_seen and (not primary.last_seen or dup.last_seen > primary.last_seen):
                    primary.last_seen = dup.last_seen
                # Soft delete duplicate
                dup.deleted_at = now
                merged += 1

        await db.commit()
        if merged:
            log.info("assets_deduplicated", org_id=org_id, merged=merged)
        return merged

    # ── Relationship Building ─────────────────────────────────

    async def _build_relationships(
        self,
        db: AsyncSession,
        org_id: str,
    ) -> List[Dict]:
        """
        Build asset relationship graph:
        - Subdomain → IP (resolves_to)
        - IP → Port (exposes)
        - Asset → Technology (runs)
        - Technology → Finding (vulnerable_to)
        """
        from workers.db_models import Asset, Subdomain, IPAddress, Technology, Finding

        relationships = []

        # Subdomain → IP relationships (from DNS resolution)
        subdomains_q = (
            select(Asset, Subdomain)
            .join(Subdomain, Subdomain.asset_id == Asset.id)
            .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
        )
        rows = (await db.execute(subdomains_q)).all()

        for asset, subdomain in rows:
            if not subdomain.ip_addresses:
                continue
            for ip in subdomain.ip_addresses:
                # Find IP asset
                ip_asset = await self._find_asset_by_value(db, org_id, ip, "ip")
                if ip_asset:
                    relationships.append({
                        "source_asset_id": str(asset.id),
                        "target_asset_id": str(ip_asset.id),
                        "relationship_type": "resolves_to",
                        "confidence": 1.0,
                        "metadata": {"dns_record": "A"},
                    })

        # Asset → Technology relationships
        tech_q = (
            select(Asset, Technology)
            .join(Technology, Technology.asset_id == Asset.id)
            .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
        )
        tech_rows = (await db.execute(tech_q)).all()

        # Group by technology name → identify tech clusters
        tech_by_name: Dict[str, List] = defaultdict(list)
        for asset, tech in tech_rows:
            tech_by_name[tech.name].append((asset, tech))

        # Technology → Finding cross-references
        finding_q = (
            select(Finding)
            .where(Finding.org_id == org_id, Finding.status == "open")
        )
        findings = (await db.execute(finding_q)).scalars().all()

        # Map finding CVEs to technologies (simple heuristic).
        # Index tech_rows by asset_id once (O(T)) instead of scanning it per
        # finding (O(F×T)) — this was a real cost at scale since this whole
        # method used to re-run on every intermediate correlation trigger.
        tech_by_asset_id: Dict[str, Any] = {}
        for asset, tech in tech_rows:
            tech_by_asset_id.setdefault(str(asset.id), (asset, tech))

        for finding in findings:
            match = tech_by_asset_id.get(str(finding.asset_id))
            if not match:
                continue
            asset, tech = match
            # Implies: tech may be the reason for this finding
            # In production, use CPE matching
            relationships.append({
                "source_asset_id": str(asset.id),
                "target_asset_id": str(finding.asset_id),
                "relationship_type": "has_finding",
                "confidence": 0.8,
                "metadata": {
                    "finding_id": str(finding.id),
                    "severity": finding.severity,
                },
            })

        return relationships

    async def _persist_relationships(
        self,
        db: AsyncSession,
        relationships: List[Dict],
    ) -> None:
        """Upsert asset relationships."""
        if not relationships:
            return

        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import AssetRelationship

        for rel in relationships:
            stmt = pg_insert(AssetRelationship.__table__).values(**rel)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_asset_relationship",
                set_={"confidence": rel["confidence"], "metadata": rel["metadata"]},
            )
            await db.execute(stmt)

        await db.commit()

    # ── Change Detection ──────────────────────────────────────

    async def _detect_changes(
        self,
        db: AsyncSession,
        org_id: str,
        scan_id: str,
    ) -> List[Dict]:
        """
        Compare current scan results to previous scan.
        Detect: new assets, removed assets, new findings, resolved findings.
        """
        from workers.db_models import Asset, Finding, Scan, ScanFinding

        changes = []

        # Get current and previous scan
        scans_q = (
            select(Scan)
            .where(Scan.org_id == org_id, Scan.status.in_(["completed", "running"]))
            .order_by(Scan.started_at.desc())
            .limit(2)
        )
        scans = (await db.execute(scans_q)).scalars().all()

        if len(scans) < 2:
            return changes  # First scan, no diff possible

        current_scan = scans[0]
        previous_scan = scans[1]

        # Get asset sets for each scan
        # Use the previous scan's started_at as the boundary so comparison
        # aligns with actual scan rounds rather than an arbitrary 24h window.
        prev_scan_start = previous_scan.started_at
        if prev_scan_start is None:
            return changes

        current_assets = set(
            row[0] for row in (await db.execute(
                select(Asset.value).where(
                    Asset.org_id == org_id,
                    Asset.last_seen >= prev_scan_start,
                    Asset.deleted_at.is_(None),
                )
            )).all()
        )

        # Assets that existed and were active before the previous scan started
        previous_assets = set(
            row[0] for row in (await db.execute(
                select(Asset.value).where(
                    Asset.org_id == org_id,
                    Asset.first_seen < prev_scan_start,
                    Asset.deleted_at.is_(None),
                )
            )).all()
        )

        # New assets (first seen during or after the previous scan)
        new_assets = current_assets - previous_assets
        for value in new_assets:
            changes.append({
                "type": "new_asset",
                "severity": "info",
                "value": value,
                "message": f"New asset discovered: {value}",
            })

        # Removed assets (went offline)
        removed = previous_assets - current_assets
        for value in removed:
            changes.append({
                "type": "removed_asset",
                "severity": "low",
                "value": value,
                "message": f"Asset no longer responding: {value}",
            })

        # New critical/high findings in this scan
        new_findings_q = (
            select(Finding, ScanFinding)
            .join(ScanFinding, ScanFinding.finding_id == Finding.id)
            .where(
                ScanFinding.scan_id == scan_id,
                ScanFinding.change_type == "new",
                Finding.severity.in_(["critical", "high"]),
            )
        )
        new_findings_rows = (await db.execute(new_findings_q)).all()

        for finding, _ in new_findings_rows:
            changes.append({
                "type": "new_finding",
                "severity": finding.severity,
                "value": finding.affected_url,
                "message": f"New {finding.severity} finding: {finding.title}",
                "finding_id": str(finding.id),
                "template_id": finding.template_id,
            })

        # TLS expiry check
        await self._check_tls_expiry(db, org_id, changes)

        log.info("changes_detected", org_id=org_id, count=len(changes))
        return changes

    async def _check_tls_expiry(
        self,
        db: AsyncSession,
        org_id: str,
        changes: List[Dict],
    ) -> None:
        """Check for TLS certificates expiring within 30 days."""
        from datetime import timedelta
        from workers.db_models import Asset, Subdomain

        warning_threshold = datetime.now(timezone.utc) + timedelta(days=30)
        critical_threshold = datetime.now(timezone.utc) + timedelta(days=7)

        expiring_q = (
            select(Subdomain, Asset)
            .join(Asset, Asset.id == Subdomain.asset_id)
            .where(
                Asset.org_id == org_id,
                Subdomain.tls_expiry.isnot(None),
                Subdomain.tls_expiry <= warning_threshold,
            )
        )
        expiring = (await db.execute(expiring_q)).all()

        for subdomain, asset in expiring:
            days_left = (subdomain.tls_expiry - datetime.now(timezone.utc)).days
            severity = "critical" if subdomain.tls_expiry <= critical_threshold else "medium"

            changes.append({
                "type": "tls_expiry",
                "severity": severity,
                "value": subdomain.fqdn,
                "message": f"TLS certificate for {subdomain.fqdn} expires in {days_left} days",
                "days_remaining": days_left,
                "expiry": subdomain.tls_expiry.isoformat(),
            })

    # ── Statistics Update ─────────────────────────────────────

    async def _update_org_stats(self, db: AsyncSession, org_id: str) -> None:
        """Update denormalized org statistics."""
        from workers.db_models import Asset, Finding, Organization

        total_assets = (await db.execute(
            select(func.count(Asset.id)).where(
                Asset.org_id == org_id,
                Asset.deleted_at.is_(None),
            )
        )).scalar_one()

        total_findings = (await db.execute(
            select(func.count(Finding.id)).where(
                Finding.org_id == org_id,
                Finding.status == "open",
                Finding.deleted_at.is_(None),
            )
        )).scalar_one()

        await db.execute(
            update(Organization).where(Organization.id == org_id).values(
                total_assets=total_assets,
                total_findings=total_findings,
                last_scan_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    # ── OpenSearch Indexing ───────────────────────────────────

    async def _index_to_opensearch(
        self,
        db: AsyncSession,
        org_id: str,
        workspace_id: str,
    ) -> None:
        """Index assets and findings to OpenSearch for full-text search."""
        if not self.opensearch:
            return

        from workers.db_models import Asset, Finding, Subdomain

        # Index assets (batch)
        assets_q = (
            select(Asset, Subdomain)
            .outerjoin(Subdomain, Subdomain.asset_id == Asset.id)
            .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
            .limit(5000)
        )
        rows = (await db.execute(assets_q)).all()

        bulk_body = []
        for asset, subdomain in rows:
            doc = {
                "id": str(asset.id),
                "org_id": org_id,
                "workspace_id": workspace_id,
                "asset_type": asset.asset_type,
                "value": asset.value,
                "status": asset.status,
                "tags": asset.tags or [],
                "criticality": asset.criticality,
                "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            }

            if subdomain:
                doc.update({
                    "title": subdomain.http_title,
                    "technologies": subdomain.technologies or [],
                    "http_status": subdomain.http_status,
                    "ip_addresses": subdomain.ip_addresses or [],
                    "cdn_provider": subdomain.cdn_provider,
                    "tls_expiry": subdomain.tls_expiry.isoformat() if subdomain.tls_expiry else None,
                })

            bulk_body.append({"index": {"_index": "asm-assets", "_id": str(asset.id)}})
            bulk_body.append(doc)

        if bulk_body:
            try:
                await self.opensearch.bulk(body=bulk_body)
            except Exception as e:
                log.error("opensearch_index_assets_error", error=str(e))

        # Index findings
        findings_q = (
            select(Finding)
            .where(Finding.org_id == org_id, Finding.deleted_at.is_(None))
            .limit(10000)
        )
        findings = (await db.execute(findings_q)).scalars().all()

        bulk_body = []
        for finding in findings:
            doc = {
                "id": str(finding.id),
                "org_id": org_id,
                "workspace_id": workspace_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "category": finding.category,
                "status": finding.status,
                "template_id": finding.template_id,
                "cve_ids": finding.cve_ids or [],
                "cvss_score": finding.cvss_score,
                "affected_url": finding.affected_url,
                "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            }
            bulk_body.append({"index": {"_index": "asm-findings", "_id": str(finding.id)}})
            bulk_body.append(doc)

        if bulk_body:
            try:
                await self.opensearch.bulk(body=bulk_body)
            except Exception as e:
                log.error("opensearch_index_findings_error", error=str(e))

    async def _ensure_indices(self) -> None:
        """Create OpenSearch indices with mappings if they don't exist."""
        asset_mapping = {
            "settings": {"number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "org_id": {"type": "keyword"},
                    "workspace_id": {"type": "keyword"},
                    "asset_type": {"type": "keyword"},
                    "value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "status": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "criticality": {"type": "integer"},
                    "title": {"type": "text"},
                    "technologies": {"type": "keyword"},
                    "http_status": {"type": "integer"},
                    "ip_addresses": {"type": "ip"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                }
            }
        }

        finding_mapping = {
            "settings": {"number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "id": {"type": "keyword"},
                    "org_id": {"type": "keyword"},
                    "workspace_id": {"type": "keyword"},
                    "title": {"type": "text"},
                    "description": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "template_id": {"type": "keyword"},
                    "cve_ids": {"type": "keyword"},
                    "cvss_score": {"type": "float"},
                    "affected_url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                }
            }
        }

        for index, mapping in [
            ("asm-assets", asset_mapping),
            ("asm-findings", finding_mapping),
        ]:
            try:
                exists = await self.opensearch.indices.exists(index=index)
                if not exists:
                    await self.opensearch.indices.create(index=index, body=mapping)
                    log.info("opensearch_index_created", index=index)
            except Exception as e:
                log.warning("opensearch_index_error", index=index, error=str(e))

    # ── Queue Operations ──────────────────────────────────────

    async def _complete_scan(self, db, scan_id: str) -> None:
        completed = await mark_scan_completed(db, scan_id)
        if not completed:
            log.info("scan_complete_skipped_inactive_scan", scan_id=scan_id)

    async def _queue_risk_computation(
        self,
        scan_id: str,
        org_id: str,
        workspace_id: str,
    ) -> None:
        queue = QueueClient()
        await queue.connect()
        await queue.publish(
            routing_key="risk.compute",
            message={"scan_id": scan_id, "org_id": org_id, "workspace_id": workspace_id},
        )
        await queue.close()

    async def _queue_change_notifications(
        self,
        scan_id: str,
        org_id: str,
        workspace_id: str,
        changes: List[Dict],
    ) -> None:
        queue = QueueClient()
        await queue.connect()
        await queue.publish(
            routing_key="notify.send",
            message={
                "scan_id": scan_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
                "changes": changes,
            },
        )
        await queue.close()

    async def _find_asset_by_value(
        self,
        db: AsyncSession,
        org_id: str,
        value: str,
        asset_type: str,
    ):
        from workers.db_models import Asset
        result = await db.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.value == value,
                Asset.asset_type == asset_type,
                Asset.deleted_at.is_(None),
            ).limit(1)
        )
        return result.scalar_one_or_none()


if __name__ == "__main__":
    worker = CorrelationWorker()
    asyncio.run(worker.run())

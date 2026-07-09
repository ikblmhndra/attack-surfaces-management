"""
ASM Platform — Scan Scheduler
Uses APScheduler to trigger periodic scans for all monitored organizations.
Also handles TLS expiry pre-checks, enrichment refreshes, and cleanup tasks.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, update

from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()

SCAN_INTERVAL_HOURS = int(os.getenv("SCAN_INTERVAL_HOURS", "24"))
RUN_FULL_SCAN_ON_START = os.getenv("RUN_FULL_SCAN_ON_START", "false").lower() in {"1", "true", "yes"}
TLS_CHECK_INTERVAL_HOURS = 12
CLEANUP_INTERVAL_HOURS = 6
ENRICHMENT_REFRESH_HOURS = 48
VALIDATION_REFRESH_HOURS = int(os.getenv("VALIDATION_REFRESH_HOURS", "24"))
QUICK_SCAN_INTERVAL_HOURS = 6
ACTIVE_SCAN_STATUSES = ("queued", "pending", "running")


class ScanScheduler:
    """
    Central scheduler for all periodic platform tasks:

    - Full scans:          Every N hours per active organization
    - Quick scans:         Every 6 hours (DNS + TLS only)
    - TLS expiry checks:   Every 12 hours
    - Asset cleanup:       Every 6 hours (mark stale assets)
    - Score recompute:     Every 4 hours (ensure freshness)
    - Enrichment refresh:  Every 48 hours (re-enrich IPs/domains)
    """

    def __init__(self):
        self.scheduler = AsyncIOScheduler(
            job_defaults={
                "coalesce": True,         # Merge missed runs
                "max_instances": 1,       # One instance per job
                "misfire_grace_time": 300, # 5 min grace window
            }
        )
        self.queue: QueueClient = QueueClient()

    async def start(self) -> None:
        """Initialize queue connection and start scheduler."""
        await self.queue.connect()
        log.info("scheduler_queue_connected")

        # Register all jobs
        self._register_jobs()

        self.scheduler.start()
        log.info(
            "scheduler_started",
            scan_interval_hours=SCAN_INTERVAL_HOURS,
            jobs=len(self.scheduler.get_jobs()),
        )

        # Run initial health check
        await self._health_check()

        # Keep running
        try:
            while True:
                await asyncio.sleep(60)
                await self._health_check()
        except (KeyboardInterrupt, asyncio.CancelledError):
            await self.stop()

    async def stop(self) -> None:
        """Graceful shutdown."""
        self.scheduler.shutdown(wait=False)
        await self.queue.close()
        log.info("scheduler_stopped")

    def _register_jobs(self) -> None:
        """Register all scheduled jobs."""

        # ── Full scans (main) ──────────────────────────────────
        self.scheduler.add_job(
            self._schedule_full_scans,
            trigger=IntervalTrigger(hours=SCAN_INTERVAL_HOURS),
            id="full_scans",
            name="Schedule full scans for all active organizations",
            next_run_time=(
                datetime.now(timezone.utc) + timedelta(minutes=2)
                if RUN_FULL_SCAN_ON_START
                else None
            ),
        )

        # ── Quick scans (DNS/TLS/headers only) ────────────────
        self.scheduler.add_job(
            self._schedule_quick_scans,
            trigger=IntervalTrigger(hours=QUICK_SCAN_INTERVAL_HOURS),
            id="quick_scans",
            name="Quick scans: DNS, TLS, security headers",
        )

        # ── TLS expiry monitoring ─────────────────────────────
        self.scheduler.add_job(
            self._check_tls_expiry,
            trigger=IntervalTrigger(hours=TLS_CHECK_INTERVAL_HOURS),
            id="tls_expiry_check",
            name="Check TLS certificate expiry",
        )

        # ── Stale asset cleanup ───────────────────────────────
        self.scheduler.add_job(
            self._cleanup_stale_assets,
            trigger=IntervalTrigger(hours=CLEANUP_INTERVAL_HOURS),
            id="asset_cleanup",
            name="Mark stale assets inactive",
        )

        # ── Score freshness recompute ─────────────────────────
        self.scheduler.add_job(
            self._refresh_stale_scores,
            trigger=IntervalTrigger(hours=4),
            id="score_refresh",
            name="Recompute stale risk scores",
        )

        # ── Threat intel enrichment refresh ───────────────────
        self.scheduler.add_job(
            self._schedule_enrichment_refresh,
            trigger=IntervalTrigger(hours=ENRICHMENT_REFRESH_HOURS),
            id="enrichment_refresh",
            name="Refresh threat intelligence enrichment",
        )

        # ── Asset ownership/scope validation refresh ──────────
        self.scheduler.add_job(
            self._schedule_asset_validation,
            trigger=IntervalTrigger(hours=VALIDATION_REFRESH_HOURS),
            id="asset_validation_refresh",
            name="Refresh asset ownership and scope validation",
        )

        log.info("scheduler_jobs_registered", count=len(self.scheduler.get_jobs()))

    # ── Job implementations ───────────────────────────────────

    async def _schedule_full_scans(self) -> None:
        """Queue full discovery scans for all active organizations."""
        log.info("scheduling_full_scans")

        async with get_session() as db:
            orgs = await self._get_active_organizations(db)

        if not orgs:
            log.info("no_active_organizations")
            return

        queued = 0
        for org in orgs:
            try:
                scan_id = await self._create_scheduled_scan(
                    org["id"],
                    org["workspace_id"],
                    "full",
                    targets={
                        "domains": org["domains"] + org["root_domains"],
                        "ip_ranges": org["ip_ranges"],
                        "asns": org["asns"],
                    },
                    config={
                        "scan_type": "full",
                        "severities": ["critical", "high", "medium", "low"],
                        "modules": ["discovery", "port", "crawl", "nuclei", "screenshot"],
                        "use_amass": False,
                        "ports": "top-1000",
                    },
                    priority=5,
                )
                if scan_id:
                    queued += 1
            except Exception as e:
                log.error("scan_queue_error", org_id=org["id"], error=str(e))

        log.info("full_scans_queued", count=queued)

    async def _schedule_quick_scans(self) -> None:
        """Queue lightweight scans: DNS + HTTP headers + TLS only."""
        log.info("scheduling_quick_scans")

        async with get_session() as db:
            orgs = await self._get_active_organizations(db)

        queued = 0
        for org in orgs:
            try:
                scan_id = await self._create_scheduled_scan(
                    org["id"],
                    org["workspace_id"],
                    "quick",
                    targets={
                        "domains": org["domains"] + org["root_domains"],
                    },
                    config={
                        "scan_type": "quick",
                        "severities": ["critical", "high"],
                        "modules": ["discovery", "crawl", "nuclei"],
                    },
                    priority=3,
                )
                if scan_id:
                    queued += 1
            except Exception as e:
                log.error("quick_scan_queue_error", org_id=org["id"], error=str(e))
        log.info("quick_scans_queued", count=queued)

    async def _check_tls_expiry(self) -> None:
        """Find certificates expiring soon and create findings/notifications."""
        from workers.db_models import Asset, Subdomain, Notification

        log.info("checking_tls_expiry")
        now = datetime.now(timezone.utc)
        warning_threshold = now + timedelta(days=30)
        critical_threshold = now + timedelta(days=7)

        async with get_session() as db:
            from sqlalchemy import and_
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            expiring_q = (
                select(Subdomain, Asset)
                .join(Asset, Asset.id == Subdomain.asset_id)
                .where(
                    Subdomain.tls_expiry.isnot(None),
                    Subdomain.tls_expiry <= warning_threshold,
                    Subdomain.tls_expiry >= now,  # Not already expired
                    Asset.deleted_at.is_(None),
                )
            )
            rows = (await db.execute(expiring_q)).all()

            for subdomain, asset in rows:
                days_left = (subdomain.tls_expiry - now).days
                severity = "critical" if subdomain.tls_expiry <= critical_threshold else "medium"

                log.info(
                    "tls_expiry_detected",
                    fqdn=subdomain.fqdn,
                    days_left=days_left,
                    severity=severity,
                )

                # Queue notification
                await self.queue.publish(
                    routing_key="notify.send",
                    message={
                        "scan_id": "tls-monitor",
                        "org_id": str(asset.org_id),
                        "workspace_id": str(asset.workspace_id),
                        "changes": [{
                            "type": "tls_expiry",
                            "severity": severity,
                            "value": subdomain.fqdn,
                            "message": f"TLS certificate for {subdomain.fqdn} expires in {days_left} day(s)",
                            "days_remaining": days_left,
                            "expiry": subdomain.tls_expiry.isoformat(),
                        }],
                    },
                )

        log.info("tls_expiry_check_complete", checked=len(rows))

    async def _cleanup_stale_assets(self) -> None:
        """
        Mark assets as inactive if not seen in 7+ days.
        This handles disappeared subdomains and decommissioned IPs.
        """
        from workers.db_models import Asset

        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        log.info("cleaning_stale_assets", cutoff=cutoff.isoformat())

        async with get_session() as db:
            result = await db.execute(
                update(Asset)
                .where(
                    Asset.last_seen < cutoff,
                    Asset.status == "active",
                    Asset.deleted_at.is_(None),
                )
                .values(status="inactive")
                .returning(Asset.id)
            )
            stale_ids = result.scalars().all()
            await db.commit()

        log.info("stale_assets_marked_inactive", count=len(stale_ids))

    async def _refresh_stale_scores(self) -> None:
        """Recompute risk scores for orgs whose score is >4 hours old."""
        from workers.db_models import Organization, RiskScore

        cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
        log.info("refreshing_stale_scores")

        async with get_session() as db:
            # Find orgs with stale scores
            stale_orgs_q = (
                select(Organization)
                .where(
                    Organization.deleted_at.is_(None),
                    Organization.is_monitoring_active == True,
                )
            )
            orgs = (await db.execute(stale_orgs_q)).scalars().all()

            refreshed = 0
            for org in orgs:
                # Check last score timestamp
                latest_score_q = (
                    select(RiskScore.computed_at)
                    .where(RiskScore.org_id == org.id)
                    .order_by(RiskScore.computed_at.desc())
                    .limit(1)
                )
                latest = (await db.execute(latest_score_q)).scalar_one_or_none()

                if latest is None or latest < cutoff:
                    await self.queue.publish(
                        routing_key="risk.compute",
                        message={
                            "scan_id": "scheduler-refresh",
                            "org_id": str(org.id),
                            "workspace_id": str(org.workspace_id),
                        },
                        priority=2,
                    )
                    refreshed += 1

        log.info("stale_scores_queued_for_refresh", count=refreshed)

    async def _schedule_enrichment_refresh(self) -> None:
        """Re-enrich IPs and domains whose intel is expired."""
        from workers.db_models import Asset, ThreatIntel

        log.info("scheduling_enrichment_refresh")
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=ENRICHMENT_REFRESH_HOURS)

        async with get_session() as db:
            stale_intel_q = (
                select(Asset.id, Asset.value, Asset.asset_type, Asset.org_id, Asset.workspace_id)
                .outerjoin(ThreatIntel, ThreatIntel.asset_id == Asset.id)
                .where(
                    Asset.deleted_at.is_(None),
                    Asset.status == "active",
                    Asset.asset_type.in_(["ip", "subdomain"]),
                )
                .where(
                    (ThreatIntel.enriched_at < cutoff) | ThreatIntel.id.is_(None)
                )
                .limit(500)
            )
            stale = (await db.execute(stale_intel_q)).all()

        log.info("assets_queued_for_enrichment", count=len(stale))

        # Queue in batches of 20
        batch = []
        for asset in stale:
            batch.append({
                "asset_id": str(asset.id),
                "value": asset.value,
                "asset_type": asset.asset_type,
                "org_id": str(asset.org_id),
                "workspace_id": str(asset.workspace_id),
            })
            if len(batch) >= 20:
                await self.queue.publish(
                    routing_key="enrich.assets",
                    message={"assets": batch},
                    priority=1,
                )
                batch = []

        if batch:
            await self.queue.publish(
                routing_key="enrich.assets",
                message={"assets": batch},
                priority=1,
            )

    async def _schedule_asset_validation(self) -> None:
        """Queue periodic validation for active organizations."""
        log.info("scheduling_asset_validation_refresh")
        async with get_session() as db:
            orgs = await self._get_active_organizations(db)

        queued = 0
        for org in orgs:
            await self.queue.publish(
                routing_key="asset.validate",
                message={
                    "org_id": org["id"],
                    "workspace_id": org["workspace_id"],
                    "limit": int(os.getenv("VALIDATION_REFRESH_LIMIT", "250")),
                    "stale_hours": VALIDATION_REFRESH_HOURS,
                },
                priority=1,
            )
            queued += 1

        log.info("asset_validation_refresh_queued", count=queued)

    # ── Helpers ───────────────────────────────────────────────

    async def _get_active_organizations(self, db) -> List[dict]:
        from workers.db_models import Organization, Workspace

        result = await db.execute(
            select(Organization, Workspace.settings).join(
                Workspace, Organization.workspace_id == Workspace.id
            ).where(
                Organization.deleted_at.is_(None),
                Organization.is_monitoring_active == True,
                Workspace.is_active == True,
            )
        )
        rows = result.all()
        orgs = [
            org for org, ws_settings in rows
            if ws_settings.get("auto_scan_enabled", True)
            and getattr(org, "auto_scan_enabled", True)
        ]

        return [
            {
                "id": str(o.id),
                "workspace_id": str(o.workspace_id),
                "name": o.name,
                "domains": o.domains or [],
                "root_domains": o.root_domains or [],
                "ip_ranges": o.ip_ranges or [],
                "asns": o.asns or [],
            }
            for o in orgs
        ]

    async def _create_scheduled_scan(
        self,
        org_id: str,
        workspace_id: str,
        scan_type: str,
        targets: dict,
        config: dict,
        priority: int,
    ) -> Optional[str]:
        """Create a scan record and return its ID."""
        import uuid
        from workers.db_models import Scan

        scan_id = str(uuid.uuid4())

        # Estimate total tasks for progress tracking
        modules = config.get("modules") or (
            ["discovery", "crawl", "nuclei"]
            if scan_type == "quick"
            else ["discovery", "port", "crawl", "nuclei", "screenshot"]
        )
        total_tasks = len(modules)
        recency_hours = QUICK_SCAN_INTERVAL_HOURS if scan_type == "quick" else SCAN_INTERVAL_HOURS

        async with get_session() as db:
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            from workers.db_models import OutboxEvent

            if await self._has_recent_or_active_scan(db, org_id, scan_type, recency_hours):
                log.info("scheduled_scan_skipped_recent_or_active", org_id=org_id, scan_type=scan_type)
                return None

            await db.execute(
                pg_insert(Scan.__table__).values(
                    id=scan_id,
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scan_type=scan_type,
                    status="queued",
                    total_tasks=total_tasks,
                    modules=modules,
                    config={**config, "triggered_by": "scheduler"},
                )
            )
            db.add(
                OutboxEvent(
                    event_type="queue.publish",
                    routing_key="scan.discovery",
                    payload={
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "workspace_id": workspace_id,
                        "targets": targets,
                        "config": config,
                        "triggered_by": "scheduler",
                    },
                    priority=priority,
                    aggregate_type="scan",
                    aggregate_id=scan_id,
                )
            )
            await db.commit()

        try:
            from app.services.outbox_service import dispatch_pending_outbox_once
            await dispatch_pending_outbox_once(limit=5)
        except Exception as exc:
            log.warning("scheduled_scan_outbox_dispatch_deferred", scan_id=scan_id, error=str(exc))

        return scan_id

    async def _has_recent_or_active_scan(
        self,
        db,
        org_id: str,
        scan_type: str,
        recency_hours: int,
    ) -> bool:
        """Avoid duplicate automated scans on restart or scheduler catch-up."""
        from workers.db_models import Scan

        cutoff = datetime.now(timezone.utc) - timedelta(hours=recency_hours)
        result = await db.execute(
            select(Scan.id)
            .where(
                Scan.org_id == org_id,
                Scan.scan_type == scan_type,
                (
                    Scan.status.in_(ACTIVE_SCAN_STATUSES)
                    | (
                        (Scan.status == "completed")
                        & (Scan.created_at >= cutoff)
                    )
                ),
            )
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def _health_check(self) -> None:
        """Log scheduler health metrics and touch the heartbeat file the
        Dockerfile HEALTHCHECK relies on (this process doesn't subclass
        BaseWorker, so it needs its own heartbeat — see base_worker.py)."""
        jobs = self.scheduler.get_jobs()
        if self.queue.is_connected:
            try:
                Path(os.getenv("WORKER_HEARTBEAT_PATH", "/tmp/worker_heartbeat")).touch()
            except Exception:
                pass
        log.info(
            "scheduler_health",
            active_jobs=len(jobs),
            queue_connected=self.queue.is_connected,
            next_runs={
                j.id: j.next_run_time.isoformat() if j.next_run_time else None
                for j in jobs[:5]
            },
        )


async def main():
    scheduler = ScanScheduler()
    await scheduler.start()


if __name__ == "__main__":
    asyncio.run(main())

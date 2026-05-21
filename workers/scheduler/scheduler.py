"""
ASM Platform — Scan Scheduler
Uses APScheduler to trigger periodic scans for all monitored organizations.
Also handles TLS expiry pre-checks, enrichment refreshes, and cleanup tasks.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import List

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, update

from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()

SCAN_INTERVAL_HOURS = int(os.getenv("SCAN_INTERVAL_HOURS", "24"))
TLS_CHECK_INTERVAL_HOURS = 12
CLEANUP_INTERVAL_HOURS = 6
ENRICHMENT_REFRESH_HOURS = 48


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
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
        )

        # ── Quick scans (DNS/TLS/headers only) ────────────────
        self.scheduler.add_job(
            self._schedule_quick_scans,
            trigger=IntervalTrigger(hours=6),
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

        # ── Daily report generation ───────────────────────────
        self.scheduler.add_job(
            self._generate_daily_summaries,
            trigger=CronTrigger(hour=8, minute=0, timezone="UTC"),
            id="daily_reports",
            name="Generate daily security summaries",
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
                await self.queue.publish(
                    routing_key="scan.discovery",
                    message={
                        "scan_id": await self._create_scheduled_scan(org["id"], org["workspace_id"], "full"),
                        "org_id": org["id"],
                        "workspace_id": org["workspace_id"],
                        "targets": {
                            "domains": org["domains"] + org["root_domains"],
                            "ip_ranges": org["ip_ranges"],
                            "asns": org["asns"],
                        },
                        "config": {
                            "scan_type": "full",
                            "severities": ["critical", "high", "medium", "low"],
                            "modules": ["discovery", "port", "nuclei", "screenshot"],
                            "use_amass": False,
                            "ports": "top-1000",
                        },
                        "triggered_by": "scheduler",
                    },
                    priority=5,
                )
                queued += 1
            except Exception as e:
                log.error("scan_queue_error", org_id=org["id"], error=str(e))

        log.info("full_scans_queued", count=queued)

    async def _schedule_quick_scans(self) -> None:
        """Queue lightweight scans: DNS + HTTP headers + TLS only."""
        log.info("scheduling_quick_scans")

        async with get_session() as db:
            orgs = await self._get_active_organizations(db)

        for org in orgs:
            try:
                await self.queue.publish(
                    routing_key="scan.discovery",
                    message={
                        "scan_id": await self._create_scheduled_scan(org["id"], org["workspace_id"], "quick"),
                        "org_id": org["id"],
                        "workspace_id": org["workspace_id"],
                        "targets": {
                            "domains": org["domains"] + org["root_domains"],
                        },
                        "config": {
                            "scan_type": "quick",
                            "severities": ["critical", "high"],
                            "modules": ["discovery", "nuclei"],
                        },
                        "triggered_by": "scheduler",
                    },
                    priority=3,
                )
            except Exception as e:
                log.error("quick_scan_queue_error", org_id=org["id"], error=str(e))

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

    async def _generate_daily_summaries(self) -> None:
        """Queue daily summary report generation for all workspaces."""
        from workers.db_models import Workspace

        log.info("generating_daily_summaries")

        async with get_session() as db:
            result = await db.execute(
                select(Workspace).where(Workspace.is_active == True)
            )
            workspaces = result.scalars().all()

        for ws in workspaces:
            await self.queue.publish(
                routing_key="report.daily",
                message={
                    "workspace_id": str(ws.id),
                    "report_date": datetime.now(timezone.utc).date().isoformat(),
                    "report_type": "daily_summary",
                },
                priority=1,
            )

        log.info("daily_reports_queued", workspaces=len(workspaces))

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
    ) -> str:
        """Create a scan record and return its ID."""
        import uuid
        from workers.db_models import Scan

        scan_id = str(uuid.uuid4())

        # Estimate total tasks for progress tracking
        if scan_type == "quick":
            modules = ["discovery", "nuclei"]
        else:
            modules = ["discovery", "port", "nuclei", "screenshot"]
        total_tasks = 1  # discovery
        if "port" in modules:
            total_tasks += 1
        if "nuclei" in modules:
            total_tasks += 1
        if "screenshot" in modules:
            total_tasks += 1

        async with get_session() as db:
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            await db.execute(
                pg_insert(Scan.__table__).values(
                    id=scan_id,
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scan_type=scan_type,
                    status="pending",
                    total_tasks=total_tasks,
                    modules=modules,
                    config={"triggered_by": "scheduler"},
                )
            )
            await db.commit()

        return scan_id

    async def _health_check(self) -> None:
        """Log scheduler health metrics."""
        jobs = self.scheduler.get_jobs()
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

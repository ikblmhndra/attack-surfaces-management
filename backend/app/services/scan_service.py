"""
ASM Platform — Scan Service
Creates scan records and publishes tasks to RabbitMQ queue.
"""
from typing import Any, Dict, List
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.models import Organization, Scan
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once

log = structlog.get_logger()

DEFAULT_MODULES = {
    "full":      ["discovery", "port", "crawl", "nuclei", "screenshot"],
    "quick":     ["discovery", "crawl", "nuclei"],
    "discovery": ["discovery"],
    "vuln":      ["nuclei"],
}

DEFAULT_SCAN_CONFIG = {
    "full": {
        "crawl": True,
        "fuzz": False,
        "nuclei_batch_size": 15,
        "crawl_nuclei_batch_size": 15,
        "scan_timeout": 1800,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 6,
        "bulk_size": 6,
        "automatic_scan": True,
        "use_tech_tags": True,
    },
    "quick": {
        "crawl": True,
        "fuzz": False,
        "nuclei_batch_size": 50,
        "crawl_nuclei_batch_size": 25,
        "scan_timeout": 300,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 15,
        "bulk_size": 15,
        "automatic_scan": False,
        "use_tech_tags": False,
        "vuln_depth": "critical",
    },
    "vuln": {
        "nuclei_batch_size": 25,
        "scan_timeout": 900,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 8,
        "bulk_size": 8,
        "automatic_scan": True,
        "use_tech_tags": True,
    },
}


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_and_queue(
        self,
        org_id: UUID,
        workspace_id: UUID,
        created_by: UUID,
        scan_type: str,
        modules: List[str],
        config: Dict[str, Any],
        org: Organization,
    ) -> Scan:
        """Create a scan record in DB and publish discovery task to queue."""
        scan_modules = modules or DEFAULT_MODULES.get(scan_type, DEFAULT_MODULES["full"])
        effective_config = {
            **DEFAULT_SCAN_CONFIG.get(scan_type, {}),
            **(config or {}),
        }

        scan = Scan(
            org_id=org_id,
            workspace_id=workspace_id,
            created_by=created_by,
            scan_type=scan_type,
            status="queued",
            modules=scan_modules,
            config=effective_config,
            total_tasks=len(scan_modules),
        )
        self.db.add(scan)
        await self.db.flush()

        self.db.add(
            create_queue_event(
                routing_key="scan.discovery",
                payload={
                    "scan_id": str(scan.id),
                    "org_id": str(org_id),
                    "workspace_id": str(workspace_id),
                    "targets": {
                        "domains": (org.domains or []) + (org.root_domains or []),
                        "ip_ranges": org.ip_ranges or [],
                        "asns": org.asns or [],
                    },
                    "config": {
                        **effective_config,
                        "scan_type": scan_type,
                        "modules": scan_modules,
                    },
                    "triggered_by": "api",
                },
                priority=7,
                aggregate_type="scan",
                aggregate_id=str(scan.id),
            )
        )
        await self.db.commit()
        await self.db.refresh(scan)
        await dispatch_pending_outbox_once(limit=5)
        log.info("scan_queued", scan_id=str(scan.id), scan_type=scan_type, org_id=str(org_id))

        return scan

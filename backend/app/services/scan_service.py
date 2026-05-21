"""
ASM Platform — Scan Service
Creates scan records and publishes tasks to RabbitMQ queue.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.models import Organization, Scan
from app.core.config import settings

log = structlog.get_logger()

DEFAULT_MODULES = {
    "full":      ["discovery", "port", "nuclei", "screenshot"],
    "quick":     ["discovery", "nuclei"],
    "discovery": ["discovery"],
    "vuln":      ["nuclei"],
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

        scan = Scan(
            org_id=org_id,
            workspace_id=workspace_id,
            created_by=created_by,
            scan_type=scan_type,
            status="pending",
            modules=scan_modules,
            config=config,
            total_tasks=len(scan_modules),
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        # Publish to queue
        try:
            from app.core.queue_client import QueueClient
            queue = QueueClient()
            await queue.connect()
            await queue.publish(
                routing_key="scan.discovery",
                message={
                    "scan_id": str(scan.id),
                    "org_id": str(org_id),
                    "workspace_id": str(workspace_id),
                    "targets": {
                        "domains": (org.domains or []) + (org.root_domains or []),
                        "ip_ranges": org.ip_ranges or [],
                        "asns": org.asns or [],
                    },
                    "config": {
                        **config,
                        "scan_type": scan_type,
                        "modules": scan_modules,
                    },
                    "triggered_by": "api",
                },
                priority=7,
            )
            await queue.close()
            log.info("scan_queued", scan_id=str(scan.id), scan_type=scan_type, org_id=str(org_id))
        except Exception as e:
            log.error("scan_queue_publish_failed", scan_id=str(scan.id), error=str(e))
            scan.status = "failed"
            scan.error_message = f"Failed to queue scan: {str(e)}"
            await self.db.commit()
            raise

        return scan

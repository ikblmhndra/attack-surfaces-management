"""
ASM Platform — Audit Service
Async audit log writing with structured event recording.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import structlog
from app.core import database as db_module
from app.db.models.models import AuditLog

log = structlog.get_logger()


async def audit_log(
    workspace_id: str,
    action: str,
    resource_type: str,
    user_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    changes: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    severity: str = "info",
) -> None:
    """Write an audit log entry asynchronously."""
    try:
        async with db_module.AsyncSessionLocal() as session:
            entry = AuditLog(
                workspace_id=workspace_id,
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                changes=changes,
                metadata=metadata,
                ip_address=ip_address,
                user_agent=user_agent,
                severity=severity,
            )
            session.add(entry)
            await session.commit()
    except Exception as e:
        log.error("audit_log_write_failed", action=action, error=str(e))


async def audit_scan_started(workspace_id: str, org_id: str, scan_id: str, user_id: str) -> None:
    await audit_log(workspace_id=workspace_id, user_id=user_id, action="scan.start",
                    resource_type="scan", resource_id=scan_id,
                    metadata={"org_id": org_id})


async def audit_scan_completed(workspace_id: str, scan_id: str, stats: dict) -> None:
    await audit_log(workspace_id=workspace_id, action="scan.complete",
                    resource_type="scan", resource_id=scan_id, metadata=stats)

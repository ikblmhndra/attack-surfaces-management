"""
ASM Platform — Bug Bounty pipeline: notify.send integration for confirmed
critical/high findings.

Reuses the existing ASM `notify.send` queue/NotificationWorker (Slack/
Discord/Telegram/email/webhook, keyed off the workspace's own
NotificationRule rows) rather than building a bounty-specific channel sender
-- whatever the operator already has configured for their workspace picks
this up for free, and it lands in the same in-app notification center.
BountyProgram has no `org_id` (organizations are an ASM-pipeline concept
bounty doesn't share) -- the notify pipeline already supports that:
`Notification.org_id` is nullable and `NotificationRule` is looked up by
`workspace_id` alone, not `org_id`. See CHANGELOG.md.
"""
from typing import Any, Dict, List, Optional

import structlog

from workers.queue_client import QueueClient

log = structlog.get_logger()

_NOTIFY_SEVERITIES = {"critical", "high"}


def _finding_target(f: Dict[str, Any]) -> str:
    evidence = f.get("evidence") or {}
    return evidence.get("target_url") or evidence.get("url") or evidence.get("matched_at") or ""


async def notify_critical_findings(
    program_id: str, program_name: str, workspace_id: Optional[str], findings: List[Dict[str, Any]],
) -> int:
    """Publish one notify.send message covering every newly-persisted finding
    that is both severity critical/high AND status confirmed. A candidate
    (inconclusive) finding, however severe it would be if true, is exactly
    what this pipeline is careful never to overclaim -- excluded here too, so
    a notification always means "confirmed", never "maybe". Returns how many
    findings qualified (0 means nothing sent, not an error)."""
    if not workspace_id:
        return 0
    changes = [
        {
            "type": "bounty_finding_confirmed",
            "severity": f.get("severity"),
            "value": _finding_target(f),
            "message": (
                f"[{program_name}] {f.get('technique')} confirmed ({f.get('severity')}) on "
                f"{_finding_target(f) or 'target'}"
            ),
            "finding_module": f.get("module"),
            "technique": f.get("technique"),
            "program_id": str(program_id),
        }
        for f in findings
        if f.get("severity") in _NOTIFY_SEVERITIES and f.get("status") == "confirmed"
    ]
    if not changes:
        return 0

    client = QueueClient()
    try:
        await client.connect()
        await client.publish(
            "notify.send",
            {"scan_id": str(program_id), "org_id": None, "workspace_id": str(workspace_id), "changes": changes},
            priority=6,
        )
    except Exception as exc:
        log.warning("bounty_notify_publish_error", program_id=program_id, error=str(exc)[:200])
        return 0
    finally:
        await client.close()
    log.info("bounty_notify_published", program_id=program_id, count=len(changes))
    return len(changes)

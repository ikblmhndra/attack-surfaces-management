"""
ASM Platform — Notification Worker
Evaluates notification rules and dispatches alerts across channels.
"""
import asyncio
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from workers.base_worker import BaseWorker
from workers.db import get_session

log = structlog.get_logger()

# Legacy Telegram "Markdown" parse_mode treats _ * ` [ as syntax -- an
# unbalanced one anywhere in interpolated text (real example: a finding
# titled "Drupal User Enumeration [Redirect]") makes the whole sendMessage
# call fail with "can't parse entities", which _dispatch()'s try/except
# then swallows silently. Escape dynamic text before interpolating.
_TELEGRAM_MD_SPECIAL_RE = re.compile(r"([_*`\[])")


def _escape_telegram_md(text: str) -> str:
    return _TELEGRAM_MD_SPECIAL_RE.sub(r"\\\1", text)

SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
SEVERITY_COLOR = {
    "critical": 0xFF0000,
    "high": 0xFF6600,
    "medium": 0xFFCC00,
    "low": 0x0066FF,
    "info": 0x808080,
}


class NotificationWorker(BaseWorker):
    """
    Evaluates workspace notification rules against scan change events
    and dispatches to configured channels.

    Supported channels:
    - email (SMTP)
    - slack (Incoming Webhook)
    - discord (Webhook)
    - telegram (Bot API)
    - webhook (generic HTTP POST)
    """

    QUEUE = "notify.send"
    CONCURRENCY = 1

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        changes = message.get("changes", [])

        if not changes:
            return

        log.info("notification_processing", scan_id=scan_id, changes=len(changes))

        async with get_session() as db:
            # Load notification rules for this workspace
            rules = await self._get_notification_rules(db, workspace_id)
            if not rules:
                return

            # Load org name for context
            org_name = await self._get_org_name(db, org_id)

            # Create notification records
            notifications_created = await self._create_notifications(
                db, workspace_id, org_id, changes
            )

            # Evaluate each rule against changes
            for rule in rules:
                if not rule["is_active"]:
                    continue

                matching_changes = self._filter_changes(changes, rule)
                if not matching_changes:
                    continue

                # Dispatch to each configured channel
                for channel in rule.get("channels", []):
                    try:
                        await self._dispatch(
                            channel=channel,
                            rule=rule,
                            changes=matching_changes,
                            org_name=org_name,
                            org_id=org_id,
                            scan_id=scan_id,
                        )
                    except Exception as e:
                        log.error(
                            "notification_dispatch_error",
                            channel=channel,
                            rule_id=rule["id"],
                            error=str(e),
                        )

        log.info("notifications_sent", scan_id=scan_id)

    def _filter_changes(self, changes: List[Dict], rule: Dict) -> List[Dict]:
        """Filter changes that match the notification rule criteria."""
        min_sev_priority = SEVERITY_PRIORITY.get(rule.get("min_severity", "high"), 1)
        event_types = set(rule.get("event_types", []))

        matching = []
        for change in changes:
            # Check event type
            if event_types and change.get("type") not in event_types:
                continue

            # Check severity threshold
            sev = change.get("severity", "info")
            if SEVERITY_PRIORITY.get(sev, 99) > min_sev_priority:
                continue

            matching.append(change)

        return matching

    async def _dispatch(
        self,
        channel: str,
        rule: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        """Route to the appropriate channel sender."""
        config = rule.get("config", {})

        dispatch_map = {
            "slack": self._send_slack,
            "discord": self._send_discord,
            "telegram": self._send_telegram,
            "email": self._send_email,
            "webhook": self._send_webhook,
        }

        sender = dispatch_map.get(channel)
        if sender:
            await sender(config, changes, org_name, org_id, scan_id)
        else:
            log.warning("unknown_notification_channel", channel=channel)

    # ── Slack ─────────────────────────────────────────────────

    async def _send_slack(
        self,
        config: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        webhook_url = config.get("webhook_url") or os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            return

        # Group by severity
        critical = [c for c in changes if c.get("severity") == "critical"]
        high = [c for c in changes if c.get("severity") == "high"]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🛡️ ASM Alert — {org_name}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Organization:*\n{org_name}"},
                    {"type": "mrkdwn", "text": f"*Changes Detected:*\n{len(changes)}"},
                    {"type": "mrkdwn", "text": f"*Critical:*\n{len(critical)}"},
                    {"type": "mrkdwn", "text": f"*High:*\n{len(high)}"},
                ],
            },
            {"type": "divider"},
        ]

        # Add top 5 changes
        for change in changes[:5]:
            sev = change.get("severity", "info")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{change.get('type', 'change').replace('_', ' ').title()}*\n"
                            f"{change.get('message', '')}",
                },
            })

        if len(changes) > 5:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"_...and {len(changes) - 5} more changes_"},
                ],
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in ASM Platform"},
                    "url": f"{os.getenv('PLATFORM_URL', 'http://localhost')}/dashboard/organizations/{org_id}",
                    "style": "primary",
                },
            ],
        })

        payload = {"blocks": blocks}

        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise Exception(f"Slack error {resp.status}: {body}")

        log.info("slack_notification_sent", changes=len(changes), org=org_name)

    # ── Discord ───────────────────────────────────────────────

    async def _send_discord(
        self,
        config: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        webhook_url = config.get("webhook_url") or os.getenv("DISCORD_WEBHOOK_URL")
        if not webhook_url:
            return

        # Determine highest severity color
        severities = [c.get("severity", "info") for c in changes]
        max_sev = min(severities, key=lambda s: SEVERITY_PRIORITY.get(s, 99))
        color = SEVERITY_COLOR.get(max_sev, 0x808080)

        # Build embed fields (Discord limit: 25 fields)
        fields = []
        for change in changes[:10]:
            fields.append({
                "name": f"{SEVERITY_EMOJI.get(change.get('severity', 'info'), '⚪')} "
                        f"{change.get('type', 'change').replace('_', ' ').title()}",
                "value": change.get("message", "No details")[:1024],
                "inline": False,
            })

        embed = {
            "title": f"🛡️ ASM Security Alert — {org_name}",
            "description": f"**{len(changes)} change(s)** detected in the attack surface scan.",
            "color": color,
            "fields": fields,
            "footer": {"text": f"ASM Platform • Scan ID: {scan_id[:8]}"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": f"{os.getenv('PLATFORM_URL', 'http://localhost')}/dashboard/organizations/{org_id}",
        }

        payload = {
            "username": "ASM Platform",
            "embeds": [embed],
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    raise Exception(f"Discord error {resp.status}: {body}")

        log.info("discord_notification_sent", changes=len(changes))

    # ── Telegram ──────────────────────────────────────────────

    async def _send_telegram(
        self,
        config: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        bot_token = config.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = config.get("chat_id") or os.getenv("TELEGRAM_CHAT_ID")

        if not bot_token or not chat_id:
            return

        lines = [f"🛡️ *ASM Alert — {_escape_telegram_md(org_name)}*", f"_{len(changes)} change(s) detected_", ""]

        for change in changes[:8]:
            sev = change.get("severity", "info")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            change_type = _escape_telegram_md(change.get("type", "").replace("_", " ").title())
            change_message = _escape_telegram_md(change.get("message", ""))
            lines.append(f"{emoji} *{change_type}*")
            lines.append(f"  {change_message}")

        if len(changes) > 8:
            lines.append(f"_...and {len(changes) - 8} more_")

        text = "\n".join(lines)

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    raise Exception(f"Telegram error: {data.get('description')}")

        log.info("telegram_notification_sent", changes=len(changes))

    # ── Email ─────────────────────────────────────────────────

    async def _send_email(
        self,
        config: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        recipients = config.get("recipients", [])
        if not recipients:
            return

        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_pass = os.getenv("SMTP_PASSWORD", "")
        smtp_from = os.getenv("SMTP_FROM", "noreply@asm-platform.local")

        if not smtp_host:
            log.warning("smtp_not_configured")
            return

        subject = f"[ASM] Security Alert — {org_name}: {len(changes)} Change(s) Detected"

        html_rows = ""
        for change in changes:
            sev = change.get("severity", "info")
            colors = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "info": "#6b7280",
            }
            color = colors.get(sev, "#6b7280")
            html_rows += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #1e293b;">
                    <span style="color: {color}; font-weight: bold; text-transform: uppercase; font-size: 11px;">
                        {sev}
                    </span>
                </td>
                <td style="padding: 8px; border-bottom: 1px solid #1e293b; color: #94a3b8;">
                    {change.get('type', '').replace('_', ' ').title()}
                </td>
                <td style="padding: 8px; border-bottom: 1px solid #1e293b; color: #e2e8f0;">
                    {change.get('message', '')}
                </td>
            </tr>"""

        html = f"""
        <!DOCTYPE html>
        <html>
        <body style="background: #0a0f1a; color: #e2e8f0; font-family: system-ui, sans-serif; margin: 0; padding: 20px;">
            <div style="max-width: 700px; margin: 0 auto; background: #0f172a; border-radius: 12px; padding: 24px; border: 1px solid #1e293b;">
                <div style="margin-bottom: 20px;">
                    <h1 style="color: #0ea5e9; font-size: 20px; margin: 0;">🛡️ ASM Security Alert</h1>
                    <p style="color: #64748b; margin: 4px 0 0;">{org_name}</p>
                </div>

                <div style="background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
                    <p style="margin: 0; font-size: 15px;">
                        <strong>{len(changes)} change(s)</strong> were detected during the latest security scan.
                    </p>
                </div>

                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <thead>
                        <tr style="background: #1e293b;">
                            <th style="padding: 10px 8px; text-align: left; color: #64748b; font-size: 11px; text-transform: uppercase;">Severity</th>
                            <th style="padding: 10px 8px; text-align: left; color: #64748b; font-size: 11px; text-transform: uppercase;">Type</th>
                            <th style="padding: 10px 8px; text-align: left; color: #64748b; font-size: 11px; text-transform: uppercase;">Details</th>
                        </tr>
                    </thead>
                    <tbody>{html_rows}</tbody>
                </table>

                <a href="{os.getenv('PLATFORM_URL', 'http://localhost')}/dashboard/organizations/{org_id}"
                   style="display: inline-block; background: #0ea5e9; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600;">
                    View in ASM Platform →
                </a>

                <p style="color: #334155; font-size: 11px; margin-top: 24px;">
                    ASM Platform · Scan ID: {scan_id[:16]} · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
                </p>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(html, "html"))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self._smtp_send(msg, smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, recipients)
        )

        log.info("email_notification_sent", recipients=len(recipients))

    def _smtp_send(self, msg, host, port, user, password, from_addr, recipients):
        import smtplib
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            if port != 465:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, recipients, msg.as_string())

    # ── Generic Webhook ───────────────────────────────────────

    async def _send_webhook(
        self,
        config: Dict,
        changes: List[Dict],
        org_name: str,
        org_id: str,
        scan_id: str,
    ) -> None:
        url = config.get("url")
        if not url:
            return

        headers = config.get("headers", {"Content-Type": "application/json"})
        payload = {
            "event": "asm.scan.changes",
            "org_id": org_id,
            "org_name": org_name,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "changes": changes,
            "summary": {
                "total": len(changes),
                "critical": sum(1 for c in changes if c.get("severity") == "critical"),
                "high": sum(1 for c in changes if c.get("severity") == "high"),
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    raise Exception(f"Webhook error {resp.status}: {body[:200]}")

        log.info("webhook_notification_sent", url=url[:50])

    # ── DB helpers ────────────────────────────────────────────

    async def _get_notification_rules(self, db: AsyncSession, workspace_id: str) -> List[Dict]:
        from workers.db_models import NotificationRule
        result = await db.execute(
            select(NotificationRule).where(
                NotificationRule.workspace_id == workspace_id,
                NotificationRule.is_active == True,
            )
        )
        rules = result.scalars().all()
        return [
            {
                "id": str(r.id),
                "event_types": r.event_types or [],
                "channels": r.channels or [],
                "min_severity": r.min_severity,
                "config": r.config or {},
                "is_active": r.is_active,
            }
            for r in rules
        ]

    async def _get_org_name(self, db: AsyncSession, org_id: str) -> str:
        from workers.db_models import Organization
        result = await db.execute(
            select(Organization.name).where(Organization.id == org_id)
        )
        row = result.scalar_one_or_none()
        return row or "Unknown Organization"

    async def _create_notifications(
        self,
        db: AsyncSession,
        workspace_id: str,
        org_id: str,
        changes: List[Dict],
    ) -> int:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Notification

        created = 0
        for change in changes:
            stmt = pg_insert(Notification.__table__).values(
                workspace_id=workspace_id,
                org_id=org_id,
                event_type=change.get("type", "unknown"),
                severity=change.get("severity", "info"),
                title=change.get("message", "Security change detected"),
                message=change.get("message", ""),
                payload=change,
            ).on_conflict_do_nothing()
            await db.execute(stmt)
            created += 1

        await db.commit()
        return created


if __name__ == "__main__":
    worker = NotificationWorker()
    asyncio.run(worker.run())

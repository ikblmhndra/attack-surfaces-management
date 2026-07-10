"""
ASM Platform — Nikto Web Server Scanner Worker
Runs nikto against discovered web endpoints to identify
outdated software, dangerous files, and misconfigurations.
"""
import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()

NIKTO_TIMEOUT = int(os.getenv("NIKTO_TIMEOUT", "600"))

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class NiktoWorker(BaseWorker):
    """
    Runs nikto against web endpoints and persists findings.

    Nikto detects:
    - Outdated server software
    - Dangerous files/CGIs
    - Default files and directories
    - Server configuration issues
    """

    QUEUE = "scan.nikto"
    CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "2"))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        targets = message["targets"]
        config = message.get("config", {})

        if not targets:
            log.warning("nikto_no_targets", scan_id=scan_id)
            return

        log.info("nikto_scan_started", scan_id=scan_id, targets=len(targets), org_id=org_id)

        with tempfile.TemporaryDirectory(prefix="asm-nikto-") as tmpdir:
            tmpdir = Path(tmpdir)
            output_file = tmpdir / "nikto_results.json"

            all_findings = []

            for target in targets:
                findings = await self._scan_target(target, output_file, config, scan_id)
                if findings:
                    all_findings.extend(findings)

            if not all_findings:
                log.info("nikto_no_findings", scan_id=scan_id, targets=len(targets))
                return

            log.info("nikto_raw_findings", count=len(all_findings), scan_id=scan_id)

            parsed = [self._parse_finding(f, org_id, workspace_id, scan_id) for f in all_findings]
            parsed = [f for f in parsed if f is not None]

            async with get_session() as db:
                persisted = await self._persist_findings(db, parsed, scan_id)
                await self._update_scan_findings_count(db, scan_id, len(persisted))

            await self._queue_correlation(scan_id, org_id, workspace_id)

        log.info("nikto_scan_completed", scan_id=scan_id, findings=len(all_findings))

    async def _scan_target(
        self,
        target: str,
        output_file: Path,
        config: Dict,
        scan_id: str,
    ) -> List[Dict]:
        """Run nikto against a single target and return findings."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        cmd = [
            "nikto",
            "-host", target,
            "-Format", "json",
            "-output", str(output_file),
            "-nointeractive",
            "-timeout", "10",
            "-maxtime", str(NIKTO_TIMEOUT),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=NIKTO_TIMEOUT + 60)

            if proc.returncode not in (0, 1):
                log.warning("nikto_error", target=target, stderr=stderr.decode()[:500], scan_id=scan_id)

        except asyncio.TimeoutError:
            log.warning("nikto_timeout", target=target, scan_id=scan_id)
            try:
                proc.kill()
            except Exception:
                pass
            return []
        except FileNotFoundError:
            log.error("nikto_not_found")
            return []
        except Exception as e:
            log.error("nikto_exception", error=str(e), scan_id=scan_id, target=target)
            return []

        if not output_file.exists():
            return []

        try:
            raw = json.loads(output_file.read_text())
            items = raw.get("items", []) if isinstance(raw, dict) else []
            for item in items:
                item["_nikto_host"] = target
            return items
        except (json.JSONDecodeError, AttributeError) as e:
            log.warning("nikto_parse_error", error=str(e), scan_id=scan_id, target=target)
            return []

    def _parse_finding(
        self,
        raw: Dict,
        org_id: str,
        workspace_id: str,
        scan_id: str,
    ) -> Optional[Dict]:
        """Map a nikto finding to platform finding format."""
        try:
            host = raw.get("_nikto_host", raw.get("host", ""))
            url = raw.get("url", "")
            description = raw.get("description", "")
            osvdb_id = raw.get("OSVDBid", "")
            method = raw.get("method", "GET")

            affected_url = f"{host}{url}" if url else host
            osvdb_str = str(osvdb_id) if osvdb_id else ""

            fingerprint = hashlib.sha256(
                f"{org_id}:nikto:{affected_url}:{description}".encode()
            ).hexdigest()

            severity = self._map_severity(raw)
            category = self._map_category(raw)
            references = []
            refs_text = raw.get("references", "")
            if refs_text:
                references = [r.strip() for r in refs_text.split(",") if r.strip()]

            return {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "scan_id": scan_id,
                "title": description[:500] if description else f"OSVDB-{osvdb_str}",
                "description": description[:5000],
                "severity": severity,
                "category": category,
                "source": "nikto",
                "template_id": f"nikto-{osvdb_str}" if osvdb_str else "nikto-generic",
                "template_url": f"https://osvdb.org/{osvdb_str}" if osvdb_str else "",
                "scanner": "nikto",
                "cve_ids": [],
                "cvss_score": None,
                "affected_url": affected_url[:1000],
                "evidence": f"URL: {affected_url}\nMethod: {method}\nOSVDB: {osvdb_str}",
                "request_raw": "",
                "response_raw": "",
                "proof": {
                    "host": host,
                    "url": url,
                    "method": method,
                    "osvdb_id": osvdb_str,
                    "nikto_id": raw.get("id", ""),
                    "plugin_output": raw.get("plugin-output", ""),
                },
                "remediation": "",
                "references": references[:20],
                "fingerprint": fingerprint,
                "status": "open",
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
            }
        except Exception as e:
            log.warning("nikto_parse_error_detail", error=str(e))
            return None

    def _map_severity(self, raw: Dict) -> str:
        """Map nikto finding to platform severity."""
        osvdb_id = raw.get("OSVDBid", "")
        osvdb_str = str(osvdb_id) if osvdb_id else ""

        # Higher-severity OSVDB ranges
        if osvdb_str:
            oid = int(osvdb_str)
            if oid < 2000:
                return "critical"
            elif oid < 5000:
                return "high"
            elif oid < 8000:
                return "medium"
        return "low"

    def _map_category(self, raw: Dict) -> str:
        """Map nikto finding to platform category."""
        desc = raw.get("description", "").lower()
        url = raw.get("url", "").lower()

        if any(k in desc or k in url for k in ["backdoor", "webshell", "shell"]):
            return "known_cve"
        if any(k in desc or k in url for k in ["admin", "login", "panel", "dashboard"]):
            return "exposed_admin_panel"
        if any(k in desc or k in url for k in ["git", "env", "config", "backup", "db_"]):
            return "exposed_git"
        if any(k in desc or k in url for k in ["ssl", "tls", "certificate"]):
            return "expired_certificate"
        if any(k in desc for k in ["cors", "redirect", "xss", "injection"]):
            return "cors_misconfiguration"
        if any(k in desc for k in ["directory listing", "indexing"]):
            return "information_disclosure"
        if any(k in desc for k in ["outdated", "old version", "deprecated"]):
            return "outdated_software"

        return "exposed_service"

    async def _persist_findings(
        self,
        db,
        findings: List[Dict],
        scan_id: str,
    ) -> List[str]:
        """Upsert findings, return list of persisted finding IDs."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, Finding, ScanFinding
        from workers.scanner.scanner_common import status_preserving_conflict_updates

        persisted_ids = []
        now = datetime.now(timezone.utc)

        for f in findings:
            asset = await self._find_asset(db, f["org_id"], f["affected_url"])

            if not asset:
                log.debug("nikto_finding_no_asset", url=f["affected_url"])
                continue

            values = {
                "org_id": f["org_id"],
                "workspace_id": f["workspace_id"],
                "asset_id": asset.id,
                "title": f["title"],
                "description": f["description"],
                "fingerprint": f["fingerprint"],
                "severity": f["severity"],
                "category": f["category"],
                "status": "open",
                "source": f["source"],
                "template_id": f.get("template_id"),
                "template_url": f.get("template_url"),
                "scanner": f.get("scanner"),
                "cve_ids": f.get("cve_ids", []),
                "cvss_score": f.get("cvss_score"),
                "affected_url": f.get("affected_url"),
                "evidence": f.get("evidence"),
                "request_raw": f.get("request_raw"),
                "response_raw": f.get("response_raw"),
                "proof": f.get("proof", {}),
                "remediation": f.get("remediation"),
                "references": f.get("references", []),
                "last_seen": now,
            }

            stmt = pg_insert(Finding.__table__).values(**values, first_seen=now)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_finding_fingerprint_org",
                set_=status_preserving_conflict_updates(now),
            ).returning(Finding.__table__.c.id, Finding.__table__.c.first_seen)

            result = await db.execute(stmt)
            row = result.fetchone()
            if row:
                finding_id = row[0]
                is_new = (now - row[1]).seconds < 5
                persisted_ids.append(str(finding_id))

                if is_new:
                    sfind = ScanFinding(
                        scan_id=scan_id,
                        finding_id=finding_id,
                    )
                    db.add(sfind)

        await db.commit()
        log.info("nikto_findings_persisted", scan_id=scan_id, count=len(persisted_ids))
        return persisted_ids

    async def _find_asset(
        self,
        db,
        org_id: str,
        url: str,
    ) -> Optional[Any]:
        """Find the asset matching a URL."""
        from urllib.parse import urlparse
        from sqlalchemy import select
        from workers.db_models import Asset

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path or url

        result = await db.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.hostname == hostname,
            ).limit(1)
        )
        asset = result.scalar_one_or_none()

        # Try subdomain match
        if not asset:
            result = await db.execute(
                select(Asset).where(
                    Asset.org_id == org_id,
                    Asset.subdomain == hostname,
                ).limit(1)
            )
            asset = result.scalar_one_or_none()

        return asset

    async def _update_scan_findings_count(self, db, scan_id: str, count: int) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan

        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                findings_count=Scan.findings_count + count,
                progress_pct=func.greatest(Scan.progress_pct, 82),
            )
        )
        await db.commit()

    async def _queue_correlation(self, scan_id: str, org_id: str, workspace_id: str) -> None:
        queue = QueueClient()
        await queue.connect()

        await queue.publish(
            routing_key="correlation.process",
            message={
                "scan_id": scan_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
            },
        )

        await queue.close()


if __name__ == "__main__":
    worker = NiktoWorker()
    asyncio.run(worker.run())

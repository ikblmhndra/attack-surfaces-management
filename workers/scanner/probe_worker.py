"""
ASM Platform — Probe Worker
HTTP probing of discovered assets (status codes, titles, tech detection).
Consumes from scan.probe queue.
"""
import asyncio
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import structlog

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()


class ProbeWorker(BaseWorker):
    QUEUE = "scan.probe"
    CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "5"))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message.get("scan_id")
        org_id = message.get("org_id")
        targets = message.get("targets", [])
        config = message.get("config", {})

        log.info("probe_started", scan_id=scan_id, org_id=org_id, targets=len(targets))

        if not targets:
            log.info("probe_no_targets", scan_id=scan_id)
            return

        with tempfile.TemporaryDirectory(prefix="asm-probe-") as tmpdir:
            tmpdir = Path(tmpdir)
            results = await self._run_httpx(targets, tmpdir, config)

            if results:
                async with get_session() as db:
                    await self._persist_results(db, org_id, scan_id, results)

        log.info("probe_completed", scan_id=scan_id, probed=len(results))

    async def _run_httpx(
        self, targets: List[str], tmpdir: Path, config: Dict
    ) -> Dict[str, Any]:
        if not shutil.which("httpx"):
            log.warning("httpx_not_available")
            return {}

        input_file = tmpdir / "targets.txt"
        input_file.write_text("\n".join(targets))
        output_file = tmpdir / "httpx_output.json"

        cmd = [
            "httpx",
            "-l", str(input_file),
            "-json", "-o", str(output_file),
            "-silent",
            "-follow-redirects",
            "-max-redirects", "5",
            "-title",
            "-web-server",
            "-status-code",
            "-tech-detect",
            "-tls-grab",
            "-content-length",
            "-response-time",
            "-t", "50",
            "-timeout", "15",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            log.warning("httpx_timeout")
        except Exception as e:
            log.error("httpx_error", error=str(e))

        results = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    host = data.get("host", "")
                    if not host and "//" in url:
                        host = url.split("//")[-1].split("/")[0]
                    if host:
                        results[host] = data
                except json.JSONDecodeError:
                    continue
        return results

    async def _persist_results(
        self, db, org_id: str, scan_id: str, results: Dict[str, Any]
    ) -> None:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Subdomain

        now = datetime.now(timezone.utc)

        for host, data in results.items():
            tls = data.get("tls", {})
            subdomain_values = {
                "asset_id": None,
                "org_id": org_id,
                "fqdn": host,
                "http_status": data.get("status_code"),
                "http_title": (data.get("title", "") or "")[:500],
                "http_server": (data.get("webserver", "") or "")[:255],
                "content_length": data.get("content_length"),
                "technologies": data.get("tech", []),
                "cdn_provider": (data.get("cdn_name", "") or None),
                "tls_info": tls if tls else None,
                "tls_expiry": self._parse_tls_expiry(tls),
                "tls_issuer": (tls.get("issuer", {}).get("organization", "") or "")[:500] if tls else None,
                "tls_version": (tls.get("version", "") or "")[:20] if tls else None,
                "last_seen": now,
                "last_probed": now,
            }

            stmt = pg_insert(Subdomain.__table__).values(**subdomain_values)
            stmt = stmt.on_conflict_do_update(
                constraint="subdomains_asset_id_key",
                set_={k: v for k, v in subdomain_values.items() if k != "asset_id"},
            )
            await db.execute(stmt)

        await db.commit()

    def _parse_tls_expiry(self, tls: Dict) -> Any:
        if not tls:
            return None
        try:
            not_after = tls.get("not_after", "")
            if not_after:
                return datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        except Exception:
            pass
        return None


if __name__ == "__main__":
    worker = ProbeWorker()
    asyncio.run(worker.run())

"""
ASM Platform — Port Scan Worker
Runs naabu for fast port scanning of discovered IPs.
Consumes from scan.port queue.
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

log = structlog.get_logger()


class PortWorker(BaseWorker):
    QUEUE = "scan.port"
    CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "3"))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message.get("scan_id")
        org_id = message.get("org_id")
        workspace_id = message.get("workspace_id")
        ips = message.get("ips", [])
        config = message.get("config", {})

        log.info("port_scan_started", scan_id=scan_id, org_id=org_id, ips=len(ips))

        if not ips:
            log.info("port_scan_no_targets", scan_id=scan_id)
            return

        if not shutil.which("naabu"):
            log.warning("naabu_not_available")
            return

        with tempfile.TemporaryDirectory(prefix="asm-port-") as tmpdir:
            tmpdir = Path(tmpdir)
            results = await self._run_naabu(ips, tmpdir, config)

            if results:
                async with get_session() as db:
                    await self._persist_results(db, org_id, workspace_id, scan_id, results)

        async with get_session() as db:
            await self._update_scan_progress(db, scan_id)

        log.info("port_scan_completed", scan_id=scan_id, ips_scanned=len(ips))

    async def _run_naabu(
        self, ips: List[str], tmpdir: Path, config: Dict
    ) -> Dict[str, List[Dict]]:
        input_file = tmpdir / "ips.txt"
        input_file.write_text("\n".join(ips))
        output_file = tmpdir / "naabu_output.json"

        ports = config.get("ports", "top-100")
        rate = config.get("rate", 1000)

        cmd = [
            "naabu",
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-p", ports,
            "-rate", str(rate),
            "-t", "25",
            "-timeout", "5",
            "-retries", "2",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            log.warning("naabu_timeout")
        except Exception as e:
            log.error("naabu_error", error=str(e))

        results: Dict[str, List[Dict]] = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                    ip = data.get("ip", "")
                    port = data.get("port")
                    if ip and port:
                        if ip not in results:
                            results[ip] = []
                        results[ip].append({
                            "port": port,
                            "protocol": data.get("protocol", "tcp"),
                            "service": data.get("protocol", ""),
                        })
                except json.JSONDecodeError:
                    continue

        return results

    async def _persist_results(
        self, db, org_id: str, workspace_id: str, scan_id: str, results: Dict[str, List[Dict]]
    ) -> None:
        from sqlalchemy import select
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, Port

        now = datetime.now(timezone.utc)

        for ip, ports in results.items():
            # Find asset by IP
            asset_result = await db.execute(
                select(Asset).where(
                    Asset.org_id == org_id,
                    Asset.value == ip,
                ).limit(1)
            )
            asset = asset_result.scalar_one_or_none()

            if not asset:
                # Create asset
                asset_values = {
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "asset_type": "ip",
                    "value": ip,
                    "status": "active",
                    "discovery_method": "port_scan",
                    "last_seen": now,
                    "metadata": {"source": "port_worker"},
                }
                stmt = pg_insert(Asset.__table__).values(**asset_values)
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_asset_org_type_value",
                    set_={"last_seen": now, "status": "active"},
                ).returning(Asset.__table__.c.id)
                result = await db.execute(stmt)
                asset_id = result.scalar_one()
            else:
                asset_id = asset.id

            # Insert ports
            for port_data in ports:
                port_values = {
                    "ip_id": asset_id,
                    "port_number": port_data["port"],
                    "protocol": port_data.get("protocol", "tcp"),
                    "service_name": port_data.get("service", ""),
                    "state": "open",
                    "last_seen": now,
                }
                stmt = pg_insert(Port.__table__).values(**port_values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["ip_id", "port_number", "protocol"],
                    set_={"last_seen": now, "state": "open"},
                )
                await db.execute(stmt)

        await db.commit()
        log.info("ports_persisted", org_id=org_id, total_ports=sum(len(p) for p in results.values()))

    async def _update_scan_progress(self, db, scan_id: str) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan
        from datetime import datetime, timezone
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                completed_tasks=Scan.completed_tasks + 1,
                progress_pct=func.greatest(Scan.progress_pct, 50),
            )
        )
        await db.commit()


if __name__ == "__main__":
    worker = PortWorker()
    asyncio.run(worker.run())

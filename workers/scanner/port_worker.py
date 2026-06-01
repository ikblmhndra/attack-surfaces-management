"""
ASM Platform — Port Scan Worker
Runs naabu for fast port scanning of discovered IPs.
Consumes from scan.port queue.
"""
import asyncio
import ipaddress
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
from workers.scan_state import mark_scan_running

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

        async with get_session() as db:
            if not await mark_scan_running(db, scan_id, progress_floor=25):
                log.info("port_scan_skipped_inactive_scan", scan_id=scan_id)
                return

        if not ips:
            log.info("port_scan_no_targets", scan_id=scan_id)
            async with get_session() as db:
                await self._update_scan_progress(db, scan_id)
            await self._mark_port_done(scan_id, org_id, workspace_id)
            return

        naabu_path = shutil.which("naabu") or "/go/bin/naabu"
        if not Path(naabu_path).exists():
            raise RuntimeError("naabu binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="asm-port-") as tmpdir:
            tmpdir = Path(tmpdir)
            results = await self._run_naabu(ips, tmpdir, config, naabu_path)

            async with get_session() as db:
                ip_ids = await self._persist_ip_assets(db, org_id, workspace_id, ips)
                if results:
                    await self._persist_results(db, org_id, workspace_id, scan_id, results, ip_ids)

        async with get_session() as db:
            await self._update_scan_progress(db, scan_id)

        await self._mark_port_done(scan_id, org_id, workspace_id)

        log.info("port_scan_completed", scan_id=scan_id, ips_scanned=len(ips))

    async def _run_naabu(
        self, ips: List[str], tmpdir: Path, config: Dict, naabu_path: str = "naabu"
    ) -> Dict[str, List[Dict]]:
        input_file = tmpdir / "ips.txt"
        input_file.write_text("\n".join(ips))
        output_file = tmpdir / "naabu_output.json"

        ports = str(config.get("ports", "top-100"))
        rate = config.get("rate", 1000)

        cmd = [
            naabu_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-rate", str(rate),
            "-c", "25",
            "-timeout", "5",
            "-retries", "2",
            "-disable-update-check",
        ]
        if ports.startswith("top-"):
            cmd.extend(["-top-ports", ports.removeprefix("top-")])
        elif ports == "full":
            cmd.extend(["-top-ports", "full"])
        else:
            cmd.extend(["-p", ports])

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

    async def _persist_ip_assets(
        self, db, org_id: str, workspace_id: str, ips: List[str]
    ) -> Dict[str, Any]:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, IPAddress

        now = datetime.now(timezone.utc)
        ip_ids: Dict[str, Any] = {}

        for ip in sorted(set(ips)):
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue

            asset_values = {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "asset_type": "ip",
                "value": ip,
                "status": "active",
                "discovery_method": "dns_resolution",
                "last_seen": now,
                "metadata": {"source": "port_worker"},
            }
            asset_stmt = pg_insert(Asset.__table__).values(**asset_values)
            asset_stmt = asset_stmt.on_conflict_do_update(
                constraint="uq_asset_org_type_value",
                set_={"last_seen": now, "status": "active"},
            ).returning(Asset.__table__.c.id)
            asset_id = (await db.execute(asset_stmt)).scalar_one()

            ip_values = {
                "asset_id": asset_id,
                "org_id": org_id,
                "ip": ip,
                "version": parsed.version,
                "is_private": parsed.is_private,
                "last_seen": now,
            }
            ip_stmt = pg_insert(IPAddress.__table__).values(**ip_values)
            ip_stmt = ip_stmt.on_conflict_do_update(
                constraint="ip_addresses_asset_id_key",
                set_={"last_seen": now, "is_private": parsed.is_private},
            ).returning(IPAddress.__table__.c.id)
            ip_ids[ip] = (await db.execute(ip_stmt)).scalar_one()

        await db.commit()
        log.info("ip_assets_persisted", org_id=org_id, total_ips=len(ip_ids))
        return ip_ids

    async def _persist_results(
        self,
        db,
        org_id: str,
        workspace_id: str,
        scan_id: str,
        results: Dict[str, List[Dict]],
        ip_ids: Dict[str, Any] | None = None,
    ) -> None:
        from sqlalchemy import select, update
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, IPAddress, Port

        now = datetime.now(timezone.utc)
        ip_ids = ip_ids or {}

        for ip, ports in results.items():
            ip_address_id = ip_ids.get(ip)

            # Find asset by IP
            if not ip_address_id:
                asset_result = await db.execute(
                    select(Asset).where(
                        Asset.org_id == org_id,
                        Asset.asset_type == "ip",
                        Asset.value == ip,
                    ).limit(1)
                )
                asset = asset_result.scalar_one_or_none()
                if asset:
                    ip_result = await db.execute(
                        select(IPAddress.id).where(IPAddress.asset_id == asset.id).limit(1)
                    )
                    ip_address_id = ip_result.scalar_one_or_none()
            if not ip_address_id:
                continue

            # Insert ports
            for port_data in ports:
                port_values = {
                    "ip_id": ip_address_id,
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

            await db.execute(
                update(IPAddress)
                .where(IPAddress.id == ip_address_id)
                .values(open_ports_count=len(ports), last_seen=now)
            )

        await db.commit()
        log.info("ports_persisted", org_id=org_id, total_ports=sum(len(p) for p in results.values()))

    async def _mark_port_done(self, scan_id: str, org_id: str, workspace_id: str) -> None:
        from workers.task_coordinator import TaskCoordinator

        coord = TaskCoordinator()
        await coord.incr_port_done(scan_id)
        if await coord.mark_terminal_if_all_done(scan_id):
            queue = QueueClient()
            await queue.connect()
            await queue.publish(
                routing_key="correlation.process",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "is_terminal": True,
                },
            )
            await queue.close()
            await coord.cleanup(scan_id)
        await coord.close()

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

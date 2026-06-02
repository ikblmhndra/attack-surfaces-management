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
from urllib.parse import urlsplit

import structlog

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running

log = structlog.get_logger()

WEB_PORT_SCHEMES = {
    80: "http",
    81: "http",
    443: "https",
    591: "http",
    593: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8834: "https",
    8888: "http",
    9443: "https",
}


def _tool_path(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    go_path = Path(f"/go/bin/{name}")
    return str(go_path) if go_path.exists() else None


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
            await update_scan_phase(db, scan_id, "port", "running", targets_total=len(ips))

        if not ips:
            log.info("port_scan_no_targets", scan_id=scan_id)
            async with get_session() as db:
                await self._update_scan_progress(db, scan_id)
                await update_scan_phase(db, scan_id, "port", "skipped", targets_total=0)
            await self._mark_port_done(scan_id, org_id, workspace_id)
            return

        naabu_path = _tool_path("naabu")
        if not naabu_path:
            raise RuntimeError("naabu binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="asm-port-") as tmpdir:
            tmpdir = Path(tmpdir)
            results = await self._run_naabu(ips, tmpdir, config, naabu_path)
            if results:
                await self._fingerprint_web_ports(results, tmpdir, config)

            async with get_session() as db:
                ip_ids = await self._persist_ip_assets(db, org_id, workspace_id, ips)
                if results:
                    await self._persist_results(db, org_id, workspace_id, scan_id, results, ip_ids)
                await self._publish_enrichment_if_enabled(db, scan_id, org_id, workspace_id, ips, config)

        async with get_session() as db:
            await self._update_scan_progress(db, scan_id)
            await update_scan_phase(
                db,
                scan_id,
                "port",
                "completed",
                targets_total=len(ips),
                open_ports=sum(len(items) for items in results.values()),
            )

        await self._mark_port_done(scan_id, org_id, workspace_id)

        log.info("port_scan_completed", scan_id=scan_id, ips_scanned=len(ips))

    async def _run_naabu(
        self, ips: List[str], tmpdir: Path, config: Dict, naabu_path: str = "naabu"
    ) -> Dict[str, List[Dict]]:
        input_file = tmpdir / "ips.txt"
        input_file.write_text("\n".join(ips))
        output_file = tmpdir / "naabu_output.json"

        ports = str(config.get("ports", "top-100"))
        rate = int(config.get("port_rate", config.get("rate", 1000)))
        timeout = str(config.get("port_timeout", "5s"))
        retries = int(config.get("port_retries", 2))
        concurrency = int(config.get("port_concurrency", 25))

        cmd = [
            naabu_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-rate", str(rate),
            "-c", str(concurrency),
            "-timeout", timeout,
            "-retries", str(retries),
            "-verify",
            "-cdn",
            "-disable-update-check",
        ]
        if config.get("port_exclude_cdn_full_scan", True) and ports in {"full", "top-1000"}:
            cmd.append("-exclude-cdn")
        if ports.startswith("top-"):
            top_ports = ports.removeprefix("top-")
            if top_ports not in {"100", "1000", "full"}:
                log.warning("naabu_unsupported_top_ports", requested=ports, fallback="top-100")
                top_ports = "100"
            cmd.extend(["-top-ports", top_ports])
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
                        service_name = (
                            data.get("service")
                            or data.get("service_name")
                            or data.get("service_name_detected")
                            or self._service_name(port, data.get("protocol", ""))
                        )
                        results[ip].append({
                            "port": port,
                            "protocol": data.get("protocol", "tcp"),
                            "service": service_name,
                            "service_version": data.get("service_version") or data.get("version"),
                            "product": data.get("product"),
                            "extrainfo": data.get("extrainfo"),
                            "banner": data.get("banner") or data.get("raw"),
                            "tls_info": data.get("tls") or data.get("ssl"),
                        })
                except json.JSONDecodeError:
                    continue

        return results

    async def _fingerprint_web_ports(self, results: Dict[str, List[Dict]], tmpdir: Path, config: Dict) -> None:
        httpx_path = _tool_path("httpx")
        if not httpx_path or not config.get("port_httpx_fingerprint", True):
            return

        url_to_port: Dict[str, tuple[str, Dict]] = {}
        endpoint_to_port: Dict[tuple[str, int], tuple[str, Dict]] = {}
        for ip, ports in results.items():
            for port_data in ports:
                port = int(port_data.get("port") or 0)
                scheme = WEB_PORT_SCHEMES.get(port)
                if not scheme:
                    continue
                url = f"{scheme}://{ip}:{port}"
                url_to_port[url] = (ip, port_data)
                endpoint_to_port[(ip, port)] = (ip, port_data)

        if not url_to_port:
            return

        input_file = tmpdir / "httpx_ports.txt"
        output_file = tmpdir / "httpx_ports.json"
        input_file.write_text("\n".join(url_to_port.keys()))
        cmd = [
            httpx_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-follow-host-redirects",
            "-max-redirects", "3",
            "-status-code",
            "-title",
            "-web-server",
            "-tech-detect",
            "-tls-grab",
            "-content-length",
            "-content-type",
            "-favicon",
            "-jarm",
            "-cdn",
            "-timeout", str(int(config.get("port_httpx_timeout", 10))),
            "-t", str(int(config.get("port_httpx_threads", 25))),
            "-rl", str(int(config.get("port_httpx_rate_limit", 100))),
            "-no-color",
            "-duc",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=int(config.get("port_httpx_scan_timeout", 180)))
            if proc.returncode not in (0, None):
                log.warning("port_httpx_nonzero", stderr=stderr.decode(errors="ignore")[:500])
        except asyncio.TimeoutError:
            log.warning("port_httpx_timeout")
            return
        except Exception as exc:
            log.warning("port_httpx_error", error=str(exc))
            return

        if not output_file.exists():
            return

        for line in output_file.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("failed"):
                continue
            url = row.get("url")
            target = url_to_port.get(url)
            if not target:
                parsed = urlsplit(url or "")
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                target = endpoint_to_port.get((parsed.hostname or "", port))
            if not target:
                continue
            _, port_data = target
            scheme = "https" if str(url).startswith("https://") else "http"
            port_data["service"] = scheme
            port_data["product"] = row.get("webserver") or port_data.get("product")
            port_data["banner"] = row.get("title") or port_data.get("banner")
            port_data["tls_info"] = row.get("tls") or port_data.get("tls_info")
            port_data["service_version"] = ", ".join(row.get("tech") or [])[:255] or port_data.get("service_version")
            port_data["http_probe"] = {
                "url": url,
                "status_code": row.get("status_code"),
                "content_type": row.get("content_type"),
                "content_length": row.get("content_length"),
                "favicon": row.get("favicon"),
                "jarm": row.get("jarm"),
                "cdn": row.get("cdn"),
                "cdn_name": row.get("cdn_name"),
            }

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
                    "service_version": port_data.get("service_version"),
                    "product": port_data.get("product"),
                    "extrainfo": port_data.get("extrainfo"),
                    "banner": port_data.get("banner"),
                    "tls_info": port_data.get("tls_info"),
                    "state": "open",
                    "last_seen": now,
                }
                stmt = pg_insert(Port.__table__).values(**port_values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["ip_id", "port_number", "protocol"],
                    set_={
                        "last_seen": now,
                        "state": "open",
                        "service_name": port_values["service_name"],
                        "service_version": port_values["service_version"],
                        "product": port_values["product"],
                        "extrainfo": port_values["extrainfo"],
                        "banner": port_values["banner"],
                        "tls_info": port_values["tls_info"],
                    },
                )
                await db.execute(stmt)

            await db.execute(
                update(IPAddress)
                .where(IPAddress.id == ip_address_id)
                .values(open_ports_count=len(ports), last_seen=now)
            )

        await db.commit()
        log.info("ports_persisted", org_id=org_id, total_ports=sum(len(p) for p in results.values()))

    async def _publish_enrichment_if_enabled(
        self,
        db,
        scan_id: str,
        org_id: str,
        workspace_id: str,
        ips: List[str],
        config: Dict[str, Any],
    ) -> None:
        modules = set(config.get("modules") or [])
        if "enrich" not in modules or not config.get("enrichment_enabled", True) or not ips:
            return

        from sqlalchemy import select
        from workers.db_models import Asset
        from workers.task_coordinator import TaskCoordinator

        result = await db.execute(
            select(Asset.id, Asset.value, Asset.asset_type)
            .where(
                Asset.org_id == org_id,
                Asset.asset_type == "ip",
                Asset.value.in_(sorted(set(ips))),
                Asset.deleted_at.is_(None),
            )
        )
        assets = [
            {
                "asset_id": str(row.id),
                "value": row.value,
                "asset_type": row.asset_type,
                "org_id": org_id,
                "workspace_id": workspace_id,
            }
            for row in result.all()
        ]
        if not assets:
            return

        queue = QueueClient()
        await queue.connect()
        try:
            await queue.publish(
                routing_key="enrich.assets",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "assets": assets,
                    "config": config,
                },
                priority=4,
            )
        finally:
            await queue.close()

        coord = TaskCoordinator()
        await coord.add_enrich_expected(scan_id)
        await coord.close()
        await self._add_scan_task(db, scan_id)
        await update_scan_phase(db, scan_id, "enrich", "queued", targets_total=len(assets))
        log.info("enrichment_queued", scan_id=scan_id, assets=len(assets))

    async def _add_scan_task(self, db, scan_id: str) -> None:
        from sqlalchemy import update
        from workers.db_models import Scan

        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(total_tasks=Scan.total_tasks + 1)
        )
        await db.commit()

    def _service_name(self, port: int, fallback: str = "") -> str:
        common = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            465: "smtps",
            587: "smtp",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            2049: "nfs",
            3306: "mysql",
            3389: "rdp",
            5432: "postgres",
            6379: "redis",
            8080: "http",
            8443: "https",
            9200: "opensearch",
            9300: "opensearch",
            27017: "mongodb",
        }
        return common.get(int(port), fallback or "")

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

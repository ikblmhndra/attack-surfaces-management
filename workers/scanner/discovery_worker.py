"""
ASM Platform — Discovery Worker
Runs subdomain discovery, DNS enumeration, and HTTP probing.
Integrates: subfinder, amass, assetfinder, dnsx, httpx, naabu
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aio_pika
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()

# Tool availability cache
_TOOL_CACHE: Dict[str, bool] = {}


def tool_available(name: str) -> bool:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name) is not None
    return _TOOL_CACHE[name]


class DiscoveryWorker(BaseWorker):
    """
    Handles the subdomain discovery phase of a scan.

    Pipeline:
    1. Run passive discovery tools (subfinder, assetfinder, crt.sh)
    2. Run active DNS enumeration (amass, dnsx)
    3. Deduplicate results
    4. Persist assets to DB
    5. Publish probe and port tasks for discovered assets
    """

    QUEUE = "scan.discovery"
    CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "3"))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        targets = message["targets"]  # domains, IPs, CIDRs
        config = message.get("config", {})

        log.info("discovery_started", scan_id=scan_id, org_id=org_id, targets=targets)

        async with get_session() as db:
            await self._update_scan_status(db, scan_id, "running")

        with tempfile.TemporaryDirectory(prefix="asm-discovery-") as tmpdir:
            tmpdir = Path(tmpdir)

            # ── Phase 1: Subdomain Discovery ──────────────────
            all_subdomains: Set[str] = set()

            for domain in targets.get("domains", []):
                subdomains = await self._discover_subdomains(domain, tmpdir, config)
                all_subdomains.update(subdomains)
                log.info("subdomains_discovered", domain=domain, count=len(subdomains))

            # ── Phase 2: DNS Resolution ───────────────────────
            resolved = await self._resolve_dns(list(all_subdomains), tmpdir)
            log.info("dns_resolved", total=len(resolved))

            # ── Phase 3: HTTP Probing ─────────────────────────
            alive_hosts = await self._probe_http(list(resolved.keys()), tmpdir, config)
            log.info("http_probed", alive=len(alive_hosts))

            # ── Phase 4: Persist Assets ───────────────────────
            async with get_session() as db:
                new_count = await self._persist_assets(
                    db, org_id, workspace_id, scan_id,
                    alive_hosts, resolved
                )
                await self._update_scan_progress(db, scan_id, assets_found=len(alive_hosts))

            # ── Phase 5: Queue downstream tasks ───────────────
            all_ips = set()
            for host, dns_data in resolved.items():
                all_ips.update(dns_data.get("a", []))
                all_ips.update(dns_data.get("aaaa", []))

            await self._queue_downstream(
                scan_id=scan_id,
                org_id=org_id,
                workspace_id=workspace_id,
                subdomains=list(all_subdomains),
                ips=list(all_ips),
                config=config,
            )

        log.info("discovery_completed", scan_id=scan_id, subdomains=len(all_subdomains))

    # ── Subdomain Discovery ───────────────────────────────────

    async def _discover_subdomains(
        self,
        domain: str,
        tmpdir: Path,
        config: Dict,
    ) -> Set[str]:
        results: Set[str] = set()

        # Run all discovery methods in parallel
        tasks = [
            self._run_subfinder(domain, tmpdir),
            self._run_assetfinder(domain, tmpdir),
            self._run_crtsh(domain),
            self._run_chaos(domain, tmpdir, config),
        ]

        if config.get("use_amass", False):
            tasks.append(self._run_amass(domain, tmpdir))

        discovered = await asyncio.gather(*tasks, return_exceptions=True)

        for result in discovered:
            if isinstance(result, Exception):
                log.warning("discovery_tool_failed", error=str(result))
                continue
            if isinstance(result, set):
                results.update(result)

        # Sanitize
        clean = set()
        for sub in results:
            sub = sub.strip().lower().rstrip(".")
            if sub and domain in sub and self._is_valid_hostname(sub):
                clean.add(sub)

        return clean

    async def _run_subfinder(self, domain: str, tmpdir: Path) -> Set[str]:
        if not tool_available("subfinder"):
            log.warning("subfinder_not_available")
            return set()

        outfile = tmpdir / f"subfinder_{domain}.txt"
        cmd = [
            "subfinder", "-d", domain,
            "-o", str(outfile),
            "-silent",
            "-t", "50",
            "-timeout", "30",
        ]

        # Add API keys from environment
        api_keys = []
        if os.getenv("SHODAN_API_KEY"):
            api_keys.extend(["-provider-config", "/etc/subfinder/provider-config.yaml"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if outfile.exists():
                return set(outfile.read_text().splitlines())
        except asyncio.TimeoutError:
            log.warning("subfinder_timeout", domain=domain)
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as e:
            log.error("subfinder_error", domain=domain, error=str(e))

        return set()

    async def _run_assetfinder(self, domain: str, tmpdir: Path) -> Set[str]:
        if not tool_available("assetfinder"):
            return set()

        try:
            proc = await asyncio.create_subprocess_exec(
                "assetfinder", "--subs-only", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            if proc.returncode != 0:
                log.warning("assetfinder_exit", domain=domain, code=proc.returncode, stderr=stderr.decode()[:200])
            return set(stdout.decode().splitlines())
        except asyncio.TimeoutError:
            log.warning("assetfinder_timeout", domain=domain)
        except Exception as e:
            log.warning("assetfinder_error", domain=domain, error=f"{type(e).__name__}: {e}"[:200])

    async def _run_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh certificate transparency logs with retries."""
        import aiohttp
        results = set()
        user_agents = [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "curl/8.5.0",
        ]
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"User-Agent": user_agents[attempt]},
                ) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for name in name_value.splitlines():
                                    name = name.strip().lstrip("*.")
                                    if name and domain in name:
                                        results.add(name.lower())
                            return results
                        elif resp.status in (502, 503, 429) and attempt < 2:
                            wait = 2 ** attempt
                            log.warning("crtsh_retry", domain=domain, status=resp.status, attempt=attempt, wait=wait)
                            await asyncio.sleep(wait)
                        else:
                            log.warning("crtsh_http_error", domain=domain, status=resp.status, attempt=attempt)
                            return results
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                if attempt < 2:
                    wait = 2 ** attempt
                    log.warning("crtsh_retry", domain=domain, error=str(e), attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                else:
                    log.warning("crtsh_failed", domain=domain, error=f"{type(e).__name__}: {e}"[:200])

        return results

    async def _run_chaos(self, domain: str, tmpdir: Path, config: Dict) -> Set[str]:
        """Query ProjectDiscovery Chaos dataset."""
        chaos_key = os.getenv("CHAOS_API_KEY", "")
        if not chaos_key or not tool_available("chaos"):
            return set()

        outfile = tmpdir / f"chaos_{domain}.txt"
        try:
            proc = await asyncio.create_subprocess_exec(
                "chaos", "-d", domain, "-o", str(outfile), "-silent",
                env={**os.environ, "CHAOS_KEY": chaos_key},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
            if outfile.exists():
                return set(outfile.read_text().splitlines())
        except Exception as e:
            log.warning("chaos_error", domain=domain, error=str(e))

        return set()

    async def _run_amass(self, domain: str, tmpdir: Path) -> Set[str]:
        if not tool_available("amass"):
            return set()

        outfile = tmpdir / f"amass_{domain}.txt"
        cmd = [
            "amass", "enum",
            "-passive",
            "-d", domain,
            "-o", str(outfile),
            "-timeout", "5",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=360)
            if outfile.exists():
                return set(outfile.read_text().splitlines())
        except Exception as e:
            log.warning("amass_error", domain=domain, error=str(e))

        return set()

    # ── DNS Resolution ────────────────────────────────────────

    async def _resolve_dns(
        self,
        hosts: List[str],
        tmpdir: Path,
    ) -> Dict[str, Dict[str, Any]]:
        """Run dnsx to resolve all record types for discovered hosts."""
        if not hosts:
            return {}

        if not tool_available("dnsx"):
            return {h: {} for h in hosts}

        input_file = tmpdir / "hosts_to_resolve.txt"
        input_file.write_text("\n".join(hosts))
        output_file = tmpdir / "dnsx_output.json"

        cmd = [
            "dnsx",
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns",
            "-resp",
            "-silent",
            "-t", "100",
            "-retry", "3",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            log.warning("dnsx_timeout")
        except Exception as e:
            log.error("dnsx_error", error=str(e))

        resolved = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        resolved[host] = {
                            "a": data.get("a", []),
                            "aaaa": data.get("aaaa", []),
                            "cname": data.get("cname", []),
                            "mx": data.get("mx", []),
                            "txt": data.get("txt", []),
                            "ns": data.get("ns", []),
                            "status_code": data.get("status_code", ""),
                        }
                except json.JSONDecodeError:
                    continue

        return resolved

    # ── HTTP Probing ──────────────────────────────────────────

    async def _probe_http(
        self,
        hosts: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Dict[str, Dict[str, Any]]:
        """Run httpx to probe alive HTTP/HTTPS services."""
        if not hosts or not tool_available("httpx"):
            return {}

        input_file = tmpdir / "probe_targets.txt"
        # Add both http and https variants
        targets = []
        for h in hosts:
            targets.append(h)

        input_file.write_text("\n".join(targets))
        output_file = tmpdir / "httpx_output.json"

        cmd = [
            "httpx",
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
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
            "-hash", "sha256",
            "-t", "50",
            "-timeout", "15",
            "-no-color",
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

        alive = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    host = data.get("host", url.split("//")[-1].split("/")[0] if "//" in url else url)

                    alive[host] = {
                        "url": url,
                        "status_code": data.get("status_code"),
                        "title": data.get("title", ""),
                        "webserver": data.get("webserver", ""),
                        "content_length": data.get("content_length"),
                        "response_time": data.get("response_time", ""),
                        "hash": data.get("hash", {}).get("body_sha256", ""),
                        "technologies": data.get("tech", []),
                        "tls": data.get("tls", {}),
                        "cdn": data.get("cdn", False),
                        "cdn_name": data.get("cdn_name", ""),
                        "failed": data.get("failed", False),
                        "redirect_chain": [r.get("url") for r in data.get("chain", [])],
                        "headers": data.get("headers", {}),
                    }
                except json.JSONDecodeError:
                    continue

        return alive

    # ── Port Scanning ─────────────────────────────────────────

    async def _run_port_scan(
        self,
        ips: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Dict[str, List[Dict]]:
        """Run naabu for fast port scanning."""
        if not ips or not tool_available("naabu"):
            return {}

        input_file = tmpdir / "ips_to_scan.txt"
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
            f"-p", ports,
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
            return {}
        except Exception as e:
            log.error("naabu_error", error=str(e))
            return {}

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
                        })
                except json.JSONDecodeError:
                    continue

        return results

    # ── Persistence ───────────────────────────────────────────

    async def _persist_assets(
        self,
        db: AsyncSession,
        org_id: str,
        workspace_id: str,
        scan_id: str,
        alive_hosts: Dict[str, Dict],
        dns_data: Dict[str, Dict],
    ) -> int:
        """Upsert discovered assets into the database."""
        from sqlalchemy import select, update
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, Subdomain

        new_count = 0
        now = datetime.now(timezone.utc)

        for host, http_data in alive_hosts.items():
            # Upsert Asset
            asset_values = {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "asset_type": "subdomain",
                "value": host,
                "status": "active",
                "discovery_method": "automated",
                "last_seen": now,
                "metadata": {"source": "discovery_worker"},
            }

            stmt = pg_insert(Asset.__table__).values(**asset_values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_asset_org_type_value",
                set_={"last_seen": now, "status": "active"},
            ).returning(Asset.__table__.c.id, Asset.__table__.c.first_seen)

            result = await db.execute(stmt)
            row = result.fetchone()
            asset_id = row[0]
            is_new = row[1] and (now - row[1]).seconds < 5
            if is_new:
                new_count += 1

            # Upsert Subdomain details
            dns_info = dns_data.get(host, {})
            tls = http_data.get("tls", {})

            subdomain_values = {
                "asset_id": asset_id,
                "org_id": org_id,
                "fqdn": host,
                "root_domain": self._extract_root_domain(host),
                "ip_addresses": dns_info.get("a", []) + dns_info.get("aaaa", []),
                "cname_chain": dns_info.get("cname", []),
                "dns_records": {
                    "a": dns_info.get("a", []),
                    "aaaa": dns_info.get("aaaa", []),
                    "mx": dns_info.get("mx", []),
                    "txt": dns_info.get("txt", []),
                    "ns": dns_info.get("ns", []),
                    "cname": dns_info.get("cname", []),
                },
                "http_status": http_data.get("status_code"),
                "http_title": http_data.get("title", "")[:500],
                "http_server": http_data.get("webserver", "")[:255],
                "content_length": http_data.get("content_length"),
                "response_hash": http_data.get("hash", "")[:64],
                "technologies": http_data.get("technologies", []),
                "cdn_provider": http_data.get("cdn_name", "")[:100] or None,
                "tls_info": tls if tls else None,
                "tls_expiry": self._parse_tls_expiry(tls),
                "tls_issuer": tls.get("issuer", {}).get("organization", "")[:500] if tls else None,
                "tls_subject": tls.get("subject_dn", "")[:500] if tls else None,
                "tls_sans": tls.get("subject_an", []) if tls else [],
                "tls_version": tls.get("version", "")[:20] if tls else None,
                "redirect_chain": http_data.get("redirect_chain", []),
                "http_headers": http_data.get("headers", {}),
                "last_seen": now,
                "last_probed": now,
            }

            sub_stmt = pg_insert(Subdomain.__table__).values(**subdomain_values)
            sub_stmt = sub_stmt.on_conflict_do_update(
                constraint="subdomains_asset_id_key",
                set_={k: v for k, v in subdomain_values.items() if k != "asset_id"},
            )
            await db.execute(sub_stmt)

        await db.commit()
        log.info("assets_persisted", org_id=org_id, total=len(alive_hosts), new=new_count)
        return new_count

    # ── Queue downstream tasks ────────────────────────────────

    async def _queue_downstream(
        self,
        scan_id: str,
        org_id: str,
        workspace_id: str,
        subdomains: List[str],
        ips: List[str],
        config: Dict,
    ) -> None:
        """Publish port scan and nuclei tasks for discovered assets."""
        from workers.task_coordinator import TaskCoordinator
        queue = QueueClient()
        await queue.connect()

        coord = TaskCoordinator()

        # Port scan task per IP batch (100 IPs per task)
        batch_size = 100
        for i in range(0, len(ips), batch_size):
            ip_batch = ips[i:i + batch_size]
            await queue.publish(
                routing_key="scan.port",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "ips": ip_batch,
                    "config": config,
                },
            )

        # Nuclei scan per subdomain batch (50 per task)
        for i in range(0, len(subdomains), 50):
            batch = subdomains[i:i + 50]
            await queue.publish(
                routing_key="scan.nuclei",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "targets": batch,
                    "config": config,
                },
            )
            await coord.add_nuclei_expected(scan_id)

        # Screenshot task
        await queue.publish(
            routing_key="scan.screenshot",
            message={
                "scan_id": scan_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
                "targets": subdomains[:200],  # Limit screenshots
                "config": config,
            },
        )

        await queue.close()
        await coord.close()

    # ── Utilities ─────────────────────────────────────────────

    def _is_valid_hostname(self, hostname: str) -> bool:
        import re
        pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        return bool(pattern.match(hostname)) and len(hostname) <= 253

    def _extract_root_domain(self, fqdn: str) -> str:
        """Extract root domain from FQDN (naive, use tldextract in production)."""
        try:
            import tldextract
            ext = tldextract.extract(fqdn)
            return f"{ext.domain}.{ext.suffix}"
        except ImportError:
            parts = fqdn.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

    def _parse_tls_expiry(self, tls: Optional[Dict]) -> Optional[datetime]:
        if not tls:
            return None
        try:
            not_after = tls.get("not_after", "")
            if not_after:
                return datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        except Exception:
            pass
        return None

    async def _update_scan_status(self, db: AsyncSession, scan_id: str, status: str) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                status=status,
                progress_pct=func.greatest(Scan.progress_pct, 10),
                started_at=datetime.now(timezone.utc) if status == "running" else None,
            )
        )
        await db.commit()

    async def _update_scan_progress(
        self,
        db: AsyncSession,
        scan_id: str,
        assets_found: int = 0,
    ) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                assets_found=assets_found,
                completed_tasks=Scan.completed_tasks + 1,
                progress_pct=func.greatest(Scan.progress_pct, 25),
            )
        )
        await db.commit()


if __name__ == "__main__":
    worker = DiscoveryWorker()
    asyncio.run(worker.run())

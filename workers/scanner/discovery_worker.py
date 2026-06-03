"""
ASM Platform — Discovery Worker
Runs subdomain discovery, DNS enumeration, HTTP probing, endpoint crawling, and fuzzing.
Integrates: subfinder, amass, assetfinder, dnsx, httpx, naabu, katana, ffuf
"""
import asyncio
import re
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
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running
from app.services.scan_profiles import build_target_candidates, child_profile_config
from app.services.asset_validation import should_scan_validated_asset, validate_discovered_host

log = structlog.get_logger()

# Tool availability cache
_TOOL_CACHE: Dict[str, bool] = {}

TECH_VERSION_RE = re.compile(r"^(.+?)[/:@ ]v?([0-9][A-Za-z0-9._+-]*)$")
CRAWL_STATUS_CLASSES = {"ok", "redirect"}
NUCLEI_STANDARD_STATUS_CLASSES = {"ok", "redirect"}
NUCLEI_LIMITED_STATUS_CLASSES = {"auth_required", "server_error", "rate_limited"}


def tool_available(name: str) -> bool:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = tool_path(name) is not None
    return _TOOL_CACHE[name]


def tool_path(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    go_path = Path(f"/go/bin/{name}")
    return str(go_path) if go_path.exists() else None


def normalize_technology(raw: Any) -> Optional[Dict[str, Optional[str]]]:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None

    version = None
    name = value
    match = TECH_VERSION_RE.match(value)
    if match:
        name = match.group(1).strip()
        version = match.group(2).strip()

    name = " ".join(name.replace("_", " ").split())
    if not name:
        return None
    return {"name": name[:255], "version": version[:100] if version else ""}


def classify_http_status(status_code: Optional[int]) -> str:
    if status_code is None:
        return "probe_failed"
    try:
        status = int(status_code)
    except (TypeError, ValueError):
        return "probe_failed"
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redirect"
    if status in {401, 403}:
        return "auth_required"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if 500 <= status < 600:
        return "server_error"
    return "other"


def dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


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
        modules = config.get("modules", [])
        config.setdefault("scan_type", message.get("scan_type", config.get("scan_type", "full")))

        log.info("discovery_started", scan_id=scan_id, org_id=org_id, targets=targets)

        async with get_session() as db:
            if not await mark_scan_running(db, scan_id, progress_floor=10):
                log.info("discovery_skipped_inactive_scan", scan_id=scan_id)
                return
            await update_scan_phase(db, scan_id, "discovery", "running")

        # For targeted scans (e.g. vuln-only), skip discovery phase and
        # queue downstream tasks directly with the input targets.
        if "discovery" not in modules and "probe" not in modules:
            had_work = await self._queue_downstream(
                scan_id=scan_id,
                org_id=org_id,
                workspace_id=workspace_id,
                subdomains=[],
                ips=[],
                config=config,
                direct_targets=targets.get("domains", []),
            )
            if not had_work:
                await self._finalize_if_no_work(scan_id, org_id, workspace_id)
            log.info("discovery_skipped", scan_id=scan_id, modules=modules)
            return

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
            validation_by_host = {}
            for host, dns_info in resolved.items():
                validation_by_host[host] = validate_discovered_host(
                    host=host,
                    root_domains=targets.get("domains", []),
                    dns_info=dns_info,
                    http_info=alive_hosts.get(host, {}),
                )
            for host, http_data in alive_hosts.items():
                http_data["validation"] = validation_by_host.get(host)
            log.info("http_probed", alive=len(alive_hosts))

            # ── Phase 4: Persist Assets ───────────────────────
            async with get_session() as db:
                new_count = await self._persist_assets(
                    db, org_id, workspace_id, scan_id,
                    alive_hosts, resolved
                )
                await self._update_scan_progress(db, scan_id, assets_found=len(alive_hosts))
                await update_scan_phase(
                    db,
                    scan_id,
                    "discovery",
                    "completed",
                    subdomains=len(all_subdomains),
                    resolved_hosts=len(resolved),
                    alive_hosts=len(alive_hosts),
                    new_assets=new_count,
                )

            # ── Phase 5: Queue downstream tasks ───────────────
            all_ips = set()
            eligible_hosts = {
                host
                for host, info in alive_hosts.items()
                if should_scan_validated_asset(
                    info.get("validation"),
                    require_validation=bool(config.get("enforce_scope_validation", True)),
                )
            }
            for host in eligible_hosts:
                dns_data = resolved.get(host, {})
                all_ips.update(dns_data.get("a", []))
                all_ips.update(dns_data.get("aaaa", []))

            had_work = await self._queue_downstream(
                scan_id=scan_id,
                org_id=org_id,
                workspace_id=workspace_id,
                subdomains=list(all_subdomains),
                ips=list(all_ips),
                alive_hosts=alive_hosts,
                validation_by_host=validation_by_host,
                tmpdir=tmpdir,
                config=config,
            )
            if not had_work:
                await self._finalize_if_no_work(scan_id, org_id, workspace_id)

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
            self._run_subfinder(domain, tmpdir, config),
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

    async def _run_subfinder(self, domain: str, tmpdir: Path, config: Dict) -> Set[str]:
        subfinder_path = tool_path("subfinder")
        if not subfinder_path:
            log.warning("subfinder_not_available")
            return set()

        outfile = tmpdir / f"subfinder_{domain}.txt"
        cmd = [
            subfinder_path, "-d", domain,
            "-o", str(outfile),
            "-silent",
            "-t", str(int(config.get("subfinder_threads", 50))),
            "-timeout", str(int(config.get("subfinder_timeout", 30))),
            "-max-time", str(int(config.get("subfinder_max_time", 10))),
            "-duc",
        ]

        provider_config = config.get("subfinder_provider_config") or os.getenv("SUBFINDER_PROVIDER_CONFIG")
        if not provider_config:
            provider_config = "/etc/subfinder/provider-config.yaml"
        if provider_config and Path(provider_config).exists():
            cmd.extend(["-pc", provider_config])
        if config.get("subfinder_all_sources", False):
            cmd.append("-all")

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
        assetfinder_path = tool_path("assetfinder")
        if not assetfinder_path:
            return set()

        try:
            proc = await asyncio.create_subprocess_exec(
                assetfinder_path, "--subs-only", domain,
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
        chaos_path = tool_path("chaos")
        if not chaos_key or not chaos_path:
            return set()

        outfile = tmpdir / f"chaos_{domain}.txt"
        try:
            proc = await asyncio.create_subprocess_exec(
                chaos_path, "-d", domain, "-o", str(outfile), "-silent",
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
        amass_path = tool_path("amass")
        if not amass_path:
            return set()

        outfile = tmpdir / f"amass_{domain}.txt"
        cmd = [
            amass_path, "enum",
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

        dnsx_path = tool_path("dnsx")
        if not dnsx_path:
            return {h: {} for h in hosts}

        input_file = tmpdir / "hosts_to_resolve.txt"
        input_file.write_text("\n".join(hosts))
        output_file = tmpdir / "dnsx_output.json"

        cmd = [
            dnsx_path,
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

    # ── Endpoint Crawling (Katana) ────────────────────────────

    async def _crawl_endpoints(
        self,
        urls: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Set[str]:
        """Run katana to crawl alive URLs and discover hidden endpoints, JS paths, API routes."""
        katana_path = tool_path("katana")
        if not urls or not katana_path:
            return set()

        input_file = tmpdir / "katana_targets.txt"
        input_file.write_text("\n".join(urls))
        output_file = tmpdir / "katana_output.txt"

        depth = config.get("crawl_depth", 1)
        rate_limit = config.get("crawl_rate", 50)

        cmd = [
            katana_path,
            "-list", str(input_file),
            "-o", str(output_file),
            "-silent",
            "-depth", str(depth),
            "-rate-limit", str(rate_limit),
            "-host-rate-limit", str(int(config.get("crawl_host_rate_limit", 20))),
            "-timeout", "10",
            "-retries", "1",
            "-concurrency", "10",
            "-fs", str(config.get("katana_field_scope", "fqdn")),
            "-mdp", str(int(config.get("katana_max_domain_pages", 200))),
            "-disable-update-check",
            "-jc",  # Extract JS endpoints
        ]

        log.info("katana_crawl_started", urls=len(urls), depth=depth)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            log.warning("katana_timeout")
            return set()
        except Exception as e:
            log.error("katana_error", error=str(e))
            return set()

        discovered = set()
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    discovered.add(line)

        log.info("katana_crawl_completed", discovered=len(discovered))
        return discovered

    # ── Directory/Endpoint Fuzzing (FFUF) ─────────────────────

    async def _fuzz_endpoints(
        self,
        urls: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Set[str]:
        """Fuzz discovered URLs with ffuf to find hidden endpoints, backups, admin panels."""
        ffuf_path = tool_path("ffuf")
        if not urls or not ffuf_path:
            return set()

        discovered = set()
        wordlist = config.get("fuzz_wordlist", "")
        for candidate in [wordlist, "/usr/share/wordlists/dirb/common.txt", "/usr/share/seclists/Discovery/Web-Content/common.txt"]:
            if candidate and os.path.exists(candidate):
                wordlist = candidate
                break
        else:
            fallback = tmpdir / "fuzz_words.txt"
            fallback.write_text("\n".join([
                "admin", "login", "dashboard", "api", "v1", "v2", "graphql",
                "backup", ".git", ".env", "config", "wp-admin", "wp-content",
                "uploads", "files", "assets", "static", "status", "health",
                ".well-known", "sitemap.xml", "robots.txt", "swagger",
                "api-docs", "openapi.json", "jenkins", ".aws", ".azure",
            ]))
            wordlist = str(fallback)

        input_file = tmpdir / "fuzz_targets.txt"
        input_file.write_text("\n".join(urls))
        output_file = tmpdir / "ffuf_output.json"

        rate = config.get("fuzz_rate", 50)
        timeout = config.get("fuzz_timeout", 10)

        for url in urls[:50]:  # Limit to 50 URLs max to avoid runaway
            parsed = url.rstrip("/")
            out = tmpdir / f"ffuf_{hash(parsed)}.json"

            cmd = [
                ffuf_path,
                "-u", f"{parsed}/FUZZ",
                "-w", wordlist,
                "-o", str(out),
                "-of", "json",
                "-mc", str(config.get("fuzz_match_codes", "200-299,301,302,307,308,401,403,405,500")),
                "-fc", str(config.get("fuzz_filter_codes", "404")),
                "-fs", "0",                 # Filter out zero-length
                "-t", "20",
                "-rate", str(rate),
                "-timeout", str(timeout),
                "-maxtime", "120",
                "-noninteractive",
                "-ac",  # Auto-calibrate filtering
                "-ach",
            ]

            log.info("ffuf_fuzz_started", url=parsed)
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=180)
            except asyncio.TimeoutError:
                log.warning("ffuf_timeout", url=parsed)
                continue
            except Exception as e:
                log.error("ffuf_error", url=parsed, error=str(e))
                continue

            if out.exists():
                try:
                    data = json.loads(out.read_text())
                    for result in data.get("results", []):
                        discovered_url = result.get("url", "")
                        if discovered_url:
                            discovered.add(discovered_url)
                except (json.JSONDecodeError, KeyError):
                    pass

        log.info("ffuf_fuzz_completed", discovered=len(discovered))
        return discovered

    # ── HTTP Probing ──────────────────────────────────────────

    async def _probe_http(
        self,
        hosts: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Dict[str, Dict[str, Any]]:
        """Run httpx to probe alive HTTP/HTTPS services."""
        httpx_path = tool_path("httpx")
        if not hosts or not httpx_path:
            return {}

        input_file = tmpdir / "probe_targets.txt"
        # Add both http and https variants
        targets = []
        for h in hosts:
            targets.append(h)

        input_file.write_text("\n".join(targets))
        output_file = tmpdir / "httpx_output.json"

        cmd = [
            httpx_path,
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
            "-cpe",
            "-tls-grab",
            "-ip",
            "-cname",
            "-asn",
            "-cdn",
            "-favicon",
            "-jarm",
            "-method",
            "-location",
            "-websocket",
            "-pipeline",
            "-http2",
            "-probe",
            "-include-chain",
            "-content-length",
            "-content-type",
            "-response-time",
            "-hash", "sha256",
            "-t", str(int(config.get("httpx_threads", config.get("crawl_httpx_threads", 50)))),
            "-rl", str(int(config.get("httpx_rate_limit", 150))),
            "-timeout", str(int(config.get("httpx_timeout", 15))),
            "-max-host-error", str(int(config.get("httpx_max_host_error", 20))),
            "-no-color",
            "-duc",
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
                    if data.get("failed") and not config.get("httpx_include_failed", False):
                        continue
                    url = data.get("url", "")
                    host = data.get("host", url.split("//")[-1].split("/")[0] if "//" in url else url)
                    hash_data = data.get("hash") or {}
                    body_hash = hash_data.get("body_sha256", "") if isinstance(hash_data, dict) else str(hash_data)

                    alive[host] = {
                        "url": url,
                        "status_code": data.get("status_code"),
                        "status_class": classify_http_status(data.get("status_code")),
                        "title": data.get("title", ""),
                        "webserver": data.get("webserver", ""),
                        "content_length": data.get("content_length"),
                        "response_time": data.get("response_time", ""),
                        "hash": body_hash,
                        "favicon": data.get("favicon", ""),
                        "jarm": data.get("jarm", ""),
                        "ip": data.get("ip", ""),
                        "cname": data.get("cname", []),
                        "asn": data.get("asn", {}),
                        "method": data.get("method", ""),
                        "location": data.get("location", ""),
                        "websocket": data.get("websocket", False),
                        "pipeline": data.get("pipeline", False),
                        "http2": data.get("http2", False),
                        "cpe": data.get("cpe", []),
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

        status_counts: Dict[str, int] = {}
        for item in alive.values():
            status_class = item.get("status_class", "probe_failed")
            status_counts[status_class] = status_counts.get(status_class, 0) + 1
        if status_counts:
            log.info("http_status_classified", counts=status_counts)

        return alive

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
        from workers.db_models import Asset, Subdomain, Technology

        new_count = 0
        now = datetime.now(timezone.utc)

        for host, http_data in alive_hosts.items():
            validation = http_data.get("validation") or {}
            # Upsert Asset
            asset_values = {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "asset_type": "subdomain",
                "value": host,
                "status": "active",
                "discovery_method": "automated",
                "confidence": validation.get("confidence", 1.0),
                "is_in_scope": validation.get("is_in_scope", True),
                "scope_status": validation.get("scope_status", "in_scope"),
                "ownership_confidence": validation.get("ownership_confidence", 1.0),
                "ownership_reason": validation.get("ownership_reason"),
                "exposure_status": validation.get("exposure_status", "unknown"),
                "liveness_status": validation.get("liveness_status", "alive"),
                "validation_sources": validation.get("validation_sources", {}),
                "last_verified_at": validation.get("last_verified_at", now),
                "last_seen": now,
                "metadata": {
                    "source": "discovery_worker",
                    "validation": validation.get("validation_sources", {}),
                },
            }

            stmt = pg_insert(Asset.__table__).values(**asset_values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_asset_org_type_value",
                set_={
                    "last_seen": now,
                    "status": "active",
                    "confidence": asset_values["confidence"],
                    "is_in_scope": asset_values["is_in_scope"],
                    "scope_status": asset_values["scope_status"],
                    "ownership_confidence": asset_values["ownership_confidence"],
                    "ownership_reason": asset_values["ownership_reason"],
                    "exposure_status": asset_values["exposure_status"],
                    "liveness_status": asset_values["liveness_status"],
                    "validation_sources": asset_values["validation_sources"],
                    "last_verified_at": asset_values["last_verified_at"],
                    "metadata": asset_values["metadata"],
                },
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

            technologies = []
            seen_tech = set()
            for raw_tech in http_data.get("technologies", []):
                tech = normalize_technology(raw_tech)
                if not tech:
                    continue
                key = (tech["name"].lower(), tech["version"] or "")
                if key in seen_tech:
                    continue
                seen_tech.add(key)
                technologies.append(tech)

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
                "technologies": [tech["name"] for tech in technologies],
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

            for tech in technologies:
                tech_values = {
                    "asset_id": asset_id,
                    "org_id": org_id,
                    "name": tech["name"],
                    "version": tech["version"] or "",
                    "category": None,
                    "confidence": 1.0,
                    "detection_method": "httpx-tech-detect",
                    "metadata": {
                        "source": "httpx",
                        "fingerprint": "wappalyzer-compatible",
                    },
                    "last_detected": now,
                }
                tech_stmt = pg_insert(Technology.__table__).values(
                    **tech_values,
                    first_detected=now,
                )
                tech_stmt = tech_stmt.on_conflict_do_update(
                    constraint="uq_tech_asset_name_version",
                    set_={
                        "confidence": tech_values["confidence"],
                        "detection_method": tech_values["detection_method"],
                        "metadata": tech_values["metadata"],
                        "last_detected": now,
                    },
                )
                await db.execute(tech_stmt)

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
        direct_targets: Optional[List[str]] = None,
        alive_hosts: Optional[Dict[str, Dict]] = None,
        validation_by_host: Optional[Dict[str, Dict]] = None,
        tmpdir: Optional[Path] = None,
    ) -> None:
        """Publish port scan and nuclei tasks for discovered assets."""
        from workers.task_coordinator import TaskCoordinator
        modules = config.get("modules", [])
        queue = QueueClient()
        await queue.connect()

        coord = TaskCoordinator()
        port_batches_queued = 0
        nuclei_batches_queued = 0
        crawl_batches_queued = 0
        screenshot_queued = False
        candidates = build_target_candidates(
            subdomains=subdomains,
            ips=ips,
            direct_targets=direct_targets,
            alive_hosts=alive_hosts,
            validation_by_host=validation_by_host,
            config=config,
        )

        async with get_session() as db:
            await update_scan_phase(db, scan_id, "targeting", "completed", **candidates["summary"])
            await record_target_selections(
                db,
                scan_id=scan_id,
                phase="targeting",
                targets=self._target_selection_rows(candidates),
            )

        # Port scan task per IP batch (100 IPs per task)
        if "port" in modules:
            batch_size = 100
            network_targets = candidates["network_targets"]
            for i in range(0, len(network_targets), batch_size):
                ip_batch = network_targets[i:i + batch_size]
                await coord.add_port_expected(scan_id)
                port_batches_queued += 1
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

        crawl_targets = []
        if "crawl" in modules and config.get("crawl", True):
            crawl_targets = candidates["crawl_targets"]
            if crawl_targets:
                await coord.add_crawl_expected(scan_id)
                crawl_batches_queued += 1
                await queue.publish(
                    routing_key="scan.crawl",
                    message={
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "workspace_id": workspace_id,
                        "targets": crawl_targets,
                        "config": config,
                    },
                )

        nuclei_queued = False

        # Nuclei scan per subdomain batch (50 per task)
        if "nuclei" in modules:
            standard_targets = candidates["web_standard_targets"]
            limited_targets = candidates["web_limited_targets"]
            tech_map = candidates["tech_map"]

            batch_size = max(1, min(int(config.get("nuclei_batch_size", 25)), 50))
            limited_config = child_profile_config(
                "limited",
                config,
                {"scan_timeout": int(config.get("scan_timeout", 900))},
            )
            for target_group, group_config, profile in (
                (standard_targets, config, "standard"),
                (limited_targets, limited_config, "limited"),
            ):
                target_group = dedupe_preserve_order(target_group)
                if not target_group:
                    continue
                log.info(
                    "nuclei_targets_selected",
                    scan_id=scan_id,
                    profile=profile,
                    targets=len(target_group),
                )
                for i in range(0, len(target_group), batch_size):
                    batch = target_group[i:i + batch_size]
                    msg = {
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "workspace_id": workspace_id,
                        "targets": batch,
                        "config": group_config,
                    }
                    if tech_map:
                        msg["tech_map"] = tech_map
                    await coord.add_nuclei_expected(scan_id)
                    nuclei_batches_queued += 1
                    await queue.publish(
                        routing_key="scan.nuclei",
                        message=msg,
                    )
                    nuclei_queued = True

        screenshot_targets = candidates["screenshot_targets"] or subdomains

        # Screenshot task
        if "screenshot" in modules and screenshot_targets:
            await queue.publish(
                routing_key="scan.screenshot",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "targets": screenshot_targets[:200],  # Limit screenshots
                    "config": config,
                },
            )
            screenshot_queued = True
        else:
            # No screenshot work was queued. Mark it done so terminal
            # coordination does not wait for a worker message that will
            # never exist.
            await coord.set_screenshot_done(scan_id)

        await self._update_total_tasks(
            scan_id,
            total_tasks=1 + port_batches_queued + crawl_batches_queued + nuclei_batches_queued + int(screenshot_queued),
        )

        await queue.close()
        await coord.close()

        return bool(port_batches_queued or crawl_batches_queued or nuclei_batches_queued or screenshot_queued)

    def _target_selection_rows(self, candidates: Dict[str, Any]) -> List[Dict[str, Any]]:
        profile = candidates.get("profile") or ""
        rows: List[Dict[str, Any]] = []
        for target in candidates.get("network_targets") or []:
            rows.append({
                "target": target,
                "target_type": "ip",
                "profile": profile,
                "selected": True,
                "reasons": ["network_target", "resolved_ip"],
                "metadata": {"downstream_phase": "port"},
            })
        for target in candidates.get("web_standard_targets") or []:
            rows.append({
                "target": target,
                "target_type": "host",
                "profile": profile,
                "selected": True,
                "reasons": ["live_web", "standard_nuclei"],
                "metadata": {"downstream_phase": "nuclei", "target_group": "web_standard"},
            })
        for target in candidates.get("web_limited_targets") or []:
            rows.append({
                "target": target,
                "target_type": "host",
                "profile": "limited",
                "selected": True,
                "reasons": ["limited_web_status", "conservative_nuclei"],
                "metadata": {"downstream_phase": "nuclei", "target_group": "web_limited"},
            })
        for target in candidates.get("crawl_targets") or []:
            rows.append({
                "target": target.get("url") or target.get("host"),
                "target_type": "url",
                "profile": profile,
                "selected": True,
                "reasons": ["crawl_candidate", target.get("status_class")],
                "metadata": {
                    "downstream_phase": "crawl",
                    "host": target.get("host"),
                    "status_code": target.get("status_code"),
                    "technologies": target.get("technologies") or [],
                },
            })
        for target in candidates.get("screenshot_targets") or []:
            rows.append({
                "target": target,
                "target_type": "host",
                "profile": profile,
                "selected": True,
                "reasons": ["screenshot_candidate"],
                "metadata": {"downstream_phase": "screenshot"},
            })
        for target in candidates.get("validation_skipped_targets") or []:
            validation = target.get("validation") or {}
            rows.append({
                "target": target.get("host"),
                "target_type": "host",
                "profile": profile,
                "selected": False,
                "reasons": ["validation_gate"],
                "skip_reason": target.get("reason") or "validation_gate",
                "metadata": {
                    "downstream_phase": "targeting",
                    "scope_status": validation.get("scope_status"),
                    "liveness_status": validation.get("liveness_status"),
                    "exposure_status": validation.get("exposure_status"),
                    "ownership_confidence": validation.get("ownership_confidence"),
                    "ownership_reason": validation.get("ownership_reason"),
                    "validation_reasons": (validation.get("validation_sources") or {}).get("reasons", []),
                },
            })
        return rows

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

    async def _update_total_tasks(self, scan_id: str, total_tasks: int) -> None:
        from sqlalchemy import update
        from workers.db_models import Scan

        async with get_session() as db:
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(total_tasks=max(1, total_tasks))
            )
            await db.commit()

    async def _finalize_if_no_work(
        self,
        scan_id: str,
        org_id: str,
        workspace_id: str,
    ) -> None:
        """Called when discovery queued zero downstream tasks — finalize so scan doesn't hang."""
        from workers.queue_client import QueueClient
        from workers.task_coordinator import TaskCoordinator

        coord = TaskCoordinator()
        # Ensure screenshot_done is set so terminal condition can be met
        await coord.set_screenshot_done(scan_id)
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


if __name__ == "__main__":
    worker = DiscoveryWorker()
    asyncio.run(worker.run())

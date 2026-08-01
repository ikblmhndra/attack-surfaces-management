"""
ASM Platform — Discovery Worker
Runs subdomain discovery, DNS enumeration, HTTP probing, endpoint crawling, and fuzzing.
Integrates: subfinder, amass, assetfinder, dnsx, httpx, naabu, katana, ffuf
"""
import asyncio
import ipaddress
import re
import hashlib
import json
import os
import random
import shutil
import subprocess
import string
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aio_pika
import aiohttp
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.fuzz_wordlist import resolve_fuzz_wordlist
from workers.queue_client import QueueClient
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running
from workers.discovery.dns_candidates import (
    dns_fingerprint,
    generate_bruteforce_hosts,
    generate_permutation_hosts,
    is_unconfirmed_generated_guess,
    normalize_host,
)
from app.services.scan_profiles import build_target_candidates, child_profile_config
from app.services.asset_validation import (
    apply_scope_controls,
    should_scan_validated_asset,
    validate_discovered_host,
    validation_skip_reason,
)

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


# subfinder passive-source name -> env var already documented in .env.example.
# These keys previously sat unused: subfinder's own -pc flag support existed in
# _run_subfinder() below, but nothing ever generated the provider-config file.
SUBFINDER_SOURCE_ENV_MAP = {
    "shodan": "SHODAN_API_KEY",
    "censys": "CENSYS_PAT",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "alienvault": "OTX_API_KEY",  # subfinder's source name for AlienVault OTX
}


def ensure_subfinder_provider_config(path: str = "/etc/subfinder/provider-config.yaml") -> None:
    """Populate subfinder's provider-config from whichever premium-source API keys
    are set in the environment, so passive discovery isn't limited to free/keyless
    sources. No-op if the file already exists or no keys are configured."""
    config_path = Path(path)
    if config_path.exists():
        return

    lines = []
    configured_sources = []
    for source, env_var in SUBFINDER_SOURCE_ENV_MAP.items():
        value = os.getenv(env_var)
        if value:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{source}:\n  - "{escaped}"')
            configured_sources.append(source)

    if not lines:
        return

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("\n".join(lines) + "\n")
    log.info("subfinder_provider_config_written", sources=configured_sources)


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


def json_safe(value: Any) -> Any:
    """Convert scanner evidence into values PostgreSQL JSONB can serialize."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, set):
        return [json_safe(item) for item in sorted(value, key=str)]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


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

    async def setup(self) -> None:
        ensure_subfinder_provider_config()

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
            discovery_evidence: Dict[str, Dict[str, Any]] = {}
            source_health: Dict[str, Dict[str, Any]] = {}
            extra_discoveries: List[Dict[str, Any]] = []
            known_sans = await self._fetch_known_tls_sans(org_id)

            for domain in targets.get("domains", []):
                subdomains = await self._discover_subdomains_with_sources(domain, tmpdir, config, source_health, known_sans)
                self._merge_discovery_evidence(discovery_evidence, subdomains)
                log.info("subdomains_discovered", domain=domain, count=len(subdomains))

            manual_asns = targets.get("asns", [])
            extra_discoveries.extend(await self._expand_asn_targets(manual_asns, config, source_health))
            if not manual_asns and config.get("asn_auto_discovery", True):
                auto_asns = await self._discover_org_asns(
                    [targets.get("organization_name"), targets.get("company_name")]
                )
                if auto_asns:
                    extra_discoveries.extend(await self._expand_asn_targets(
                        [info["asn"] for info in auto_asns], config, source_health,
                        source_label="asn_auto_discovery",
                        confidence=0.4,
                        extra_evidence={
                            info["asn"]: {
                                "matched_name": info["matched_name"],
                                "ripestat_description": info["ripestat_description"],
                            }
                            for info in auto_asns
                        },
                    ))
            extra_discoveries.extend(await self._discover_reverse_dns_targets(org_id, targets, config, source_health))
            extra_discoveries.extend(await self._discover_cloud_storage(targets, config, source_health))

            all_subdomains: Set[str] = set(discovery_evidence)

            # ── Phase 2: DNS Resolution ───────────────────────
            resolved = await self._resolve_dns(list(all_subdomains), tmpdir)
            wildcard_report = await self._detect_wildcard_dns(targets.get("domains", []), tmpdir, config)
            resolved, wildcard_skipped = self._suppress_wildcard_generated_hosts(
                resolved,
                discovery_evidence,
                wildcard_report,
            )
            all_subdomains.difference_update(wildcard_skipped)
            log.info("dns_resolved", total=len(resolved))

            # ── Phase 3: HTTP Probing ─────────────────────────
            alive_hosts = await self._probe_http(list(resolved.keys()), tmpdir, config)
            validation_by_host = {}
            for host, dns_info in resolved.items():
                validation = validate_discovered_host(
                    host=host,
                    root_domains=targets.get("domains", []),
                    dns_info=dns_info,
                    http_info=alive_hosts.get(host, {}),
                )
                sources = validation.setdefault("validation_sources", {})
                evidence = sources.setdefault("evidence", {})
                evidence["discovery"] = self._serializable_discovery_evidence(
                    discovery_evidence.get(host, {})
                )
                validation_by_host[host] = apply_scope_controls(
                    validation,
                    target=host,
                    allow_patterns=targets.get("scope_allow_patterns", []),
                    deny_patterns=targets.get("scope_deny_patterns", []),
                )
            for host in sorted(all_subdomains - set(validation_by_host)):
                validation = validate_discovered_host(
                    host=host,
                    root_domains=targets.get("domains", []),
                    dns_info={},
                    http_info={},
                )
                sources = validation.setdefault("validation_sources", {})
                evidence = sources.setdefault("evidence", {})
                evidence["discovery"] = self._serializable_discovery_evidence(
                    discovery_evidence.get(host, {})
                )
                validation_by_host[host] = apply_scope_controls(
                    validation,
                    target=host,
                    allow_patterns=targets.get("scope_allow_patterns", []),
                    deny_patterns=targets.get("scope_deny_patterns", []),
                )
            for host, http_data in alive_hosts.items():
                http_data["validation"] = validation_by_host.get(host)
            log.info("http_probed", alive=len(alive_hosts))

            persisted_hosts = {}
            generated_misses_skipped = 0
            for host in resolved:
                http_data = dict(alive_hosts.get(host, {}))
                validation = validation_by_host.get(host)
                http_data["validation"] = validation
                evidence_sources = discovery_evidence.get(host, {}).get("sources") or set()
                if is_unconfirmed_generated_guess(
                    evidence_sources,
                    (validation or {}).get("liveness_status"),
                ):
                    generated_misses_skipped += 1
                    continue
                persisted_hosts[host] = http_data

            # ── Phase 4: Persist Assets ───────────────────────
            wildcard_fps = {
                tuple(fingerprint)
                for domain_report in (wildcard_report.get("domains") or {}).values()
                for fingerprint in domain_report.get("fingerprints") or []
            }
            async with get_session() as db:
                new_count, asset_ids_by_host = await self._persist_assets(
                    db, org_id, workspace_id, scan_id,
                    persisted_hosts, resolved, discovery_evidence,
                    root_domains=targets.get("domains", []),
                    wildcard_fps=wildcard_fps,
                )
                cloud_new_count, cloud_asset_ids = await self._persist_cloud_assets(
                    db, org_id, workspace_id, scan_id, extra_discoveries
                )
                new_count += cloud_new_count
                await self._persist_discovered_assets(
                    db,
                    org_id,
                    workspace_id,
                    scan_id,
                    discovery_evidence,
                    validation_by_host,
                    asset_ids_by_host,
                    wildcard_skipped,
                    extra_discoveries,
                    cloud_asset_ids,
                )
                await self._update_scan_progress(
                    db,
                    scan_id,
                    assets_found=len(persisted_hosts) + len(cloud_asset_ids),
                )
                await update_scan_phase(
                    db,
                    scan_id,
                    "discovery",
                    "completed",
                    subdomains=len(all_subdomains),
                    resolved_hosts=len(resolved),
                    alive_hosts=len(alive_hosts),
                    new_assets=new_count,
                    source_breakdown=self._source_breakdown(discovery_evidence),
                    wildcard_dns=wildcard_report,
                    wildcard_skipped=len(wildcard_skipped),
                    source_health=source_health,
                    asn_candidates=sum(1 for item in extra_discoveries if item.get("asset_type") == "cidr"),
                    reverse_dns_candidates=sum(1 for item in extra_discoveries if item.get("source") == "reverse_dns"),
                    cloud_candidates=sum(1 for item in extra_discoveries if item.get("asset_type") == "cloud_bucket"),
                    generated_candidates=sum(
                        1
                        for evidence in discovery_evidence.values()
                        if evidence.get("generated")
                    ),
                    generated_misses_skipped=generated_misses_skipped,
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
        discovered = await self._discover_subdomains_with_sources(domain, tmpdir, config, {})
        return set(discovered)

    async def _discover_subdomains_with_sources(
        self,
        domain: str,
        tmpdir: Path,
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
        known_sans: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Run passive/generated discovery and keep per-host source evidence."""
        candidates: Dict[str, Dict[str, Any]] = {}
        source_tasks = [
            ("subfinder", self._run_subfinder(domain, tmpdir, config)),
            ("assetfinder", self._run_assetfinder(domain, tmpdir)),
            ("crtsh", self._run_crtsh(domain, source_health)),
        ]

        if config.get("use_amass", False):
            source_tasks.append(("amass", self._run_amass(domain, tmpdir)))
        if config.get("wayback_discovery", True):
            source_tasks.append(("wayback", self._run_wayback(domain, config, source_health)))
        if config.get("commoncrawl_discovery", True):
            source_tasks.append(("commoncrawl", self._run_commoncrawl(domain, config, source_health)))

        discovered = await asyncio.gather(
            *(task for _, task in source_tasks),
            return_exceptions=True,
        )

        for (source, _), result in zip(source_tasks, discovered):
            if isinstance(result, Exception):
                log.warning("discovery_tool_failed", source=source, error=str(result))
                self._record_source_health(source_health, source, domain, "failed", error=str(result)[:200])
                continue
            if not isinstance(result, set):
                continue
            existing = (source_health.get(source, {}).get("domains") or {}).get(domain, {})
            if existing.get("status") not in {"failed", "skipped"}:
                self._record_source_health(source_health, source, domain, "ok", count=len(result))
            for host in result:
                self._add_discovery_candidate(
                    candidates,
                    host,
                    domain,
                    source,
                    generated=False,
                    evidence={"source": source},
                )

        if config.get("dns_bruteforce", True):
            max_hosts = int(config.get("dns_bruteforce_max_hosts", 80))
            words = config.get("dns_bruteforce_words") or None
            generated = generate_bruteforce_hosts(domain, words=words, max_hosts=max_hosts)
            self._record_source_health(source_health, "dns_bruteforce", domain, "ok", count=len(generated))
            for host in generated:
                self._add_discovery_candidate(
                    candidates,
                    host,
                    domain,
                    "dns_bruteforce",
                    generated=True,
                    evidence={"source": "dns_bruteforce", "strategy": "wordlist"},
                )

        if config.get("dns_permutations", True):
            max_hosts = int(config.get("dns_permutation_max_hosts", 80))
            generated = generate_permutation_hosts(domain, candidates.keys(), max_hosts=max_hosts)
            self._record_source_health(source_health, "dns_permutation", domain, "ok", count=len(generated))
            for host in generated:
                self._add_discovery_candidate(
                    candidates,
                    host,
                    domain,
                    "dns_permutation",
                    generated=True,
                    evidence={"source": "dns_permutation", "strategy": "env_affix"},
                )

        if config.get("tls_san_mining", True) and known_sans:
            # SAN values already sitting in this org's own subdomains.tls_sans
            # column (collected earlier from certs served by already-in-scope
            # hosts — no new network requests here). _add_discovery_candidate's
            # own domain-suffix check discards anything not actually a subdomain
            # of this root domain, which matters: a shared-hosting cert's SAN
            # list can carry hundreds of unrelated third-party mail-server
            # hostnames alongside the org's own — verified against real data
            # before wiring this (see Milestone 17 CHANGELOG entry).
            matched = sum(1 for san in known_sans if self._in_domain(san, domain))
            self._record_source_health(source_health, "tls_san_mining", domain, "ok", count=matched)
            for san in known_sans:
                self._add_discovery_candidate(
                    candidates,
                    san,
                    domain,
                    "tls_san_mining",
                    generated=False,
                    evidence={"source": "tls_san_mining"},
                )

        return candidates

    async def _fetch_known_tls_sans(self, org_id: str) -> List[str]:
        """Every SAN value already collected on this org's Subdomain rows —
        fetched once per scan and reused across all of the org's root domains,
        rather than re-querying per domain."""
        from sqlalchemy import select
        from workers.db_models import Subdomain

        async with get_session() as db:
            rows = (await db.execute(
                select(Subdomain.tls_sans).where(
                    Subdomain.org_id == org_id,
                    Subdomain.tls_sans.is_not(None),
                )
            )).scalars().all()
        sans: Set[str] = set()
        for san_list in rows:
            for san in (san_list or []):
                if san:
                    sans.add(str(san).strip())
        return sorted(sans)

    def _add_discovery_candidate(
        self,
        candidates: Dict[str, Dict[str, Any]],
        host: str,
        domain: str,
        source: str,
        *,
        generated: bool,
        evidence: Dict[str, Any],
    ) -> None:
        host = normalize_host(host).lstrip("*.")
        domain = normalize_host(domain)
        if not host or not (host == domain or host.endswith(f".{domain}")) or not self._is_valid_hostname(host):
            return
        entry = candidates.setdefault(
            host,
            {
                "sources": set(),
                "evidence": {},
                "generated": False,
            },
        )
        entry["sources"].add(source)
        entry["generated"] = bool(entry.get("generated")) or generated
        entry.setdefault("evidence", {})[source] = evidence

    def _merge_discovery_evidence(
        self,
        target: Dict[str, Dict[str, Any]],
        source: Dict[str, Dict[str, Any]],
    ) -> None:
        for host, evidence in source.items():
            entry = target.setdefault(
                host,
                {
                    "sources": set(),
                    "evidence": {},
                    "generated": False,
                },
            )
            entry["sources"].update(evidence.get("sources") or [])
            entry["evidence"].update(evidence.get("evidence") or {})
            entry["generated"] = bool(entry.get("generated")) or bool(evidence.get("generated"))

    def _serializable_discovery_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        sources = sorted(evidence.get("sources") or [])
        return {
            "sources": sources,
            "source_count": len(sources),
            "generated": bool(evidence.get("generated", False)),
            "evidence": json_safe(evidence.get("evidence") or {}),
        }

    def _source_breakdown(self, discovery_evidence: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for evidence in discovery_evidence.values():
            for source in evidence.get("sources") or []:
                counts[source] = counts.get(source, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[0]))

    def _record_source_health(
        self,
        source_health: Dict[str, Dict[str, Any]],
        source: str,
        domain: str,
        status: str,
        *,
        count: int = 0,
        error: Optional[str] = None,
    ) -> None:
        entry = source_health.setdefault(
            source,
            {"status": "ok", "count": 0, "errors": [], "domains": {}},
        )
        previous = entry["domains"].get(domain, {})
        domain_count = int(previous.get("count") or 0) + int(count or 0)
        domain_entry = {
            "status": status,
            "count": domain_count,
        }
        if error:
            domain_entry["error"] = error
            entry["errors"].append({"domain": domain, "error": error})
        entry["domains"][domain] = domain_entry
        entry["count"] = sum(int(item.get("count") or 0) for item in entry["domains"].values())
        statuses = {item.get("status") for item in entry["domains"].values()}
        if "failed" in statuses:
            entry["status"] = "partial" if statuses - {"failed"} else "failed"
        elif "skipped" in statuses and statuses <= {"skipped"}:
            entry["status"] = "skipped"
        else:
            entry["status"] = "ok"

    def _in_domain(self, host: str, domain: str) -> bool:
        host = normalize_host(host).lstrip("*.")
        domain = normalize_host(domain)
        return bool(host and (host == domain or host.endswith(f".{domain}")))

    async def _run_wayback(
        self,
        domain: str,
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
    ) -> Set[str]:
        """Extract hostnames from the Internet Archive CDX API."""
        import aiohttp

        limit = int(config.get("wayback_limit", 500))
        url = (
            "https://web.archive.org/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
        )
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        log.warning("wayback_http_error", domain=domain, status=resp.status)
                        self._record_source_health(source_health, "wayback", domain, "failed", error=f"http_{resp.status}")
                        return set()
                    rows = await resp.json(content_type=None)
        except Exception as exc:
            log.warning("wayback_error", domain=domain, error=str(exc)[:200])
            self._record_source_health(source_health, "wayback", domain, "failed", error=f"{type(exc).__name__}: {exc}"[:200])
            return set()

        hosts = set()
        for row in rows[1:] if isinstance(rows, list) else []:
            raw_url = row[0] if isinstance(row, list) and row else ""
            host = self._host_from_url(raw_url)
            if self._in_domain(host, domain):
                hosts.add(host)
        return hosts

    async def _run_commoncrawl(
        self,
        domain: str,
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
    ) -> Set[str]:
        """Extract hostnames from the latest Common Crawl index."""
        import aiohttp

        limit = int(config.get("commoncrawl_limit", 500))
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get("https://index.commoncrawl.org/collinfo.json") as resp:
                    if resp.status != 200:
                        self._record_source_health(source_health, "commoncrawl", domain, "failed", error=f"collinfo_http_{resp.status}")
                        return set()
                    indexes = await resp.json(content_type=None)
                if not indexes:
                    return set()
                index_id = indexes[0].get("id")
                if not index_id:
                    return set()
                query_url = (
                    f"https://index.commoncrawl.org/{index_id}-index"
                    f"?url=*.{domain}/*&output=json&fl=url&limit={limit}"
                )
                async with session.get(query_url) as resp:
                    if resp.status != 200:
                        log.warning("commoncrawl_http_error", domain=domain, status=resp.status)
                        self._record_source_health(source_health, "commoncrawl", domain, "failed", error=f"http_{resp.status}")
                        return set()
                    text = await resp.text()
        except Exception as exc:
            log.warning("commoncrawl_error", domain=domain, error=str(exc)[:200])
            self._record_source_health(source_health, "commoncrawl", domain, "failed", error=f"{type(exc).__name__}: {exc}"[:200])
            return set()

        hosts = set()
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = self._host_from_url(row.get("url", ""))
            if self._in_domain(host, domain):
                hosts.add(host)
        return hosts

    def _host_from_url(self, raw_url: str) -> str:
        parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
        return normalize_host(parsed.hostname or "")

    async def _expand_asn_targets(
        self,
        asns: List[str],
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
        *,
        source_label: str = "asn_expansion",
        confidence: float = 0.65,
        extra_evidence: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        # Previously queried whois.cymru's bulk "begin/verbose/ASxxxx/end"
        # protocol expecting a per-prefix response (7 pipe-separated fields:
        # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name). Verified
        # live this query actually returns a single ASN-*info* summary row (5
        # fields: AS | CC | Registry | Allocated | AS Name -- no prefix data
        # at all), so `parts[2]` was silently reading the registry name as if
        # it were a CIDR (correctly rejected by ipaddress.ip_network, but the
        # net effect was this always returned zero real prefixes for every
        # ASN, manually-entered or not). Replaced with RIPEstat's
        # announced-prefixes + as-overview endpoints (already proven reliable
        # in this environment by _discover_org_asns -- same host, same
        # keyless access).
        if not config.get("asn_expansion", True):
            return []
        candidates: List[Dict[str, Any]] = []
        max_prefixes = int(config.get("asn_prefix_max", 25))
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            for raw_asn in asns or []:
                asn = str(raw_asn or "").upper().replace("AS", "").strip()
                if not asn.isdigit():
                    continue
                source_key = f"AS{asn}"

                try:
                    async with session.get(
                        "https://stat.ripe.net/data/announced-prefixes/data.json",
                        params={"resource": source_key},
                    ) as resp:
                        if resp.status != 200:
                            raise RuntimeError(f"http_{resp.status}")
                        prefix_payload = await resp.json()
                except Exception as exc:
                    self._record_source_health(
                        source_health, "asn_expansion", source_key, "failed",
                        error=f"{type(exc).__name__}: {exc}"[:200],
                    )
                    continue

                asn_org = None
                try:
                    async with session.get(
                        "https://stat.ripe.net/data/as-overview/data.json",
                        params={"resource": source_key},
                    ) as resp:
                        if resp.status == 200:
                            overview_payload = await resp.json()
                            asn_org = ((overview_payload or {}).get("data") or {}).get("holder")
                except Exception:
                    pass  # holder name is evidence-only, not required for the prefix itself

                prefixes = []
                for entry in ((prefix_payload or {}).get("data") or {}).get("prefixes") or []:
                    prefix = str(entry.get("prefix") or "")
                    try:
                        ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        continue
                    prefixes.append({
                        "value": prefix,
                        "asset_type": "cidr",
                        "source": source_label,
                        "confidence": confidence,
                        "status": "candidate",
                        "selected": False,
                        "skip_reason": "asn_prefix_not_auto_scanned",
                        "evidence": {
                            "asn": source_key,
                            "asn_org": asn_org,
                            **((extra_evidence or {}).get(source_key, {})),
                        },
                    })
                    if len(prefixes) >= max_prefixes:
                        break
                candidates.extend(prefixes)
                self._record_source_health(source_health, "asn_expansion", source_key, "ok", count=len(prefixes))
        return candidates

    # RIPEstat's searchcomplete endpoint behaves like a single-token
    # autocomplete, not a phrase search -- confirmed live: "Cloudflare" finds
    # 11 ASNs, "Cloudflare, Inc." or "Cloudflare Inc" finds 0; "Akamai" finds
    # 39, "Akamai Technologies" (no punctuation, just a second word) finds 0.
    # A real Organization.name/company_name is almost always a full legal
    # name, so querying it verbatim would find nothing in practice.
    _ORG_SUFFIX_RE = re.compile(
        r",?\s*\b(incorporated|inc|llc|ltd|limited|corp|corporation|co|company|"
        r"gmbh|plc|tbk|group|holdings?)\.?\s*$",
        re.IGNORECASE,
    )

    def _org_name_stripped(self, name: str) -> str:
        """Corporate-suffix-stripped form of an org name (repeatedly, for
        "X Corp, Inc." style double suffixes)."""
        stripped = name.strip()
        while True:
            next_stripped = self._ORG_SUFFIX_RE.sub("", stripped).strip().rstrip(",").strip()
            if not next_stripped or next_stripped == stripped:
                return stripped
            stripped = next_stripped

    def _org_name_search_variants(self, stripped: str) -> List[str]:
        """Progressively simplified *query* terms to send to RIPEstat,
        most-specific first -- the endpoint behaves like a single-token
        autocomplete, not a phrase search, so a multi-word name needs
        narrowing just to get any results back at all. The first-word tier
        is deliberately lossy as a *query* (only used to fetch candidates
        from RIPEstat) -- see _discover_org_asns for why it doesn't
        introduce false positives on its own."""
        variants: List[str] = [stripped] if stripped else []
        first_word = re.split(r"\s+", stripped)[0] if stripped else ""
        if len(first_word) >= 3 and first_word.lower() != stripped.lower():
            variants.append(first_word)
        return variants

    async def _discover_org_asns(self, org_names: List[Optional[str]]) -> List[Dict[str, Any]]:
        """Auto-discover candidate ASNs for an org that hasn't manually
        entered any, via RIPEstat's free/keyless searchcomplete API (BGPView,
        the more commonly-cited alternative, was unreachable entirely when
        checked live -- connection failed outright). Confirmed live:
        RIPEstat's search only works well against a single bare word --
        "Cloudflare" finds 11 ASNs, "Cloudflare, Inc." finds 0 -- so a
        multi-word name is queried progressively more narrowly just to get
        candidates back at all.

        Acceptance is kept strict regardless of which query variant found
        the candidate: every "significant" word (len >= 3) of the
        *suffix-stripped* name must appear in RIPEstat's own AS-holder
        description, not just the (possibly single-word) query term. This
        matters in practice -- confirmed live: querying "Digital" (the
        first-word fallback for "Digital Ocean", which has no corporate
        suffix to strip) returns "Digital Cafe", "Digital Ink", "Digital
        Media Group" alongside the real DigitalOcean entries. Requiring
        "ocean" to also appear (it does, as a substring of "DigitalOcean")
        correctly keeps the real match and rejects the unrelated ones,
        without needing an arbitrary stoplist of generic words.

        Feeds into _expand_asn_targets's existing candidate-only pipeline
        (never auto-scanned), just tagged with a lower confidence and a
        distinct source so analysts know to double-check these harder
        before promoting one.
        """
        names = [str(name).strip() for name in org_names if name and str(name).strip()]
        if not names:
            return []

        found: Dict[str, Dict[str, Any]] = {}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
                for name in dict.fromkeys(names):
                    stripped = self._org_name_stripped(name)
                    significant_words = [w.lower() for w in re.split(r"\s+", stripped) if len(w) >= 3]
                    if not significant_words:
                        continue

                    for variant in self._org_name_search_variants(stripped):
                        try:
                            async with session.get(
                                "https://stat.ripe.net/data/searchcomplete/data.json",
                                params={"resource": variant},
                            ) as resp:
                                if resp.status != 200:
                                    continue
                                payload = await resp.json()
                        except Exception as exc:
                            log.warning("asn_auto_discovery_query_failed", name=variant, error=str(exc))
                            continue

                        categories = ((payload or {}).get("data") or {}).get("categories") or []
                        asn_category = next((c for c in categories if c.get("category") == "ASNs"), None)
                        if not asn_category or not asn_category.get("suggestions"):
                            continue

                        for suggestion in asn_category.get("suggestions") or []:
                            description = str(suggestion.get("description") or "")
                            description_lower = description.lower()
                            if not all(word in description_lower for word in significant_words):
                                continue
                            asn_value = str(suggestion.get("value") or "").upper().replace("AS", "").strip()
                            if not asn_value.isdigit():
                                continue
                            found.setdefault(f"AS{asn_value}", {
                                "asn": f"AS{asn_value}",
                                "matched_name": stripped,
                                "ripestat_description": description,
                            })
                        break  # a variant returned real ASN results -- don't broaden further
        except Exception as exc:
            log.warning("asn_auto_discovery_failed", error=str(exc))
            return []

        return list(found.values())

    async def _fetch_known_ip_assets(self, org_id: str) -> List[str]:
        """Already-confirmed IP Asset rows for this org (resolved from a
        validated in-scope host in a prior scan, per port_worker.py's
        _persist_ip_assets). Reverse-DNS on these doesn't expand scope at
        all — it's the same IPs we already have standing to touch — it just
        extracts more info (co-hosted vhosts not found via forward
        subdomain enumeration) from data we're already authorized to see."""
        from sqlalchemy import select
        from workers.db_models import Asset

        async with get_session() as db:
            rows = (await db.execute(
                select(Asset.value).where(
                    Asset.org_id == org_id, Asset.asset_type == "ip", Asset.status == "active"
                )
            )).scalars().all()
        return [str(v) for v in rows if v]

    async def _discover_reverse_dns_targets(
        self,
        org_id: str,
        targets: Dict[str, Any],
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not config.get("reverse_dns_discovery", True):
            return []
        known_ips = await self._fetch_known_ip_assets(org_id) if config.get("reverse_dns_known_ips", True) else []
        ip_ranges = list(targets.get("ip_ranges") or []) + known_ips
        if not ip_ranges:
            self._record_source_health(source_health, "reverse_dns", "ip_ranges", "skipped", error="no_ip_ranges")
            return []

        max_ips = max(0, int(config.get("reverse_dns_max_ips", 64)))
        if max_ips <= 0:
            self._record_source_health(source_health, "reverse_dns", "ip_ranges", "skipped", error="budget_zero")
            return []

        ips: List[str] = []
        for raw_target in ip_ranges:
            if len(ips) >= max_ips:
                break
            try:
                network = ipaddress.ip_network(str(raw_target).strip(), strict=False)
            except ValueError:
                try:
                    address = ipaddress.ip_address(str(raw_target).strip())
                except ValueError:
                    continue
                if address.version == 4:
                    ips.append(str(address))
                continue
            if network.version != 4:
                continue
            for address in network.hosts():
                ips.append(str(address))
                if len(ips) >= max_ips:
                    break

        if not ips:
            self._record_source_health(source_health, "reverse_dns", "ip_ranges", "skipped", error="no_ipv4_candidates")
            return []

        root_domains = [normalize_host(domain) for domain in targets.get("domains", []) if normalize_host(domain)]
        semaphore = asyncio.Semaphore(max(1, int(config.get("reverse_dns_concurrency", 16))))

        async def lookup(ip: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                try:
                    loop = asyncio.get_running_loop()
                    host, _ = await asyncio.wait_for(loop.getnameinfo((ip, 0), 0), timeout=3)
                except Exception:
                    return None
            host = normalize_host(str(host).rstrip("."))
            if not host or host == ip:
                return None
            in_scope = any(self._in_domain(host, domain) for domain in root_domains)
            return {
                "value": host,
                "asset_type": "subdomain",
                "source": "reverse_dns",
                "confidence": 0.7 if in_scope else 0.45,
                "status": "candidate",
                "selected": False,
                "skip_reason": "reverse_dns_not_auto_scanned",
                "evidence": {
                    "ip": ip,
                    "ptr": host,
                    "scope_match": in_scope,
                    "ownership_confidence": "medium" if in_scope else "low",
                },
            }

        results = await asyncio.gather(*(lookup(ip) for ip in ips))
        discoveries = [item for item in results if item]
        self._record_source_health(source_health, "reverse_dns", "ip_ranges", "ok", count=len(discoveries))
        return discoveries

    async def _discover_cloud_storage(
        self,
        targets: Dict[str, Any],
        config: Dict,
        source_health: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not config.get("cloud_storage_discovery", True):
            return []
        import aiohttp

        bucket_names = self._cloud_bucket_names(targets, int(config.get("cloud_bucket_max_candidates", 24)))
        if not bucket_names:
            return []

        providers = [
            ("aws_s3", "https://{bucket}.s3.amazonaws.com/"),
            ("gcs", "https://storage.googleapis.com/{bucket}/"),
            ("azure_blob", "https://{bucket}.blob.core.windows.net/"),
        ]
        discoveries: List[Dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for provider, template in providers:
                provider_count = 0
                for bucket in bucket_names:
                    url = template.format(bucket=bucket)
                    try:
                        async with session.head(url, allow_redirects=True) as resp:
                            status_code = resp.status
                    except Exception:
                        try:
                            async with session.get(url, allow_redirects=True) as resp:
                                status_code = resp.status
                        except Exception as exc:
                            discoveries.append(self._cloud_candidate(provider, bucket, url, None, "unknown", f"{type(exc).__name__}: {exc}"[:200]))
                            continue

                    exposure = self._classify_bucket_status(status_code)
                    discoveries.append(self._cloud_candidate(provider, bucket, url, status_code, exposure, None))
                    if exposure in {"public", "private_exists"}:
                        provider_count += 1
                self._record_source_health(source_health, provider, "cloud_storage", "ok", count=provider_count)
        return discoveries

    def _cloud_bucket_names(self, targets: Dict[str, Any], max_candidates: int) -> List[str]:
        values = []
        raw_values = list(targets.get("domains", []) or [])
        raw_values.extend([targets.get("organization_name"), targets.get("company_name")])
        for value in raw_values:
            normalized = re.sub(r"[^a-z0-9.-]+", "-", str(value or "").lower()).strip("-.")
            if not normalized:
                continue
            no_dot = normalized.replace(".", "")
            dashed = normalized.replace(".", "-")
            first = normalized.split(".")[0]
            values.extend([normalized, no_dot, dashed, first])
            values.extend([f"{first}-assets", f"{first}-static", f"{first}-backup", f"{first}-media"])
        return dedupe_preserve_order([value for value in values if 3 <= len(value) <= 63])[:max_candidates]

    def _classify_bucket_status(self, status_code: Optional[int]) -> str:
        if status_code in {200, 206}:
            return "public"
        if status_code in {401, 403}:
            return "private_exists"
        if status_code == 404:
            return "not_found"
        return "unknown"

    def _cloud_candidate(
        self,
        provider: str,
        bucket: str,
        url: str,
        status_code: Optional[int],
        exposure: str,
        error: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "value": f"{provider}:{bucket}",
            "asset_type": "cloud_bucket",
            "source": provider,
            "confidence": 0.7 if exposure in {"public", "private_exists"} else 0.25,
            "status": exposure,
            "selected": False,
            "skip_reason": "cloud_storage_safe_check_only",
            "evidence": {
                "provider": provider,
                "bucket": bucket,
                "url": url,
                "http_status": status_code,
                "exposure": exposure,
                "error": error,
            },
        }

    async def _detect_wildcard_dns(
        self,
        domains: List[str],
        tmpdir: Path,
        config: Dict,
    ) -> Dict[str, Any]:
        if not config.get("wildcard_dns_detection", True):
            return {"enabled": False, "domains": {}}

        report = {"enabled": True, "domains": {}}
        for domain in domains:
            # 6, not 3: a round-robin/load-balanced wildcard backend can fail
            # to repeat a DNS fingerprint across only 3 random probes, leaving
            # it undetected and its generated-subdomain noise unsuppressed.
            labels = [
                "asm-wildcard-"
                + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
                for _ in range(6)
            ]
            probes = [f"{label}.{domain}" for label in labels]
            resolved = await self._resolve_dns(probes, tmpdir)
            fingerprints = [dns_fingerprint(record) for record in resolved.values()]
            fingerprints = [fp for fp in fingerprints if fp]
            wildcard_fingerprints = []
            for fp in fingerprints:
                if fingerprints.count(fp) >= 2 and fp not in wildcard_fingerprints:
                    wildcard_fingerprints.append(fp)
            report["domains"][domain] = {
                "probes": probes,
                "wildcard": bool(wildcard_fingerprints),
                "fingerprints": [list(fp) for fp in wildcard_fingerprints],
            }
        return report

    def _suppress_wildcard_generated_hosts(
        self,
        resolved: Dict[str, Dict[str, Any]],
        discovery_evidence: Dict[str, Dict[str, Any]],
        wildcard_report: Dict[str, Any],
    ) -> tuple[Dict[str, Dict[str, Any]], list[str]]:
        wildcard_fps = {
            tuple(fingerprint)
            for domain_report in (wildcard_report.get("domains") or {}).values()
            for fingerprint in domain_report.get("fingerprints") or []
        }
        if not wildcard_fps:
            return resolved, []

        filtered = {}
        skipped = []
        for host, record in resolved.items():
            evidence = discovery_evidence.get(host, {})
            fingerprint = dns_fingerprint(record)
            generated_only = bool(evidence.get("generated")) and not (
                set(evidence.get("sources") or []) - {"dns_bruteforce", "dns_permutation"}
            )
            if generated_only and fingerprint in wildcard_fps:
                skipped.append(host)
                evidence["wildcard_suppressed"] = True
                continue
            filtered[host] = record
        return filtered, skipped

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

    async def _run_crtsh(self, domain: str, source_health: Dict[str, Dict[str, Any]]) -> Set[str]:
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
                                    if name and (name == domain or name.endswith(f".{domain}")):
                                        results.add(name.lower())
                            return results
                        elif resp.status in (502, 503, 429) and attempt < 2:
                            wait = 2 ** attempt
                            log.warning("crtsh_retry", domain=domain, status=resp.status, attempt=attempt, wait=wait)
                            await asyncio.sleep(wait)
                        else:
                            log.warning("crtsh_http_error", domain=domain, status=resp.status, attempt=attempt)
                            self._record_source_health(source_health, "crtsh", domain, "failed", error=f"http_{resp.status}")
                            return results
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                if attempt < 2:
                    wait = 2 ** attempt
                    log.warning("crtsh_retry", domain=domain, error=str(e), attempt=attempt, wait=wait)
                    await asyncio.sleep(wait)
                else:
                    log.warning("crtsh_failed", domain=domain, error=f"{type(e).__name__}: {e}"[:200])
                    self._record_source_health(source_health, "crtsh", domain, "failed", error=f"{type(e).__name__}: {e}"[:200])

        return results

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
        wordlist = resolve_fuzz_wordlist(tmpdir, config)

        input_file = tmpdir / "fuzz_targets.txt"
        input_file.write_text("\n".join(urls))
        output_file = tmpdir / "ffuf_output.json"

        rate = config.get("fuzz_rate", 50)
        timeout = config.get("fuzz_timeout", 10)
        recursion_depth = int(config.get("fuzz_recursion_depth", 0))
        extensions = str(config.get("fuzz_extensions", "") or "")

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
            # See web_crawl_worker.py::_run_ffuf for why these are separate,
            # bounded, off-by-default flags — same reasoning applies here.
            if recursion_depth > 0:
                cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
            if extensions:
                cmd.extend(["-e", extensions])

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
        discovery_evidence: Optional[Dict[str, Dict[str, Any]]] = None,
        root_domains: Optional[List[str]] = None,
        wildcard_fps: Optional[Set[tuple]] = None,
    ) -> tuple[int, Dict[str, Any]]:
        """Upsert discovered assets into the database."""
        from sqlalchemy import select, update
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.asset_criticality import infer_asset_criticality
        from workers.db_models import Asset, Organization, Subdomain, Technology

        new_count = 0
        asset_ids_by_host: Dict[str, Any] = {}
        now = datetime.now(timezone.utc)
        root_domain_set = set(root_domains or [])

        org_criticality = (await db.execute(
            select(Organization.criticality).where(Organization.id == org_id)
        )).scalar_one_or_none()

        for host, http_data in alive_hosts.items():
            validation = http_data.get("validation") or {}
            discovery = self._serializable_discovery_evidence(
                (discovery_evidence or {}).get(host, {})
            )
            inferred_criticality, criticality_reason = infer_asset_criticality(
                host, is_root_domain=host in root_domain_set, org_criticality=org_criticality,
            )
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
                # Auto-inferred default only — new-asset INSERT path only, see
                # below; a human can always override via PATCH /assets/{id},
                # which stamps labels.criticality_source="manual" so this
                # inference (and the one-off backfill script) never clobbers it.
                "criticality": inferred_criticality,
                "labels": {"criticality_source": "auto", "criticality_reason": criticality_reason},
                "metadata": {
                    "source": "discovery_worker",
                    "discovery": {
                        **discovery,
                        "scan_id": scan_id,
                        "last_observed_at": now.isoformat(),
                    },
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
            asset_ids_by_host[host] = asset_id
            is_new = row[1] and (now - row[1]).seconds < 5
            if is_new:
                new_count += 1

            # Upsert Subdomain details
            dns_info = dns_data.get(host, {})
            tls = http_data.get("tls", {})
            tls_issuer = ", ".join(tls.get("issuer_org") or []) or (tls.get("issuer_cn") or "") if tls else ""

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
                    "discovery_sources": discovery.get("sources", []),
                    "discovery_evidence": discovery.get("evidence", {}),
                },
                "http_status": http_data.get("status_code"),
                "http_title": (http_data.get("title") or "")[:500],
                "http_server": (http_data.get("webserver") or "")[:255],
                "content_length": http_data.get("content_length"),
                "response_hash": (http_data.get("hash") or "")[:64],
                "technologies": [tech["name"] for tech in technologies],
                "cdn_provider": (http_data.get("cdn_name") or "")[:100] or None,
                "tls_info": tls if tls else None,
                "tls_expiry": self._parse_tls_expiry(tls),
                # httpx's real -tls-grab JSON uses flat issuer_org (a list) and
                # tls_version keys, not a nested {"issuer": {"organization": ...}}
                # or bare "version" — those never existed, so tls_issuer/
                # tls_version silently persisted as empty strings forever.
                "tls_issuer": tls_issuer[:500] or None,
                "tls_subject": tls.get("subject_dn", "")[:500] if tls else None,
                "tls_sans": tls.get("subject_an", []) if tls else [],
                "tls_version": (tls.get("tls_version") or "")[:20] or None,
                "redirect_chain": http_data.get("redirect_chain", []),
                "http_headers": http_data.get("headers", {}),
                # This host survived (kept because of real corroborating
                # evidence -- wildcard-suppressed hosts never reach this
                # function at all) but its own DNS answer still matches the
                # domain's wildcard catch-all fingerprint -- worth surfacing
                # to an analyst, previously a dead/never-populated column.
                "is_wildcard": bool(wildcard_fps) and dns_fingerprint(dns_info) in wildcard_fps,
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
        return new_count, asset_ids_by_host

    async def _persist_cloud_assets(
        self,
        db: AsyncSession,
        org_id: str,
        workspace_id: str,
        scan_id: str,
        discoveries: List[Dict[str, Any]],
    ) -> tuple[int, Dict[str, Any]]:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset

        new_count = 0
        asset_ids: Dict[str, Any] = {}
        now = datetime.now(timezone.utc)
        for item in discoveries:
            if item.get("asset_type") != "cloud_bucket":
                continue
            exposure = item.get("status")
            if exposure not in {"public", "private_exists"}:
                continue
            value = item["value"]
            evidence = item.get("evidence") or {}
            validation = {
                "method": "cloud_storage_safe_check",
                "evidence": evidence,
                "validated_at": now.isoformat(),
            }
            asset_values = {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "asset_type": "cloud_bucket",
                "value": value,
                "status": "active",
                "discovery_method": "cloud_storage",
                "confidence": item.get("confidence", 0.7),
                "is_in_scope": True,
                "scope_status": "probable",
                "ownership_confidence": item.get("confidence", 0.7),
                "ownership_reason": "bucket name matched organization/domain candidate pattern",
                "exposure_status": "exposed" if exposure == "public" else "not_exposed",
                "liveness_status": "alive" if exposure == "public" else "dns_only",
                "validation_sources": validation,
                "last_verified_at": now,
                "last_seen": now,
                "metadata": {
                    "source": "discovery_worker",
                    "discovery": {
                        "sources": [item.get("source")],
                        "source_count": 1,
                        "generated": True,
                        "scan_id": scan_id,
                        "last_observed_at": now.isoformat(),
                        "evidence": {item.get("source"): evidence},
                    },
                    "validation": validation,
                },
            }
            stmt = pg_insert(Asset.__table__).values(**asset_values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_asset_org_type_value",
                set_={
                    "last_seen": now,
                    "status": "active",
                    "confidence": asset_values["confidence"],
                    "scope_status": asset_values["scope_status"],
                    "ownership_confidence": asset_values["ownership_confidence"],
                    "ownership_reason": asset_values["ownership_reason"],
                    "exposure_status": asset_values["exposure_status"],
                    "liveness_status": asset_values["liveness_status"],
                    "validation_sources": asset_values["validation_sources"],
                    "last_verified_at": now,
                    "metadata": asset_values["metadata"],
                },
            ).returning(Asset.__table__.c.id, Asset.__table__.c.first_seen)
            result = await db.execute(stmt)
            row = result.fetchone()
            asset_ids[value] = row[0]
            if row[1] and (now - row[1]).seconds < 5:
                new_count += 1
        return new_count, asset_ids

    async def _persist_discovered_assets(
        self,
        db: AsyncSession,
        org_id: str,
        workspace_id: str,
        scan_id: str,
        discovery_evidence: Dict[str, Dict[str, Any]],
        validation_by_host: Dict[str, Dict[str, Any]],
        asset_ids_by_host: Dict[str, Any],
        wildcard_skipped: List[str],
        extra_discoveries: List[Dict[str, Any]],
        extra_asset_ids: Dict[str, Any],
    ) -> None:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import DiscoveredAsset

        now = datetime.now(timezone.utc)
        suppressed = set(wildcard_skipped or [])
        rows: List[Dict[str, Any]] = []
        for host, evidence in discovery_evidence.items():
            validation = validation_by_host.get(host)
            selected = should_scan_validated_asset(validation, require_validation=True)
            status = "suppressed" if host in suppressed else (validation or {}).get("liveness_status", "candidate")
            skip_reason = "wildcard_suppressed" if host in suppressed else (None if selected else validation_skip_reason(validation))
            for source in sorted(evidence.get("sources") or []):
                rows.append({
                    "id": self._uuid4(),
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "scan_id": scan_id,
                    "asset_id": asset_ids_by_host.get(host),
                    "value": host,
                    "asset_type": "subdomain",
                    "source": source,
                    "confidence": (validation or {}).get("confidence", 0.5),
                    "status": status,
                    "selected": selected,
                    "skip_reason": skip_reason,
                    "evidence": json_safe({
                        "source_evidence": (evidence.get("evidence") or {}).get(source, {}),
                        "generated": bool(evidence.get("generated")),
                        "wildcard_suppressed": host in suppressed,
                        "validation": validation or {},
                    }),
                    "last_seen": now,
                    "updated_at": now,
                })
        for item in extra_discoveries:
            rows.append({
                "id": self._uuid4(),
                "org_id": org_id,
                "workspace_id": workspace_id,
                "scan_id": scan_id,
                "asset_id": extra_asset_ids.get(item.get("value")),
                "value": item.get("value"),
                "asset_type": item.get("asset_type"),
                "source": item.get("source"),
                "confidence": item.get("confidence", 0.5),
                "status": item.get("status", "candidate"),
                "selected": bool(item.get("selected", False)),
                "skip_reason": item.get("skip_reason"),
                "evidence": json_safe(item.get("evidence") or {}),
                "last_seen": now,
                "updated_at": now,
            })
        for row in rows:
            if not row.get("value") or not row.get("source") or not row.get("asset_type"):
                continue
            stmt = pg_insert(DiscoveredAsset.__table__).values(**row)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_discovered_asset_scan_source",
                set_={
                    "scan_id": row["scan_id"],
                    "asset_id": row["asset_id"],
                    "confidence": row["confidence"],
                    "status": row["status"],
                    "selected": row["selected"],
                    "skip_reason": row["skip_reason"],
                    "evidence": row["evidence"],
                    "last_seen": now,
                    "updated_at": now,
                },
            )
            await db.execute(stmt)

    def _uuid4(self):
        import uuid
        return uuid.uuid4()

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
        scanner_batches_queued = 0
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

            # Was capped at 4 — raised to match web_crawl_worker.py's endpoint
            # batching fix (nuclei's own per-template timeout plus partial-
            # result recovery on a batch timeout already isolate a slow host
            # without needing tiny batches).
            batch_size = max(1, min(int(config.get("nuclei_batch_size", 25)), 8))
            standard_config = {
                **config,
                "scan_timeout": min(int(config.get("scan_timeout", 900)), 900),
                "nuclei_batch_size": batch_size,
                # Don't strip "info" here — scan_profiles.py now deliberately
                # includes it (exposed-panel/exposure templates are mostly
                # info-tagged), and nuclei_worker.py's
                # _is_low_value_info_finding() already filters fingerprinting
                # noise out of whatever info-severity findings come back.
                "severities": config.get("severities") or ["critical", "high", "medium", "low", "info"],
            }
            limited_config = child_profile_config(
                "limited",
                config,
                {
                    "scan_timeout": min(int(config.get("scan_timeout", 900)), 600),
                    "concurrency": min(int(config.get("concurrency", 4)), 4),
                    "bulk_size": min(int(config.get("bulk_size", 4)), 4),
                    "nuclei_batch_size": 4,
                },
            )
            for target_group, group_config, profile in (
                (standard_targets, standard_config, "standard"),
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

        if "scanner" in modules and config.get("scanner_enabled", True):
            crawl_scan_targets = [
                item.get("url") or item.get("host")
                for item in (candidates.get("crawl_targets") or [])
                if isinstance(item, dict) and (item.get("url") or item.get("host"))
            ]
            scanner_targets = dedupe_preserve_order(
                (candidates.get("web_standard_targets") or [])
                + (candidates.get("web_limited_targets") or [])
                + crawl_scan_targets
                + (subdomains or [])
            )
            scanner_families = ["tls", "dns", "takeover", "cloud", "git_secrets", "eol", "version_cve"]
            async with get_session() as db:
                for family in scanner_families:
                    await update_scan_phase(
                        db,
                        scan_id,
                        {
                            "tls": "tls",
                            "dns": "dns_security",
                            "takeover": "takeover",
                            "cloud": "cloud_exposure",
                            "git_secrets": "git_secrets",
                            "eol": "eol_check",
                            "version_cve": "version_cve",
                        }[family],
                        "queued",
                        targets_total=len(scanner_targets),
                    )
            for family in scanner_families:
                await coord.add_scanner_expected(scan_id)
                scanner_batches_queued += 1
                await queue.publish(
                    routing_key="scan.scanner",
                    message={
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "workspace_id": workspace_id,
                        "family": family,
                        "targets": scanner_targets,
                        "config": config,
                    },
                    priority=4,
                )

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
            total_tasks=1 + port_batches_queued + crawl_batches_queued + nuclei_batches_queued + scanner_batches_queued + int(screenshot_queued),
        )

        await queue.close()
        await coord.close()

        return bool(port_batches_queued or crawl_batches_queued or nuclei_batches_queued or scanner_batches_queued or screenshot_queued)

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

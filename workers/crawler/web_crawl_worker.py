"""
ASM Platform — Web Crawl Worker
Combines active crawling (katana), passive URL discovery (gau), and httpx
validation to persist web endpoints and feed high-signal URLs to nuclei.
"""
import asyncio
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import aiohttp
import structlog
import tldextract
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.services.scan_profiles import child_profile_config
from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.fuzz_wordlist import resolve_fuzz_wordlist
from workers.queue_client import QueueClient
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running, should_process_scan
from workers.scanner.scanner_common import persist_findings, make_finding
from workers.secrets_scan import find_endpoints, find_secrets, find_subdomains
from workers.task_coordinator import TaskCoordinator

log = structlog.get_logger()

API_PATH_RE = re.compile(r"(^|/)(api|v[0-9]+|graphql|rest|rpc)(/|$)", re.I)
AUTH_PATH_RE = re.compile(r"(login|signin|signup|auth|oauth|sso|admin|dashboard|wp-admin)", re.I)
ADMIN_PATH_RE = re.compile(r"(admin|dashboard|manage|console|jenkins|grafana|kibana)", re.I)
UPLOAD_PATH_RE = re.compile(r"(upload|uploads|file|files|media|import)", re.I)
STATIC_PATH_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip|tar|gz)$", re.I)
GRAPHQL_PATH_RE = re.compile(r"graphql", re.I)
SWAGGER_PATH_RE = re.compile(r"(swagger|openapi|api-docs|redoc)", re.I)
HEALTH_PATH_RE = re.compile(r"(health|status|ready|live|metrics)", re.I)
DEBUG_PATH_RE = re.compile(r"(debug|trace|actuator|phpinfo|server-status|\.env|\.git)", re.I)
INTERESTING_PATH_RE = re.compile(
    r"(admin|login|signin|api|graphql|swagger|openapi|upload|backup|config|debug|status|health|\.env|\.git|wp-admin|jenkins)",
    re.I,
)
MAX_ENDPOINT_URL_LENGTH = 2000
MAX_ENDPOINT_HOST_LENGTH = 500
MAX_ENDPOINT_PATH_LENGTH = 1500
MAX_ENDPOINT_SOURCE_LENGTH = 50
MAX_ENDPOINT_CONTENT_TYPE_LENGTH = 255
MAX_ENDPOINT_TITLE_LENGTH = 500
ENDPOINT_NUCLEI_TIMEOUT_CAP = 600


def _tool_path(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    go_path = f"/go/bin/{name}"
    if Path(go_path).exists():
        return go_path
    return None


def _tool_available(name: str) -> bool:
    return _tool_path(name) is not None


def _status_class(status_code: Optional[int]) -> str:
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


def _normalize_url(raw_url: str) -> Optional[str]:
    raw_url = raw_url.strip()
    if not raw_url:
        return None
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"https://{raw_url}"
    parsed = urlsplit(raw_url)
    if not parsed.netloc:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host:
        return None
    netloc = host
    if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = "&".join(f"{k}={v}" for k, v in sorted(query_pairs))
    return urlunsplit((scheme, netloc, path, query, ""))


def _endpoint_flags(url: str) -> Dict[str, bool]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    has_params = bool(parsed.query)
    is_api = bool(API_PATH_RE.search(path))
    is_auth = bool(AUTH_PATH_RE.search(path))
    is_interesting = has_params or is_api or is_auth or bool(INTERESTING_PATH_RE.search(path))
    return {
        "has_params": has_params,
        "is_api": is_api,
        "is_auth": is_auth,
        "is_interesting": is_interesting,
    }


def _endpoint_type(url: str, flags: Dict[str, bool]) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if path == "/" and not parsed.query:
        return "root"
    if GRAPHQL_PATH_RE.search(path):
        return "graphql"
    if SWAGGER_PATH_RE.search(path):
        return "swagger"
    if DEBUG_PATH_RE.search(path):
        return "debug"
    if HEALTH_PATH_RE.search(path):
        return "health"
    if UPLOAD_PATH_RE.search(path):
        return "upload"
    if ADMIN_PATH_RE.search(path):
        return "admin"
    if flags.get("is_auth"):
        return "auth"
    if flags.get("is_api"):
        return "api"
    if parsed.query:
        return "parameterized"
    if STATIC_PATH_RE.search(path):
        return "static"
    return "unknown"


def _endpoint_score(endpoint: Dict[str, Any], flags: Dict[str, bool], endpoint_type: str) -> tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    sources = endpoint.get("sources") or str(endpoint.get("source", "")).split("+")
    status_class = endpoint.get("status_class") or _status_class(endpoint.get("http_status"))
    content_type = (endpoint.get("content_type") or "").lower()

    for key, weight, reason in (
        ("has_params", 25, "query_params"),
        ("is_api", 25, "api_path"),
        ("is_auth", 20, "auth_path"),
        ("is_interesting", 10, "interesting_path"),
    ):
        if flags.get(key):
            score += weight
            reasons.append(reason)

    type_weights = {
        "graphql": (30, "graphql_endpoint"),
        "swagger": (30, "api_documentation"),
        "debug": (35, "debug_endpoint"),
        "admin": (25, "admin_endpoint"),
        "upload": (25, "upload_endpoint"),
        "parameterized": (15, "parameterized_endpoint"),
        "health": (10, "health_endpoint"),
        "root": (5, "root_endpoint"),
    }
    if endpoint_type in type_weights:
        weight, reason = type_weights[endpoint_type]
        score += weight
        reasons.append(reason)

    if "ffuf" in sources:
        score += 20
        reasons.append("fuzz_discovered")
    if "gau" in sources:
        score += 10
        reasons.append("passive_history")
    if len(set(sources)) > 1:
        score += 10
        reasons.append("multiple_sources")
    if status_class in {"ok", "redirect"}:
        score += 10
        reasons.append(status_class)
    elif status_class in {"auth_required", "server_error", "rate_limited"}:
        score += 15
        reasons.append(status_class)
    if "json" in content_type:
        score += 10
        reasons.append("json")

    return min(score, 100), list(dict.fromkeys(reasons))


class WebCrawlWorker(BaseWorker):
    QUEUE = "scan.crawl"
    CONCURRENCY = int(os.getenv("CRAWL_CONCURRENCY", "2"))
    PREFETCH_COUNT = 2

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        targets = message.get("targets", [])
        config = message.get("config", {})

        async with get_session() as db:
            if not await mark_scan_running(db, scan_id, progress_floor=35):
                log.info("crawl_skipped_inactive_scan", scan_id=scan_id)
                await self._mark_crawl_done(scan_id, org_id, workspace_id)
                return
            await update_scan_phase(db, scan_id, "crawl", "running", targets_total=len(targets))

        max_targets = int(config.get("crawl_max_targets", 100))
        targets = targets[:max_targets]
        if not targets:
            log.info("crawl_no_targets", scan_id=scan_id)
            async with get_session() as db:
                await update_scan_phase(db, scan_id, "crawl", "skipped", targets_total=0)
            await self._mark_crawl_done(scan_id, org_id, workspace_id)
            return

        with tempfile.TemporaryDirectory(prefix="asm-crawl-") as tmp:
            tmpdir = Path(tmp)
            katana_urls = await self._run_katana(targets, tmpdir, config)
            gau_urls = await self._run_gau(targets, tmpdir, config)
            ffuf_urls = await self._run_ffuf(targets, tmpdir, config)

            root_urls = [str(target.get("url") or "").strip() for target in targets if target.get("url")]
            source_by_url = self._build_source_map(root_urls, katana_urls, gau_urls, ffuf_urls)
            normalized = list(source_by_url.keys())
            max_total = int(config.get("crawl_max_total_urls", 2000))
            normalized = normalized[:max_total]
            validated = await self._validate_urls(normalized, tmpdir, config)
            for endpoint in validated:
                sources = source_by_url.get(endpoint["url"], [endpoint.get("source", "crawl")])
                endpoint["sources"] = sources
                endpoint["source"] = "+".join(sources)

            root_domains = self._root_domains_for_urls(root_urls)
            js_result = await self._analyze_js_endpoints(validated, root_domains, org_id, workspace_id, config)
            if js_result["extracted_endpoints"]:
                js_validated = await self._validate_urls(js_result["extracted_endpoints"], tmpdir, config)
                for endpoint in js_validated:
                    endpoint["sources"] = ["js_extracted"]
                    endpoint["source"] = "js_extracted"
                validated.extend(js_validated)

            api_spec_result = await self._analyze_api_specs(validated, org_id, workspace_id, config)
            if api_spec_result["extracted_endpoints"]:
                api_validated = await self._validate_urls(api_spec_result["extracted_endpoints"], tmpdir, config)
                for endpoint in api_validated:
                    endpoint["sources"] = ["api_spec_extracted"]
                    endpoint["source"] = "api_spec_extracted"
                validated.extend(api_validated)

            graphql_result = await self._analyze_graphql_endpoints(validated, org_id, workspace_id, config)

        async with get_session() as db:
            if not await should_process_scan(db, scan_id):
                log.info("crawl_results_skipped_inactive_scan", scan_id=scan_id)
                await self._mark_crawl_done(scan_id, org_id, workspace_id)
                return
            persisted, selected_records, endpoint_summary = await self._persist_endpoints(
                db,
                org_id,
                workspace_id,
                validated,
                max_selected=int(config.get("crawl_nuclei_max_targets", 200)),
            )
            if js_result["findings"]:
                await persist_findings(db, scan_id, js_result["findings"])
            if api_spec_result["findings"]:
                await persist_findings(db, scan_id, api_spec_result["findings"])
            if graphql_result["findings"]:
                await persist_findings(db, scan_id, graphql_result["findings"])
            await record_target_selections(
                db,
                scan_id=scan_id,
                phase="crawl",
                targets=selected_records,
            )
            await self._update_progress(db, scan_id, persisted)
            await update_scan_phase(
                db,
                scan_id,
                "crawl",
                "completed",
                targets_total=len(targets),
                endpoints=persisted,
                selected_for_nuclei=len(selected_records),
                js_files_analyzed=js_result["js_files_analyzed"],
                js_extracted_candidate_subdomains=js_result["extracted_subdomains"],
                api_specs_analyzed=api_spec_result["specs_analyzed"],
                api_spec_extracted_endpoints=len(api_spec_result["extracted_endpoints"]),
                graphql_endpoints_tested=graphql_result["endpoints_tested"],
                **endpoint_summary,
            )

        selected = [item["target"] for item in selected_records]
        await self._publish_selected_nuclei(scan_id, org_id, workspace_id, selected, config)
        await self._mark_crawl_done(scan_id, org_id, workspace_id)
        log.info("crawl_completed", scan_id=scan_id, endpoints=persisted, selected=len(selected))

    async def _run_katana(self, targets: List[Dict[str, Any]], tmpdir: Path, config: Dict[str, Any]) -> List[str]:
        katana_path = _tool_path("katana")
        if not katana_path:
            log.info("katana_unavailable")
            return []
        urls = [t["url"] for t in targets if t.get("url")]
        if not urls:
            return []
        input_file = tmpdir / "katana_targets.txt"
        output_file = tmpdir / "katana_output.txt"
        input_file.write_text("\n".join(urls))
        cmd = [
            katana_path,
            "-list", str(input_file),
            "-o", str(output_file),
            "-silent",
            "-depth", str(int(config.get("crawl_depth", 1))),
            "-rate-limit", str(int(config.get("crawl_rate", 50))),
            "-host-rate-limit", str(int(config.get("crawl_host_rate_limit", 20))),
            "-timeout", str(int(config.get("crawl_timeout", 10))),
            "-retries", "1",
            "-concurrency", str(int(config.get("crawl_concurrency", 10))),
            "-parallelism", str(int(config.get("crawl_parallelism", 5))),
            "-fs", str(config.get("katana_field_scope", "fqdn")),
            "-mdp", str(int(config.get("katana_max_domain_pages", 200))),
            "-disable-update-check",
            "-jc",
        ]
        if config.get("katana_known_files", True) and int(config.get("crawl_depth", 1)) >= 3:
            cmd.extend(["-kf", "all"])
        await self._run_command(cmd, timeout=int(config.get("katana_timeout", 180)), label="katana")
        if not output_file.exists():
            return []
        return [line.strip() for line in output_file.read_text().splitlines() if line.strip().startswith("http")]

    async def _run_gau(self, targets: List[Dict[str, Any]], tmpdir: Path, config: Dict[str, Any]) -> List[str]:
        gau_path = _tool_path("gau")
        if not config.get("crawl_use_gau", True) or not gau_path:
            log.info("gau_unavailable_or_disabled")
            return []
        hosts = sorted({t["host"] for t in targets if t.get("host")})
        max_hosts = int(config.get("gau_max_hosts", 50))
        gau_config = config.get("gau_config_path") or os.getenv("GAU_CONFIG_PATH", "/app/workers/config/gau.toml")
        timeout = int(config.get("gau_timeout", 60))
        semaphore = asyncio.Semaphore(max(1, min(int(config.get("gau_concurrency", 5)), 10)))

        async def run_host(host: str) -> List[str]:
            output_file = tmpdir / f"gau_{abs(hash(host))}.txt"
            cmd = [gau_path, "--config", gau_config, "--subs", "--threads", "5", host]
            async with semaphore:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    output_file.write_bytes(stdout)
                except asyncio.TimeoutError:
                    log.warning("gau_timeout", host=host)
                    return []
                except Exception as exc:
                    log.warning("gau_error", host=host, error=str(exc))
                    return []
            return [line.strip() for line in output_file.read_text().splitlines() if line.strip().startswith("http")]

        batches = await asyncio.gather(*(run_host(host) for host in hosts[:max_hosts]))
        urls: List[str] = []
        for batch in batches:
            urls.extend(batch)
        return urls

    async def _run_ffuf(self, targets: List[Dict[str, Any]], tmpdir: Path, config: Dict[str, Any]) -> List[str]:
        ffuf_path = _tool_path("ffuf")
        if not config.get("fuzz", False) or not ffuf_path:
            log.info("ffuf_unavailable_or_disabled")
            return []

        urls = [t["url"].rstrip("/") for t in targets if t.get("url")]
        urls = urls[: int(config.get("fuzz_max_targets", 25))]
        if not urls:
            return []

        wordlist = self._resolve_fuzz_wordlist(tmpdir, config)
        rate = int(config.get("fuzz_rate", 50))
        timeout = int(config.get("fuzz_timeout", 10))
        max_time = int(config.get("fuzz_max_time", 120))
        threads = int(config.get("fuzz_threads", 20))
        recursion_depth = int(config.get("fuzz_recursion_depth", 0))
        extensions = str(config.get("fuzz_extensions", "") or "")
        semaphore = asyncio.Semaphore(max(1, min(int(config.get("fuzz_concurrency", 3)), 10)))

        async def run_target(url: str) -> List[str]:
            output_file = tmpdir / f"ffuf_{abs(hash(url))}.json"
            cmd = [
                ffuf_path,
                "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-o", str(output_file),
                "-of", "json",
                "-mc", str(config.get("fuzz_match_codes", "200-299,301,302,307,308,401,403,405,500")),
                "-fc", str(config.get("fuzz_filter_codes", "404")),
                "-fs", "0",
                "-t", str(threads),
                "-rate", str(rate),
                "-timeout", str(timeout),
                "-maxtime", str(max_time),
                "-noninteractive",
                "-ac",
                "-ach",
            ]
            # "Depth" here means two independent things ffuf supports natively:
            # descending into discovered directories (-recursion, bounded by
            # -recursion-depth so it can't run away) and widening each
            # wordlist entry with common sensitive-file suffixes (-e) — both
            # off by default (0 / "") so this doesn't change behavior for any
            # profile that hasn't opted in via scan_profiles.py.
            if recursion_depth > 0:
                cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
            if extensions:
                cmd.extend(["-e", extensions])
            async with semaphore:
                await self._run_command(cmd, timeout=max_time + 60, label="ffuf")

            discovered: List[str] = []
            if not output_file.exists():
                return discovered
            try:
                data = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                return discovered
            for result in data.get("results", []):
                discovered_url = result.get("url", "")
                if discovered_url.startswith("http"):
                    discovered.append(discovered_url)
            return discovered

        batches = await asyncio.gather(*(run_target(url) for url in urls))
        discovered: List[str] = []
        for batch in batches:
            discovered.extend(batch)
        log.info("ffuf_fuzz_completed", targets=len(urls), discovered=len(discovered))
        return discovered

    def _resolve_fuzz_wordlist(self, tmpdir: Path, config: Dict[str, Any]) -> str:
        return resolve_fuzz_wordlist(tmpdir, config)

    async def _validate_urls(self, urls: List[str], tmpdir: Path, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not urls:
            return []
        httpx_path = _tool_path("httpx")
        if not httpx_path:
            return [{"url": url, "source": "unvalidated"} for url in urls]
        input_file = tmpdir / "httpx_urls.txt"
        output_file = tmpdir / "httpx_urls.json"
        input_file.write_text("\n".join(urls))
        cmd = [
            httpx_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-follow-redirects",
            "-max-redirects", "3",
            "-status-code",
            "-title",
            "-content-type",
            "-content-length",
            "-location",
            "-method",
            "-web-server",
            "-response-time",
            "-timeout", str(int(config.get("crawl_httpx_timeout", 10))),
            "-t", str(int(config.get("crawl_httpx_threads", 50))),
            "-rl", str(int(config.get("crawl_httpx_rate_limit", 150))),
            "-no-color",
        ]
        await self._run_command(cmd, timeout=int(config.get("crawl_validate_timeout", 240)), label="httpx_crawl")
        results: List[Dict[str, Any]] = []
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("failed"):
                    continue
                url = _normalize_url(row.get("url", ""))
                if not url:
                    continue
                status = row.get("status_code")
                results.append({
                    "url": url,
                    "http_status": status,
                    "status_class": _status_class(status),
                    "content_type": row.get("content_type", ""),
                    "content_length": row.get("content_length"),
                    "title": row.get("title", ""),
                    "location": row.get("location", ""),
                    "method": row.get("method", ""),
                    "webserver": row.get("webserver", ""),
                    "response_time": row.get("response_time", ""),
                    "source": "validated",
                })
        return results

    async def _run_command(self, cmd: List[str], timeout: int, label: str) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode not in (0, None):
                log.warning(f"{label}_nonzero", stderr=stderr.decode(errors="ignore")[:500])
        except asyncio.TimeoutError:
            log.warning(f"{label}_timeout")
        except Exception as exc:
            log.warning(f"{label}_error", error=str(exc))

    def _dedupe(self, urls: List[str]) -> List[str]:
        seen = set()
        result = []
        for raw in urls:
            normalized = _normalize_url(raw)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(normalized)
        return result

    def _build_source_map(
        self,
        root_urls: List[str],
        katana_urls: List[str],
        gau_urls: List[str],
        ffuf_urls: List[str],
    ) -> Dict[str, List[str]]:
        sources: Dict[str, List[str]] = {}
        for raw in root_urls:
            normalized = _normalize_url(raw)
            if not normalized:
                continue
            sources.setdefault(normalized, [])
            if "root_probe" not in sources[normalized]:
                sources[normalized].append("root_probe")
        for raw in katana_urls:
            normalized = _normalize_url(raw)
            if normalized:
                sources.setdefault(normalized, [])
                if "katana" not in sources[normalized]:
                    sources[normalized].append("katana")
        for raw in gau_urls:
            normalized = _normalize_url(raw)
            if not normalized:
                continue
            sources.setdefault(normalized, [])
            if "gau" not in sources[normalized]:
                sources[normalized].append("gau")
        for raw in ffuf_urls:
            normalized = _normalize_url(raw)
            if not normalized:
                continue
            sources.setdefault(normalized, [])
            if "ffuf" not in sources[normalized]:
                sources[normalized].append("ffuf")
        return sources

    def _root_domains_for_urls(self, urls: List[str]) -> Set[str]:
        roots: Set[str] = set()
        for url in urls:
            host = urlsplit(url if "://" in url else f"//{url}").hostname or ""
            if not host:
                continue
            ext = tldextract.extract(host)
            root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
            roots.add(root)
        return roots

    async def _analyze_graphql_endpoints(
        self,
        validated: List[Dict[str, Any]],
        org_id: str,
        workspace_id: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """GraphQL introspection query test against already-crawled
        graphql-shaped URLs. Nuclei has no template for this — checked the
        real nuclei-templates checkout: 39 graphql-related templates exist
        (playground/voyager/apollo-sandbox exposure, per-implementation
        fingerprinting), but none send an actual __schema introspection
        query, so this is genuinely new coverage. Runs in this same worker
        (not as a separate scanner-family dispatch) deliberately: a
        discovery-phase scanner-family message and the crawl worker's own
        endpoint persistence are two independently-scheduled, concurrently-
        published queue consumers with no ordering guarantee between them —
        querying WebEndpoint rows for endpoint_type="graphql" from a
        different worker would race against this worker's own not-yet-
        committed persistence. Using the endpoint_type this worker just
        computed in memory for the same crawl pass avoids that entirely."""
        empty = {"findings": [], "endpoints_tested": 0}
        if not config.get("graphql_introspection_enabled", True):
            return empty

        max_targets = int(config.get("graphql_max_targets", 20))
        graphql_urls: List[str] = []
        for entry in validated:
            url = entry.get("url", "")
            status_class = entry.get("status_class") or _status_class(entry.get("http_status"))
            if status_class not in {"ok", "redirect"}:
                continue
            if not GRAPHQL_PATH_RE.search(urlsplit(url).path):
                continue
            graphql_urls.append(url)
            if len(graphql_urls) >= max_targets:
                break

        if not graphql_urls:
            return empty

        introspection_query = {"query": "query IntrospectionQuery { __schema { types { name } } }"}
        findings: List[Dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=int(config.get("graphql_timeout", 10)))

        async def probe(session: aiohttp.ClientSession, url: str) -> None:
            try:
                async with session.post(
                    url, json=introspection_query,
                    headers={"Content-Type": "application/json"}, ssl=False,
                ) as response:
                    body = await response.json(content_type=None)
            except Exception:
                return

            types = None
            if isinstance(body, dict):
                schema = (body.get("data") or {}).get("__schema") if isinstance(body.get("data"), dict) else None
                types = schema.get("types") if isinstance(schema, dict) else None
            if not (isinstance(types, list) and types):
                return

            type_names = [t.get("name") for t in types if isinstance(t, dict) and t.get("name")]
            findings.append(make_finding(
                org_id=org_id,
                workspace_id=workspace_id,
                scanner="graphql_scanner",
                check_id="graphql_introspection_enabled",
                target=url,
                title="GraphQL introspection enabled",
                severity="medium",
                category="exposed_api",
                description="The GraphQL endpoint responds to a standard introspection query, exposing "
                            "the full schema (types, fields, mutations) to unauthenticated clients — an "
                            "attacker-friendly map of the entire API surface.",
                evidence=f"{url} returned {len(types)} schema types in response to a __schema "
                         f"introspection query.",
                proof={"type_count": len(types), "sample_types": type_names[:15]},
                remediation="Disable introspection in production GraphQL deployments, or require "
                            "authentication before allowing introspection queries.",
            ))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            await asyncio.gather(*(probe(session, url) for url in graphql_urls))

        return {"findings": findings, "endpoints_tested": len(graphql_urls)}

    async def _analyze_api_specs(
        self,
        validated: List[Dict[str, Any]],
        org_id: str,
        workspace_id: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fetch already-crawled Swagger/OpenAPI-shaped URLs and, if the
        response is a genuine spec document (verified via real JSON structure
        — a "swagger"/"openapi" or non-empty "paths" key — not just a URL
        that happens to match /swagger|openapi/: a real target returned a
        generic app-level JSON error at exactly that path shape during manual
        verification, so URL pattern alone isn't proof), extract every
        documented route as a new crawl candidate. API routes are almost never
        linked from HTML, so a link-following crawler structurally can't find
        them any other way — a real spec enumerates them directly. Extracted
        endpoints flow through the same _validate_urls -> _persist_endpoints
        -> _publish_selected_nuclei path as every other crawler-discovered
        endpoint (tagged source="api_spec_extracted"), mirroring
        _analyze_js_endpoints's own established pattern below."""
        empty = {"findings": [], "extracted_endpoints": [], "specs_analyzed": 0}
        if not config.get("api_spec_analysis_enabled", True):
            return empty

        max_specs = int(config.get("api_spec_analysis_max_specs", 10))
        spec_urls: List[str] = []
        for entry in validated:
            url = entry.get("url", "")
            status_class = entry.get("status_class") or _status_class(entry.get("http_status"))
            if status_class not in {"ok", "redirect"}:
                continue
            if not SWAGGER_PATH_RE.search(urlsplit(url).path):
                continue
            spec_urls.append(url)
            if len(spec_urls) >= max_specs:
                break

        if not spec_urls:
            return empty

        findings: List[Dict[str, Any]] = []
        extracted_endpoints: List[str] = []
        max_body_bytes = int(config.get("api_spec_analysis_max_bytes", 1_000_000))
        semaphore = asyncio.Semaphore(int(config.get("api_spec_analysis_concurrency", 5)))
        timeout = aiohttp.ClientTimeout(total=int(config.get("api_spec_analysis_timeout", 8)))

        async def analyze_one(session: aiohttp.ClientSession, url: str) -> None:
            async with semaphore:
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        body = await response.content.read(max_body_bytes)
                except Exception:
                    return

            try:
                spec = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return
            if not isinstance(spec, dict):
                return
            paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
            is_spec = "swagger" in spec or "openapi" in spec or bool(paths)
            if not is_spec:
                return

            base = urlsplit(url)
            base_path = spec.get("basePath") if isinstance(spec.get("basePath"), str) else ""
            for route in list(paths.keys())[:200]:
                if not isinstance(route, str) or not route.startswith("/"):
                    continue
                full_path = f"{base_path.rstrip('/')}{route}" if base_path else route
                extracted_endpoints.append(urlunsplit((base.scheme, base.netloc, full_path, "", "")))

            findings.append(make_finding(
                org_id=org_id,
                workspace_id=workspace_id,
                scanner="api_spec_analysis",
                check_id="exposed_api_specification",
                target=url,
                title="Publicly accessible API specification",
                severity="low",
                category="exposed_api",
                description="A machine-readable API specification (Swagger/OpenAPI) is publicly "
                            "accessible, enumerating the application's full API surface including "
                            "routes not otherwise discoverable by crawling.",
                evidence=f"{url} returned a valid OpenAPI/Swagger document listing {len(paths)} route(s).",
                proof={"spec_url": url, "route_count": len(paths), "routes_sample": list(paths.keys())[:20]},
                remediation="Restrict access to API documentation in production, or confirm every "
                            "listed route is intentionally public.",
            ))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            await asyncio.gather(*(analyze_one(session, url) for url in spec_urls))

        return {
            "findings": findings,
            "extracted_endpoints": list(dict.fromkeys(extracted_endpoints))[:200],
            "specs_analyzed": len(spec_urls),
        }

    async def _analyze_js_endpoints(
        self,
        validated: List[Dict[str, Any]],
        root_domains: Set[str],
        org_id: str,
        workspace_id: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Fetch same-root .js files discovered by the crawl and extract hidden
        endpoints/secrets/subdomains. Extracted endpoints flow through the same
        _validate_urls -> _persist_endpoints -> _publish_selected_nuclei path as
        every other crawler-discovered endpoint (tagged source="js_extracted").
        Extracted subdomains are surfaced as an observability field only (crawl
        phase_status), not auto-created as Assets — a string literal inside a
        .js file hasn't gone through the scope/ownership validation gate every
        other asset-creation path in this codebase goes through, unlike a
        confirmed DNS resolution or a brand-derived bucket-name hit."""
        empty = {
            "findings": [],
            "extracted_endpoints": [],
            "extracted_subdomains": [],
            "js_files_analyzed": 0,
        }
        if not config.get("js_analysis_enabled", False):
            return empty

        max_files = int(config.get("js_analysis_max_files", 50))
        js_urls: List[str] = []
        for entry in validated:
            url = entry.get("url", "")
            content_type = str(entry.get("content_type") or "").lower()
            path = urlsplit(url).path.lower()
            if not (path.endswith(".js") or "javascript" in content_type):
                continue
            host = urlsplit(url).hostname or ""
            ext = tldextract.extract(host)
            root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
            if root_domains and root not in root_domains:
                continue
            js_urls.append(url)
            if len(js_urls) >= max_files:
                break

        if not js_urls:
            return empty

        findings: List[Dict[str, Any]] = []
        extracted_endpoints: List[str] = []
        extracted_subdomains: Set[str] = set()
        max_body_bytes = int(config.get("js_analysis_max_bytes", 512_000))
        semaphore = asyncio.Semaphore(int(config.get("js_analysis_concurrency", 5)))
        timeout = aiohttp.ClientTimeout(total=int(config.get("js_analysis_timeout", 8)))

        async def analyze_one(session: aiohttp.ClientSession, url: str) -> None:
            async with semaphore:
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        body = await response.content.read(max_body_bytes)
                        text = body.decode(errors="ignore")
                except Exception:
                    return

            for endpoint in find_endpoints(text, url):
                extracted_endpoints.append(endpoint)
            for root in root_domains:
                extracted_subdomains.update(find_subdomains(text, root))
            for secret in find_secrets(text):
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="js_analysis",
                    check_id=f"credential_exposure_{secret['type']}",
                    target=url,
                    title=f"Credential exposure in JavaScript ({secret['type']})",
                    severity="critical",
                    category="credential_exposure",
                    description="A secret-like value was found embedded in a crawled JavaScript file. "
                                "The value is masked below and never stored in full.",
                    evidence=f"{url} matched a {secret['type']} pattern (masked): {secret['masked']}",
                    proof={"source_url": url, "secret_type": secret["type"], "secret_masked": secret["masked"], "secret_sha256": secret["sha256"]},
                    remediation="Remove hardcoded credentials from client-side JavaScript and rotate "
                                "the exposed value immediately.",
                ))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            await asyncio.gather(*(analyze_one(session, url) for url in js_urls))

        return {
            "findings": findings,
            "extracted_endpoints": list(dict.fromkeys(extracted_endpoints))[:200],
            "extracted_subdomains": sorted(extracted_subdomains)[:100],
            "js_files_analyzed": len(js_urls),
        }

    async def _persist_endpoints(
        self,
        db,
        org_id: str,
        workspace_id: str,
        endpoints: List[Dict[str, Any]],
        max_selected: int,
    ) -> tuple[int, List[Dict[str, Any]], Dict[str, Any]]:
        from workers.db_models import Asset, WebEndpoint

        if not endpoints:
            return 0, [], {}

        hosts = sorted({urlsplit(e["url"]).hostname for e in endpoints if urlsplit(e["url"]).hostname})
        asset_rows = (await db.execute(
            select(Asset.id, Asset.value).where(
                Asset.org_id == org_id,
                Asset.asset_type == "subdomain",
                Asset.value.in_(hosts),
            )
        )).all()
        asset_by_host = {value: asset_id for asset_id, value in asset_rows}
        now = datetime.now(timezone.utc)
        prepared: List[Dict[str, Any]] = []
        eligible: List[tuple[int, str, int]] = []
        persisted = 0
        skipped_oversized = 0

        for index, endpoint in enumerate(endpoints):
            url = endpoint["url"]
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            if len(url) > MAX_ENDPOINT_URL_LENGTH or len(host) > MAX_ENDPOINT_HOST_LENGTH:
                skipped_oversized += 1
                continue
            asset_id = asset_by_host.get(host)
            if not asset_id:
                continue
            flags = _endpoint_flags(url)
            endpoint_type = _endpoint_type(url, flags)
            score, score_reasons = _endpoint_score(endpoint, flags, endpoint_type)
            sources = endpoint.get("sources") or [s for s in str(endpoint.get("source", "crawl")).split("+") if s]
            sources = list(dict.fromkeys(sources or ["crawl"]))
            status_class = endpoint.get("status_class") or _status_class(endpoint.get("http_status"))
            values = {
                "asset_id": asset_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
                "url": url,
                "host": host,
                "path": (parsed.path or "/")[:MAX_ENDPOINT_PATH_LENGTH],
                "source": "+".join(sources)[:MAX_ENDPOINT_SOURCE_LENGTH],
                "http_status": endpoint.get("http_status"),
                "status_class": status_class,
                "content_type": (endpoint.get("content_type") or "")[:MAX_ENDPOINT_CONTENT_TYPE_LENGTH] or None,
                "content_length": endpoint.get("content_length"),
                "title": (endpoint.get("title") or "")[:MAX_ENDPOINT_TITLE_LENGTH] or None,
                **flags,
                "score": score,
                "score_reasons": score_reasons,
                "endpoint_type": endpoint_type,
                "selected_for_scan": False,
                "selected_reason": None,
                "scan_status": "not_scanned",
                "sources": sources,
                "source_count": len(sources),
                "metadata": {"query": parsed.query},
                "last_seen": now,
            }
            prepared.append({"values": values, "asset_id": asset_id})
            if score >= 25 and status_class in {"ok", "redirect", "auth_required", "server_error", "rate_limited"}:
                eligible.append((score, url, len(prepared) - 1))

        selected_indices = {
            index
            for _, _, index in sorted(eligible, key=lambda item: (-item[0], item[1]))[: max(0, max_selected)]
        }
        selected: List[tuple[int, str, Dict[str, Any]]] = []
        endpoint_type_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}

        for index, item in enumerate(prepared):
            values = item["values"]
            asset_id = item["asset_id"]
            endpoint_type_counts[values["endpoint_type"]] = endpoint_type_counts.get(values["endpoint_type"], 0) + 1
            for source in values["sources"]:
                source_counts[source] = source_counts.get(source, 0) + 1
            if index in selected_indices:
                values["selected_for_scan"] = True
                values["selected_reason"] = "endpoint_score"
                values["scan_status"] = "queued"
            stmt = pg_insert(WebEndpoint.__table__).values(**values, first_seen=now)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_web_endpoint_org_url",
                set_={k: v for k, v in values.items() if k not in {"asset_id", "org_id", "workspace_id", "url"}},
            )
            await db.execute(stmt)
            persisted += 1
            if values["selected_for_scan"]:
                selected.append((
                    values["score"],
                    values["url"],
                    {
                        "target": values["url"],
                        "target_type": "url",
                        "profile": "endpoint",
                        "asset_id": asset_id,
                        "selected": True,
                        "score": values["score"],
                        "reasons": values["score_reasons"],
                        "metadata": {
                            "downstream_phase": "nuclei",
                            "source": values["source"],
                            "sources": values["sources"],
                            "endpoint_type": values["endpoint_type"],
                            "status_class": values["status_class"],
                            "http_status": values["http_status"],
                            "asset_id": str(asset_id),
                        },
                    },
                ))
        await db.commit()
        if skipped_oversized:
            log.info(
                "crawl_endpoint_skipped_oversized",
                org_id=org_id,
                workspace_id=workspace_id,
                skipped=skipped_oversized,
                max_url_length=MAX_ENDPOINT_URL_LENGTH,
            )
        selected.sort(key=lambda item: (-item[0], item[1]))
        summary = {
            "endpoint_types": endpoint_type_counts,
            "endpoint_sources": source_counts,
            "endpoint_selection_cap": max_selected,
            "endpoint_selection_threshold": 25,
            "endpoint_candidates_eligible": len(eligible),
        }
        return persisted, [item for _, _, item in selected], summary

    async def _update_progress(self, db, scan_id: str, endpoints_found: int) -> None:
        from workers.db_models import Scan
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(progress_pct=func.greatest(Scan.progress_pct, 45))
        )
        await db.commit()

    async def _publish_selected_nuclei(self, scan_id: str, org_id: str, workspace_id: str, targets: List[str], config: Dict[str, Any]) -> None:
        if not targets:
            return
        coord = TaskCoordinator()
        queue = QueueClient()
        await queue.connect()
        # Was hardcoded to 1 (one nuclei subprocess per URL) to isolate a slow
        # endpoint from blocking the rest of a batch — but nuclei_worker.py's
        # own per-template timeout (-timeout, capped at 6-8s) already isolates
        # at that granularity, and a batch timeout still recovers whatever
        # partial results were written before the kill (see
        # nuclei_worker.py::_run_nuclei's TimeoutError handler). Batch size 1
        # meant paying nuclei's template-load/init overhead once per URL
        # instead of once per batch — the dominant cost of a full scan.
        batch_size = max(1, min(int(config.get("crawl_nuclei_batch_size", 25)), 10))
        nuclei_config = child_profile_config(
            "endpoint",
            config,
            {
                "scan_timeout": min(
                    int(config.get("crawl_nuclei_scan_timeout", min(int(config.get("scan_timeout", 900)), ENDPOINT_NUCLEI_TIMEOUT_CAP))),
                    ENDPOINT_NUCLEI_TIMEOUT_CAP,
                ),
                "template_timeout": min(int(config.get("template_timeout", 6)), 6),
                "concurrency": min(int(config.get("concurrency", 4)), 4),
                "bulk_size": min(int(config.get("bulk_size", 4)), 4),
                "nuclei_batch_size": batch_size,
                # Don't hardcode severities here — let it inherit from the
                # "endpoint" profile (scan_profiles.py), which now includes
                # "info" (exposed-panel/exposure templates are ~info-tagged).
            },
        )
        for i in range(0, len(targets), batch_size):
            await coord.add_nuclei_expected(scan_id)
            await queue.publish(
                routing_key="scan.nuclei",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "targets": targets[i:i + batch_size],
                    "config": nuclei_config,
                },
            )
        batches = (len(targets) + batch_size - 1) // batch_size
        async with get_session() as db:
            await self._add_scan_tasks(db, scan_id, batches)
            await update_scan_phase(
                db,
                scan_id,
                "nuclei",
                "running",
                source="crawl",
                endpoint_batches_queued=batches,
                endpoint_targets_queued=len(targets),
            )
        await coord.close()
        await queue.close()

    async def _add_scan_tasks(self, db, scan_id: str, count: int) -> None:
        if count <= 0:
            return
        from workers.db_models import Scan

        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(total_tasks=Scan.total_tasks + count)
        )
        await db.commit()

    async def _mark_crawl_done(self, scan_id: str, org_id: str, workspace_id: str) -> None:
        coord = TaskCoordinator()
        await coord.incr_crawl_done(scan_id)
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
    worker = WebCrawlWorker()
    asyncio.run(worker.run())

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
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import structlog
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
from workers.scan_state import mark_scan_running, should_process_scan
from workers.task_coordinator import TaskCoordinator

log = structlog.get_logger()

API_PATH_RE = re.compile(r"(^|/)(api|v[0-9]+|graphql|rest|rpc)(/|$)", re.I)
AUTH_PATH_RE = re.compile(r"(login|signin|signup|auth|oauth|sso|admin|dashboard|wp-admin)", re.I)
INTERESTING_PATH_RE = re.compile(
    r"(admin|login|signin|api|graphql|swagger|openapi|upload|backup|config|debug|status|health|\.env|\.git|wp-admin|jenkins)",
    re.I,
)


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

        max_targets = int(config.get("crawl_max_targets", 100))
        targets = targets[:max_targets]
        if not targets:
            log.info("crawl_no_targets", scan_id=scan_id)
            await self._mark_crawl_done(scan_id, org_id, workspace_id)
            return

        with tempfile.TemporaryDirectory(prefix="asm-crawl-") as tmp:
            tmpdir = Path(tmp)
            katana_urls = await self._run_katana(targets, tmpdir, config)
            gau_urls = await self._run_gau(targets, tmpdir, config)

            source_by_url = self._build_source_map(katana_urls, gau_urls)
            normalized = list(source_by_url.keys())
            max_total = int(config.get("crawl_max_total_urls", 2000))
            normalized = normalized[:max_total]
            validated = await self._validate_urls(normalized, tmpdir, config)
            for endpoint in validated:
                endpoint["source"] = source_by_url.get(endpoint["url"], endpoint.get("source", "crawl"))

        async with get_session() as db:
            if not await should_process_scan(db, scan_id):
                log.info("crawl_results_skipped_inactive_scan", scan_id=scan_id)
                await self._mark_crawl_done(scan_id, org_id, workspace_id)
                return
            persisted, selected = await self._persist_endpoints(
                db, org_id, workspace_id, validated
            )
            await self._update_progress(db, scan_id, persisted)

        selected = selected[: int(config.get("crawl_nuclei_max_targets", 200))]
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
            "-timeout", str(int(config.get("crawl_timeout", 10))),
            "-retries", "1",
            "-concurrency", str(int(config.get("crawl_concurrency", 10))),
            "-disable-update-check",
            "-jc",
        ]
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
        urls: List[str] = []
        for host in hosts[:max_hosts]:
            output_file = tmpdir / f"gau_{abs(hash(host))}.txt"
            gau_config = config.get("gau_config_path") or os.getenv("GAU_CONFIG_PATH", "/app/workers/config/gau.toml")
            cmd = [gau_path, "--config", gau_config, "--subs", "--threads", "5", host]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=int(config.get("gau_timeout", 60)))
                output_file.write_bytes(stdout)
            except asyncio.TimeoutError:
                log.warning("gau_timeout", host=host)
                continue
            except Exception as exc:
                log.warning("gau_error", host=host, error=str(exc))
                continue
            urls.extend([line.strip() for line in output_file.read_text().splitlines() if line.strip().startswith("http")])
        return urls

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
            "-timeout", str(int(config.get("crawl_httpx_timeout", 10))),
            "-t", str(int(config.get("crawl_httpx_threads", 50))),
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

    def _build_source_map(self, katana_urls: List[str], gau_urls: List[str]) -> Dict[str, str]:
        sources: Dict[str, str] = {}
        for raw in katana_urls:
            normalized = _normalize_url(raw)
            if normalized:
                sources.setdefault(normalized, "katana")
        for raw in gau_urls:
            normalized = _normalize_url(raw)
            if not normalized:
                continue
            if sources.get(normalized) == "katana":
                sources[normalized] = "katana+gau"
            else:
                sources.setdefault(normalized, "gau")
        return sources

    async def _persist_endpoints(self, db, org_id: str, workspace_id: str, endpoints: List[Dict[str, Any]]) -> tuple[int, List[str]]:
        from workers.db_models import Asset, WebEndpoint

        if not endpoints:
            return 0, []

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
        selected = []
        persisted = 0

        for endpoint in endpoints:
            url = endpoint["url"]
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            asset_id = asset_by_host.get(host)
            if not asset_id:
                continue
            flags = _endpoint_flags(url)
            values = {
                "asset_id": asset_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
                "url": url,
                "host": host,
                "path": parsed.path or "/",
                "source": endpoint.get("source", "crawl")[:50],
                "http_status": endpoint.get("http_status"),
                "status_class": endpoint.get("status_class") or _status_class(endpoint.get("http_status")),
                "content_type": (endpoint.get("content_type") or "")[:255] or None,
                "content_length": endpoint.get("content_length"),
                "title": (endpoint.get("title") or "")[:500] or None,
                **flags,
                "metadata": {"query": parsed.query},
                "last_seen": now,
            }
            stmt = pg_insert(WebEndpoint.__table__).values(**values, first_seen=now)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_web_endpoint_org_url",
                set_={k: v for k, v in values.items() if k not in {"asset_id", "org_id", "workspace_id", "url"}},
            )
            await db.execute(stmt)
            persisted += 1
            if flags["is_interesting"] and values["status_class"] in {"ok", "redirect", "auth_required", "server_error"}:
                selected.append(url)
        await db.commit()
        return persisted, selected

    async def _update_progress(self, db, scan_id: str, endpoints_found: int) -> None:
        from workers.db_models import Scan
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(progress_pct=45)
        )
        await db.commit()

    async def _publish_selected_nuclei(self, scan_id: str, org_id: str, workspace_id: str, targets: List[str], config: Dict[str, Any]) -> None:
        if not targets:
            return
        coord = TaskCoordinator()
        queue = QueueClient()
        await queue.connect()
        batch_size = max(1, min(int(config.get("crawl_nuclei_batch_size", 25)), 50))
        nuclei_config = {
            **config,
            "automatic_scan": False,
            "vuln_depth": "default",
            "severities": ["critical", "high", "medium"],
            "scan_timeout": min(int(config.get("scan_timeout", 600)), 300),
        }
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
        await coord.close()
        await queue.close()

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

"""
ASM Platform — Nuclei Vulnerability Scanner Worker
Runs nuclei templates against discovered assets and persists findings.
"""
import asyncio
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from app.services.scan_profiles import PROFILE_TEMPLATE_DIRS, SAFE_EXCLUDED_TAGS
from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running

log = structlog.get_logger()

# Severity mapping from nuclei to platform
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Nuclei category → platform category
CATEGORY_MAP = {
    "network": "exposed_service",
    "dns": "missing_spf",
    "ssl": "expired_certificate",
    "http": "exposed_admin_panel",
    "cve": "known_cve",
    "exposed-panels": "exposed_admin_panel",
    "misconfiguration": "cors_misconfiguration",
    "default-logins": "default_credentials",
    "takeovers": "subdomain_takeover",
    "technologies": "outdated_software",
    "exposures": "exposed_api",
    "vulnerabilities": "known_cve",
    "fuzzing": "exposed_service",
    "helpers": "info",
    "workflows": "info",
}

# Template severity allow-list (don't run info templates by default)
DEFAULT_SEVERITIES = ["critical", "high", "medium", "low"]
MAX_RAW_FIELD_CHARS = 10000
MAX_RESPONSE_RAW_CHARS = 5000
MAX_BATCH_TIMEOUT = int(os.getenv("NUCLEI_MAX_BATCH_TIMEOUT", "900"))
MAX_ENDPOINT_BATCH_TIMEOUT = int(os.getenv("NUCLEI_ENDPOINT_MAX_BATCH_TIMEOUT", "600"))

NOISY_INFO_TEMPLATE_IDS = {
    "favicon-detect",
    "fingerprinthub-web-fingerprints",
    "metatag-cms",
    "php-detect",
    "tech-detect",
    "waf-detect",
    "wordpress-detect",
    "wordpress-passive-detection",
    "wordpress-plugin-detect",
}

WORDPRESS_INFO_ALLOWLIST = {
    "wordpress-eol",
    "wordpress-rdf-user-enum",
    "wordpress-readme-file",
}

INFO_SECURITY_KEYWORDS = {
    "debug",
    "default",
    "disclosure",
    "eol",
    "end-of-life",
    "exposed",
    "hsts",
    "license",
    "manager",
    "readme",
    "stacktrace",
    "takeover",
    "user-enum",
    "weak",
}

TECH_TAG_ALIASES = {
    "apache http server": "apache",
    "apache": "apache",
    "nginx": "nginx",
    "microsoft iis": "iis",
    "iis": "iis",
    "php": "php",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "magento": "magento",
    "shopify": "shopify",
    "react": "react",
    "next.js": "nextjs",
    "nextjs": "nextjs",
    "angular": "angular",
    "vue.js": "vuejs",
    "vuejs": "vuejs",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "express": "express",
    "django": "django",
    "flask": "flask",
    "laravel": "laravel",
    "spring": "spring",
    "apache tomcat": "tomcat",
    "tomcat": "tomcat",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "jira": "jira",
    "confluence": "confluence",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
}


class NucleiWorker(BaseWorker):
    """
    Runs nuclei against target URLs/IPs and persists findings.

    Template categories used:
    - CVEs (matched to known vulnerabilities)
    - Exposures (admin panels, config files, secrets)
    - Misconfigurations (CORS, headers, TLS)
    - Default logins
    - Subdomain takeovers
    - DNS misconfigs
    - SSL/TLS issues
    """

    QUEUE = "scan.nuclei"
    CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "2"))
    TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))

    async def setup(self) -> None:
        """Refresh nuclei templates once at startup. TEMPLATES_PATH now sits on a
        persistent volume (see docker-compose.yml), so this keeps templates current
        across container restarts instead of only at image build time."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-update-templates", "-silent",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=120)
            log.info("nuclei_templates_refreshed", path=self.TEMPLATES_PATH)
        except Exception as e:
            log.warning("nuclei_templates_refresh_failed", error=str(e))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        targets = message["targets"]  # List of URLs/subdomains
        config = message.get("config", {})
        tech_map = message.get("tech_map", {})  # {url: [tech_names]}

        async with get_session() as db:
            if not await mark_scan_running(db, scan_id, progress_floor=10):
                log.info("nuclei_skipped_inactive_scan", scan_id=scan_id)
                return
            await update_scan_phase(db, scan_id, "nuclei", "running", targets_total=len(targets))
            await record_target_selections(
                db,
                scan_id=scan_id,
                phase="nuclei",
                targets=[
                    {
                        "target": target,
                        "target_type": "url" if str(target).startswith(("http://", "https://")) else "host",
                        "profile": config.get("vuln_depth") or config.get("scan_profile") or "default",
                        "selected": True,
                        "reasons": ["nuclei_batch_target"],
                        "metadata": {
                            "batch_size": len(targets),
                            "automatic_scan": config.get("automatic_scan"),
                            "nuclei_profiles": config.get("nuclei_profiles") or config.get("nuclei_profile"),
                            "template_dirs": config.get("template_dirs") or [],
                        },
                    }
                    for target in targets
                ],
            )
            await self._mark_endpoint_targets(
                db,
                org_id=org_id,
                workspace_id=workspace_id,
                targets=targets,
                scan_status="running",
            )

        if not targets:
            log.warning("nuclei_no_targets", scan_id=scan_id)
            async with get_session() as db:
                await update_scan_phase(db, scan_id, "nuclei", "skipped", targets_total=0)
            await self._queue_correlation(scan_id, org_id, workspace_id)
            return

        log.info("nuclei_scan_started", scan_id=scan_id, targets=len(targets), org_id=org_id)

        # Optional tech tags are curated for observability. Do not turn them
        # into a global nuclei -tags filter by default because that narrows
        # coverage and can skip generic exposure/misconfiguration templates.
        all_techs = set()
        if tech_map and config.get("use_tech_tags", True):
            for url, techs in tech_map.items():
                if techs:
                    all_techs.update(self._tech_tags(techs))
            if all_techs:
                log.info("nuclei_tech_tags", count=len(all_techs), tags=list(all_techs)[:20], scan_id=scan_id)
                if config.get("enable_tech_tag_filter", False):
                    existing_tags = config.get("tags", [])
                    config["tags"] = list(set(existing_tags) | all_techs)

        with tempfile.TemporaryDirectory(prefix="asm-nuclei-") as tmpdir:
            tmpdir = Path(tmpdir)

            original_targets = list(targets)
            targets = await self._validate_endpoint_targets(targets, tmpdir, config)
            skipped_targets = [
                target for target in original_targets
                if str(target).startswith(("http://", "https://")) and target not in targets
            ]
            skipped_inactive = len(skipped_targets)
            if skipped_inactive:
                async with get_session() as db:
                    await self._mark_endpoint_targets(
                        db,
                        org_id=org_id,
                        workspace_id=workspace_id,
                        targets=skipped_targets,
                        scan_status="failed",
                    )
                    await self._refresh_endpoint_status_summary(
                        db,
                        scan_id=scan_id,
                        org_id=org_id,
                        workspace_id=workspace_id,
                    )
                    await update_scan_phase(
                        db,
                        scan_id,
                        "nuclei",
                        "running",
                        endpoint_liveness_skipped=skipped_inactive,
                    )
            if not targets:
                async with get_session() as db:
                    await update_scan_phase(
                        db,
                        scan_id,
                        "nuclei",
                        "skipped",
                        targets_total=0,
                        endpoint_liveness_skipped=skipped_inactive,
                    )
                    await self._mark_nuclei_task_complete(db, scan_id)
                await self._queue_correlation(scan_id, org_id, workspace_id, targets_scanned=0, findings_found=0)
                return

            # Write targets
            target_file = tmpdir / "targets.txt"
            target_file.write_text("\n".join(targets))

            output_file = tmpdir / "nuclei_results.jsonl"

            # Run nuclei
            nuclei_profile = config.get("scan_profile") or config.get("vuln_depth") or "default"
            async with get_session() as db:
                await update_scan_phase(
                    db,
                    scan_id,
                    "nuclei",
                    "running",
                    active_profile=nuclei_profile,
                    active_batch_targets=len(targets),
                    active_batch_timeout=int(config.get("scan_timeout", 900)),
                    active_endpoint_timeout_cap=MAX_ENDPOINT_BATCH_TIMEOUT,
                )
            findings_raw, timed_out, effective_scan_timeout = await self._run_nuclei(
                target_file=target_file,
                output_file=output_file,
                config=config,
                scan_id=scan_id,
            )

            findings = []
            findings_linked = 0
            if findings_raw:
                log.info("nuclei_raw_findings", count=len(findings_raw), scan_id=scan_id)

                findings = [self._parse_finding(f, org_id, workspace_id, scan_id) for f in findings_raw]
                findings = [f for f in findings if f is not None]
                suppressed_count = 0
                if not config.get("nuclei_persist_info_findings", False):
                    before_filter = len(findings)
                    findings = [f for f in findings if not self._is_low_value_info_finding(f)]
                    suppressed_count = before_filter - len(findings)

                if suppressed_count:
                    log.info(
                        "nuclei_info_findings_suppressed",
                        count=suppressed_count,
                        scan_id=scan_id,
                    )
                    async with get_session() as db:
                        await update_scan_phase(
                            db,
                            scan_id,
                            "nuclei",
                            "running",
                            suppressed_info_findings=suppressed_count,
                        )

                async with get_session() as db:
                    persisted = await self._persist_findings(db, findings, scan_id)
                    findings_linked = len(persisted)
                    await self._update_scan_findings_count(db, scan_id, len(persisted))
            elif not timed_out:
                log.info("nuclei_no_findings", scan_id=scan_id, targets=len(targets))

            if timed_out:
                log.warning(
                    "nuclei_timeout_partial",
                    scan_id=scan_id,
                    targets=len(targets),
                    timeout=effective_scan_timeout,
                    raw_findings=len(findings_raw),
                    persisted_findings=findings_linked,
                )
                async with get_session() as db:
                    await self._record_timeout_summary(
                        db,
                        scan_id=scan_id,
                        targets_count=len(targets),
                        timeout_seconds=effective_scan_timeout,
                        raw_findings=len(findings_raw),
                        persisted_findings=findings_linked,
                    )

            async with get_session() as db:
                await self._mark_nuclei_task_complete(db, scan_id)

            # Queue correlation — ALWAYS called, even with zero findings.
            # This increments nuclei_done and checks for terminal condition.
            await self._queue_correlation(
                scan_id,
                org_id,
                workspace_id,
                targets_scanned=len(targets),
                findings_found=findings_linked,
            )

        log.info("nuclei_scan_completed", scan_id=scan_id, findings=findings_linked)

        async with get_session() as db:
            await self._mark_endpoint_targets(
                db,
                org_id=org_id,
                workspace_id=workspace_id,
                targets=targets,
                scan_status="timeout" if timed_out else "completed",
                last_scanned=True,
            )
            await self._refresh_endpoint_status_summary(
                db,
                scan_id=scan_id,
                org_id=org_id,
                workspace_id=workspace_id,
            )

    async def _validate_endpoint_targets(self, targets: List[str], tmpdir: Path, config: Dict[str, Any]) -> List[str]:
        """Filter endpoint URL targets through httpx before nuclei to reduce dead/noisy endpoint scans."""
        if not config.get("nuclei_validate_endpoint_liveness", True):
            return targets
        url_targets = [target for target in targets if str(target).startswith(("http://", "https://"))]
        host_targets = [target for target in targets if target not in url_targets]
        if not url_targets:
            return targets
        httpx_path = shutil.which("httpx") or ("/go/bin/httpx" if Path("/go/bin/httpx").exists() else None)
        if not httpx_path:
            return targets

        input_file = tmpdir / "nuclei_endpoint_liveness.txt"
        output_file = tmpdir / "nuclei_endpoint_liveness.json"
        input_file.write_text("\n".join(url_targets))
        cmd = [
            httpx_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-follow-redirects",
            "-max-redirects", "3",
            "-status-code",
            "-timeout", str(int(config.get("crawl_httpx_timeout", 10))),
            "-t", str(int(config.get("crawl_httpx_threads", 50))),
            "-rl", str(int(config.get("crawl_httpx_rate_limit", 150))),
            "-no-color",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=int(config.get("nuclei_endpoint_liveness_timeout", 180)))
        except Exception as exc:
            log.warning("nuclei_endpoint_liveness_failed", error=str(exc))
            return targets

        alive = set()
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("failed"):
                    continue
                key = row.get("input") or row.get("url")
                if key:
                    alive.add(str(key).rstrip("/"))
                if row.get("url"):
                    alive.add(str(row.get("url")).rstrip("/"))
        return host_targets + [target for target in url_targets if target.rstrip("/") in alive]

    def _tech_tags(self, techs: List[Any]) -> List[str]:
        tags = []
        for tech in techs:
            if not isinstance(tech, str):
                continue
            normalized = tech.lower().strip()
            for sep in ("/", ":", "@"):
                normalized = normalized.split(sep, 1)[0]
            normalized = " ".join(normalized.replace("_", " ").split())
            tag = TECH_TAG_ALIASES.get(normalized)
            if tag:
                tags.append(tag)
        return tags

    async def _mark_endpoint_targets(
        self,
        db,
        *,
        org_id: str,
        workspace_id: str,
        targets: List[str],
        scan_status: str,
        last_scanned: bool = False,
    ) -> None:
        endpoint_targets = [
            str(target).strip()
            for target in targets
            if str(target).startswith(("http://", "https://"))
        ]
        if not endpoint_targets:
            return

        from sqlalchemy import update
        from workers.db_models import WebEndpoint

        values: Dict[str, Any] = {"scan_status": scan_status}
        if last_scanned:
            values["last_scanned_at"] = datetime.now(timezone.utc)

        await db.execute(
            update(WebEndpoint)
            .where(
                WebEndpoint.org_id == org_id,
                WebEndpoint.workspace_id == workspace_id,
                WebEndpoint.url.in_(endpoint_targets),
            )
            .values(**values)
        )
        await db.commit()

    async def _refresh_endpoint_status_summary(
        self,
        db,
        *,
        scan_id: str,
        org_id: str,
        workspace_id: str,
    ) -> None:
        from sqlalchemy import func, select
        from workers.db_models import ScanTargetSelection, WebEndpoint

        status_rows = (await db.execute(
            select(WebEndpoint.scan_status, func.count(func.distinct(WebEndpoint.url)))
            .join(
                ScanTargetSelection,
                ScanTargetSelection.target == WebEndpoint.url,
            )
            .where(
                ScanTargetSelection.scan_id == scan_id,
                ScanTargetSelection.phase.in_(["crawl", "nuclei"]),
                ScanTargetSelection.target_type == "url",
                ScanTargetSelection.selected.is_(True),
                WebEndpoint.org_id == org_id,
                WebEndpoint.workspace_id == workspace_id,
            )
            .group_by(WebEndpoint.scan_status)
        )).all()
        counts = {str(status or "unknown"): int(count or 0) for status, count in status_rows}
        endpoint_total = sum(counts.values())

        await update_scan_phase(
            db,
            scan_id,
            "nuclei",
            "running",
            endpoint_targets=endpoint_total,
            endpoint_completed=counts.get("completed", 0),
            endpoint_timeout=counts.get("timeout", 0),
            endpoint_failed=counts.get("failed", 0),
            endpoint_running=counts.get("running", 0),
            endpoint_queued=counts.get("queued", 0),
            endpoint_not_scanned=counts.get("not_scanned", 0),
        )

    async def _record_timeout_summary(
        self,
        db,
        *,
        scan_id: str,
        targets_count: int,
        timeout_seconds: int,
        raw_findings: int,
        persisted_findings: int,
    ) -> None:
        from sqlalchemy import select
        from workers.db_models import Scan

        result = await db.execute(select(Scan.phase_status).where(Scan.id == scan_id).limit(1))
        phase_status = result.scalar_one_or_none() or {}
        current = dict((phase_status or {}).get("nuclei") or {})

        await update_scan_phase(
            db,
            scan_id,
            "nuclei",
            "running",
            warnings=int(current.get("warnings") or 0) + 1,
            timeout_batches=int(current.get("timeout_batches") or 0) + 1,
            last_warning="nuclei_timeout_partial",
            last_timeout_seconds=timeout_seconds,
            last_timeout_targets=targets_count,
            last_timeout_raw_findings=raw_findings,
            last_timeout_persisted_findings=persisted_findings,
        )

    async def _run_nuclei(
        self,
        target_file: Path,
        output_file: Path,
        config: Dict,
        scan_id: str,
    ) -> tuple[List[Dict], bool, int]:
        """Execute nuclei with configured templates and return raw JSON results."""
        severities = config.get("severities", DEFAULT_SEVERITIES)
        tags = config.get("tags", [])
        templates = config.get("templates", [])
        exclude_tags = config.get("exclude_tags", SAFE_EXCLUDED_TAGS)
        rate_limit = config.get("rate_limit", self.RATE_LIMIT)
        bulk_size = config.get("bulk_size", 10)
        concurrency = config.get("concurrency", 10)
        template_timeout = min(int(config.get("template_timeout", 8)), 8)
        retries = int(config.get("retries", 0))
        scan_timeout = int(config.get("scan_timeout", 900))
        profile_name = str(config.get("scan_profile") or config.get("vuln_depth") or "")
        timeout_cap = MAX_ENDPOINT_BATCH_TIMEOUT if profile_name == "endpoint" else MAX_BATCH_TIMEOUT
        if scan_timeout > timeout_cap:
            log.info(
                "nuclei_timeout_capped",
                requested=scan_timeout,
                capped=timeout_cap,
                profile=profile_name or "default",
                scan_id=scan_id,
            )
            scan_timeout = timeout_cap
        response_size_read = int(config.get("nuclei_response_size_read", 1048576))
        response_size_save = int(config.get("nuclei_response_size_save", 262144))
        nuclei_path = shutil.which("nuclei") or "/go/bin/nuclei"

        cmd = [
            nuclei_path,
            "-l", str(target_file),
            "-jsonl",
            "-o", str(output_file),
            "-silent",
            "-no-color",
            "-stream",
            "-rate-limit", str(rate_limit),
            "-bulk-size", str(bulk_size),
            "-c", str(concurrency),
            "-timeout", str(template_timeout),
            "-retries", str(retries),
            "-max-redirects", "3",
            "-rsr", str(response_size_read),
            "-rss", str(response_size_save),
            "-redact", "authorization,token,password,secret,api_key,apikey,access_token,refresh_token",
            "-disable-update-check",
            "-no-stdin",
        ]
        if config.get("allow_cross_host_redirects", False):
            cmd.append("-follow-redirects")
        else:
            cmd.append("-follow-host-redirects")
        if config.get("nuclei_store_responses", False):
            response_dir = output_file.parent / "nuclei-responses"
            cmd.extend(["-sresp", "-srd", str(response_dir)])

        # Template selection based on vuln_depth
        vuln_depth = config.get("vuln_depth", "default")
        automatic_scan = bool(config.get("automatic_scan", vuln_depth in {"default", "full"}))
        if automatic_scan:
            cmd.append("-as")

        # Severity filter (restrict further for critical-only depth)
        if vuln_depth == "critical":
            cmd.extend(["-severity", "critical,high"])
        elif severities:
            cmd.extend(["-severity", ",".join(severities)])

        # Map depth -> template directories. Central scan profiles now pass
        # explicit nuclei_profiles; depth mapping remains for older messages.
        TEMPLATE_DIRS_BY_DEPTH = {
            "critical": [
                "http/cves",
                "network/cves",
            ],
            "default": [
                "http/exposures",
                "http/misconfiguration",
                "http/default-logins",
                "http/takeovers",
                "dns",
                "ssl",
                "http/exposed-panels",
                "network/exposures",
            ],
            "endpoint": [
                "http/exposures",
                "http/misconfiguration",
                "http/default-logins",
                "http/takeovers",
                "http/exposed-panels",
            ],
            "full": [
                "http/cves",
                "http/vulnerabilities",
                "http/exposures",
                "http/misconfiguration",
                "http/default-logins",
                "http/takeovers",
                "dns",
                "ssl",
                "http/exposed-panels",
                "network/cves",
                "network/vulnerabilities",
                "network/exposures",
            ],
        }

        profile_dirs = self._template_dirs_for_profiles(config.get("nuclei_profiles") or config.get("nuclei_profile"))
        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
        elif profile_dirs:
            for tmpl_dir in profile_dirs:
                tmpl_path = Path(self.TEMPLATES_PATH) / str(tmpl_dir)
                if tmpl_path.exists():
                    cmd.extend(["-t", str(tmpl_path)])
        elif config.get("template_dirs"):
            for tmpl_dir in config.get("template_dirs", []):
                tmpl_path = Path(self.TEMPLATES_PATH) / str(tmpl_dir)
                if tmpl_path.exists():
                    cmd.extend(["-t", str(tmpl_path)])
        else:
            dirs = TEMPLATE_DIRS_BY_DEPTH.get(vuln_depth, TEMPLATE_DIRS_BY_DEPTH["default"])
            for tmpl_dir in dirs:
                tmpl_path = Path(self.TEMPLATES_PATH) / tmpl_dir
                if tmpl_path.exists():
                    cmd.extend(["-t", str(tmpl_path)])

        # Tag filters are only applied when explicitly requested. Broad ASM
        # coverage comes from template directories plus -as, not tech tags.
        final_tags = list(tags)
        if final_tags:
            cmd.extend(["-tags", ",".join(final_tags)])
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])

        # Custom headers
        cmd.extend(["-H", "X-ASM-Scanner: ASM-Platform/1.0"])

        log.info("nuclei_command", cmd=" ".join(cmd[:10]) + "...", scan_id=scan_id)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=scan_timeout)

            if proc.returncode not in (0, 1):  # nuclei returns 1 if findings exist
                log.error("nuclei_error", stderr=stderr.decode()[:500], scan_id=scan_id)

        except asyncio.TimeoutError:
            log.error("nuclei_timeout", scan_id=scan_id)
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return self._parse_results_file(output_file), True, scan_timeout
        except FileNotFoundError:
            log.error("nuclei_not_found", message="nuclei binary not found in PATH")
            return [], False, scan_timeout
        except Exception as e:
            log.error("nuclei_exception", error=str(e), scan_id=scan_id)
            return [], False, scan_timeout

        return self._parse_results_file(output_file), False, scan_timeout

    def _template_dirs_for_profiles(self, profiles: Any) -> List[str]:
        if not profiles:
            return []
        if isinstance(profiles, str):
            profiles = [profiles]
        dirs: List[str] = []
        seen = set()
        for profile in profiles:
            for tmpl_dir in PROFILE_TEMPLATE_DIRS.get(str(profile), []):
                if tmpl_dir not in seen:
                    seen.add(tmpl_dir)
                    dirs.append(tmpl_dir)
        return dirs

    def _parse_results_file(self, output_file: Path) -> List[Dict]:
        """Parse nuclei JSON output, including partial files after timeout."""
        results = []
        if output_file.exists():
            for line in output_file.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, list):
                        results.extend(parsed)
                    elif isinstance(parsed, dict):
                        results.append(parsed)
                except json.JSONDecodeError:
                    continue

        return results

    def _parse_finding(
        self,
        raw: Any,
        org_id: str,
        workspace_id: str,
        scan_id: str,
    ) -> Optional[Dict]:
        """Parse a nuclei JSON result into platform finding format."""
        if not isinstance(raw, dict):
            return None
        try:
            template_id = raw.get("template-id", "")
            template_info = raw.get("info", {})
            matched = raw.get("matched-at", raw.get("host", ""))
            severity = SEVERITY_MAP.get(template_info.get("severity", "info").lower(), "info")

            # Extract CVE IDs
            cve_ids = []
            classifications = template_info.get("classification", {})
            cve_id = classifications.get("cve-id", [])
            if isinstance(cve_id, str):
                cve_ids = [cve_id]
            elif isinstance(cve_id, list):
                cve_ids = cve_id

            # CVSS
            cvss_score = classifications.get("cvss-score")

            # Category mapping
            tags = template_info.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            category = self._map_category(template_id, tags)

            # Fingerprint for deduplication
            fingerprint = hashlib.sha256(
                f"{org_id}:{template_id}:{matched}".encode()
            ).hexdigest()

            # Evidence
            request_raw = self._clean_text(raw.get("request", ""), limit=MAX_RAW_FIELD_CHARS)
            response_raw = self._clean_text(raw.get("response", ""), limit=MAX_RESPONSE_RAW_CHARS)
            if isinstance(raw.get("response", ""), str) and len(raw.get("response", "")) > MAX_RESPONSE_RAW_CHARS:
                response_raw = f"{response_raw}\n... [truncated]"

            # References
            references = template_info.get("reference", [])
            if isinstance(references, str):
                references = [references]

            return {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "scan_id": scan_id,
                "title": self._clean_text(template_info.get("name", template_id), limit=500),
                "description": self._clean_text(template_info.get("description", ""), limit=5000),
                "severity": severity,
                "category": category,
                "source": "nuclei",
                "template_id": self._clean_text(template_id, limit=255),
                "template_url": self._clean_text(
                    f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{template_id}.yaml",
                    limit=1000,
                ),
                "scanner": "nuclei",
                "cve_ids": [self._clean_text(cve_id, limit=100) for cve_id in cve_ids[:10]],
                "cvss_score": float(cvss_score) if cvss_score else None,
                "affected_url": self._clean_text(matched, limit=1000),
                "evidence": self._clean_text(f"Template: {template_id}\nMatch: {matched}", limit=5000),
                "request_raw": request_raw,
                "response_raw": response_raw,
                "proof": self._clean_json({
                    "matched_at": matched,
                    "matcher_name": raw.get("matcher-name", ""),
                    "extracted_results": raw.get("extracted-results", []),
                    "curl_command": raw.get("curl-command", ""),
                    "ip": raw.get("ip", ""),
                    "timestamp": raw.get("timestamp", ""),
                    "template_id": template_id,
                    "tags": tags,
                }),
                "remediation": self._clean_text(template_info.get("remediation", ""), limit=5000),
                "references": [self._clean_text(ref, limit=1000) for ref in references[:20]],
                "fingerprint": fingerprint,
                "status": "open",
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
            }
        except Exception as e:
            log.warning("finding_parse_error", error=str(e))
            return None

    def _clean_text(self, value: Any, *, limit: int) -> str:
        """Return Postgres-safe text from tool output."""
        if value is None:
            return ""
        if not isinstance(value, str):
            value = str(value)
        cleaned = value.replace("\x00", "")
        cleaned = "".join(
            char if char in {"\n", "\r", "\t"} or ord(char) >= 32 else " "
            for char in cleaned
        )
        return cleaned[:limit]

    def _clean_json(self, value: Any) -> Any:
        """Recursively remove values PostgreSQL JSONB cannot store."""
        if isinstance(value, dict):
            return {self._clean_text(k, limit=500): self._clean_json(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._clean_json(item) for item in value]
        if isinstance(value, str):
            return self._clean_text(value, limit=10000)
        return value

    def _is_low_value_info_finding(self, finding: Dict[str, Any]) -> bool:
        """Suppress technology inventory signals that should not become findings."""
        if finding.get("severity") != "info":
            return False

        template_id = str(finding.get("template_id") or "").lower()
        title = str(finding.get("title") or "").lower()
        tags = [
            str(tag).lower()
            for tag in (finding.get("proof") or {}).get("tags", [])
            if tag
        ]
        haystack = " ".join([template_id, title, *tags])

        if template_id in WORDPRESS_INFO_ALLOWLIST:
            return False
        if any(keyword in haystack for keyword in INFO_SECURITY_KEYWORDS):
            return False
        if template_id in NOISY_INFO_TEMPLATE_IDS:
            return True
        if template_id.startswith("wordpress-"):
            return True
        if any(tag in {"tech", "favicon", "waf", "wordpress", "plugin", "fingerprint"} for tag in tags):
            return True
        return finding.get("category") == "exposed_service"

    def _map_category(self, template_id: str, tags: List[str]) -> str:
        """Map nuclei template to platform finding category."""
        template_lower = template_id.lower()

        # Check template ID prefix
        for prefix, category in CATEGORY_MAP.items():
            if template_lower.startswith(prefix):
                return category

        # Check tags
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in CATEGORY_MAP:
                return CATEGORY_MAP[tag_lower]

        # Keyword matching
        if "cve" in template_lower:
            return "known_cve"
        if any(k in template_lower for k in ["panel", "admin", "login", "dashboard"]):
            return "exposed_admin_panel"
        if any(k in template_lower for k in ["debug", "ignition", "stacktrace", "stack-trace", "trace"]):
            return "debug_endpoint"
        if any(k in template_lower for k in ["git", "env", "config", "backup"]):
            return "exposed_git"
        if any(k in template_lower for k in ["header", "hsts", "csp", "xss"]):
            return "missing_hsts"
        if any(k in template_lower for k in ["ssl", "tls", "cert"]):
            return "expired_certificate"
        if any(k in template_lower for k in ["cors", "redirect"]):
            return "cors_misconfiguration"
        if any(k in template_lower for k in ["spf", "dmarc", "dkim", "dnssec"]):
            return "missing_spf"
        if any(k in template_lower for k in ["takeover", "subdomain"]):
            return "subdomain_takeover"

        # Unmatched templates default to the lowest-weighted category (misconfiguration)
        # instead of falsely asserting a specific claim like "exposed_service"/network risk.
        return "cors_misconfiguration"

    async def _persist_findings(
        self,
        db,
        findings: List[Dict],
        scan_id: str,
    ) -> List[str]:
        """Upsert findings, return list of persisted finding IDs."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from workers.db_models import Asset, Finding, ScanFinding

        persisted_ids = []
        now = datetime.now(timezone.utc)

        for f in findings:
            # Find matching asset
            asset = await self._find_asset(db, f["org_id"], f["affected_url"])

            if not asset:
                log.debug("finding_no_asset", url=f["affected_url"])
                continue

            # Upsert finding
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
                index_elements=["fingerprint", "org_id"],
                set_={"last_seen": now, "status": "open"},
            ).returning(Finding.__table__.c.id, Finding.__table__.c.first_seen)

            result = await db.execute(stmt)
            row = result.fetchone()
            if row:
                finding_id = row[0]
                is_new = (now - row[1]).seconds < 5
                change_type = "new" if is_new else "recurring"

                # Link to scan
                link_result = await db.execute(
                    pg_insert(ScanFinding.__table__).values(
                        scan_id=scan_id,
                        finding_id=finding_id,
                        change_type=change_type,
                    ).on_conflict_do_nothing(
                        constraint="uq_scan_findings_scan_finding"
                    ).returning(ScanFinding.__table__.c.finding_id)
                )
                link_row = link_result.fetchone()
                if link_row:
                    persisted_ids.append(str(finding_id))

        await db.commit()
        return persisted_ids

    async def _find_asset(self, db, org_id: str, url: str):
        """Find asset by URL/hostname."""
        from sqlalchemy import select
        from workers.db_models import Asset

        host = url.split("//")[-1].split("/")[0].split(":")[0] if "//" in url else url.split("/")[0].split(":")[0]

        result = await db.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.value == host,
            ).limit(1)
        )
        return result.scalar_one_or_none()

    async def _update_nuclei_progress(self, scan_id: str, coord) -> None:
        """Update progress from 75 toward 99 based on nuclei_done / nuclei_expected."""
        r = await coord._get_redis()
        expected = int(await r.get(f"scan:{scan_id}:nuclei_expected") or 1)
        done = int(await r.get(f"scan:{scan_id}:nuclei_done") or 0)
        pct = min(75 + int((done / expected) * 24), 99)
        async with get_session() as db:
            from sqlalchemy import update, func
            from workers.db_models import Scan
            await db.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    progress_pct=func.greatest(Scan.progress_pct, pct),
                )
            )
            await db.commit()

    async def _update_scan_findings_count(self, db, scan_id: str, count: int) -> None:
        from sqlalchemy import update, func, select
        from workers.db_models import Scan, ScanFinding
        result = await db.execute(
            select(func.count(ScanFinding.finding_id)).where(ScanFinding.scan_id == scan_id)
        )
        total_findings = result.scalar() or 0
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                findings_found=total_findings,
                progress_pct=func.greatest(Scan.progress_pct, 75),
            )
        )
        await db.commit()

    async def _mark_nuclei_task_complete(self, db, scan_id: str) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                completed_tasks=Scan.completed_tasks + 1,
                progress_pct=func.greatest(Scan.progress_pct, 75),
            )
        )
        await db.commit()

    async def _queue_correlation(
        self,
        scan_id: str,
        org_id: str,
        workspace_id: str,
        targets_scanned: int = 0,
        findings_found: int = 0,
    ) -> None:
        from workers.task_coordinator import TaskCoordinator
        queue = QueueClient()
        await queue.connect()

        coord = TaskCoordinator()
        await coord.incr_nuclei_done(scan_id, targets_scanned=targets_scanned, findings_found=findings_found)
        counts = await coord.get_counts(scan_id)
        expected = max(counts.get("nuclei_expected", 0), 0)
        done = max(counts.get("nuclei_done", 0), 0)
        status = "completed" if expected and done >= expected else "running"

        async with get_session() as db:
            await update_scan_phase(
                db,
                scan_id,
                "nuclei",
                status,
                expected_batches=expected,
                completed_batches=done,
                remaining_batches=max(expected - done, 0),
                targets_scanned=counts.get("nuclei_targets_scanned", 0),
                findings=counts.get("nuclei_findings_found", 0),
            )

        # Update progress proportionally so the bar keeps moving
        # even after screenshot set it to 90%.
        # Range: 75 → 99 (terminal will set 100).
        await self._update_nuclei_progress(scan_id, coord)

        # Intermediate correlation (dedup, relationships, indexing)
        await queue.publish(
            routing_key="correlation.process",
            message={
                "scan_id": scan_id,
                "org_id": org_id,
                "workspace_id": workspace_id,
            },
        )

        # Atomic terminal claim — only one worker (nuclei or screenshot)
        # will get `True` and send the terminal message.
        if await coord.mark_terminal_if_all_done(scan_id):
            await queue.publish(
                routing_key="correlation.process",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "is_terminal": True,
                },
            )
            await coord.cleanup(scan_id)

        await coord.close()
        await queue.close()


if __name__ == "__main__":
    worker = NucleiWorker()
    asyncio.run(worker.run())

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

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
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

        if not targets:
            log.warning("nuclei_no_targets", scan_id=scan_id)
            await self._queue_correlation(scan_id, org_id, workspace_id)
            return

        log.info("nuclei_scan_started", scan_id=scan_id, targets=len(targets), org_id=org_id)

        # Optional tech tags are curated so detection can guide nuclei without
        # expanding into every Wappalyzer label.
        all_techs = set()
        if tech_map and config.get("use_tech_tags", True):
            for url, techs in tech_map.items():
                if techs:
                    all_techs.update(self._tech_tags(techs))
            if all_techs:
                existing_tags = config.get("tags", [])
                config["tags"] = list(set(existing_tags) | all_techs)
                log.info("nuclei_tech_tags", count=len(all_techs), tags=list(all_techs)[:20], scan_id=scan_id)

        with tempfile.TemporaryDirectory(prefix="asm-nuclei-") as tmpdir:
            tmpdir = Path(tmpdir)

            # Write targets
            target_file = tmpdir / "targets.txt"
            target_file.write_text("\n".join(targets))

            output_file = tmpdir / "nuclei_results.json"

            # Run nuclei
            findings_raw = await self._run_nuclei(
                target_file=target_file,
                output_file=output_file,
                config=config,
                scan_id=scan_id,
            )

            findings = []
            if findings_raw:
                log.info("nuclei_raw_findings", count=len(findings_raw), scan_id=scan_id)

                findings = [self._parse_finding(f, org_id, workspace_id, scan_id) for f in findings_raw]
                findings = [f for f in findings if f is not None]

                async with get_session() as db:
                    persisted = await self._persist_findings(db, findings, scan_id)
                    await self._update_scan_findings_count(db, scan_id, len(persisted))
            else:
                log.info("nuclei_no_findings", scan_id=scan_id, targets=len(targets))

            async with get_session() as db:
                await self._mark_nuclei_task_complete(db, scan_id)

            # Queue correlation — ALWAYS called, even with zero findings.
            # This increments nuclei_done and checks for terminal condition.
            await self._queue_correlation(scan_id, org_id, workspace_id)

        log.info("nuclei_scan_completed", scan_id=scan_id, findings=len(findings))

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

    async def _run_nuclei(
        self,
        target_file: Path,
        output_file: Path,
        config: Dict,
        scan_id: str,
    ) -> List[Dict]:
        """Execute nuclei with configured templates and return raw JSON results."""
        severities = config.get("severities", DEFAULT_SEVERITIES)
        tags = config.get("tags", [])
        templates = config.get("templates", [])
        exclude_tags = config.get("exclude_tags", ["dos", "fuzz", "intrusive"])
        rate_limit = config.get("rate_limit", self.RATE_LIMIT)
        bulk_size = config.get("bulk_size", 10)
        concurrency = config.get("concurrency", 10)
        template_timeout = int(config.get("template_timeout", 8))
        retries = int(config.get("retries", 0))
        scan_timeout = int(config.get("scan_timeout", 600))
        nuclei_path = shutil.which("nuclei") or "/go/bin/nuclei"

        cmd = [
            nuclei_path,
            "-l", str(target_file),
            "-json-export", str(output_file),
            "-silent",
            "-no-color",
            "-rate-limit", str(rate_limit),
            "-bulk-size", str(bulk_size),
            "-c", str(concurrency),
            "-timeout", str(template_timeout),
            "-retries", str(retries),
            "-follow-redirects",
            "-max-redirects", "3",
            "-disable-update-check",
        ]

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

        # Map depth → template directories
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

        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
        else:
            dirs = TEMPLATE_DIRS_BY_DEPTH.get(vuln_depth, TEMPLATE_DIRS_BY_DEPTH["default"])
            for tmpl_dir in dirs:
                tmpl_path = Path(self.TEMPLATES_PATH) / tmpl_dir
                if tmpl_path.exists():
                    cmd.extend(["-t", str(tmpl_path)])

        # Tag filters — always include cve + vulnerabilities so tech filtering
        # doesn't miss security issues. Tech-specific tags add on top.
        final_tags = list(tags)
        if tags:
            for required in ("cve", "vulnerabilities"):
                if required not in final_tags:
                    final_tags.append(required)
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
            return []
        except FileNotFoundError:
            log.error("nuclei_not_found", message="nuclei binary not found in PATH")
            return []
        except Exception as e:
            log.error("nuclei_exception", error=str(e), scan_id=scan_id)
            return []

        # Parse results
        results = []
        if output_file.exists():
            for line in output_file.read_text().splitlines():
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
            request_raw = raw.get("request", "")
            response_raw = raw.get("response", "")
            if len(response_raw) > 5000:
                response_raw = response_raw[:5000] + "\n... [truncated]"

            # References
            references = template_info.get("reference", [])
            if isinstance(references, str):
                references = [references]

            return {
                "org_id": org_id,
                "workspace_id": workspace_id,
                "scan_id": scan_id,
                "title": template_info.get("name", template_id)[:500],
                "description": template_info.get("description", "")[:5000],
                "severity": severity,
                "category": category,
                "source": "nuclei",
                "template_id": template_id[:255],
                "template_url": f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{template_id}.yaml",
                "scanner": "nuclei",
                "cve_ids": cve_ids[:10],
                "cvss_score": float(cvss_score) if cvss_score else None,
                "affected_url": matched[:1000],
                "evidence": f"Template: {template_id}\nMatch: {matched}",
                "request_raw": request_raw[:10000],
                "response_raw": response_raw[:10000],
                "proof": {
                    "matched_at": matched,
                    "matcher_name": raw.get("matcher-name", ""),
                    "extracted_results": raw.get("extracted-results", []),
                    "curl_command": raw.get("curl-command", ""),
                    "ip": raw.get("ip", ""),
                    "timestamp": raw.get("timestamp", ""),
                    "template_id": template_id,
                    "tags": tags,
                },
                "remediation": template_info.get("remediation", "")[:5000],
                "references": references[:20],
                "fingerprint": fingerprint,
                "status": "open",
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
            }
        except Exception as e:
            log.warning("finding_parse_error", error=str(e))
            return None

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

        return "exposed_service"  # Default

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
                await db.execute(
                    pg_insert(ScanFinding.__table__).values(
                        scan_id=scan_id,
                        finding_id=finding_id,
                        change_type=change_type,
                    ).on_conflict_do_nothing()
                )
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
        from sqlalchemy import update, func
        from workers.db_models import Scan
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                findings_found=Scan.findings_found + count,
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

    async def _queue_correlation(self, scan_id: str, org_id: str, workspace_id: str) -> None:
        from workers.task_coordinator import TaskCoordinator
        queue = QueueClient()
        await queue.connect()

        coord = TaskCoordinator()
        await coord.incr_nuclei_done(scan_id)

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

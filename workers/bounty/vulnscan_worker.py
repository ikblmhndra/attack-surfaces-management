"""
ASM Platform — Bug Bounty Vulnscan Worker
Module 6: nuclei vulnerability scanning against explicitly human-approved,
in-scope BountyTarget rows. Reuses the ASM pipeline's nuclei execution
engine (workers/bounty/tools.py::run_nuclei, adapted from
workers/scanner/nuclei_worker.py) but with a deliberately different tag
policy: `intrusive`/`bruteforce` templates are allowed by default (this
pipeline exists for active confirmation, not passive detection), while
`dos`/`destructive` stay excluded unless a program's rules_of_engagement
explicitly opts in. See CHANGELOG.md for the full design rationale.
"""
import asyncio
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import structlog
from sqlalchemy import select

from app.services.bounty_report import PRIORITY_BUCKETS
from app.services.bounty_scope import is_target_in_scope
from app.services.scan_profiles import PROFILE_TEMPLATE_DIRS
from workers.bounty.bounty_stage import BountyStageWorker, persist_deduped_attempts
from workers.bounty.detect import (
    CatchAllCache,
    check_403_bypass,
    check_cors,
    check_graphql_batching,
    check_security_headers,
    check_sensitive_files,
    check_vulnerable_components,
    graphql_schema_scan,
)
from workers.bounty.notify import notify_critical_findings
from workers.bounty.tools import login_and_get_token, run_nuclei, run_subzy
from workers.db import get_session
from workers.db_models import BountyAsset, BountyProgram, BountyTarget
from workers.scanner.scanner_common import host_from_target

log = structlog.get_logger()

# Deliberately narrower than SAFE_EXCLUDED_TAGS (which also excludes
# intrusive/bruteforce for the passive ASM pipeline) -- this pipeline is
# for active, authorized confirmation. dos/destructive stay off unless a
# program's rules_of_engagement explicitly lists them under
# allowed_extra_tags, mirroring the SQLi aggressiveness dial in the exploit
# stage (built later, on top of this same per-program escalation pattern).
BOUNTY_DEFAULT_EXCLUDED_TAGS = ["dos", "destructive", "unsafe"]

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MAX_RAW_FIELD_CHARS = 4000

# Bounds so one scan run stays finite regardless of scope width -- a scan
# budget, not a scope restriction (mirrors recon_worker.py's own bounds).
MAX_TARGETS_PER_RUN = 50
# Detection-module bounds (each check is a burst of GETs per host/endpoint).
MAX_DETECT_HOSTS = 20
MAX_DETECT_ENDPOINTS = 40
MAX_DETECT_JS_FILES = 25
# Same "graphql" pattern the priority-bucket classifier already uses to flag
# these URLs for a researcher's attention -- reused here to pick which
# endpoint URLs get the deeper GraphQL checks.
GRAPHQL_URL_RE = PRIORITY_BUCKETS["graphql"]


class BountyVulnscanWorker(BountyStageWorker):
    QUEUE = "bounty.vulnscan"
    STAGE = "vulnscan"
    CONCURRENCY = int(os.getenv("BOUNTY_VULNSCAN_CONCURRENCY", "1"))
    TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")
    RATE_LIMIT = int(os.getenv("BOUNTY_NUCLEI_RATE_LIMIT", "100"))

    async def setup(self) -> None:
        """Shares the same templates volume as worker-nuclei; refreshing
        here is a harmless, idempotent no-op if it's already current."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-update-templates", "-silent",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=120)
        except Exception as exc:
            log.warning("bounty_nuclei_templates_refresh_failed", error=str(exc))

    async def run_stage(self, message: Dict[str, Any]):
        program_id = message["program_id"]

        async with get_session() as db:
            program = (await db.execute(
                select(BountyProgram).where(BountyProgram.id == program_id)
            )).scalar_one_or_none()

            if not program:
                log.warning("bounty_vulnscan_program_missing", program_id=program_id)
                return {"skipped": "program_missing"}
            if program.status != "active":
                log.info("bounty_vulnscan_skipped_inactive", program_id=program_id, status=program.status)
                return {"skipped": "program_not_active"}

            targets = (await db.execute(
                select(BountyTarget).where(BountyTarget.program_id == program.id)
            )).scalars().all()

        scope_rules = program.scope_rules or []
        roe = program.rules_of_engagement or {}

        # Optional single-identity auth (see exploit_worker.py). Threaded into
        # nuclei (its own -H flag already redacts Authorization from output)
        # and the sensitive-file/CORS checks below -- NOT into check_403_bypass,
        # which specifically measures unauthenticated/anonymous access and
        # would silently stop measuring that if given a valid session.
        extra_headers: Dict[str, str] = {}
        auth_login_url = roe.get("auth_login_url")
        auth_email = roe.get("auth_email")
        auth_password = roe.get("auth_password")
        if auth_login_url and auth_email and auth_password:
            token = await login_and_get_token(
                auth_login_url, auth_email, auth_password,
                email_field=roe.get("auth_email_field", "email"),
                password_field=roe.get("auth_password_field", "password"),
            )
            if token:
                extra_headers = {"Authorization": f"Bearer {token}"}
            log.info("bounty_vulnscan_auth", program_id=program_id, authenticated=bool(token))

        # Skip targets probe already confirmed dead; unprobed (is_alive is
        # None) targets still get scanned -- nuclei does its own liveness
        # check per-request regardless.
        in_scope_targets = [
            t for t in targets
            if t.is_alive is not False and is_target_in_scope(t.value, scope_rules)
        ][:MAX_TARGETS_PER_RUN]

        if not in_scope_targets:
            log.info("bounty_vulnscan_no_in_scope_targets", program_id=program_id)
            return {"skipped": "no_in_scope_targets"}

        allowed_extra_tags = set(roe.get("allowed_extra_tags") or [])
        exclude_tags = [t for t in BOUNTY_DEFAULT_EXCLUDED_TAGS if t not in allowed_extra_tags]
        template_dirs = roe.get("nuclei_template_dirs") or self._default_template_dirs(roe.get("nuclei_profiles"))
        severities = roe.get("nuclei_severities") or ["critical", "high", "medium", "low", "info"]
        rate_limit = int(roe.get("rate_limit_rps") or self.RATE_LIMIT)

        log.info(
            "bounty_vulnscan_started",
            program_id=program_id,
            targets=len(in_scope_targets),
            exclude_tags=exclude_tags,
        )

        target_by_host = {host_from_target(t.value): t.id for t in in_scope_targets}
        # Nuclei's template catalog (misconfig/CVE/tech-detection) is host-level,
        # not endpoint-level. Feeding it one entry per promoted url-type target
        # (e.g. 19 promoted endpoints on the same origin) rescans the same host
        # 19x for no extra coverage -- and in practice this once ran long enough
        # to hit the scan timeout and yield zero results. Dedup to one entry per
        # origin; url-injection testing of the individual endpoints is exploit_
        # worker's job (xss/sqli/idor/etc.), not nuclei's.
        nuclei_origins: Dict[str, str] = {}
        for t in in_scope_targets:
            parsed = urlparse(t.value if "://" in t.value else f"https://{t.value}")
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else t.value
            nuclei_origins.setdefault(origin, t.value)
        probe_values = list(nuclei_origins.keys())

        with tempfile.TemporaryDirectory(prefix="asm-bounty-vulnscan-") as tmpdir_raw:
            tmpdir = Path(tmpdir_raw)
            raw_results = await run_nuclei(
                probe_values,
                tmpdir,
                templates_path=self.TEMPLATES_PATH,
                template_dirs=template_dirs,
                severities=severities,
                exclude_tags=exclude_tags,
                rate_limit=rate_limit,
                bulk_size=int(roe.get("nuclei_bulk_size") or 10),
                concurrency=int(roe.get("nuclei_concurrency") or 10),
                scan_timeout=int(roe.get("nuclei_scan_timeout") or 600),
                extra_headers=extra_headers,
            )

        nuclei_attempts: List[Dict[str, Any]] = []
        for raw in raw_results:
            attempt = self._build_attempt(raw, program_id, target_by_host)
            if attempt is not None:
                nuclei_attempts.append(attempt)
        async with get_session() as db:
            persisted = await persist_deduped_attempts(db, nuclei_attempts)
            await db.commit()

        # Phase-2 detection modules (sensitive-file exposure, CORS, 403 bypass)
        # on the in-scope targets + a sample of their in-scope recon URLs.
        detect_attempts = await self._run_detection(program_id, in_scope_targets, target_by_host, scope_rules, extra_headers)
        takeover_attempts = await self._run_takeover_check(program_id, target_by_host)
        async with get_session() as db:
            await persist_deduped_attempts(db, detect_attempts + takeover_attempts)
            await db.commit()

        await notify_critical_findings(
            program_id, program.name, str(program.workspace_id),
            nuclei_attempts + detect_attempts + takeover_attempts,
        )

        total = persisted + len(detect_attempts) + len(takeover_attempts)
        authenticated = bool(extra_headers)
        log.info(
            "bounty_vulnscan_completed", program_id=program_id, nuclei=persisted,
            detection=len(detect_attempts), takeover=len(takeover_attempts), authenticated=authenticated,
        )
        return {
            "targets": len(in_scope_targets), "findings": total,
            "detection_findings": len(detect_attempts), "takeover_findings": len(takeover_attempts),
            "authenticated": authenticated,
        }

    async def _run_takeover_check(self, program_id, target_by_host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Subdomain takeover check (subzy) against every in-scope target's
        host. Already-installed tool the main ASM pipeline uses
        (workers/scanner/coverage_worker.py), never previously wired into the
        bounty pipeline. A confirmed hit is genuinely confirmed -- subzy's own
        fingerprint match against the live CNAME target IS the proof, no
        further pipeline-side verification needed or possible."""
        hosts = list(target_by_host.keys())[:MAX_DETECT_HOSTS]
        if not hosts:
            return []
        with tempfile.TemporaryDirectory(prefix="asm-bounty-subzy-") as tmpdir_raw:
            results = await run_subzy(hosts, Path(tmpdir_raw))
        attempts: List[Dict[str, Any]] = []
        for host, result in results.items():
            if not result.get("vulnerable"):
                continue
            tid = target_by_host.get(host)
            if tid is None:
                continue
            engine = result.get("engine") or "unknown"
            attempts.append(self._detect_attempt(program_id, tid, "takeover", {
                "technique": f"subdomain-takeover-{engine}".lower(),
                "severity": "high",
                "evidence": {
                    "url": f"https://{host}", "engine": engine, "cname": result.get("cname"),
                    "documentation": result.get("documentation"),
                    "note": f"{host}'s CNAME points to an unclaimed {engine} resource -- subzy fingerprint match.",
                },
            }))
        return attempts

    async def _run_detection(
        self, program_id, in_scope_targets, target_by_host, scope_rules,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Sensitive-file / CORS / 403-bypass detection against in-scope target
        base URLs and a bounded sample of their in-scope recon URLs. Each check
        is a plain bounded GET; findings map back to their owning target."""
        # Base URLs from targets (prefer the probed url), collapsed to the
        # origin (scheme://host). url-type targets carry a path in `.value`
        # (e.g. a promoted "/security.txt" endpoint) -- walking sensitive-file
        # paths underneath that path instead of the true site root produces
        # nonsense URLs, and repeats the same host-level scan once per promoted
        # URL target instead of once per host.
        base_urls: Dict[str, Any] = {}   # origin -> target_id
        for t in in_scope_targets[:MAX_DETECT_HOSTS]:
            meta = t.probe_metadata or {}
            resolved = meta.get("url") or (t.value if "://" in t.value else f"https://{host_from_target(t.value)}")
            parsed = urlparse(resolved)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else resolved
            base_urls.setdefault(origin, t.id)

        # A sample of in-scope recon URLs (for endpoint-level CORS/403).
        async with get_session() as db:
            url_assets = (await db.execute(
                select(BountyAsset.value).where(
                    BountyAsset.program_id == program_id,
                    BountyAsset.asset_type == "url",
                ).limit(400)
            )).scalars().all()
        endpoint_urls: Dict[str, Any] = {}
        js_urls: Dict[str, Any] = {}
        for u in url_assets:
            if not is_target_in_scope(u, scope_rules):
                continue
            tid = target_by_host.get(host_from_target(u))
            if tid is None:
                continue
            # Same suffix check run_katana's own output filter already uses
            # (tools.py) -- reusing the same 400-row fetch above rather than a
            # second query, since url_assets already has everything needed.
            if u.split("?")[0].lower().endswith(".js"):
                if len(js_urls) < MAX_DETECT_JS_FILES:
                    js_urls.setdefault(u, tid)
            else:
                if len(endpoint_urls) < MAX_DETECT_ENDPOINTS:
                    endpoint_urls.setdefault(u, tid)
            if len(endpoint_urls) >= MAX_DETECT_ENDPOINTS and len(js_urls) >= MAX_DETECT_JS_FILES:
                break

        attempts: List[Dict[str, Any]] = []
        # Shared so a given base's catch-all-200 probe (detect.py) fires once
        # per run, not once per host/endpoint that happens to share an origin.
        catch_all_cache: CatchAllCache = {}
        # Sensitive files + CORS on base URLs.
        for base, tid in base_urls.items():
            for f in await check_sensitive_files(base, extra_headers=extra_headers, catch_all_cache=catch_all_cache):
                attempts.append(self._detect_attempt(program_id, tid, "exposure", f))
            for f in await check_cors(base, extra_headers=extra_headers):
                attempts.append(self._detect_attempt(program_id, tid, "cors", f))
            for f in await check_security_headers(base, extra_headers=extra_headers):
                attempts.append(self._detect_attempt(program_id, tid, "headers", f))
        # CORS + 403-bypass on endpoint URLs. 403-bypass deliberately stays
        # unauthenticated -- it specifically measures what an anonymous caller
        # can reach, which a valid session would trivially (and misleadingly)
        # "solve".
        for url, tid in endpoint_urls.items():
            for f in await check_cors(url, extra_headers=extra_headers):
                attempts.append(self._detect_attempt(program_id, tid, "cors", f))
            for f in await check_403_bypass(url, catch_all_cache=catch_all_cache):
                attempts.append(self._detect_attempt(program_id, tid, "403bypass", f))
            # Deeper GraphQL checks (sensitive schema field names, batching
            # acceptance) on any endpoint URL that looks like a GraphQL
            # path -- recon's own graphql_introspection() only records
            # whether introspection is open, not what it actually exposes.
            if GRAPHQL_URL_RE.search(url):
                for f in await graphql_schema_scan(url, extra_headers=extra_headers):
                    attempts.append(self._detect_attempt(program_id, tid, "graphql", f))
                for f in await check_graphql_batching(url, extra_headers=extra_headers):
                    attempts.append(self._detect_attempt(program_id, tid, "graphql", f))
        # Vulnerable/outdated frontend JS library detection -- unauthenticated,
        # doesn't need extra_headers (a JS bundle is served identically to
        # anyone; auth would only change this if the bundle itself were
        # behind a login wall, which none of the URLs collected here are,
        # since js_urls is drawn from the same publicly-crawled asset list
        # as endpoint_urls above).
        for js_url, tid in js_urls.items():
            for f in await check_vulnerable_components(js_url):
                attempts.append(self._detect_attempt(program_id, tid, "components", f))
        return attempts

    def _detect_attempt(self, program_id, target_id, module: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "program_id": program_id,
            "target_id": target_id,
            "module": module,
            "technique": str(finding.get("technique") or module)[:100],
            "severity": finding.get("severity", "info"),
            # Every check that predates graphql_schema_scan/check_graphql_
            # batching only ever returns a result when it's genuinely
            # confirmed, so "confirmed" stays the default -- but the newer
            # checks explicitly mark their own results "inconclusive" and
            # that must survive here, not get silently overwritten.
            "status": finding.get("status", "confirmed"),
            "evidence": finding.get("evidence"),
        }

    def _default_template_dirs(self, profiles: Optional[Any]) -> List[str]:
        if profiles:
            names = [profiles] if isinstance(profiles, str) else list(profiles)
            dirs: List[str] = []
            seen = set()
            for name in names:
                for tmpl_dir in PROFILE_TEMPLATE_DIRS.get(str(name), []):
                    if tmpl_dir not in seen:
                        seen.add(tmpl_dir)
                        dirs.append(tmpl_dir)
            if dirs:
                return dirs
        # No explicit profile configured: default to the broadest coverage
        # this codebase already defines, matching the user's own "broader
        # vulnerability coverage (+ RCE, deserialization, etc.)" request.
        return PROFILE_TEMPLATE_DIRS["deep_authorized"]

    def _build_attempt(
        self,
        raw: Dict[str, Any],
        program_id: str,
        target_by_host: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        template_id = str(raw.get("template-id", ""))[:100]
        if not template_id:
            return None
        matched = raw.get("matched-at") or raw.get("host") or ""
        target_id = target_by_host.get(host_from_target(matched))
        if not target_id:
            # A result nuclei attributes to a host we didn't hand it -- can't
            # attach to a target_id (NOT NULL FK), so it's dropped rather
            # than guessed at.
            log.warning("bounty_vulnscan_unmatched_result", template_id=template_id, matched=matched)
            return None

        info = raw.get("info") or {}
        severity = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "info")
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        if not cve_ids:
            match = CVE_ID_PATTERN.search(template_id) or CVE_ID_PATTERN.search(str(info.get("name", "")))
            if match:
                cve_ids = [match.group(0).upper()]
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        reference = info.get("reference") or []
        if isinstance(reference, str):
            reference = [reference]

        evidence = {
            "template_name": str(info.get("name", template_id))[:500],
            "description": str(info.get("description", ""))[:1000],
            "matched_at": str(matched)[:1000],
            "tags": tags,
            "cve_ids": cve_ids[:10],
            "reference": reference[:10],
            "request": self._clean_text(raw.get("request", "")),
            "response": self._clean_text(raw.get("response", "")),
        }

        return {
            "program_id": program_id,
            "target_id": target_id,
            "module": "nuclei",
            "technique": template_id,
            "severity": severity,
            "status": "confirmed",
            "evidence": evidence,
        }

    def _clean_text(self, value: Any, limit: int = MAX_RAW_FIELD_CHARS) -> str:
        if not isinstance(value, str):
            return ""
        value = value.strip()
        return value[:limit] + ("... [truncated]" if len(value) > limit else "")


if __name__ == "__main__":
    worker = BountyVulnscanWorker()
    asyncio.run(worker.run())

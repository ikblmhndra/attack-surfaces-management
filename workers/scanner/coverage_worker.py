"""Milestone 5 scanner coverage worker.

Consumes `scan.scanner` messages and runs one scanner family per message.
The worker keeps checks non-destructive and persists only actionable findings;
info-only observations stay in phase summaries.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import aiohttp
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.db_models import Asset, Organization, Port, Subdomain, Technology
from workers.discovery.bucket_candidates import generate_bucket_candidates
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running
from workers.secrets_scan import find_secrets
from workers.scanner.scanner_common import (
    complete_phase_with_findings,
    host_from_target,
    make_finding,
    mark_worker_task_complete,
    publish_scanner_completion,
)

log = structlog.get_logger()

PHASE_BY_FAMILY = {
    "tls": "tls",
    "dns": "dns_security",
    "takeover": "takeover",
    "cloud": "cloud_exposure",
    "service": "service_fingerprint",
    "git_secrets": "git_secrets",
    "eol": "eol_check",
    "version_cve": "version_cve",
}

RISKY_PORTS = {
    21: ("ftp", "low", "FTP service exposed"),
    23: ("telnet", "high", "Telnet service exposed"),
    445: ("smb", "high", "SMB service exposed"),
    1433: ("mssql", "high", "MSSQL service exposed"),
    1521: ("oracle", "high", "Oracle database service exposed"),
    2049: ("nfs", "high", "NFS service exposed"),
    2375: ("docker", "critical", "Docker API exposed without TLS"),
    3306: ("mysql", "high", "MySQL service exposed"),
    3389: ("rdp", "high", "RDP service exposed"),
    5432: ("postgres", "high", "PostgreSQL service exposed"),
    5601: ("kibana", "high", "Kibana service exposed"),
    5900: ("vnc", "high", "VNC service exposed"),
    6379: ("redis", "high", "Redis service exposed"),
    9200: ("elasticsearch", "high", "Elasticsearch service exposed"),
    9300: ("elasticsearch", "high", "Elasticsearch transport exposed"),
    27017: ("mongodb", "high", "MongoDB service exposed"),
}

TAKEOVER_PROVIDERS = {
    "github.io": ["There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudapp.net": ["404 Web Site not found"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "readme.io": ["Project doesnt exist"],
    "surge.sh": ["project not found"],
    "webflow.io": ["The page you are looking for doesn't exist"],
}


def _tool_path(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    go_path = Path(f"/go/bin/{name}")
    return str(go_path) if go_path.exists() else None


class ScannerCoverageWorker(BaseWorker):
    QUEUE = "scan.scanner"
    CONCURRENCY = int(os.getenv("SCANNER_CONCURRENCY", "2"))
    PREFETCH_COUNT = 2

    async def process(self, message: Dict[str, Any]) -> None:
        family = str(message.get("family") or "").strip().lower()
        phase = PHASE_BY_FAMILY.get(family)
        scan_id = message.get("scan_id")
        org_id = message.get("org_id")
        workspace_id = message.get("workspace_id")
        config = message.get("config") or {}
        targets = message.get("targets") or []

        if not phase:
            log.warning("scanner_family_unknown", family=family, scan_id=scan_id)
            return

        try:
            async with get_session() as db:
                if not await mark_scan_running(db, scan_id, progress_floor=65):
                    log.info("scanner_skipped_inactive_scan", family=family, scan_id=scan_id)
                    return
                await update_scan_phase(db, scan_id, phase, "running", targets_total=len(targets))

            if family == "tls":
                findings, summary, selected = await self._scan_tls(org_id, workspace_id, targets, config)
            elif family == "dns":
                findings, summary, selected = await self._scan_dns(org_id, workspace_id, targets, config)
            elif family == "takeover":
                findings, summary, selected = await self._scan_takeover(org_id, workspace_id, targets, config)
            elif family == "cloud":
                findings, summary, selected = await self._scan_cloud(org_id, workspace_id, targets, config)
            elif family == "git_secrets":
                findings, summary, selected = await self._scan_git_secrets(org_id, workspace_id, targets, config)
            elif family == "eol":
                findings, summary, selected = await self._scan_eol(org_id, workspace_id, targets, config)
            elif family == "version_cve":
                findings, summary, selected = await self._scan_version_cve(org_id, workspace_id, targets, config)
            else:
                findings, summary, selected = await self._scan_services(org_id, workspace_id, message.get("services") or [], config)

            async with get_session() as db:
                await record_target_selections(
                    db,
                    scan_id=scan_id,
                    phase=phase,
                    targets=[
                        {
                            "target": row["target"],
                            "target_type": row.get("target_type", "host"),
                            "profile": family,
                            "selected": row.get("selected", True),
                            "reasons": row.get("reasons", [f"{family}_scanner_target"]),
                            "skip_reason": row.get("skip_reason"),
                            "metadata": row.get("metadata") or {},
                            "asset_id": row.get("asset_id"),
                        }
                        for row in selected
                    ],
                )

            persisted = await complete_phase_with_findings(
                scan_id=scan_id,
                org_id=org_id,
                workspace_id=workspace_id,
                phase=phase,
                targets_total=len(selected),
                findings=findings,
                summary=summary,
            )
            log.info("scanner_family_completed", family=family, scan_id=scan_id, findings=persisted)
        except Exception as exc:
            log.exception("scanner_family_failed", family=family, scan_id=scan_id, error=str(exc))
            async with get_session() as db:
                await update_scan_phase(db, scan_id, phase, "failed", errors=1, last_error=str(exc)[:500])
                await mark_worker_task_complete(db, scan_id)
            await publish_scanner_completion(scan_id, org_id, workspace_id)

    async def _scan_tls(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        hosts = self._dedupe_hosts(targets)[: int(config.get("tls_max_targets", 200))]
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        for host in hosts:
            observation = await asyncio.to_thread(self._tls_observe, host)
            observations.append({"host": host, **observation})
            if observation.get("error"):
                continue
            days = observation.get("days_until_expiry")
            if days is not None and days < 0:
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="tls_scanner",
                    check_id="tls_expired_certificate",
                    target=f"https://{host}",
                    title="Expired TLS certificate",
                    severity="high",
                    category="expired_certificate",
                    description="The TLS certificate presented by this host is expired.",
                    evidence=f"{host} certificate expired {abs(days)} days ago.",
                    proof=observation,
                    remediation="Renew and deploy a valid TLS certificate for this host.",
                ))
            elif days is not None and days <= int(config.get("tls_expiry_warning_days", 30)):
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="tls_scanner",
                    check_id="tls_certificate_expiring_soon",
                    target=f"https://{host}",
                    title="TLS certificate expires soon",
                    severity="medium" if days <= 14 else "low",
                    category="expired_certificate",
                    description="The TLS certificate is close to expiry and should be renewed before service impact.",
                    evidence=f"{host} certificate expires in {days} days.",
                    proof=observation,
                    remediation="Renew the TLS certificate before the expiration date.",
                ))
            if observation.get("hostname_mismatch"):
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="tls_scanner",
                    check_id="tls_hostname_mismatch",
                    target=f"https://{host}",
                    title="TLS certificate hostname mismatch",
                    severity="medium",
                    category="tls_misconfiguration",
                    description="The TLS certificate does not match the scanned hostname.",
                    evidence=f"{host} is not covered by the certificate SAN/CN values.",
                    proof=observation,
                    remediation="Deploy a certificate whose SAN list covers this hostname.",
                ))

        # Python's ssl module (above) only ever reports on the certificate itself
        # (expiry/hostname) — it can't tell us which TLS versions/ciphers a host
        # accepts. tlsx fills that gap: risk_engine.py already scores weak_cipher/
        # old_tls_version findings under TLS_SECURITY, but nothing ever produced them.
        tlsx_results, tlsx_ran = await self._tlsx_enrich(hosts, config)
        for host, record in tlsx_results.items():
            for version in record.get("version_enum") or []:
                if version in ("ssl30", "tls10"):
                    findings.append(make_finding(
                        org_id=org_id,
                        workspace_id=workspace_id,
                        scanner="tls_scanner",
                        check_id=f"tls_old_version_{version}",
                        target=f"https://{host}",
                        title=f"Deprecated TLS protocol version accepted ({version})",
                        severity="high",
                        category="old_tls_version",
                        description="The host accepts a deprecated, insecure TLS/SSL protocol version.",
                        evidence=f"{host} accepted a connection using {version}.",
                        proof=record,
                        remediation="Disable SSLv3/TLS 1.0 on the server and require TLS 1.2 or higher.",
                    ))
                elif version == "tls11":
                    findings.append(make_finding(
                        org_id=org_id,
                        workspace_id=workspace_id,
                        scanner="tls_scanner",
                        check_id="tls_old_version_tls11",
                        target=f"https://{host}",
                        title="Deprecated TLS 1.1 accepted",
                        severity="medium",
                        category="old_tls_version",
                        description="The host accepts TLS 1.1, deprecated by RFC 8996.",
                        evidence=f"{host} accepted a connection using tls11.",
                        proof=record,
                        remediation="Disable TLS 1.1 on the server and require TLS 1.2 or higher.",
                    ))
            weak_versions = [
                entry.get("version") for entry in (record.get("cipher_enum") or [])
                if entry.get("ciphers")
            ]
            if weak_versions:
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="tls_scanner",
                    check_id="tls_weak_cipher",
                    target=f"https://{host}",
                    title="Weak TLS cipher suite accepted",
                    severity="medium",
                    category="weak_cipher",
                    description="The host negotiates a weak/insecure cipher suite for one or more TLS versions.",
                    evidence=f"{host} accepted a weak cipher for: {', '.join(weak_versions)}.",
                    proof=record,
                    remediation="Restrict the server's cipher suite configuration to modern, strong ciphers only.",
                ))

        selected = [{"target": host, "target_type": "host", "metadata": {"scanner": "tls"}} for host in hosts]
        summary = {
            "scanner_family": "tls",
            "observed": len(observations),
            "findings_candidates": len(findings),
            "tool": "python_ssl",
            "tlsx_ran": tlsx_ran,
            "tlsx_checked": len(tlsx_results),
            "info_observations": observations[:50],
        }
        return findings, summary, selected

    async def _tlsx_enrich(self, hosts: List[str], config: Dict[str, Any]) -> tuple[Dict[str, Dict[str, Any]], bool]:
        """Batch-run tlsx over all hosts for TLS-version/cipher enumeration that
        Python's ssl module can't do. Returns (host -> tlsx record, whether it ran)."""
        tlsx = _tool_path("tlsx")
        if not tlsx or not hosts:
            return {}, False

        results: Dict[str, Dict[str, Any]] = {}
        with tempfile.TemporaryDirectory(prefix="asm-tlsx-") as tmp:
            tmpdir = Path(tmp)
            input_file = tmpdir / "hosts.txt"
            output_file = tmpdir / "tlsx_output.jsonl"
            input_file.write_text("\n".join(hosts))
            cmd = [
                tlsx, "-l", str(input_file),
                "-tv", "-cipher", "-ve", "-ce", "-ct", "weak",
                "-ex", "-ss", "-mm", "-un",
                "-json", "-silent", "-o", str(output_file),
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=int(config.get("tlsx_timeout", 120)))
            except Exception as exc:
                log.warning("tlsx_error", error=str(exc)[:300])
                return {}, False

            if output_file.exists():
                for line in output_file.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = record.get("host")
                    if host:
                        results[host] = record
        return results, True

    def _tls_observe(self, host: str) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
                    cipher = tls.cipher()
            not_after = cert.get("notAfter")
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
            sans = [value for key, value in cert.get("subjectAltName", []) if key.lower() == "dns"]
            names = sans or [item[0][1] for item in cert.get("subject", []) if item and item[0][0] == "commonName"]
            mismatch = not self._host_matches_names(host, names)
            return {
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "days_until_expiry": (expires_at - datetime.now(timezone.utc)).days if expires_at else None,
                "names": names[:25],
                "hostname_mismatch": mismatch,
            }
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:300]}

    def _host_matches_names(self, host: str, names: List[str]) -> bool:
        for name in names:
            name = name.lower().strip()
            if name == host:
                return True
            if name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count("."):
                return True
        return False

    async def _scan_dns(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        roots = self._dedupe_roots(targets)[: int(config.get("dns_security_max_domains", 100))]
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        for domain in roots:
            obs = await asyncio.to_thread(self._dns_observe, domain)
            observations.append({"domain": domain, **obs})
            if obs.get("error"):
                continue
            if not obs.get("spf"):
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="dns_security_scanner",
                    check_id="dns_missing_spf",
                    target=domain,
                    title="Missing SPF record",
                    severity="low",
                    category="missing_spf",
                    description="The domain does not publish an SPF record to define authorized mail senders.",
                    evidence=f"{domain} has no TXT record starting with v=spf1.",
                    proof=obs,
                    remediation="Publish an SPF TXT record for the domain.",
                ))
            if not obs.get("dmarc"):
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="dns_security_scanner",
                    check_id="dns_missing_dmarc",
                    target=domain,
                    title="Missing DMARC record",
                    severity="medium",
                    category="missing_dmarc",
                    description="The domain does not publish a DMARC policy record.",
                    evidence=f"_dmarc.{domain} has no v=DMARC1 TXT record.",
                    proof=obs,
                    remediation="Publish a DMARC TXT record with an enforcement plan.",
                ))
            elif "p=none" in obs.get("dmarc", "").lower():
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="dns_security_scanner",
                    check_id="dns_dmarc_policy_none",
                    target=domain,
                    title="DMARC policy is monitoring only",
                    severity="low",
                    category="dmarc_misconfiguration",
                    description="The DMARC policy is set to p=none and does not enforce handling of failed messages.",
                    evidence=obs.get("dmarc", ""),
                    proof=obs,
                    remediation="Move DMARC toward quarantine or reject after validating legitimate mail flows.",
                ))
        selected = [{"target": domain, "target_type": "domain", "metadata": {"scanner": "dns_security"}} for domain in roots]
        return findings, {"scanner_family": "dns_security", "observed": len(observations), "info_observations": observations[:50]}, selected

    def _dns_observe(self, domain: str) -> Dict[str, Any]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 6
            resolver.timeout = 3
            txt = self._dns_txt(resolver, domain)
            dmarc_txt = self._dns_txt(resolver, f"_dmarc.{domain}")
            mx = [str(r.exchange).rstrip(".") for r in resolver.resolve(domain, "MX")] if self._dns_has(resolver, domain, "MX") else []
            ns = [str(r).rstrip(".") for r in resolver.resolve(domain, "NS")] if self._dns_has(resolver, domain, "NS") else []
            return {
                "spf": next((v for v in txt if v.lower().startswith("v=spf1")), None),
                "dmarc": next((v for v in dmarc_txt if v.lower().startswith("v=dmarc1")), None),
                "mx": mx[:20],
                "ns": ns[:20],
            }
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"[:300]}

    def _dns_txt(self, resolver, name: str) -> List[str]:
        try:
            return ["".join(part.decode() if isinstance(part, bytes) else str(part) for part in record.strings) for record in resolver.resolve(name, "TXT")]
        except Exception:
            return []

    def _dns_has(self, resolver, name: str, record_type: str) -> bool:
        try:
            list(resolver.resolve(name, record_type))
            return True
        except Exception:
            return False

    async def _scan_takeover(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        candidates = await self._takeover_candidates(org_id, workspace_id, targets, int(config.get("takeover_max_targets", 200)))
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []

        subzy_results, subzy_ran = await self._subzy_scan(candidates, config)
        if subzy_ran:
            for candidate in candidates:
                host = candidate["host"]
                result = subzy_results.get(host)
                obs = {**candidate, **(result or {"checked": False})}
                observations.append(obs)
                if result and result.get("vulnerable"):
                    findings.append(make_finding(
                        org_id=org_id,
                        workspace_id=workspace_id,
                        scanner="takeover_scanner",
                        check_id=f"takeover_{(result.get('engine') or 'unknown').lower()}",
                        target=f"https://{host}",
                        title="Potential subdomain takeover",
                        severity="high",
                        category="subdomain_takeover",
                        description="The subdomain points to a third-party service that appears unclaimed.",
                        evidence=f"subzy matched {host} (CNAME {candidate.get('cname')}) against the {result.get('engine')} fingerprint.",
                        proof=result,
                        remediation="Remove the dangling DNS record or claim/configure the referenced third-party service.",
                    ))
        else:
            # subzy binary unavailable — fall back to the lighter marker-matching probe
            timeout = aiohttp.ClientTimeout(total=int(config.get("takeover_http_timeout", 10)))
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for candidate in candidates:
                    obs = await self._takeover_probe(session, candidate)
                    observations.append(obs)
                    if obs.get("vulnerable"):
                        findings.append(make_finding(
                            org_id=org_id,
                            workspace_id=workspace_id,
                            scanner="takeover_scanner",
                            check_id=f"takeover_{obs.get('provider', 'unknown')}",
                            target=f"https://{candidate['host']}",
                            title="Potential subdomain takeover",
                            severity="high",
                            category="subdomain_takeover",
                            description="The subdomain points to a third-party service that appears unclaimed.",
                            evidence=obs.get("evidence", ""),
                            proof=obs,
                            remediation="Remove the dangling DNS record or claim/configure the referenced third-party service.",
                        ))

        if subzy_ran:
            tool_used = "subzy"
        elif not candidates:
            # Nothing to distinguish tools on — no CNAME matched a known provider
            tool_used = "no_candidates"
        else:
            tool_used = "http_marker_match"

        selected = [{"target": c["host"], "target_type": "host", "metadata": {"cname": c.get("cname")}} for c in candidates]
        summary = {
            "scanner_family": "takeover",
            "observed": len(observations),
            "tool": tool_used,
            "info_observations": observations[:50],
        }
        return findings, summary, selected

    async def _subzy_scan(self, candidates: List[Dict[str, str]], config: Dict[str, Any]) -> tuple[Dict[str, Dict[str, Any]], bool]:
        """Batch-run subzy against CNAME-narrowed candidates instead of a hardcoded
        marker-string dict — subzy tracks ~75+ actively-maintained provider
        fingerprints. Returns (host -> subzy record, whether it ran).

        Note: this subzy build's JSON `"vulnerable"` boolean field is unreliable
        (observed `false` even when `"status"` says `"vulnerable"` and the CLI
        console output flags it VULNERABLE) — `status` is the field actually
        trusted here.
        """
        subzy = _tool_path("subzy")
        if not subzy or not candidates:
            return {}, False

        results: Dict[str, Dict[str, Any]] = {}
        with tempfile.TemporaryDirectory(prefix="asm-subzy-") as tmp:
            tmpdir = Path(tmp)
            targets_file = tmpdir / "targets.txt"
            output_file = tmpdir / "subzy_output.json"
            targets_file.write_text("\n".join(c["host"] for c in candidates))
            cmd = [
                subzy, "run",
                "--targets", str(targets_file),
                "--output", str(output_file),
                "--https",
                "--hide_fails",
                "--timeout", str(int(config.get("takeover_http_timeout", 10))),
                "--concurrency", str(int(config.get("subzy_concurrency", 10))),
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=int(config.get("subzy_timeout", 120)))
            except Exception as exc:
                log.warning("subzy_error", error=str(exc)[:300])
                return {}, False

            if output_file.exists():
                try:
                    # subzy (with --hide_fails) writes the literal JSON `null`,
                    # not `[]`, when zero candidates are vulnerable — the
                    # overwhelmingly common case — which json.loads()s to None.
                    records = json.loads(output_file.read_text(errors="ignore") or "[]") or []
                except json.JSONDecodeError:
                    records = []
                for record in records:
                    host = record.get("subdomain")
                    if not host:
                        continue
                    results[host] = {
                        "vulnerable": record.get("status") == "vulnerable",
                        "engine": record.get("engine"),
                        "cname": record.get("cname"),
                        "documentation": record.get("documentation"),
                    }
        return results, True

    async def _takeover_candidates(self, org_id: str, workspace_id: str, targets: List[Any], limit: int) -> List[Dict[str, str]]:
        hosts = set(self._dedupe_hosts(targets))
        async with get_session() as db:
            query = select(Subdomain.fqdn, Subdomain.cname_chain).where(
                Subdomain.org_id == org_id,
                Subdomain.cname_chain.is_not(None),
            )
            rows = (await db.execute(query)).all()
        candidates = []
        for host, cnames in rows:
            if hosts and host not in hosts:
                continue
            for cname in cnames or []:
                cname = str(cname).rstrip(".").lower()
                if any(provider in cname for provider in TAKEOVER_PROVIDERS):
                    candidates.append({"host": host, "cname": cname})
                    break
        return candidates[:limit]

    async def _takeover_probe(self, session: aiohttp.ClientSession, candidate: Dict[str, str]) -> Dict[str, Any]:
        host = candidate["host"]
        cname = candidate.get("cname", "")
        provider = next((p for p in TAKEOVER_PROVIDERS if p in cname), "unknown")
        url = f"https://{host}"
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as response:
                text = await response.text(errors="ignore")
                body = text[:4000]
                for marker in TAKEOVER_PROVIDERS.get(provider, []):
                    if marker.lower() in body.lower():
                        return {
                            "host": host,
                            "cname": cname,
                            "provider": provider,
                            "status": response.status,
                            "vulnerable": True,
                            "evidence": f"{host} CNAME {cname} returned takeover marker: {marker}",
                        }
                return {"host": host, "cname": cname, "provider": provider, "status": response.status, "vulnerable": False}
        except Exception as exc:
            return {"host": host, "cname": cname, "provider": provider, "error": str(exc)[:300], "vulnerable": False}

    async def _scan_cloud(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        cloud_targets = await self._cloud_targets(org_id, workspace_id, targets, int(config.get("cloud_exposure_max_targets", 100)))
        discovered = await self._discover_cloud_buckets(org_id, workspace_id, config)
        known_values = {item["value"] for item in cloud_targets}
        cloud_targets.extend(item for item in discovered if item["value"] not in known_values)
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=int(config.get("cloud_exposure_timeout", 10)))
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for item in cloud_targets:
                obs = await self._cloud_probe(session, item)
                observations.append(obs)
                if obs.get("public"):
                    findings.append(make_finding(
                        org_id=org_id,
                        workspace_id=workspace_id,
                        scanner="cloud_exposure_scanner",
                        check_id=f"cloud_public_{item.get('provider', 'bucket')}",
                        target=item["value"],
                        title="Public cloud storage exposure",
                        severity="high",
                        category="cloud_public_exposure",
                        description="A discovered cloud storage endpoint appears publicly readable.",
                        evidence=f"{item['value']} returned HTTP {obs.get('status')} to a public-read probe.",
                        proof=obs,
                        remediation="Restrict public access or confirm the bucket/container is intentionally public.",
                    ))
        selected = [
            {
                "target": item["value"],
                "target_type": "cloud_bucket",
                "asset_id": item.get("asset_id"),
                "metadata": {
                    "value": item["value"],
                    "provider": item.get("provider"),
                    "exposure_status": item.get("exposure_status"),
                    "probe_url": self._cloud_probe_url(item),
                },
            }
            for item in cloud_targets
        ]
        return findings, {"scanner_family": "cloud_exposure", "observed": len(observations), "info_observations": observations[:50]}, selected

    async def _cloud_targets(self, org_id: str, workspace_id: str, targets: List[Any], limit: int) -> List[Dict[str, Any]]:
        async with get_session() as db:
            result = await db.execute(
                select(Asset).where(
                    Asset.org_id == org_id,
                    Asset.workspace_id == workspace_id,
                    Asset.asset_type == "cloud_bucket",
                    Asset.status == "active",
                ).limit(limit)
            )
            assets = result.scalars().all()
        return [
            {
                "asset_id": asset.id,
                "value": asset.value,
                "provider": ((asset.metadata_ or {}).get("discovery", {}).get("sources") or ["cloud"])[0],
                "exposure_status": asset.exposure_status,
            }
            for asset in assets
        ]

    async def _discover_cloud_buckets(self, org_id: str, workspace_id: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Brand-based S3 bucket-name enumeration.

        cloud/enum/aws-s3-bucket-enum.yaml (the nuclei template this was originally
        meant to wire up via `-var wordlist=<file>`) is self-contained/batteringram
        with no `payloads:` block — empirically verified (manual nuclei runs, including
        a locally patched copy with `payloads:` added) that nuclei v3.11.0 never
        actually loads/executes it regardless of -esc/-var/-dast. Implemented directly
        here instead: generate candidate names from the org's own root domains/company
        name (same reasoning as DNS bruteforce candidates — deterministically derived
        from an already-in-scope entity, not from unrelated third-party content), probe
        each, and only persist an Asset for names that come back with a real bucket
        response (200 open, or 403 exists-but-protected) rather than a DNS/connection
        failure — a non-hit is not a discovery.
        """
        async with get_session() as db:
            org = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
        if not org:
            return []

        seeds = []
        # root_domains is the intended seed source but is frequently empty in
        # practice (orgs are commonly seeded via `domains`/`name` at creation
        # time instead) — fall back through domains/name/company_name rather
        # than silently enumerating nothing for the common case.
        for domain in (org.root_domains or org.domains or []):
            label = str(domain).split(".")[0]
            if label:
                seeds.append(label)
        if org.company_name:
            seeds.append(org.company_name)
        elif org.name:
            seeds.append(str(org.name).split(".")[0])

        candidates = generate_bucket_candidates(
            seeds, max_names=int(config.get("cloud_bucket_wordlist_max_names", 60))
        )
        if not candidates:
            return []

        timeout = aiohttp.ClientTimeout(total=int(config.get("cloud_exposure_timeout", 10)))
        semaphore = asyncio.Semaphore(10)
        confirmed: List[Dict[str, Any]] = []

        async def probe(session: aiohttp.ClientSession, name: str) -> None:
            url = f"https://{name}.s3.amazonaws.com"
            async with semaphore:
                try:
                    async with session.head(url, allow_redirects=True) as response:
                        if response.status in (200, 403):
                            confirmed.append({"name": name, "status": response.status})
                except Exception:
                    return

        async with aiohttp.ClientSession(timeout=timeout) as session:
            await asyncio.gather(*(probe(session, name) for name in candidates))

        if not confirmed:
            return []

        now = datetime.now(timezone.utc)
        results: List[Dict[str, Any]] = []
        async with get_session() as db:
            for hit in confirmed:
                value = f"aws_s3:{hit['name']}"
                stmt = pg_insert(Asset.__table__).values(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    asset_type="cloud_bucket",
                    value=value,
                    discovery_method="bucket_name_enumeration",
                    metadata={"discovery": {"sources": ["aws_s3"], "method": "brand_permutation", "probe_status": hit["status"]}},
                    first_seen=now,
                    last_seen=now,
                ).on_conflict_do_update(
                    constraint="uq_asset_org_type_value",
                    set_={"last_seen": now},
                ).returning(Asset.__table__.c.id)
                row = (await db.execute(stmt)).fetchone()
                if row:
                    results.append({
                        "asset_id": row[0],
                        "value": value,
                        "provider": "aws_s3",
                        "exposure_status": None,
                    })
            await db.commit()
        return results

    async def _cloud_probe(self, session: aiohttp.ClientSession, item: Dict[str, Any]) -> Dict[str, Any]:
        url = self._cloud_probe_url(item)
        try:
            async with session.head(url, allow_redirects=True) as response:
                if response.status in {403, 405}:
                    async with session.get(url, allow_redirects=True) as get_response:
                        text = await get_response.text(errors="ignore")
                        return {"url": url, "source_value": item["value"], "status": get_response.status, "public": get_response.status == 200, "sample": text[:500]}
                return {"url": url, "source_value": item["value"], "status": response.status, "public": response.status == 200}
        except Exception as exc:
            return {"url": url, "source_value": item["value"], "error": str(exc)[:300], "public": False}

    def _cloud_probe_url(self, item: Dict[str, Any]) -> str:
        value = str(item.get("value") or "").strip()
        if value.startswith(("http://", "https://")):
            return value

        provider = str(item.get("provider") or "").lower()
        if ":" in value:
            prefix, bucket = value.split(":", 1)
            provider = provider or prefix.lower()
            value = bucket.strip()

        if provider in {"aws_s3", "s3", "amazon_s3"}:
            return f"https://{value}.s3.amazonaws.com"
        if provider in {"gcs", "google_cloud_storage"}:
            return f"https://storage.googleapis.com/{value}"
        if provider in {"azure_blob", "azure"}:
            return f"https://{value}.blob.core.windows.net"
        return value

    async def _scan_git_secrets(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        """Confirm .git exposure directly (not the keyword-matched nuclei/nikto
        guess) and scan any fetched content for secrets. Self-contained, not
        reactive to nuclei/nikto findings — those run concurrently off the same
        fan-out with no ordering guarantee, so reacting to "a finding already
        exists" would race and frequently find nothing yet."""
        hosts = self._dedupe_hosts(targets)[: int(config.get("git_secrets_max_targets", 200))]
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        timeout = aiohttp.ClientTimeout(total=int(config.get("git_secrets_timeout", 8)))
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for host in hosts:
                obs = await self._git_secrets_probe(session, host)
                observations.append(obs)
                if not obs.get("confirmed"):
                    continue
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="git_secrets_scanner",
                    check_id="exposed_git_confirmed",
                    target=f"https://{host}/.git/HEAD",
                    title="Exposed .git directory (confirmed)",
                    severity="high",
                    category="exposed_git",
                    description="/.git/HEAD is publicly accessible and returned a valid git ref/SHA, "
                                "confirming an exposed repository rather than a keyword-matched guess.",
                    evidence=obs.get("evidence", ""),
                    proof={k: v for k, v in obs.items() if k != "secrets"},
                    remediation="Remove the .git directory from the web root or block access to it at "
                                "the web server/reverse-proxy level.",
                ))
                for secret in obs.get("secrets", []):
                    findings.append(make_finding(
                        org_id=org_id,
                        workspace_id=workspace_id,
                        scanner="git_secrets_scanner",
                        check_id=f"credential_exposure_{secret['type']}",
                        target=f"https://{host}/.git/HEAD",
                        title=f"Credential exposure in exposed .git ({secret['type']})",
                        severity="critical",
                        category="credential_exposure",
                        description="A secret-like value was found in the exposed .git/HEAD or "
                                     ".git/config content. The value is masked below and never "
                                     "stored in full — only a masked preview and a hash for correlation.",
                        evidence=f"Matched a {secret['type']} pattern (masked): {secret['masked']}",
                        proof={"host": host, "secret_type": secret["type"], "secret_masked": secret["masked"], "secret_sha256": secret["sha256"]},
                        remediation="Rotate the exposed credential immediately and remove the .git "
                                     "directory from the web root.",
                    ))
        selected = [{"target": h, "target_type": "host"} for h in hosts]
        summary = {
            "scanner_family": "git_secrets",
            "observed": len(observations),
            "tool": "http_probe",
            "info_observations": [
                {k: v for k, v in obs.items() if k != "secrets"} for obs in observations[:50]
            ],
        }
        return findings, summary, selected

    async def _git_secrets_probe(self, session: aiohttp.ClientSession, host: str) -> Dict[str, Any]:
        head_url = f"https://{host}/.git/HEAD"
        try:
            async with session.get(head_url, allow_redirects=False) as response:
                if response.status != 200:
                    return {"host": host, "status": response.status, "confirmed": False}
                body = (await response.text(errors="ignore"))[:2000]
        except Exception as exc:
            return {"host": host, "error": str(exc)[:300], "confirmed": False}

        stripped = body.strip()
        confirmed = bool(re.match(r"^ref:\s*refs/", stripped) or re.match(r"^[0-9a-f]{40}$", stripped))
        if not confirmed:
            return {"host": host, "status": 200, "confirmed": False, "sample": body[:200]}

        secrets = find_secrets(body)
        config_fetched = False
        try:
            async with session.get(f"https://{host}/.git/config", allow_redirects=False) as cfg_response:
                if cfg_response.status == 200:
                    config_body = (await cfg_response.text(errors="ignore"))[:20000]
                    config_fetched = True
                    secrets.extend(find_secrets(config_body))
        except Exception:
            pass

        return {
            "host": host,
            "status": 200,
            "confirmed": True,
            "head_sample": body[:200],
            "config_fetched": config_fetched,
            "secrets": secrets,
            "evidence": f"{host}/.git/HEAD returned a valid git ref/SHA, confirming an exposed repository.",
        }

    async def _scan_eol(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        """Cross-reference already-detected Technology rows (name+version) —
        collected earlier in the scan by httpx/nuclei tech-detect, not fetched
        here — against endoflife.date. Unlike the other scanner-family checks,
        this makes no requests to the scanned org's own infrastructure at all;
        `targets` is accepted only for interface consistency with the other
        scanner-family dispatch, the actual working set comes straight from
        this org's own already-persisted Technology rows.
        """
        from app.services.eol_intel import get_eol_status

        max_products = int(config.get("eol_max_products", 150))
        async with get_session() as db:
            rows = (await db.execute(
                select(Technology.name, Technology.version, Asset.value, Asset.id)
                .join(Asset, Asset.id == Technology.asset_id)
                .where(
                    Technology.org_id == org_id,
                    Technology.version.is_not(None),
                    Technology.version != "",
                )
                .limit(max_products)
            )).all()

        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        seen_lookups: Dict[tuple, Optional[Dict[str, Any]]] = {}

        for name, version, asset_value, asset_id in rows:
            lookup_key = (name.strip().lower(), version)
            if lookup_key not in seen_lookups:
                async with get_session() as db:
                    seen_lookups[lookup_key] = await get_eol_status(db, name, version)
            status = seen_lookups[lookup_key]
            if status is None:
                continue
            eol_date = status["eol_date"]
            # date isn't JSON-serializable — every other check in this file
            # (_tls_observe's expires_at, above) converts to isoformat before
            # it ever reaches an observation/proof dict; do the same here.
            json_safe_status = {**status, "eol_date": eol_date.isoformat() if eol_date else None}
            observations.append({
                "host": asset_value, "name": name, "version": version, **json_safe_status,
            })
            if not status["is_eol"]:
                continue

            days_since_eol = (datetime.now(timezone.utc).date() - eol_date).days if eol_date else 0
            severity = "high" if days_since_eol > 365 else "medium"

            findings.append(make_finding(
                org_id=org_id,
                workspace_id=workspace_id,
                scanner="eol_scanner",
                check_id=f"eol_{status['product']}_{status['cycle']}",
                target=asset_value,
                title=f"End-of-life software: {name} {version}",
                severity=severity,
                category="eol_software",
                description=(
                    f"{name} {version} (cycle {status['cycle']}) reached end-of-life"
                    f"{' on ' + eol_date.isoformat() if eol_date else ''} and no longer "
                    "receives security updates from its maintainer."
                ),
                evidence=f"{asset_value} runs {name} {version}, matched to endoflife.date cycle {status['cycle']}.",
                proof=json_safe_status,
                remediation=f"Upgrade {name} past {status['cycle']} to a supported release (latest: {status.get('latest_version') or 'see vendor'}).",
            ))

        selected = [{"target": obs["host"], "target_type": "host", "metadata": {"tech": obs["name"], "version": obs["version"]}} for obs in observations]
        summary = {"scanner_family": "eol", "observed": len(observations), "products_checked": len(seen_lookups), "info_observations": observations[:50]}
        return findings, summary, selected

    async def _scan_version_cve(self, org_id: str, workspace_id: str, targets: List[Any], config: Dict[str, Any]):
        """Cross-reference already-detected Technology rows against
        cve.circl.lu's product/version CVE data — catches CVEs nuclei has no
        template for at all, a broader gap than nuclei_worker.py's own
        CVE-confidence system (M7's A2), which only scores confidence for
        CVEs nuclei's own templates already matched. Every finding here is
        explicitly version-inferred, not confirmed (see version_cve_intel.py's
        module docstring for why), and carries a low, fixed confidence_score
        so risk_engine.py's existing confidence-based penalty dampening
        applies the same way it already does for nuclei's own low-confidence
        CVE matches. Same safe pattern as _scan_eol: reads an already-
        populated table (no cross-worker race — Technology rows are written
        during this same discovery stage, before scanner-family dispatch,
        unlike WebEndpoint rows which are written by a concurrently-scheduled
        crawl worker — see web_crawl_worker.py's own GraphQL check for why
        that distinction mattered)."""
        from app.services.version_cve_intel import get_matching_cves, VERSION_MATCH_CONFIDENCE, _severity_from_cvss

        max_products = int(config.get("version_cve_max_products", 100))
        async with get_session() as db:
            rows = (await db.execute(
                select(Technology.name, Technology.version, Asset.value)
                .join(Asset, Asset.id == Technology.asset_id)
                .where(
                    Technology.org_id == org_id,
                    Technology.version.is_not(None),
                    Technology.version != "",
                )
                .limit(max_products)
            )).all()

        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        seen_lookups: Dict[tuple, List[Dict[str, Any]]] = {}

        for name, version, asset_value in rows:
            lookup_key = (name.strip().lower(), version)
            if lookup_key not in seen_lookups:
                async with get_session() as db:
                    seen_lookups[lookup_key] = await get_matching_cves(db, name, version)
            matches = seen_lookups[lookup_key]
            observations.append({"host": asset_value, "name": name, "version": version, "cve_count": len(matches)})

            for cve in matches:
                findings.append(make_finding(
                    org_id=org_id,
                    workspace_id=workspace_id,
                    scanner="version_cve_correlation",
                    check_id=f"version_cve_{cve['cve_id'].lower()}",
                    target=asset_value,
                    title=f"Potential {cve['cve_id']}: {name} {version} matches a known-affected version range",
                    severity=_severity_from_cvss(cve.get("cvss_score")),
                    category="known_cve",
                    description=(
                        f"{name} {version}'s version falls within {cve['cve_id']}'s published "
                        f"affected-version range. This is inferred from version comparison alone — not "
                        f"a confirmed exploit or template match — the running instance may already carry "
                        f"a vendor-backported fix without a version-string change. "
                        f"{cve.get('description', '')[:300]}"
                    ),
                    evidence=f"{asset_value} runs {name} {version}, within {cve['cve_id']}'s published affected range.",
                    proof={
                        "cve_id": cve["cve_id"],
                        "cvss_score": cve.get("cvss_score"),
                        "confidence": "low",
                        "confidence_score": VERSION_MATCH_CONFIDENCE,
                        "detection_method": "version_range_correlation",
                        "detected_version": version,
                    },
                    remediation=f"Upgrade {name} past {version}, or confirm via vendor advisory whether "
                                f"this specific build already carries a backported fix for {cve['cve_id']}.",
                    references=[f"https://cve.circl.lu/cve/{cve['cve_id']}"],
                    cve_ids=[cve["cve_id"]],
                ))

        selected = [{"target": obs["host"], "target_type": "host", "metadata": {"tech": obs["name"], "version": obs["version"]}} for obs in observations]
        summary = {"scanner_family": "version_cve", "observed": len(observations), "products_checked": len(seen_lookups), "info_observations": observations[:50]}
        return findings, summary, selected

    async def _scan_services(self, org_id: str, workspace_id: str, services: List[Dict[str, Any]], config: Dict[str, Any]):
        services = services[: int(config.get("service_fingerprint_max_targets", 200))]
        enriched = await self._nmap_enrich_services(services, config)
        findings: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        for item in enriched:
            port = int(item.get("port") or 0)
            observations.append(item)
            if port not in RISKY_PORTS:
                continue
            service, severity, title = RISKY_PORTS[port]
            target = f"{item.get('ip')}:{port}"
            findings.append(make_finding(
                org_id=org_id,
                workspace_id=workspace_id,
                scanner="service_fingerprint_scanner",
                check_id=f"exposed_{service}_{port}",
                target=target,
                title=title,
                severity=severity,
                category="exposed_service",
                description=f"The {service.upper()} service is reachable on a public scan target.",
                evidence=f"{target} is open. Service metadata: {json.dumps(item, default=str)[:1000]}",
                proof=item,
                remediation="Restrict service exposure with firewall rules, VPN, allowlists, or bind it to private interfaces when possible.",
            ))
        selected = [{"target": f"{s.get('ip')}:{s.get('port')}", "target_type": "service", "metadata": s} for s in services]
        return findings, {"scanner_family": "service_fingerprint", "observed": len(observations), "nmap_available": bool(_tool_path("nmap")), "info_observations": observations[:50]}, selected

    async def _nmap_enrich_services(self, services: List[Dict[str, Any]], config: Dict[str, Any]) -> List[Dict[str, Any]]:
        nmap = _tool_path("nmap")
        if not nmap or not config.get("service_nmap_version_light", True):
            return services
        enriched = [dict(item) for item in services]
        with tempfile.TemporaryDirectory(prefix="asm-service-") as tmp:
            tmpdir = Path(tmp)
            for item in enriched[: int(config.get("service_nmap_max_targets", 50))]:
                ip = item.get("ip")
                port = str(item.get("port"))
                if not ip or not port:
                    continue
                output = tmpdir / f"nmap-{ip.replace(':', '_')}-{port}.json"
                cmd = [nmap, "-sV"]
                if config.get("nmap_use_version_light", True):
                    cmd.append("--version-light")
                cmd.extend(["-Pn", "-p", port, "-oX", str(output), str(ip)])
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    await asyncio.wait_for(proc.communicate(), timeout=int(config.get("service_nmap_timeout", 45)))
                    item["nmap_version_light"] = output.read_text(errors="ignore")[:3000] if output.exists() else ""
                except Exception as exc:
                    item["nmap_error"] = str(exc)[:300]
        return enriched

    def _dedupe_hosts(self, targets: List[Any]) -> List[str]:
        seen = set()
        hosts = []
        for target in targets:
            raw = target.get("target") if isinstance(target, dict) else target
            host = host_from_target(str(raw))
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        return hosts

    def _dedupe_roots(self, targets: List[Any]) -> List[str]:
        import tldextract
        roots = []
        seen = set()
        for host in self._dedupe_hosts(targets):
            ext = tldextract.extract(host)
            root = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
            if root and root not in seen:
                seen.add(root)
                roots.append(root)
        return roots


if __name__ == "__main__":
    worker = ScannerCoverageWorker()
    asyncio.run(worker.run())

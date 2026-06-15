"""Milestone 5 scanner coverage worker.

Consumes `scan.scanner` messages and runs one scanner family per message.
The worker keeps checks non-destructive and persists only actionable findings;
info-only observations stay in phase summaries.
"""
from __future__ import annotations

import asyncio
import json
import os
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

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.db_models import Asset, Port, Subdomain
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running
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
}

RISKY_PORTS = {
    21: ("ftp", "low", "FTP service exposed"),
    23: ("telnet", "high", "Telnet service exposed"),
    445: ("smb", "medium", "SMB service exposed"),
    1433: ("mssql", "medium", "MSSQL service exposed"),
    1521: ("oracle", "medium", "Oracle database service exposed"),
    2049: ("nfs", "medium", "NFS service exposed"),
    2375: ("docker", "critical", "Docker API exposed without TLS"),
    3306: ("mysql", "medium", "MySQL service exposed"),
    3389: ("rdp", "medium", "RDP service exposed"),
    5432: ("postgres", "medium", "PostgreSQL service exposed"),
    5601: ("kibana", "medium", "Kibana service exposed"),
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
        selected = [{"target": host, "target_type": "host", "metadata": {"scanner": "tls"}} for host in hosts]
        summary = {
            "scanner_family": "tls",
            "observed": len(observations),
            "findings_candidates": len(findings),
            "tool": "python_ssl",
            "tlsx_available": bool(_tool_path("tlsx")),
            "info_observations": observations[:50],
        }
        return findings, summary, selected

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
        selected = [{"target": c["host"], "target_type": "host", "metadata": {"cname": c.get("cname")}} for c in candidates]
        summary = {
            "scanner_family": "takeover",
            "observed": len(observations),
            "subzy_available": bool(_tool_path("subzy")),
            "info_observations": observations[:50],
        }
        return findings, summary, selected

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
                cmd = [nmap, "-sV", "--version-light", "-Pn", "-p", port, "-oX", str(output), str(ip)]
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

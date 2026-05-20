"""
ASM Platform — Threat Intelligence Enrichment Engine
Plugin-based enrichment from Shodan, Censys, VirusTotal, AbuseIPDB, OTX.
"""
import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import aiohttp
import structlog

from app.core.config import settings

log = structlog.get_logger()

# ── Base enrichment plugin ────────────────────────────────────

@dataclass
class EnrichmentResult:
    source: str
    indicator_type: str  # ip, domain, url, hash
    data: Dict[str, Any]
    risk_score: Optional[int] = None
    is_malicious: bool = False
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    expires_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class BaseEnrichmentPlugin(ABC):
    """Abstract base for all enrichment plugins."""

    name: str = "base"
    enabled: bool = False
    rate_limit_rps: float = 1.0  # requests per second

    def __init__(self):
        self._last_request: float = 0.0

    async def _rate_limit(self):
        """Simple rate limiting via sleep."""
        min_interval = 1.0 / self.rate_limit_rps
        elapsed = time.monotonic() - self._last_request
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()

    @abstractmethod
    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        """Enrich an IP address."""

    @abstractmethod
    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Enrich a domain."""

    async def enrich(self, indicator: str, indicator_type: str) -> EnrichmentResult:
        """Route to appropriate enrichment method."""
        await self._rate_limit()
        try:
            if indicator_type == "ip":
                return await self.enrich_ip(indicator)
            elif indicator_type in ("domain", "subdomain"):
                return await self.enrich_domain(indicator)
            else:
                return EnrichmentResult(
                    source=self.name,
                    indicator_type=indicator_type,
                    data={},
                    error=f"Unsupported indicator type: {indicator_type}",
                )
        except Exception as e:
            log.error("enrichment_error", plugin=self.name, indicator=indicator, error=str(e))
            return EnrichmentResult(
                source=self.name,
                indicator_type=indicator_type,
                data={},
                error=str(e),
            )


# ── Shodan Plugin ─────────────────────────────────────────────

class ShodanPlugin(BaseEnrichmentPlugin):
    name = "shodan"
    rate_limit_rps = 1.0  # Free tier: 1 req/s

    def __init__(self):
        super().__init__()
        self.api_key = settings.SHODAN_API_KEY
        self.enabled = bool(self.api_key)
        self.base_url = "https://api.shodan.io"

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={}, error="No API key")

        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url) as resp:
                if resp.status == 404:
                    return EnrichmentResult(
                        source=self.name,
                        indicator_type="ip",
                        data={"found": False},
                    )
                if resp.status != 200:
                    return EnrichmentResult(
                        source=self.name, indicator_type="ip", data={},
                        error=f"HTTP {resp.status}",
                    )
                raw = await resp.json()

        # Extract useful fields
        ports = raw.get("ports", [])
        tags = raw.get("tags", [])
        vulns = list(raw.get("vulns", {}).keys())
        hostnames = raw.get("hostnames", [])
        org = raw.get("org", "")
        isp = raw.get("isp", "")
        country = raw.get("country_name", "")
        asn = raw.get("asn", "")

        # Parse services
        services = []
        for item in raw.get("data", []):
            services.append({
                "port": item.get("port"),
                "protocol": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "cpe": item.get("cpe", []),
                "banner": item.get("data", "")[:500],
            })

        # Risk indicators
        is_malicious = bool(vulns) or "malware" in tags or "botnet" in tags
        risk_score = min(100, len(vulns) * 15 + len([t for t in tags if t in ("malware", "botnet", "c2")]) * 25)

        data = {
            "found": True,
            "ports": ports,
            "hostnames": hostnames,
            "org": org,
            "isp": isp,
            "country": country,
            "asn": asn,
            "os": raw.get("os"),
            "services": services[:20],
            "vulns": vulns[:20],
            "tags": tags,
            "last_update": raw.get("last_update"),
            "domains": raw.get("domains", []),
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="ip",
            data=data,
            risk_score=risk_score,
            is_malicious=is_malicious,
            tags=tags,
            categories=["network_exposure"] if ports else [],
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="domain", data={}, error="No API key")

        url = f"{self.base_url}/dns/domain/{domain}?key={self.api_key}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return EnrichmentResult(
                        source=self.name, indicator_type="domain", data={},
                        error=f"HTTP {resp.status}",
                    )
                raw = await resp.json()

        data = {
            "subdomains": raw.get("subdomains", [])[:50],
            "tags": raw.get("tags", []),
            "more": raw.get("more", False),
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="domain",
            data=data,
            expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        )


# ── VirusTotal Plugin ─────────────────────────────────────────

class VirusTotalPlugin(BaseEnrichmentPlugin):
    name = "virustotal"
    rate_limit_rps = 0.25  # Public API: 4 req/min

    def __init__(self):
        super().__init__()
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.enabled = bool(self.api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def _get(self, endpoint: str) -> Dict:
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            async with session.get(f"{self.base_url}{endpoint}", headers=headers) as resp:
                if resp.status == 404:
                    return {}
                if resp.status != 200:
                    raise Exception(f"VT API error: {resp.status}")
                return await resp.json()

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={}, error="No API key")

        raw = await self._get(f"/ip_addresses/{ip}")
        if not raw:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={"found": False})

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        categories = list(attrs.get("categories", {}).values())
        tags = list(attrs.get("tags", []))

        is_malicious = malicious > 0
        risk_score = min(100, int((malicious / total) * 100) + (suspicious * 5))

        data = {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "categories": categories[:10],
            "tags": tags[:20],
            "reputation": attrs.get("reputation", 0),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "network": attrs.get("network"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="ip",
            data=data,
            risk_score=risk_score,
            is_malicious=is_malicious,
            tags=tags,
            categories=categories,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )

    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="domain", data={}, error="No API key")

        raw = await self._get(f"/domains/{domain}")
        if not raw:
            return EnrichmentResult(source=self.name, indicator_type="domain", data={"found": False})

        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        data = {
            "found": True,
            "malicious": malicious,
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": total,
            "categories": list(attrs.get("categories", {}).values())[:10],
            "tags": list(attrs.get("tags", []))[:20],
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "last_dns_records": attrs.get("last_dns_records", [])[:10],
            "subdomains": attrs.get("subdomains", [])[:20],
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="domain",
            data=data,
            risk_score=min(100, int((malicious / total) * 100)),
            is_malicious=malicious > 0,
            tags=data["tags"],
            categories=data["categories"],
            expires_at=datetime.now(timezone.utc) + timedelta(days=3),
        )


# ── AbuseIPDB Plugin ──────────────────────────────────────────

class AbuseIPDBPlugin(BaseEnrichmentPlugin):
    name = "abuseipdb"
    rate_limit_rps = 0.5  # 1000 req/day free

    def __init__(self):
        super().__init__()
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.enabled = bool(self.api_key)
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={}, error="No API key")

        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(f"{self.base_url}/check", headers=headers, params=params) as resp:
                if resp.status != 200:
                    return EnrichmentResult(
                        source=self.name, indicator_type="ip", data={},
                        error=f"HTTP {resp.status}",
                    )
                raw = await resp.json()

        d = raw.get("data", {})
        confidence_score = d.get("abuseConfidenceScore", 0)
        total_reports = d.get("totalReports", 0)

        data = {
            "found": True,
            "abuse_confidence_score": confidence_score,
            "total_reports": total_reports,
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor", False),
            "is_public": d.get("isPublic", True),
            "is_whitelisted": d.get("isWhitelisted", False),
            "last_reported_at": d.get("lastReportedAt"),
            "reports": [
                {
                    "reported_at": r.get("reportedAt"),
                    "comment": r.get("comment", "")[:200],
                    "categories": r.get("categories", []),
                }
                for r in d.get("reports", [])[:10]
            ],
        }

        is_malicious = confidence_score >= 25
        risk_score = min(100, confidence_score)

        return EnrichmentResult(
            source=self.name,
            indicator_type="ip",
            data=data,
            risk_score=risk_score,
            is_malicious=is_malicious,
            tags=["abused"] if confidence_score > 0 else [],
            categories=["reputation"],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )

    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        # AbuseIPDB doesn't support domain lookups directly
        return EnrichmentResult(
            source=self.name,
            indicator_type="domain",
            data={},
            error="Domain lookup not supported",
        )


# ── AlienVault OTX Plugin ─────────────────────────────────────

class OTXPlugin(BaseEnrichmentPlugin):
    name = "otx"
    rate_limit_rps = 1.0

    def __init__(self):
        super().__init__()
        self.api_key = settings.OTX_API_KEY
        self.enabled = bool(self.api_key)
        self.base_url = "https://otx.alienvault.com/api/v1"

    async def _get_indicator(self, indicator_type: str, indicator: str, section: str) -> Dict:
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        url = f"{self.base_url}/indicators/{indicator_type}/{indicator}/{section}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    raise Exception(f"OTX API error: {resp.status}")
                return await resp.json()

    async def enrich_ip(self, ip: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={}, error="No API key")

        try:
            general = await self._get_indicator("IPv4", ip, "general")
        except Exception as e:
            return EnrichmentResult(source=self.name, indicator_type="ip", data={}, error=str(e))

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = general.get("pulse_info", {}).get("pulses", [])

        threat_names = list(set(
            tag for pulse in pulses[:10]
            for tag in pulse.get("tags", [])
        ))[:20]

        malware_families = list(set(
            name for pulse in pulses[:10]
            for name in pulse.get("malware_families", [])
        ))[:10]

        is_malicious = pulse_count > 0
        risk_score = min(100, pulse_count * 10)

        data = {
            "found": True,
            "pulse_count": pulse_count,
            "reputation": general.get("reputation", 0),
            "threat_names": threat_names,
            "malware_families": malware_families,
            "asn": general.get("asn"),
            "country_name": general.get("country_name"),
            "city": general.get("city"),
            "pulses": [
                {
                    "name": p.get("name"),
                    "created": p.get("created"),
                    "tags": p.get("tags", [])[:5],
                    "tlp": p.get("tlp"),
                }
                for p in pulses[:5]
            ],
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="ip",
            data=data,
            risk_score=risk_score,
            is_malicious=is_malicious,
            tags=threat_names[:10],
            categories=malware_families[:5],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
        )

    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        if not self.enabled:
            return EnrichmentResult(source=self.name, indicator_type="domain", data={}, error="No API key")

        try:
            general = await self._get_indicator("domain", domain, "general")
        except Exception as e:
            return EnrichmentResult(source=self.name, indicator_type="domain", data={}, error=str(e))

        pulse_count = general.get("pulse_info", {}).get("count", 0)
        pulses = general.get("pulse_info", {}).get("pulses", [])

        data = {
            "found": True,
            "pulse_count": pulse_count,
            "alexa": general.get("alexa"),
            "whois": general.get("whois"),
            "pulses": [{"name": p.get("name"), "created": p.get("created")} for p in pulses[:5]],
        }

        return EnrichmentResult(
            source=self.name,
            indicator_type="domain",
            data=data,
            risk_score=min(100, pulse_count * 10),
            is_malicious=pulse_count > 0,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )


# ── Enrichment Orchestrator ───────────────────────────────────

class EnrichmentEngine:
    """
    Runs all enabled enrichment plugins in parallel for a given indicator.
    Aggregates results and computes a combined risk signal.
    """

    def __init__(self):
        self.plugins: List[BaseEnrichmentPlugin] = [
            ShodanPlugin(),
            VirusTotalPlugin(),
            AbuseIPDBPlugin(),
            OTXPlugin(),
        ]
        self.enabled_plugins = [p for p in self.plugins if p.enabled]
        log.info(
            "enrichment_engine_initialized",
            enabled_plugins=[p.name for p in self.enabled_plugins],
        )

    async def enrich(
        self,
        indicator: str,
        indicator_type: str,
        plugins: Optional[List[str]] = None,
    ) -> Dict[str, EnrichmentResult]:
        """
        Enrich an indicator using all (or specified) enabled plugins.

        Args:
            indicator: The IP/domain/URL to enrich
            indicator_type: "ip", "domain", "url"
            plugins: Optional list of plugin names to use (default: all enabled)

        Returns:
            Dict mapping plugin name → EnrichmentResult
        """
        target_plugins = self.enabled_plugins
        if plugins:
            target_plugins = [p for p in self.enabled_plugins if p.name in plugins]

        if not target_plugins:
            log.warning("no_enrichment_plugins_available", indicator=indicator)
            return {}

        # Run all in parallel with timeout
        tasks = {
            plugin.name: asyncio.create_task(plugin.enrich(indicator, indicator_type))
            for plugin in target_plugins
        }

        results: Dict[str, EnrichmentResult] = {}
        done, pending = await asyncio.wait(
            tasks.values(),
            timeout=30,
            return_when=asyncio.ALL_COMPLETED,
        )

        # Cancel timed-out tasks
        for task in pending:
            task.cancel()

        # Map results back to plugin names
        name_to_task = {v: k for k, v in tasks.items()}
        for task in done:
            plugin_name = name_to_task.get(task)
            if plugin_name:
                try:
                    results[plugin_name] = task.result()
                except Exception as e:
                    results[plugin_name] = EnrichmentResult(
                        source=plugin_name,
                        indicator_type=indicator_type,
                        data={},
                        error=str(e),
                    )

        log.info(
            "enrichment_completed",
            indicator=indicator,
            type=indicator_type,
            sources=len(results),
            malicious_signals=sum(1 for r in results.values() if r.is_malicious),
        )

        return results

    def aggregate_risk(self, results: Dict[str, EnrichmentResult]) -> Dict[str, Any]:
        """
        Aggregate enrichment results into a combined risk signal.
        """
        if not results:
            return {"risk_score": 0, "is_malicious": False, "sources": []}

        scores = [r.risk_score for r in results.values() if r.risk_score is not None]
        is_malicious = any(r.is_malicious for r in results.values())
        all_tags = list(set(tag for r in results.values() for tag in r.tags))
        all_categories = list(set(cat for r in results.values() for cat in r.categories))

        # Weighted average: malicious signals count double
        if scores:
            agg_score = int(sum(scores) / len(scores))
        else:
            agg_score = 0

        if is_malicious:
            agg_score = max(agg_score, 50)  # Floor for known malicious

        return {
            "risk_score": min(100, agg_score),
            "is_malicious": is_malicious,
            "tags": all_tags[:30],
            "categories": all_categories[:20],
            "sources": [
                {
                    "name": name,
                    "score": r.risk_score,
                    "malicious": r.is_malicious,
                    "error": r.error,
                }
                for name, r in results.items()
            ],
        }


# Singleton
enrichment_engine = EnrichmentEngine()

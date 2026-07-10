"""
ASM Platform — Scan Service
Creates scan records and publishes tasks to RabbitMQ queue.
"""
from copy import deepcopy
from typing import Any, Dict, List
from uuid import UUID

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.models import Asset, Organization, Scan, WebEndpoint
from app.services.scan_profiles import apply_scan_profile, child_profile_config
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once

log = structlog.get_logger()

ENDPOINT_NUCLEI_TIMEOUT_CAP = 600

DEFAULT_MODULES = {
    "full":      ["discovery", "port", "crawl", "nuclei", "scanner", "screenshot", "enrich"],
    "quick":     ["discovery", "crawl", "nuclei"],
    "discovery": ["discovery"],
    "vuln":      ["nuclei", "scanner"],
}

DEFAULT_SCAN_POLICY = {
    "scan_profile": "deep_authorized",
    "modules": DEFAULT_MODULES["full"],
    "budgets": {
        "scan_timeout": 900,
        # These feed into apply_scan_profile() as "incoming" overrides, which win
        # over SCAN_PROFILES/PROFILE_RUNTIME_CAPS defaults (profile.update(incoming)) —
        # they must be kept in sync with those, not left at the old batch-size-1 values.
        "nuclei_batch_size": 8,
        "crawl_nuclei_batch_size": 8,
        "crawl_nuclei_scan_timeout": ENDPOINT_NUCLEI_TIMEOUT_CAP,
        "max_endpoints": 2500,
        "max_hosts": 200,
    },
    "crawl": {
        "depth": 2,
        "use_gau": True,
        # Deliberately no "fuzz"/"fuzz_max_targets" key here: this dict is scan-type-
        # agnostic (merged in before the profile is even resolved, via
        # _policy_to_config()), so a hardcoded value here would clobber every profile's
        # own fuzz setting identically — including deep_authorized's fuzz=True. Leave
        # it unset so SCAN_PROFILES' own default flows through, unless an org
        # explicitly overrides it via Organization.scan_policy.
    },
    "nuclei": {
        "automatic_scan": True,
        "use_tech_tags": True,
        "template_timeout": 8,
        "exclude_tags": ["dos", "bruteforce", "intrusive"],
    },
    "rate_limits": {
        "httpx_threads": 25,
        "nuclei_concurrency": 6,
        "nuclei_bulk_size": 6,
    },
    "enrichment": {
        "enabled": True,
        "baseline": True,
        "api_plugins": True,
    },
}

DEFAULT_SCAN_CONFIG = {
    "full": {
        "scan_profile": "deep_authorized",
        "crawl": True,
        # fuzz intentionally omitted (was hardcoded False here, silently undoing
        # SCAN_PROFILES["deep_authorized"]'s fuzz=True the same way batch_size was
        # undone in Milestone 6 — profile.update(incoming) lets this dict always win).
        # Kept in sync with SCAN_PROFILES["deep_authorized"]/PROFILE_RUNTIME_CAPS —
        # this dict is merged in as apply_scan_profile()'s "incoming" override, which
        # wins over the profile default, so a stale value here silently undoes that fix.
        "nuclei_batch_size": 8,
        "crawl_nuclei_batch_size": 8,
        "crawl_nuclei_scan_timeout": ENDPOINT_NUCLEI_TIMEOUT_CAP,
        "scan_timeout": 900,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 6,
        "bulk_size": 6,
        "automatic_scan": True,
        "use_tech_tags": True,
        "crawl_use_gau": True,
        "crawl_depth": 2,
        "crawl_max_targets": 200,
        "crawl_max_total_urls": 2500,
        "fuzz_max_targets": 25,
        "enrichment_enabled": True,
        "scanner_enabled": True,
        "tls_max_targets": 200,
        "dns_security_max_domains": 100,
        "takeover_max_targets": 200,
        "cloud_exposure_max_targets": 100,
        "service_fingerprint_max_targets": 200,
        "nuclei_validate_endpoint_liveness": True,
    },
    "quick": {
        "scan_profile": "safe",
        "crawl": True,
        "fuzz": False,
        "nuclei_batch_size": 8,
        "crawl_nuclei_batch_size": 5,
        "scan_timeout": 300,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 15,
        "bulk_size": 15,
        "automatic_scan": False,
        "use_tech_tags": False,
        "vuln_depth": "critical",
        "crawl_use_gau": True,
        "crawl_depth": 1,
        "crawl_max_targets": 100,
        "crawl_max_total_urls": 1000,
        "enrichment_enabled": False,
        "scanner_enabled": False,
        "nuclei_validate_endpoint_liveness": True,
    },
    "vuln": {
        "scan_profile": "deep_authorized",
        "nuclei_batch_size": 8,
        "scan_timeout": 900,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 8,
        "bulk_size": 8,
        "automatic_scan": True,
        "use_tech_tags": True,
        "enrichment_enabled": False,
        "scanner_enabled": True,
        "nuclei_validate_endpoint_liveness": True,
    },
}

CONFIG_LIMITS = {
    "nuclei_batch_size": (1, 50),
    "crawl_nuclei_batch_size": (1, 50),
    "scan_timeout": (60, 3600),
    "crawl_nuclei_scan_timeout": (60, 1200),
    "template_timeout": (3, 30),
    "concurrency": (1, 20),
    "bulk_size": (1, 20),
    "crawl_depth": (1, 4),
    "crawl_max_targets": (1, 200),
    "crawl_max_total_urls": (100, 5000),
    "crawl_httpx_threads": (1, 75),
    "fuzz_max_targets": (1, 50),
    "tls_max_targets": (1, 500),
    "dns_security_max_domains": (1, 250),
    "takeover_max_targets": (1, 500),
    "cloud_exposure_max_targets": (1, 250),
    "service_fingerprint_max_targets": (1, 500),
}

# nuclei_batch_size/crawl_nuclei_batch_size caps were 4/1/1 (effectively one
# nuclei subprocess per host or per URL) to isolate a slow target from
# blocking a whole batch. That isolation already exists more cheaply at two
# other layers: nuclei's own per-template timeout (-timeout, 6-8s) and
# nuclei_worker.py::_run_nuclei's TimeoutError handler, which still parses
# whatever partial results were written before a batch-level timeout kills
# the process. Batch size 1 meant paying nuclei's template-load/init overhead
# once per host/URL instead of once per batch — the dominant cost of a full
# scan (observed: ~35 single-target batches x 2.5-6 min each). Raised to 8
# across the board, matching scan_profiles.py's SCAN_PROFILES values (which
# this cap would otherwise silently override back down).
PROFILE_RUNTIME_CAPS = {
    "deep_authorized": {
        "scan_timeout": 900,
        "nuclei_batch_size": 8,
        "crawl_nuclei_batch_size": 8,
        "crawl_nuclei_scan_timeout": ENDPOINT_NUCLEI_TIMEOUT_CAP,
    },
    "endpoint": {
        "scan_timeout": ENDPOINT_NUCLEI_TIMEOUT_CAP,
        "nuclei_batch_size": 8,
        "concurrency": 4,
        "bulk_size": 4,
    },
    "limited": {
        "scan_timeout": 600,
        "nuclei_batch_size": 8,
        "concurrency": 4,
        "bulk_size": 4,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _clamp_config(config: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(config or {})
    for key, (min_value, max_value) in CONFIG_LIMITS.items():
        if key not in sanitized:
            continue
        try:
            sanitized[key] = max(min_value, min(max_value, int(sanitized[key])))
        except (TypeError, ValueError):
            sanitized.pop(key, None)
    return sanitized


def _apply_runtime_caps(config: Dict[str, Any]) -> Dict[str, Any]:
    capped = dict(config or {})
    profile = str(capped.get("scan_profile") or "")
    for key, max_value in PROFILE_RUNTIME_CAPS.get(profile, {}).items():
        if key not in capped:
            continue
        try:
            capped[key] = min(int(capped[key]), max_value)
        except (TypeError, ValueError):
            capped[key] = max_value

    if profile == "deep_authorized" and not capped.get("nuclei_include_info_templates", False):
        severities = capped.get("severities") or []
        capped["severities"] = [severity for severity in severities if severity != "info"]

    return capped


def _policy_to_config(policy: Dict[str, Any]) -> Dict[str, Any]:
    budgets = policy.get("budgets", {}) if isinstance(policy.get("budgets"), dict) else {}
    crawl = policy.get("crawl", {}) if isinstance(policy.get("crawl"), dict) else {}
    nuclei = policy.get("nuclei", {}) if isinstance(policy.get("nuclei"), dict) else {}
    rate_limits = policy.get("rate_limits", {}) if isinstance(policy.get("rate_limits"), dict) else {}
    enrichment = policy.get("enrichment", {}) if isinstance(policy.get("enrichment"), dict) else {}

    config = {
        "scan_profile": policy.get("scan_profile"),
        "scan_timeout": budgets.get("scan_timeout"),
        "nuclei_batch_size": budgets.get("nuclei_batch_size"),
        "crawl_nuclei_batch_size": budgets.get("crawl_nuclei_batch_size"),
        "crawl_nuclei_scan_timeout": budgets.get("crawl_nuclei_scan_timeout"),
        "crawl_max_total_urls": budgets.get("max_endpoints"),
        "crawl_max_targets": budgets.get("max_hosts"),
        "crawl_depth": crawl.get("depth"),
        "crawl_use_gau": crawl.get("use_gau"),
        "fuzz": crawl.get("fuzz"),
        "fuzz_max_targets": crawl.get("fuzz_max_targets"),
        "automatic_scan": nuclei.get("automatic_scan"),
        "use_tech_tags": nuclei.get("use_tech_tags"),
        "nuclei_profiles": nuclei.get("nuclei_profiles"),
        "template_timeout": nuclei.get("template_timeout"),
        "exclude_tags": nuclei.get("exclude_tags"),
        "crawl_httpx_threads": rate_limits.get("httpx_threads"),
        "concurrency": rate_limits.get("nuclei_concurrency"),
        "bulk_size": rate_limits.get("nuclei_bulk_size"),
        "enrichment_enabled": enrichment.get("enabled", True),
        "enrichment_baseline": enrichment.get("baseline", True),
    }
    return {key: value for key, value in config.items() if value is not None}


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_nuclei_asset_scan(
        self,
        *,
        org_id: UUID,
        workspace_id: UUID,
        created_by: UUID,
        config: Dict[str, Any],
        scan_profile: str = "deep_authorized",
        include_hosts: bool = True,
        include_endpoints: bool = True,
        include_limited: bool = True,
        max_hosts: int = 200,
        max_endpoints: int = 50,
    ) -> Scan:
        """Queue nuclei directly against already-discovered assets and endpoints."""
        host_targets: List[str] = []
        endpoint_targets: List[str] = []

        if include_hosts and max_hosts > 0:
            host_targets = await self._discovered_nuclei_hosts(
                org_id=org_id,
                workspace_id=workspace_id,
                include_limited=include_limited,
                limit=max_hosts,
            )

        if include_endpoints and max_endpoints > 0:
            endpoint_targets = await self._discovered_nuclei_endpoints(
                org_id=org_id,
                workspace_id=workspace_id,
                limit=max_endpoints,
            )

        host_targets = _dedupe_preserve_order(host_targets)
        endpoint_targets = _dedupe_preserve_order(endpoint_targets)
        if not host_targets and not endpoint_targets:
            raise ValueError("No eligible discovered assets or endpoints are available for nuclei")

        base_config = _apply_runtime_caps(_clamp_config(apply_scan_profile(
            {
                **DEFAULT_SCAN_CONFIG["vuln"],
                **(config or {}),
                "scan_profile": scan_profile,
                "scan_type": "nuclei_assets",
                "automatic_scan": True,
                "use_tech_tags": True,
            },
            "vuln",
        )))
        endpoint_config = child_profile_config(
            "endpoint",
            base_config,
            {
                "scan_timeout": min(
                    int(base_config.get("crawl_nuclei_scan_timeout", ENDPOINT_NUCLEI_TIMEOUT_CAP)),
                    ENDPOINT_NUCLEI_TIMEOUT_CAP,
                ),
                "template_timeout": min(int(base_config.get("template_timeout", 6)), 6),
                "concurrency": min(int(base_config.get("concurrency", 4)), 4),
                "bulk_size": min(int(base_config.get("bulk_size", 4)), 4),
                "nuclei_batch_size": 8,
                "severities": ["critical", "high", "medium"],
            },
        )

        host_batch_size = max(1, min(int(base_config.get("nuclei_batch_size", 8)), 8))
        endpoint_batch_size = max(1, min(int(endpoint_config.get("nuclei_batch_size", 8)), 8))
        host_batches = _chunks(host_targets, host_batch_size)
        endpoint_batches = _chunks(endpoint_targets, endpoint_batch_size)
        total_batches = len(host_batches) + len(endpoint_batches)

        scan = Scan(
            org_id=org_id,
            workspace_id=workspace_id,
            created_by=created_by,
            scan_type="nuclei_assets",
            status="queued",
            modules=["nuclei"],
            config={
                **base_config,
                "source": "discovered_assets",
                "include_hosts": include_hosts,
                "include_endpoints": include_endpoints,
                "include_limited": include_limited,
                "target_counts": {
                    "hosts": len(host_targets),
                    "endpoints": len(endpoint_targets),
                    "batches": total_batches,
                },
            },
            phase_status={
                "nuclei": {
                    "status": "queued",
                    "source": "discovered_assets",
                    "expected_batches": total_batches,
                    "targets_total": len(host_targets) + len(endpoint_targets),
                    "host_targets": len(host_targets),
                    "endpoint_targets": len(endpoint_targets),
                }
            },
            total_tasks=total_batches,
        )
        self.db.add(scan)
        await self.db.flush()

        for batch in host_batches:
            self.db.add(create_queue_event(
                routing_key="scan.nuclei",
                payload={
                    "scan_id": str(scan.id),
                    "org_id": str(org_id),
                    "workspace_id": str(workspace_id),
                    "targets": batch,
                    "config": base_config,
                },
                priority=7,
                headers={"coordinator": {"scan_id": str(scan.id), "nuclei_expected": 1, "screenshot_done": True}},
                aggregate_type="scan",
                aggregate_id=str(scan.id),
            ))

        for batch in endpoint_batches:
            self.db.add(create_queue_event(
                routing_key="scan.nuclei",
                payload={
                    "scan_id": str(scan.id),
                    "org_id": str(org_id),
                    "workspace_id": str(workspace_id),
                    "targets": batch,
                    "config": endpoint_config,
                },
                priority=7,
                headers={"coordinator": {"scan_id": str(scan.id), "nuclei_expected": 1, "screenshot_done": True}},
                aggregate_type="scan",
                aggregate_id=str(scan.id),
            ))

        await self.db.commit()
        await self.db.refresh(scan)
        await dispatch_pending_outbox_once(limit=max(5, total_batches))
        log.info(
            "nuclei_asset_scan_queued",
            scan_id=str(scan.id),
            org_id=str(org_id),
            hosts=len(host_targets),
            endpoints=len(endpoint_targets),
            batches=total_batches,
        )
        return scan

    async def create_and_queue(
        self,
        org_id: UUID,
        workspace_id: UUID,
        created_by: UUID,
        scan_type: str,
        modules: List[str],
        config: Dict[str, Any],
        org: Organization,
    ) -> Scan:
        """Create a scan record in DB and publish discovery task to queue."""
        raw_org_policy = org.scan_policy or {}
        org_policy = _deep_merge(DEFAULT_SCAN_POLICY, raw_org_policy)
        policy_modules = (
            raw_org_policy.get("modules")
            if isinstance(raw_org_policy.get("modules"), list)
            else None
        )
        scan_modules = modules or policy_modules or DEFAULT_MODULES.get(scan_type, DEFAULT_MODULES["full"])
        effective_config = _clamp_config({
            **DEFAULT_SCAN_CONFIG.get(scan_type, {}),
            **_policy_to_config(org_policy),
            **(config or {}),
        })
        effective_config = _apply_runtime_caps(_clamp_config(apply_scan_profile(effective_config, scan_type)))
        if not effective_config.get("enrichment_enabled", True):
            scan_modules = [module for module in scan_modules if module != "enrich"]
        if not effective_config.get("scanner_enabled", True):
            scan_modules = [module for module in scan_modules if module != "scanner"]

        scan = Scan(
            org_id=org_id,
            workspace_id=workspace_id,
            created_by=created_by,
            scan_type=scan_type,
            status="queued",
            modules=scan_modules,
            config=effective_config,
            phase_status={module: {"status": "queued"} for module in scan_modules},
            total_tasks=len(scan_modules),
        )
        self.db.add(scan)
        await self.db.flush()

        self.db.add(
            create_queue_event(
                routing_key="scan.discovery",
                payload={
                    "scan_id": str(scan.id),
                    "org_id": str(org_id),
                    "workspace_id": str(workspace_id),
                    "targets": {
                        "domains": (org.domains or []) + (org.root_domains or []),
                        "ip_ranges": org.ip_ranges or [],
                        "asns": org.asns or [],
                        "scope_allow_patterns": org.scope_allow_patterns or [],
                        "scope_deny_patterns": org.scope_deny_patterns or [],
                        "company_name": org.company_name,
                        "organization_name": org.name,
                    },
                    "config": {
                        **effective_config,
                        "scan_type": scan_type,
                        "modules": scan_modules,
                    },
                    "triggered_by": "api",
                },
                priority=7,
                aggregate_type="scan",
                aggregate_id=str(scan.id),
            )
        )
        await self.db.commit()
        await self.db.refresh(scan)
        await dispatch_pending_outbox_once(limit=5)
        log.info("scan_queued", scan_id=str(scan.id), scan_type=scan_type, org_id=str(org_id))

        return scan

    async def _discovered_nuclei_hosts(
        self,
        *,
        org_id: UUID,
        workspace_id: UUID,
        include_limited: bool,
        limit: int,
    ) -> List[str]:
        liveness = ["alive"]
        exposure = ["exposed"]
        if include_limited:
            exposure.append("limited")

        result = await self.db.execute(
            select(Asset.value)
            .where(
                Asset.org_id == org_id,
                Asset.workspace_id == workspace_id,
                Asset.deleted_at.is_(None),
                Asset.status == "active",
                Asset.asset_type == "subdomain",
                Asset.is_in_scope.is_(True),
                Asset.scope_status.in_(["in_scope", "probable"]),
                Asset.liveness_status.in_(liveness),
                Asset.exposure_status.in_(exposure),
            )
            .order_by(Asset.criticality.desc(), Asset.last_seen.desc())
            .limit(max(1, min(int(limit), 500)))
        )
        return [value for value in result.scalars().all() if value]

    async def _discovered_nuclei_endpoints(
        self,
        *,
        org_id: UUID,
        workspace_id: UUID,
        limit: int,
    ) -> List[str]:
        result = await self.db.execute(
            select(WebEndpoint.url)
            .where(
                WebEndpoint.org_id == org_id,
                WebEndpoint.workspace_id == workspace_id,
                WebEndpoint.status_class.in_(["ok", "redirect", "auth_required", "server_error", "rate_limited"]),
                WebEndpoint.score >= 25,
            )
            .order_by(
                WebEndpoint.score.desc(),
                WebEndpoint.source_count.desc(),
                WebEndpoint.last_seen.desc(),
                WebEndpoint.url.asc(),
            )
            .limit(max(1, min(int(limit), 500)))
        )
        return [url for url in result.scalars().all() if url]


def _chunks(values: List[str], size: int) -> List[List[str]]:
    return [values[i:i + size] for i in range(0, len(values), size)]


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped

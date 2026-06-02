"""
ASM Platform — Scan Service
Creates scan records and publishes tasks to RabbitMQ queue.
"""
from copy import deepcopy
from typing import Any, Dict, List
from uuid import UUID

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.models import Organization, Scan
from app.services.scan_profiles import apply_scan_profile
from app.services.outbox_service import create_queue_event, dispatch_pending_outbox_once

log = structlog.get_logger()

DEFAULT_MODULES = {
    "full":      ["discovery", "port", "crawl", "nuclei", "screenshot", "enrich"],
    "quick":     ["discovery", "crawl", "nuclei"],
    "discovery": ["discovery"],
    "vuln":      ["nuclei"],
}

DEFAULT_SCAN_POLICY = {
    "scan_profile": "deep_authorized",
    "modules": DEFAULT_MODULES["full"],
    "budgets": {
        "scan_timeout": 1800,
        "nuclei_batch_size": 15,
        "crawl_nuclei_batch_size": 15,
        "crawl_nuclei_scan_timeout": 600,
        "max_endpoints": 2500,
        "max_hosts": 200,
    },
    "crawl": {
        "depth": 2,
        "use_gau": True,
        "fuzz": False,
        "fuzz_max_targets": 25,
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
        "fuzz": False,
        "nuclei_batch_size": 15,
        "crawl_nuclei_batch_size": 15,
        "scan_timeout": 1800,
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
    },
    "quick": {
        "scan_profile": "safe",
        "crawl": True,
        "fuzz": False,
        "nuclei_batch_size": 50,
        "crawl_nuclei_batch_size": 25,
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
    },
    "vuln": {
        "scan_profile": "deep_authorized",
        "nuclei_batch_size": 25,
        "scan_timeout": 900,
        "template_timeout": 8,
        "retries": 0,
        "concurrency": 8,
        "bulk_size": 8,
        "automatic_scan": True,
        "use_tech_tags": True,
        "enrichment_enabled": False,
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
        "template_timeout": nuclei.get("template_timeout"),
        "exclude_tags": nuclei.get("exclude_tags"),
        "crawl_httpx_threads": rate_limits.get("httpx_threads"),
        "concurrency": rate_limits.get("nuclei_concurrency"),
        "bulk_size": rate_limits.get("nuclei_bulk_size"),
        "enrichment_enabled": enrichment.get("enabled", True),
        "enrichment_baseline": enrichment.get("baseline", True),
        "enrichment_api_plugins": enrichment.get("api_plugins", True),
    }
    return {key: value for key, value in config.items() if value is not None}


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db

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
        effective_config = _clamp_config(apply_scan_profile(effective_config, scan_type))
        if not effective_config.get("enrichment_enabled", True):
            scan_modules = [module for module in scan_modules if module != "enrich"]

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

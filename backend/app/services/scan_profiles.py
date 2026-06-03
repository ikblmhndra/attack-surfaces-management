"""
Central scan profiles and target candidate selection.
"""
from copy import deepcopy
from typing import Any, Dict, List, Optional

from app.services.asset_validation import should_scan_validated_asset, validation_skip_reason

SAFE_EXCLUDED_TAGS = ["dos", "bruteforce", "intrusive", "destructive", "unsafe"]

PROFILE_TEMPLATE_DIRS = {
    "safe": [
        "http/cves",
        "http/exposures",
        "http/misconfiguration",
        "http/takeovers",
        "dns",
        "ssl",
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
    "deep_authorized": [
        "http/cves",
        "http/vulnerabilities",
        "http/exposures",
        "http/misconfiguration",
        "http/default-logins",
        "http/takeovers",
        "http/exposed-panels",
        "dns",
        "ssl",
        "network/cves",
        "network/vulnerabilities",
        "network/exposures",
    ],
    "endpoint": [
        "http/cves",
        "http/vulnerabilities",
        "http/exposures",
        "http/misconfiguration",
        "http/default-logins",
        "http/takeovers",
        "http/exposed-panels",
    ],
    "limited": [
        "http/exposures",
        "http/misconfiguration",
        "http/takeovers",
        "http/exposed-panels",
    ],
}

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "safe": {
        "scan_profile": "safe",
        "vuln_depth": "critical",
        "automatic_scan": False,
        "use_tech_tags": False,
        "severities": ["critical", "high"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["safe"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 600,
        "template_timeout": 8,
        "concurrency": 6,
        "bulk_size": 6,
    },
    "default": {
        "scan_profile": "default",
        "vuln_depth": "default",
        "automatic_scan": True,
        "use_tech_tags": True,
        "severities": ["critical", "high", "medium", "low"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["default"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 900,
        "template_timeout": 8,
        "concurrency": 8,
        "bulk_size": 8,
        "nuclei_batch_size": 10,
        "crawl_nuclei_max_targets": 30,
        "crawl_nuclei_batch_size": 6,
        "crawl_nuclei_scan_timeout": 300,
    },
    "deep_authorized": {
        "scan_profile": "deep_authorized",
        "vuln_depth": "full",
        "automatic_scan": True,
        "use_tech_tags": True,
        "severities": ["critical", "high", "medium", "low"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["deep_authorized"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 900,
        "template_timeout": 8,
        "concurrency": 6,
        "bulk_size": 6,
        "nuclei_batch_size": 4,
        "crawl_nuclei_max_targets": 25,
        "crawl_nuclei_batch_size": 3,
        "crawl_nuclei_scan_timeout": 300,
    },
    "endpoint": {
        "scan_profile": "endpoint",
        "vuln_depth": "endpoint",
        "automatic_scan": False,
        "use_tech_tags": True,
        "severities": ["critical", "high", "medium"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["endpoint"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 600,
        "template_timeout": 6,
        "concurrency": 4,
        "bulk_size": 4,
        "nuclei_batch_size": 5,
    },
    "limited": {
        "scan_profile": "limited",
        "vuln_depth": "default",
        "automatic_scan": False,
        "use_tech_tags": False,
        "severities": ["critical", "high", "medium"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["limited"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 600,
        "template_timeout": 8,
        "concurrency": 4,
        "bulk_size": 4,
        "nuclei_batch_size": 8,
    },
}

SCAN_PROFILE_LABELS = {
    "safe": "Safe",
    "default": "Default",
    "deep_authorized": "Deep Authorized",
    "endpoint": "Endpoint",
    "limited": "Limited",
}

HTTP_CRAWL_STATUS_CLASSES = {"ok", "redirect"}
HTTP_STANDARD_STATUS_CLASSES = {"ok", "redirect"}
HTTP_LIMITED_STATUS_CLASSES = {"auth_required", "server_error", "rate_limited"}


def normalize_scan_profile(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    normalized = str(value).strip().lower().replace("-", "_")
    aliases = {
        "deep": "deep_authorized",
        "full": "deep_authorized",
        "critical": "safe",
        "quick": "safe",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in SCAN_PROFILES else None


def resolve_scan_profile(scan_type: str, config: Optional[Dict[str, Any]] = None) -> str:
    config = config or {}
    requested = normalize_scan_profile(config.get("scan_profile"))
    if requested:
        return requested

    depth = normalize_scan_profile(config.get("vuln_depth"))
    if depth:
        return depth

    defaults = {
        "full": "deep_authorized",
        "vuln": "deep_authorized",
        "manual_nuclei": "deep_authorized",
        "quick": "safe",
        "discovery": "safe",
    }
    return defaults.get(scan_type, "default")


def apply_scan_profile(config: Optional[Dict[str, Any]], scan_type: str) -> Dict[str, Any]:
    incoming = dict(config or {})
    profile_name = resolve_scan_profile(scan_type, incoming)
    profile = deepcopy(SCAN_PROFILES[profile_name])
    profile.update(incoming)
    profile["scan_profile"] = profile_name

    excluded = list(dict.fromkeys([*SAFE_EXCLUDED_TAGS, *(profile.get("exclude_tags") or [])]))
    profile["exclude_tags"] = excluded
    return profile


def profile_config(name: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    profile_name = normalize_scan_profile(name) or "default"
    config = deepcopy(SCAN_PROFILES[profile_name])
    config.update(overrides or {})
    config["scan_profile"] = profile_name
    config["exclude_tags"] = list(dict.fromkeys([*SAFE_EXCLUDED_TAGS, *(config.get("exclude_tags") or [])]))
    return config


def child_profile_config(name: str, base: Optional[Dict[str, Any]] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a scanner sub-profile while preserving safe operational budgets from the parent config."""
    base = dict(base or {})
    inherited = {
        key: value for key, value in base.items()
        if key not in {"scan_profile", "vuln_depth", "template_dirs", "automatic_scan", "severities"}
    }
    inherited.update(overrides or {})
    return profile_config(name, inherited)


def classify_http_status(status_code: Optional[int]) -> str:
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


def dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def build_target_candidates(
    *,
    subdomains: List[str],
    ips: List[str],
    config: Dict[str, Any],
    direct_targets: Optional[List[str]] = None,
    alive_hosts: Optional[Dict[str, Dict[str, Any]]] = None,
    validation_by_host: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    profile_name = resolve_scan_profile(config.get("scan_type", "full"), config)
    alive_hosts = alive_hosts or {}
    validation_by_host = validation_by_host or {}
    skipped_by_status: Dict[str, int] = {}
    skipped_by_validation: Dict[str, int] = {}
    web_standard: List[str] = []
    web_limited: List[str] = []
    crawl_targets: List[Dict[str, Any]] = []
    screenshot_targets: List[str] = []
    validation_skipped_targets: List[Dict[str, Any]] = []
    tech_map: Dict[str, List[Any]] = {}

    if direct_targets:
        web_standard = dedupe_preserve_order(direct_targets)
    else:
        for host in dedupe_preserve_order(subdomains):
            info = alive_hosts.get(host) or {}
            validation = validation_by_host.get(host) or info.get("validation") or {}
            require_validation = bool(config.get("enforce_scope_validation", True))
            if not should_scan_validated_asset(validation, require_validation=require_validation):
                reason = validation_skip_reason(validation)
                skipped_by_validation[reason] = skipped_by_validation.get(reason, 0) + 1
                validation_skipped_targets.append({
                    "host": host,
                    "reason": reason,
                    "validation": validation,
                })
                continue
            status_class = info.get("status_class") or classify_http_status(info.get("status_code"))
            url = info.get("url")
            technologies = info.get("technologies", [])

            if status_class in HTTP_STANDARD_STATUS_CLASSES:
                web_standard.append(host)
                if url and config.get("crawl", True):
                    crawl_targets.append({
                        "host": host,
                        "url": url,
                        "status_code": info.get("status_code"),
                        "status_class": status_class,
                        "technologies": technologies,
                    })
            elif status_class in HTTP_LIMITED_STATUS_CLASSES:
                web_limited.append(host)
            else:
                skipped_by_status[status_class] = skipped_by_status.get(status_class, 0) + 1

            if status_class in (HTTP_CRAWL_STATUS_CLASSES | HTTP_LIMITED_STATUS_CLASSES):
                screenshot_targets.append(host)
            if url:
                tech_map[url] = technologies

    network_targets = dedupe_preserve_order(ips)
    candidates = {
        "profile": profile_name,
        "web_standard_targets": dedupe_preserve_order(web_standard),
        "web_limited_targets": dedupe_preserve_order(web_limited),
        "crawl_targets": crawl_targets,
        "network_targets": network_targets,
        "screenshot_targets": dedupe_preserve_order(screenshot_targets),
        "validation_skipped_targets": validation_skipped_targets,
        "tech_map": tech_map,
        "summary": {
            "profile": profile_name,
            "web_standard": len(dedupe_preserve_order(web_standard)),
            "web_limited": len(dedupe_preserve_order(web_limited)),
            "crawl": len(crawl_targets),
            "network": len(network_targets),
            "screenshot": len(dedupe_preserve_order(screenshot_targets)),
            "direct": len(direct_targets or []),
            "skipped_by_status": skipped_by_status,
            "skipped_by_validation": skipped_by_validation,
        },
    }
    return candidates

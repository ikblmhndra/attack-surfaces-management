"""
Central scan profiles and target candidate selection.
"""
from copy import deepcopy
from typing import Any, Dict, List, Optional

from app.services.asset_validation import should_scan_validated_asset, validation_skip_reason

SAFE_EXCLUDED_TAGS = ["dos", "bruteforce", "intrusive", "destructive", "unsafe"]

PROFILE_TEMPLATE_DIRS = {
    "web_baseline": [
        "http/cves",
        "http/vulnerabilities",
        "http/exposures",
        "http/misconfiguration",
        "http/default-logins",
        "http/exposed-panels",
    ],
    "endpoint_high_signal": [
        "http/cves",
        "http/vulnerabilities",
        "http/exposures",
        "http/misconfiguration",
        "http/default-logins",
        "http/takeovers",
        "http/exposed-panels",
    ],
    "exposure_misconfig": [
        "http/exposures",
        "http/misconfiguration",
        "http/default-logins",
        "http/exposed-panels",
    ],
    "network_safe": [
        "network/cves",
        "network/vulnerabilities",
        "network/exposures",
        # Never selected by any profile before this fix — confirmed present on
        # disk (e.g. apache-dubbo-unauth.yaml, clickhouse-unauth.yaml), same
        # -t-compatible shape as the three dirs above it.
        "network/misconfig",
    ],
    "tls_dns": [
        "dns",
        "ssl",
    ],
    "takeover": [
        "http/takeovers",
    ],
    "cloud_exposure": [
        "cloud",
        "http/exposures",
    ],
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
        "nuclei_profiles": ["web_baseline", "tls_dns", "takeover"],
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
        "nuclei_profiles": ["web_baseline", "tls_dns", "takeover"],
        "vuln_depth": "default",
        "automatic_scan": True,
        "use_tech_tags": True,
        # "info" is included deliberately: nuclei tags ~98% of its exposed-panels
        # templates and ~half its exposures templates as severity "info" — those
        # feed the platform's own highest-weighted risk category (exposure_mgmt,
        # 18%) and info_leakage (8%). _is_low_value_info_finding() in
        # nuclei_worker.py already filters pure tech-fingerprinting noise
        # (favicon-detect, waf-detect, etc.) out of whatever "info" comes back.
        "severities": ["critical", "high", "medium", "low", "info"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["default"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        # port_worker.py's own fallback is "top-100" — "ports" was never set by
        # any profile, so on-demand scans (the path real users trigger) got a
        # much narrower port range than the scheduler's own scheduled scans
        # (which already hardcode "top-1000"). Custom app ports (3000, 8080,
        # 9000, etc.) live outside naabu's top-100 list.
        "ports": "top-1000",
        "scan_timeout": 900,
        "template_timeout": 8,
        "concurrency": 8,
        "bulk_size": 8,
        "nuclei_batch_size": 10,
        "crawl_nuclei_max_targets": 30,
        # Was 1 (one nuclei subprocess per crawled URL) — see
        # web_crawl_worker.py::_publish_selected_nuclei for why that's fixed
        # to allow up to 10 now. This is the actual value read there
        # (config.get("crawl_nuclei_batch_size", 25)); the code-level clamp
        # alone doesn't help if the profile pins the value below it.
        "crawl_nuclei_batch_size": 8,
        "crawl_nuclei_scan_timeout": 600,
    },
    "deep_authorized": {
        "scan_profile": "deep_authorized",
        "nuclei_profiles": ["web_baseline", "network_safe", "tls_dns", "takeover", "cloud_exposure"],
        "vuln_depth": "full",
        "automatic_scan": True,
        "use_tech_tags": True,
        # See "default" profile above for why "info" is included here — this is
        # the profile actually used by "full"/"vuln" scans (the primary
        # user-facing path), so under-covering it defeats the point of the fix.
        # nuclei_include_info_templates=True bypasses _apply_runtime_caps'
        # info-stripping safety net in scan_service.py, which exists for this
        # exact profile.
        "severities": ["critical", "high", "medium", "low", "info"],
        "nuclei_include_info_templates": True,
        # Nuclei "workflows/" (207 templates) chain multiple templates
        # conditionally and are never selected by any profile before this fix —
        # confirmed via `nuclei -h` these load via -w, not -t, and (per a live
        # -validate dry run) require the nuclei process's CWD to be the
        # templates root for their relative template references to resolve
        # (see nuclei_worker.py's subprocess cwd=). Scoped to this profile only,
        # matching how fuzz/js_analysis_enabled are already scoped below —
        # workflows are multi-step and heavier than a single template match.
        "nuclei_workflows_enabled": True,
        "template_dirs": PROFILE_TEMPLATE_DIRS["deep_authorized"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        # See "default" profile above — same port-range gap, same fix.
        "ports": "top-1000",
        "scan_timeout": 900,
        "template_timeout": 8,
        # Kept in sync with scan_service.py's DEFAULT_SCAN_CONFIG["full"/"vuln"]
        # (that dict is what "incoming" actually resolves to in practice — see
        # its comments — but keeping this profile's own value correct too
        # avoids this file silently documenting a stale intent).
        "concurrency": 20,
        "bulk_size": 20,
        "nuclei_batch_size": 8,
        # Was 25 — *below* the "default" profile's own 30, backwards for the
        # platform's most-thorough tier. Confirmed against a real scan
        # (kpi.go.id): 112 crawled endpoints scored high enough to be
        # eligible, only 25 got a nuclei pass — 87 legitimately interesting
        # endpoints were crawled but never vuln-scanned. Bumped in proportion
        # to this profile's other budgets vs. "default" (concurrency/bulk_size
        # are ~2.5x default's), not to the uncapped code-level fallback (200)
        # — still bounded to protect scan wall-clock time.
        "crawl_nuclei_max_targets": 100,
        # See "default" profile above — same fix, same reasoning.
        "crawl_nuclei_batch_size": 8,
        "crawl_nuclei_scan_timeout": 600,
        # Content/directory fuzzing (ffuf) is fully implemented (discovery_worker.py
        # ::_fuzz_endpoints, web_crawl_worker.py::_run_ffuf) but was never enabled —
        # every scan profile left it off. This is the authorized/deep scan profile,
        # the one place it belongs; DEFAULT_SCAN_CONFIG/DEFAULT_SCAN_POLICY in
        # scan_service.py must NOT re-clobber this back to False (see that file).
        "fuzz": True,
        "fuzz_max_targets": 25,
        # Milestone 19: ffuf was only ever fuzzing one directory level with a
        # bare wordlist — the literal "depth" tuning the wordlist expansion
        # earlier this session didn't cover. -recursion (bounded by depth 2,
        # so it can't run away) lets ffuf descend into directories it finds;
        # -e widens each wordlist entry with common sensitive-file suffixes
        # (".bak"/".old"/".zip" etc. catch backup/config files a bare
        # directory-name wordlist entry alone would miss). Both bounded by
        # the same -maxtime/-rate budget every other fuzz run already has —
        # this makes better use of that existing time budget, not a bigger one.
        "fuzz_recursion_depth": 2,
        "fuzz_extensions": ".bak,.old,.zip,.tar.gz,.sql,.log,.swp,.orig,.save,.config",
        # JS analysis re-fetches JS files the crawler already discovered (no new
        # targets, no extra crawl surface) to extract hidden endpoints/secrets/
        # subdomains — same read-only-GET posture as everything else this
        # profile already does, so it's on by default here rather than gated
        # further.
        "js_analysis_enabled": True,
        "js_analysis_max_files": 50,
        # nmap's --version-light flag skips more thorough version-detection
        # probes for speed; this profile only nmaps a small, already-bounded
        # set of discovered ports (service_fingerprint_max_targets), so the
        # accuracy trade is worth it for the authorized/deep profile
        # specifically — full -sV feeds directly into Patch Hygiene risk
        # scoring. (Named nmap_use_version_light, not nmap_version_light —
        # that name is already used for the per-service dict key storing
        # nmap's raw output text in coverage_worker.py.)
        "nmap_use_version_light": False,
        # subfinder's own default (10 min) cuts passive-source enumeration off
        # before slower sources (e.g. certificate-transparency-adjacent APIs)
        # finish returning for a thorough scan.
        "subfinder_max_time": 15,
    },
    "endpoint": {
        "scan_profile": "endpoint",
        "nuclei_profiles": ["endpoint_high_signal"],
        "vuln_depth": "endpoint",
        "automatic_scan": False,
        "use_tech_tags": True,
        # Crawled endpoints are exactly where exposed-panel/exposure "info"
        # templates hit (see "default" profile above) — this is the profile
        # that runs against real discovered URLs, not just root hosts.
        "severities": ["critical", "high", "medium", "info"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["endpoint"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        "scan_timeout": 600,
        "template_timeout": 6,
        "concurrency": 4,
        "bulk_size": 4,
        "nuclei_batch_size": 1,
    },
    "limited": {
        "scan_profile": "limited",
        "nuclei_profiles": ["exposure_misconfig", "takeover"],
        "vuln_depth": "default",
        "automatic_scan": False,
        "use_tech_tags": False,
        "severities": ["critical", "high", "medium"],
        "template_dirs": PROFILE_TEMPLATE_DIRS["limited"],
        "exclude_tags": SAFE_EXCLUDED_TAGS,
        # See "default"/"deep_authorized" above — same port-range gap (naabu's
        # own fallback is top-100), same fix. "limited" is about scope
        # restriction, not scan speed, so it gets the same port range as the
        # other authorized-use profiles rather than "safe"'s narrower default.
        "ports": "top-1000",
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
        if key not in {"scan_profile", "vuln_depth", "nuclei_profiles", "template_dirs", "automatic_scan", "severities"}
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

from app.services.scan_service import (
    DEFAULT_SCAN_CONFIG,
    DEFAULT_SCAN_POLICY,
    _apply_runtime_caps,
    _clamp_config,
    _deep_merge,
    _policy_to_config,
)
from app.services.scan_profiles import (
    SAFE_EXCLUDED_TAGS,
    apply_scan_profile,
    build_target_candidates,
    child_profile_config,
    resolve_scan_profile,
)


def _effective_config(scan_type: str, org_policy_override=None, request_config=None):
    """Replicates create_and_queue()'s full merge chain end to end — the same
    style of test that would have caught Milestone 6's batch-size bug on the
    first pass, since it exercises every config layer (DEFAULT_SCAN_CONFIG,
    DEFAULT_SCAN_POLICY via _policy_to_config, request-body overrides, then
    apply_scan_profile/_apply_runtime_caps) instead of calling apply_scan_profile
    directly in isolation."""
    org_policy = _deep_merge(DEFAULT_SCAN_POLICY, org_policy_override or {})
    effective_config = _clamp_config({
        **DEFAULT_SCAN_CONFIG.get(scan_type, {}),
        **_policy_to_config(org_policy),
        **(request_config or {}),
    })
    return _apply_runtime_caps(_clamp_config(apply_scan_profile(effective_config, scan_type)))


def test_policy_to_config_maps_nested_scan_policy():
    policy = {
        "budgets": {
            "scan_timeout": 9999,
            "nuclei_batch_size": 100,
            "max_endpoints": 9000,
        },
        "crawl": {"depth": 3, "use_gau": False, "fuzz": True},
        "rate_limits": {"nuclei_concurrency": 50},
        "enrichment": {"enabled": False},
    }

    config = _clamp_config(_policy_to_config(policy))

    assert config["scan_timeout"] == 3600
    assert config["nuclei_batch_size"] == 50
    assert config["crawl_max_total_urls"] == 5000
    assert config["crawl_depth"] == 3
    assert config["crawl_use_gau"] is False
    assert config["fuzz"] is True
    assert config["concurrency"] == 20
    assert config["enrichment_enabled"] is False


def test_deep_merge_keeps_unoverridden_nested_defaults():
    merged = _deep_merge(
        {"crawl": {"depth": 2, "use_gau": True}, "nuclei": {"automatic_scan": True}},
        {"crawl": {"fuzz": True}},
    )

    assert merged["crawl"] == {"depth": 2, "use_gau": True, "fuzz": True}
    assert merged["nuclei"]["automatic_scan"] is True


def test_deep_authorized_profile_excludes_destructive_tags():
    config = apply_scan_profile({"scan_profile": "deep_authorized"}, "full")

    assert resolve_scan_profile("full", config) == "deep_authorized"
    assert config["vuln_depth"] == "full"
    assert "http/vulnerabilities" in config["template_dirs"]
    assert "network/vulnerabilities" in config["template_dirs"]
    for tag in SAFE_EXCLUDED_TAGS:
        assert tag in config["exclude_tags"]


def test_child_profile_keeps_parent_budgets_but_switches_template_scope():
    config = child_profile_config(
        "endpoint",
        {"scan_profile": "deep_authorized", "scan_timeout": 1800, "concurrency": 12},
        {"scan_timeout": 600},
    )

    assert config["scan_profile"] == "endpoint"
    assert config["vuln_depth"] == "endpoint"
    assert config["scan_timeout"] == 600
    assert config["concurrency"] == 12
    assert "network/vulnerabilities" not in config["template_dirs"]


def test_target_candidate_builder_routes_by_http_status():
    candidates = build_target_candidates(
        subdomains=["app.example.com", "login.example.com", "old.example.com", "missing.example.com"],
        ips=["192.0.2.10", "192.0.2.10", "192.0.2.11"],
        config={
            "scan_type": "full",
            "scan_profile": "deep_authorized",
            "crawl": True,
            "enforce_scope_validation": False,
        },
        alive_hosts={
            "app.example.com": {
                "url": "https://app.example.com",
                "status_code": 200,
                "status_class": "ok",
                "technologies": ["Next.js:14.2.3"],
            },
            "login.example.com": {
                "url": "https://login.example.com",
                "status_code": 403,
                "status_class": "auth_required",
            },
            "old.example.com": {
                "url": "https://old.example.com",
                "status_code": 500,
                "status_class": "server_error",
            },
            "missing.example.com": {
                "url": "https://missing.example.com",
                "status_code": 404,
                "status_class": "not_found",
            },
        },
    )

    assert candidates["web_standard_targets"] == ["app.example.com"]
    assert candidates["web_limited_targets"] == ["login.example.com", "old.example.com"]
    assert candidates["network_targets"] == ["192.0.2.10", "192.0.2.11"]
    assert candidates["crawl_targets"][0]["url"] == "https://app.example.com"
    assert candidates["tech_map"]["https://app.example.com"] == ["Next.js:14.2.3"]
    assert candidates["summary"]["skipped_by_status"] == {"not_found": 1}


def test_target_candidate_builder_gates_failed_validation():
    candidates = build_target_candidates(
        subdomains=["app.example.com", "other.example.net"],
        ips=[],
        config={"scan_type": "full", "scan_profile": "deep_authorized", "crawl": True},
        alive_hosts={
            "app.example.com": {
                "url": "https://app.example.com",
                "status_code": 200,
                "status_class": "ok",
                "validation": {
                    "scope_status": "in_scope",
                    "liveness_status": "alive",
                    "ownership_confidence": 0.9,
                },
            },
            "other.example.net": {
                "url": "https://other.example.net",
                "status_code": 200,
                "status_class": "ok",
                "validation": {
                    "scope_status": "out_of_scope",
                    "liveness_status": "alive",
                    "ownership_confidence": 0.2,
                },
            },
        },
    )

    assert candidates["web_standard_targets"] == ["app.example.com"]
    assert candidates["validation_skipped_targets"][0]["host"] == "other.example.net"
    assert candidates["summary"]["skipped_by_validation"] == {"scope_out_of_scope": 1}


def test_target_candidate_builder_reports_dns_only_validation():
    candidates = build_target_candidates(
        subdomains=["dns-only.example.com"],
        ips=[],
        config={"scan_type": "full", "scan_profile": "deep_authorized", "crawl": True},
        alive_hosts={},
        validation_by_host={
            "dns-only.example.com": {
                "scope_status": "in_scope",
                "liveness_status": "dns_only",
                "ownership_confidence": 0.7,
            }
        },
    )

    assert candidates["web_standard_targets"] == []
    assert candidates["summary"]["skipped_by_validation"] == {"liveness_dns_only": 1}
    assert candidates["validation_skipped_targets"][0]["reason"] == "liveness_dns_only"


def test_full_scan_effective_config_enables_fuzz_and_js_analysis():
    """Milestone 7: fuzz/js_analysis_enabled must survive the full merge chain
    for a real "full" scan with no org-policy or request-body overrides — not
    just resolve correctly when apply_scan_profile() is called in isolation."""
    config = _effective_config("full")

    assert config["fuzz"] is True
    assert config["fuzz_max_targets"] == 25
    assert config["js_analysis_enabled"] is True
    assert config["nuclei_batch_size"] == 8
    assert config["crawl_nuclei_batch_size"] == 8


def test_full_scan_ffuf_recursion_and_extensions_enabled():
    """Milestone 19: ffuf was only ever fuzzing one directory level with a bare
    wordlist. deep_authorized should get bounded recursion + sensitive-file
    extensions; "quick"/"safe" must not (fuzz is off there entirely already,
    but confirm these new keys don't leak in regardless)."""
    full_config = _effective_config("full")
    quick_config = _effective_config("quick")

    assert full_config["fuzz_recursion_depth"] == 2
    assert ".bak" in full_config["fuzz_extensions"]
    assert quick_config.get("fuzz_recursion_depth") is None


def test_full_scan_crawl_nuclei_max_targets_exceeds_default_profile():
    """Milestone 18: deep_authorized's crawl_nuclei_max_targets was 25 — below
    the "default" profile's own 30, backwards for the platform's most-thorough
    tier. A real scan (kpi.go.id) had 112 crawled endpoints eligible for a
    nuclei pass but only 25 got one. Assert the real end-to-end merge chain
    (not just the profile dict in isolation) actually resolves higher than
    "default" for a real "full" scan."""
    full_config = _effective_config("full")
    default_config = _effective_config("default")

    assert full_config["crawl_nuclei_max_targets"] > default_config["crawl_nuclei_max_targets"]
    assert full_config["crawl_nuclei_max_targets"] == 100


def test_quick_scan_actually_resolves_to_safe_profile_not_deep_authorized():
    """Milestone 18, most severe finding in this pass: DEFAULT_SCAN_POLICY
    hardcoded scan_profile="deep_authorized" (plus 7 more keys across
    budgets/nuclei/enrichment — scan_timeout, crawl_nuclei_batch_size,
    max_endpoints, max_hosts, automatic_scan, use_tech_tags, enrichment.enabled)
    — the exact scan-type-agnostic clobbering pattern this same file already
    documents fixing for crawl.depth and rate_limits.nuclei_concurrency/
    bulk_size, just never audited for these. Confirmed against real production
    data: every persisted "quick" scan's config showed scan_profile=
    deep_authorized, not "safe". A "quick"/lightweight scan request was
    silently running the full authorized/deep profile (all severities,
    automatic_scan, network_safe+cloud_exposure+takeover nuclei profiles,
    900s timeout instead of 300s, 200/2500 crawl budgets instead of 100/1000,
    enrichment forced back on) instead of "safe"'s deliberately narrower,
    lower-footprint one — a real operational/authorization-scope concern, not
    just a config nicety. Assert every one of those 8 keys resolves to
    "quick"'s own intended value through the real end-to-end merge chain."""
    config = _effective_config("quick")

    assert config["scan_profile"] == "safe"
    assert config["scan_timeout"] == 300
    assert config["automatic_scan"] is False
    assert config["use_tech_tags"] is False
    assert config["crawl_max_targets"] == 100
    assert config["crawl_max_total_urls"] == 1000
    assert config["crawl_nuclei_batch_size"] == 5
    assert config["enrichment_enabled"] is False
    assert config["severities"] == ["critical", "high"]
    assert "network_safe" not in config["nuclei_profiles"]
    assert "cloud_exposure" not in config["nuclei_profiles"]


def test_vuln_scan_enrichment_disabled_not_clobbered():
    """Same bug hit "vuln" too: enrichment.enabled=True in the policy dict
    silently overrode vuln's own enrichment_enabled=False (a pure
    vulnerability-confirmation pass has no reason to also run asset
    enrichment)."""
    config = _effective_config("vuln")

    assert config["enrichment_enabled"] is False
    assert config["scan_profile"] == "deep_authorized"


def test_default_scan_type_resolves_to_default_profile():
    """Same bug, different scan type: a bare "default" scan_type used to also
    resolve to deep_authorized via the same policy-layer clobber."""
    config = _effective_config("default")

    assert config["scan_profile"] == "default"


def test_quick_scan_effective_config_leaves_fuzz_disabled():
    """The "safe" profile behind "quick" scans must not be affected by
    deep_authorized's fuzz=True default — each profile's own value should win,
    not a scan-type-agnostic clobber in either direction."""
    config = _effective_config("quick")

    assert config["fuzz"] is False


def test_org_scan_policy_override_still_wins_over_profile_default():
    """An explicit org-level scan_policy override must still be able to turn
    fuzz off for deep_authorized — the fix removes the *hardcoded* False, not
    the ability to override at all."""
    config = _effective_config("full", org_policy_override={"crawl": {"fuzz": False}})

    assert config["fuzz"] is False

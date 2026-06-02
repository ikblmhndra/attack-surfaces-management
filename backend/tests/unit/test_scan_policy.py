from app.services.scan_service import _clamp_config, _deep_merge, _policy_to_config
from app.services.scan_profiles import (
    SAFE_EXCLUDED_TAGS,
    apply_scan_profile,
    build_target_candidates,
    child_profile_config,
    resolve_scan_profile,
)


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
        config={"scan_type": "full", "scan_profile": "deep_authorized", "crawl": True},
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

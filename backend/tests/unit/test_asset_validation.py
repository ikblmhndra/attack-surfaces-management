from app.services.asset_validation import (
    apply_scope_controls,
    merge_rdap_evidence,
    should_scan_validated_asset,
    validate_discovered_host,
)


def test_validate_discovered_host_marks_in_scope_alive_asset_scannable():
    validation = validate_discovered_host(
        host="app.example.com",
        root_domains=["example.com"],
        dns_info={"a": ["192.0.2.10"], "cname": []},
        http_info={"url": "https://app.example.com", "status_code": 200, "status_class": "ok"},
    )

    assert validation["scope_status"] == "in_scope"
    assert validation["liveness_status"] == "alive"
    assert validation["exposure_status"] == "exposed"
    assert validation["ownership_confidence"] >= 0.75
    assert should_scan_validated_asset(validation) is True


def test_validate_discovered_host_marks_out_of_scope_not_scannable():
    validation = validate_discovered_host(
        host="app.other.net",
        root_domains=["example.com"],
        dns_info={"a": ["192.0.2.10"]},
        http_info={"url": "https://app.other.net", "status_code": 200, "status_class": "ok"},
    )

    assert validation["scope_status"] == "out_of_scope"
    assert should_scan_validated_asset(validation) is False


def test_apply_scope_controls_deny_pattern_overrides_scope():
    validation = validate_discovered_host(
        host="vendor.example.com",
        root_domains=["example.com"],
        dns_info={"a": ["192.0.2.10"]},
        http_info={"url": "https://vendor.example.com", "status_code": 200, "status_class": "ok"},
    )

    updated = apply_scope_controls(
        validation,
        target="vendor.example.com",
        deny_patterns=["*.vendor.example.com", "vendor.example.com"],
    )

    assert updated["scope_status"] == "out_of_scope"
    assert updated["is_in_scope"] is False
    assert "org_deny_pattern_matched" in updated["validation_sources"]["reasons"]


def test_merge_rdap_evidence_promotes_matching_org():
    validation = {
        "scope_status": "probable",
        "ownership_confidence": 0.55,
        "ownership_reason": "limited evidence",
        "validation_sources": {"reasons": [], "evidence": {}},
    }

    updated = merge_rdap_evidence(
        validation,
        rdap={"asn": "64512", "asn_org": "Example Corp Networks"},
        org_names=["Example Corp"],
    )

    assert updated["scope_status"] == "in_scope"
    assert updated["ownership_confidence"] >= 0.8
    assert "rdap_org_matches_scope" in updated["validation_sources"]["reasons"]

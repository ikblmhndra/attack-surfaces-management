from app.services.asset_validation import should_scan_validated_asset, validate_discovered_host


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

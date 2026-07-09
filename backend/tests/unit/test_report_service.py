from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.report_service import (
    _build_chart_data,
    _date_cutoff,
    _finding_to_dict,
    _strip_evidence,
    build_report_summary_text,
)


def _fake_finding(**overrides):
    defaults = dict(
        title="Exposed .git directory",
        severity="high",
        category="info_leakage",
        status="open",
        cve_ids=["CVE-2021-1234"],
        cvss_score=7.5,
        affected_url="https://app.example.com/.git/config",
        evidence="HTTP/1.1 200 OK\n[core]\n\trepositoryformatversion = 0",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_date_cutoff_subtracts_days_from_now():
    now = datetime(2026, 7, 9, tzinfo=timezone.utc)
    cutoff = _date_cutoff(30, now=now)
    assert cutoff == now - timedelta(days=30)


def test_date_cutoff_clamps_negative_days_to_zero():
    now = datetime(2026, 7, 9, tzinfo=timezone.utc)
    assert _date_cutoff(-5, now=now) == now


def test_strip_evidence_removes_raw_fields_only():
    finding = {
        "title": "x",
        "severity": "high",
        "evidence": "raw",
        "request_raw": "raw",
        "response_raw": "raw",
        "proof": {"a": 1},
        "affected_url": "https://x",
    }
    stripped = _strip_evidence(finding)
    assert stripped == {"title": "x", "severity": "high"}


def test_finding_to_dict_includes_evidence_when_requested():
    f = _fake_finding()
    result = _finding_to_dict(f, include_evidence=True)
    assert result["affected_url"] == f.affected_url
    assert result["evidence"] is not None
    assert result["cve_ids"] == ["CVE-2021-1234"]


def test_finding_to_dict_strips_evidence_when_not_requested():
    f = _fake_finding()
    result = _finding_to_dict(f, include_evidence=False)
    assert "affected_url" not in result
    assert "evidence" not in result
    assert result["title"] == f.title
    assert result["severity"] == "high"


def test_finding_to_dict_truncates_long_evidence():
    f = _fake_finding(evidence="A" * 1000)
    result = _finding_to_dict(f, include_evidence=True)
    assert len(result["evidence"]) == 500


def test_finding_to_dict_handles_missing_evidence():
    f = _fake_finding(evidence=None)
    result = _finding_to_dict(f, include_evidence=True)
    assert result["evidence"] is None


def test_build_report_summary_text_labels_executive_vs_technical():
    exec_text = build_report_summary_text("executive", 10, 5, 1, 2, "abcdef1234567890")
    tech_text = build_report_summary_text("technical", 10, 5, 1, 2, "abcdef1234567890")
    assert exec_text.startswith("Executive")
    assert tech_text.startswith("Technical")
    assert "10 assets" in exec_text
    assert "1 critical, 2 high" in exec_text


def test_build_chart_data_severity_bars_scale_to_max():
    report_data = {
        "summary": {"critical": 2, "high": 8, "medium": 0, "low": 4},
        "findings_by_category": {"info_leakage": 5, "misconfig": 1},
    }
    charts = _build_chart_data(report_data)
    severity_by_label = {b["label"]: b for b in charts["severity"]}
    assert severity_by_label["High"]["pct"] == 100.0
    assert severity_by_label["Critical"]["pct"] == 25.0
    assert severity_by_label["Medium"]["pct"] == 0.0
    assert charts["category"][0]["count"] == 5


def test_build_chart_data_handles_no_findings_without_division_error():
    report_data = {
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings_by_category": {},
    }
    charts = _build_chart_data(report_data)
    assert all(b["pct"] == 0.0 for b in charts["severity"])
    assert charts["category"] == []

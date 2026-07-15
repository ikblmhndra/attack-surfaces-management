"""
ASM Platform — Unit Tests: Report Executive Narrative
"""
from app.services.report_narrative import build_executive_narrative


class TestBuildExecutiveNarrative:
    def test_includes_grade_and_score(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp",
            risk_score={"grade": "C", "overall_score": 60, "computed_at": "2026-07-14T00:00:00+00:00",
                        "categories": {"network_security": 100}},
            summary={"total_findings": 0, "critical": 0, "high": 0},
            findings_by_category={},
        )
        assert "Acme Corp's overall security posture is rated C (60/100)" in narrative

    def test_calls_out_worst_category_below_threshold(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp",
            risk_score={"grade": "D", "overall_score": 45, "computed_at": "2026-07-14T00:00:00+00:00",
                        "categories": {"network_security": 100, "patch_hygiene": 20, "tls_security": 80}},
            summary={"total_findings": 5, "critical": 1, "high": 0},
            findings_by_category={"known_cve": 5},
        )
        assert "Patch Hygiene (20/100)" in narrative

    def test_does_not_call_out_a_category_when_all_healthy(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp",
            risk_score={"grade": "A", "overall_score": 98, "computed_at": "2026-07-14T00:00:00+00:00",
                        "categories": {"network_security": 100, "patch_hygiene": 95}},
            summary={"total_findings": 0, "critical": 0, "high": 0},
            findings_by_category={},
        )
        assert "risk driver" not in narrative

    def test_no_risk_score_yet(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 0, "critical": 0, "high": 0}, findings_by_category={},
        )
        assert "Acme Corp does not yet have a computed risk score." in narrative

    def test_zero_findings_says_no_open_findings(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 0, "critical": 0, "high": 0}, findings_by_category={},
        )
        assert "There are no open findings at this time." in narrative

    def test_severity_breakdown_mentions_critical_and_high(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 10, "critical": 2, "high": 3}, findings_by_category={},
        )
        assert "10 open findings, including 2 critical and 3 high severity" in narrative

    def test_top_finding_category_mentioned(self):
        narrative = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 10, "critical": 0, "high": 0},
            findings_by_category={"known_cve": 7, "missing_hsts": 3},
        )
        assert "Known cve accounts for the largest share of open findings (7)." in narrative

    def test_remediation_sentence_only_when_critical_or_high_present(self):
        no_severe = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 3, "critical": 0, "high": 0}, findings_by_category={},
        )
        assert "Prioritizing remediation" not in no_severe

        with_severe = build_executive_narrative(
            org_name="Acme Corp", risk_score=None,
            summary={"total_findings": 3, "critical": 1, "high": 0}, findings_by_category={},
        )
        assert "Prioritizing remediation" in with_severe

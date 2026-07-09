"""
ASM Platform — Unit Tests: Risk Scoring Engine
Tests for category scoring, decay model, grade computation, and edge cases.
"""
import math
from datetime import datetime, timedelta, timezone

import pytest

from app.services.risk_engine import (
    CategoryScore,
    FindingInput,
    RiskScoringEngine,
    ScoreCategory,
    Severity,
    compute_decay_factor,
    compute_org_score,
    compute_severity_penalty,
    score_to_grade,
)


# ── Grade computation ─────────────────────────────────────────

class TestScoreToGrade:
    def test_grade_a(self):
        assert score_to_grade(100) == "A"
        assert score_to_grade(90)  == "A"

    def test_grade_b(self):
        assert score_to_grade(89) == "B"
        assert score_to_grade(75) == "B"

    def test_grade_c(self):
        assert score_to_grade(74) == "C"
        assert score_to_grade(60) == "C"

    def test_grade_d(self):
        assert score_to_grade(59) == "D"
        assert score_to_grade(40) == "D"

    def test_grade_f(self):
        assert score_to_grade(39) == "F"
        assert score_to_grade(0)  == "F"

    def test_boundary_89(self):
        assert score_to_grade(89) == "B"

    def test_boundary_90(self):
        assert score_to_grade(90) == "A"


# ── Decay factor ──────────────────────────────────────────────

class TestDecayFactor:
    def test_no_date_returns_full_weight(self):
        assert compute_decay_factor(None) == 1.0

    def test_today_no_decay(self):
        now = datetime.now(timezone.utc)
        factor = compute_decay_factor(now, now)
        assert factor == pytest.approx(1.0, abs=0.01)

    def test_30_days_ago_half_life(self):
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        # λ=0.05 → e^(-0.05*30) ≈ 0.223
        factor = compute_decay_factor(thirty_days_ago, now)
        assert factor == pytest.approx(math.exp(-0.05 * 30), abs=0.01)

    def test_older_is_less_impactful(self):
        now = datetime.now(timezone.utc)
        recent = compute_decay_factor(now - timedelta(days=5), now)
        old    = compute_decay_factor(now - timedelta(days=60), now)
        assert recent > old

    def test_future_date_clips_to_full(self):
        now    = datetime.now(timezone.utc)
        future = now + timedelta(days=10)
        factor = compute_decay_factor(future, now)
        assert factor == pytest.approx(1.0, abs=0.01)

    def test_naive_datetime_handled(self):
        naive = datetime.utcnow() - timedelta(days=1)
        factor = compute_decay_factor(naive)
        assert 0 < factor <= 1.0


# ── Severity penalty ──────────────────────────────────────────

class TestSeverityPenalty:
    def test_critical_highest_penalty(self):
        p = compute_severity_penalty("critical", confidence=1.0, decay=1.0)
        assert p == pytest.approx(25.0)

    def test_info_lowest_penalty(self):
        p = compute_severity_penalty("info", confidence=1.0, decay=1.0)
        assert p == pytest.approx(1.0)

    def test_confidence_scales_penalty(self):
        full   = compute_severity_penalty("high", confidence=1.0, decay=1.0)
        half   = compute_severity_penalty("high", confidence=0.5, decay=1.0)
        assert half == pytest.approx(full * 0.5)

    def test_decay_scales_penalty(self):
        fresh = compute_severity_penalty("medium", confidence=1.0, decay=1.0)
        aged  = compute_severity_penalty("medium", confidence=1.0, decay=0.5)
        assert aged == pytest.approx(fresh * 0.5)

    def test_cvss_blends_with_severity(self):
        without_cvss = compute_severity_penalty("high", 1.0, 1.0, cvss=None)
        with_cvss    = compute_severity_penalty("high", 1.0, 1.0, cvss=9.8)
        # CVSS 9.8 is near-critical → higher than pure "high"
        assert with_cvss > without_cvss

    def test_unknown_severity_defaults_to_info(self):
        p = compute_severity_penalty("unknown_sev", confidence=1.0, decay=1.0)
        assert p == pytest.approx(1.0)  # defaults to INFO penalty


# ── Scoring engine ────────────────────────────────────────────

class TestRiskScoringEngine:
    """Integration-level tests for the full scoring pipeline."""

    def setup_method(self):
        self.engine = RiskScoringEngine()
        self.now = datetime.now(timezone.utc)

    def _make_finding(self, severity="high", category="open_port", status="open",
                      confidence=1.0, days_ago=0):
        last_seen = self.now - timedelta(days=days_ago)
        return FindingInput(
            id="test-id",
            category=category,
            severity=severity,
            status=status,
            confidence=confidence,
            last_seen=last_seen,
        )

    def test_no_findings_perfect_score(self):
        result = self.engine.compute("org-1", [], total_assets=10, now=self.now)
        assert result.overall_score == 100
        assert result.grade == "A"

    def test_critical_finding_drops_score_significantly(self):
        findings = [self._make_finding("critical", "exposed_admin_panel")]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score < 80

    def test_multiple_criticals_approach_f(self):
        findings = [
            self._make_finding("critical", "exposed_admin_panel"),
            self._make_finding("critical", "default_credentials"),
            self._make_finding("critical", "exposed_database"),
            self._make_finding("critical", "exposed_storage"),
        ]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score <= 60

    def test_false_positives_excluded(self):
        fp = FindingInput(
            id="fp-1", category="open_port", severity="critical",
            status="false_positive", is_false_positive=True, last_seen=self.now,
        )
        result = self.engine.compute("org-1", [fp], now=self.now)
        assert result.overall_score == 100

    def test_accepted_risk_excluded(self):
        ar = FindingInput(
            id="ar-1", category="open_port", severity="critical",
            status="accepted", is_risk_accepted=True, last_seen=self.now,
        )
        result = self.engine.compute("org-1", [ar], now=self.now)
        assert result.overall_score == 100

    def test_resolved_findings_excluded(self):
        resolved = FindingInput(
            id="res-1", category="open_port", severity="high",
            status="resolved", last_seen=self.now,
        )
        result = self.engine.compute("org-1", [resolved], now=self.now)
        assert result.overall_score == 100

    def test_old_finding_decays(self):
        recent_finding = [self._make_finding("critical", "open_port", days_ago=0)]
        old_finding    = [self._make_finding("critical", "open_port", days_ago=90)]

        recent_score = self.engine.compute("org-1", recent_finding, now=self.now)
        old_score    = self.engine.compute("org-1", old_finding,    now=self.now)

        assert old_score.overall_score > recent_score.overall_score

    def test_category_scores_populated(self):
        findings = [self._make_finding("high", "missing_spf")]  # DNS category
        result = self.engine.compute("org-1", findings, now=self.now)

        assert ScoreCategory.DNS_HEALTH.value in result.score_breakdown
        dns_score = result.score_breakdown[ScoreCategory.DNS_HEALTH.value]["score"]
        assert dns_score < 100

    def test_overall_score_bounded_0_100(self):
        findings = [self._make_finding("critical") for _ in range(50)]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert 0 <= result.overall_score <= 100

    def test_score_factors_generated(self):
        findings = [
            self._make_finding("critical", "exposed_admin_panel"),
            self._make_finding("high", "missing_spf"),
        ]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert len(result.score_factors) > 0
        for factor in result.score_factors:
            assert "category" in factor
            assert "score" in factor
            assert "impact" in factor

    def test_severity_counts_correct(self):
        findings = [
            self._make_finding("critical"),
            self._make_finding("critical"),
            self._make_finding("high"),
            self._make_finding("medium"),
            self._make_finding("low"),
            self._make_finding("info"),
        ]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1

    def test_total_findings_includes_all_statuses(self):
        all_findings = [
            self._make_finding("high", status="open"),
            self._make_finding("high", status="resolved"),
            FindingInput(id="fp", category="open_port", severity="high",
                        status="false_positive", is_false_positive=True, last_seen=self.now),
        ]
        result = self.engine.compute("org-1", all_findings, now=self.now)
        assert result.total_findings == 3

    def test_weights_sum_to_one(self):
        from app.services.risk_engine import CATEGORY_WEIGHTS
        total = sum(CATEGORY_WEIGHTS.values())
        assert total == pytest.approx(1.0, abs=0.001)

    def test_compute_org_score_convenience(self):
        """Test the convenience wrapper function."""
        findings_dicts = [
            {
                "id": "f1",
                "category": "open_port",
                "severity": "high",
                "status": "open",
                "confidence": 1.0,
                "first_seen": self.now,
                "last_seen": self.now,
                "is_false_positive": False,
                "is_risk_accepted": False,
                "cvss_score": None,
            }
        ]
        result = compute_org_score("org-test", findings_dicts, total_assets=5)
        assert 0 <= result.overall_score <= 100
        assert result.grade in ("A", "B", "C", "D", "F")

    def test_score_delta_computation(self):
        prev_findings = [self._make_finding("high")]
        curr_findings = [self._make_finding("high"), self._make_finding("critical")]

        prev = self.engine.compute("org-1", prev_findings, now=self.now)
        curr = self.engine.compute("org-1", curr_findings, now=self.now)

        delta = self.engine.compute_score_delta(prev, curr)
        assert delta["overall_delta"] < 0  # Score worsened
        assert delta["degraded"] is True
        assert delta["improved"] is False
        assert delta["previous_score"] == prev.overall_score
        assert delta["current_score"] == curr.overall_score

    def test_category_penalty_capped_at_100(self):
        """Even 100 critical findings can't push a category below 0."""
        findings = [self._make_finding("critical", "exposed_admin_panel") for _ in range(100)]
        result = self.engine.compute("org-1", findings, now=self.now)
        for cat_data in result.score_breakdown.values():
            assert cat_data["score"] >= 0

    def test_scattered_highs_across_categories_capped_below_a(self):
        """
        Regression test for the false-negative grade found on a real scan: zero criticals,
        but several HIGH-severity exposures (exposed DB/remote-admin ports, an unpatched CVE)
        spread across categories, plus a couple of unrelated mediums. Per-category weighting
        alone let this average out to a 90/A — the high_penalty aggregate cap must catch it.
        """
        findings = [
            self._make_finding("high", "exposed_service"),   # network_security
            self._make_finding("high", "exposed_service"),
            self._make_finding("high", "exposed_service"),
            self._make_finding("high", "exposed_service"),
            self._make_finding("high", "exposed_service"),
            self._make_finding("high", "known_cve"),          # patch_hygiene
            self._make_finding("medium", "missing_dmarc"),    # dns_health
            self._make_finding("medium", "debug_endpoint"),   # info_leakage
        ]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score < 90
        assert result.grade != "A"

    def test_single_high_finding_cannot_reach_grade_a(self):
        findings = [self._make_finding("high", "known_cve")]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score <= 84
        assert result.grade != "A"

    def test_mediums_only_unaffected_by_high_penalty_cap(self):
        """The new HIGH aggregate cap shouldn't fire when there are no HIGH findings at all."""
        findings = [self._make_finding("medium", "missing_dmarc")]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.grade == "A"

    def test_different_categories_score_independently(self):
        """Finding in DNS category shouldn't affect network security score."""
        dns_finding = [self._make_finding("critical", "missing_spf")]
        result = self.engine.compute("org-1", dns_finding, now=self.now)

        dns_score     = result.score_breakdown.get(ScoreCategory.DNS_HEALTH.value, {}).get("score", 100)
        network_score = result.score_breakdown.get(ScoreCategory.NETWORK_SECURITY.value, {}).get("score", 100)

        assert dns_score     < 100   # DNS affected
        assert network_score == 100  # Network unaffected


# ── Edge cases ────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_org_id(self):
        engine = RiskScoringEngine()
        result = engine.compute("", [], now=datetime.now(timezone.utc))
        assert result.org_id == ""
        assert result.overall_score == 100

    def test_single_info_finding_minimal_impact(self):
        engine = RiskScoringEngine()
        now = datetime.now(timezone.utc)
        finding = FindingInput(id="info-1", category="open_port", severity="info",
                               status="open", last_seen=now)
        result = engine.compute("org-1", [finding], now=now)
        assert result.overall_score >= 95  # Minimal impact

    def test_mixed_statuses_only_open_counts(self):
        engine = RiskScoringEngine()
        now = datetime.now(timezone.utc)
        findings = [
            FindingInput(id="open-1", category="open_port", severity="critical",
                        status="open", last_seen=now),
            FindingInput(id="res-1", category="open_port", severity="critical",
                        status="resolved", last_seen=now),
            FindingInput(id="fp-1", category="open_port", severity="critical",
                        status="false_positive", is_false_positive=True, last_seen=now),
        ]
        result = engine.compute("org-1", findings, now=now)
        # Only one critical active
        assert result.critical_count == 1  # Only active one counted in severity counts from active

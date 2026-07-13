"""
ASM Platform — Unit Tests: Risk Scoring Engine
Tests for category scoring, decay model, grade computation, and edge cases.
"""
import math
from datetime import datetime, timedelta, timezone

import pytest

from app.services.risk_engine import (
    CategoryScore,
    CvssImpactMetrics,
    FindingInput,
    ImpactLevel,
    LikelihoodLevel,
    MatrixRating,
    RiskScoringEngine,
    ScoreCategory,
    Severity,
    combine_criticality,
    compute_criticality_multiplier,
    compute_decay_factor,
    compute_impact_level,
    compute_likelihood_level,
    compute_matrix_rating,
    compute_org_score,
    compute_severity_penalty,
    parse_cvss_vector,
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

    def test_exploit_boost_scales_penalty_up(self):
        """Milestone 8: EPSS/KEV exploit intelligence escalates a penalty —
        opposite direction from confidence, which only ever de-escalates."""
        baseline = compute_severity_penalty("high", confidence=1.0, decay=1.0, exploit_boost=1.0)
        boosted = compute_severity_penalty("high", confidence=1.0, decay=1.0, exploit_boost=1.5)
        assert boosted == pytest.approx(baseline * 1.5)

    def test_exploit_boost_never_reduces_penalty(self):
        """A boost below 1.0 must not be honored — absence of exploit-intel
        data is not evidence a finding is safe to deprioritize."""
        baseline = compute_severity_penalty("high", confidence=1.0, decay=1.0, exploit_boost=1.0)
        with_low_boost = compute_severity_penalty("high", confidence=1.0, decay=1.0, exploit_boost=0.3)
        assert with_low_boost == pytest.approx(baseline)

    def test_criticality_multiplier_scales_penalty_up(self):
        """Stage 1 of the NIST/OWASP risk-engine redesign: a finding on a
        criticality-5 asset must hurt more than the identical finding on a
        criticality-3 (default) asset."""
        baseline = compute_severity_penalty("high", confidence=1.0, decay=1.0, criticality_multiplier=1.0)
        escalated = compute_severity_penalty("high", confidence=1.0, decay=1.0, criticality_multiplier=1.30)
        assert escalated == pytest.approx(baseline * 1.30)

    def test_criticality_multiplier_scales_penalty_down(self):
        """Unlike exploit_boost, criticality_multiplier is NOT floor-clamped at
        1.0 — a low-criticality (disposable dev/staging) asset must actually
        see its findings' contribution shrink."""
        baseline = compute_severity_penalty("high", confidence=1.0, decay=1.0, criticality_multiplier=1.0)
        deescalated = compute_severity_penalty("high", confidence=1.0, decay=1.0, criticality_multiplier=0.70)
        assert deescalated == pytest.approx(baseline * 0.70)
        assert deescalated < baseline


class TestCriticalityMultiplier:
    """Stage 1: Asset/Organization.criticality (1-5) -> scoring multiplier."""

    @pytest.mark.parametrize("criticality,expected", [
        (1, 0.70), (2, 0.85), (3, 1.00), (4, 1.15), (5, 1.30),
    ])
    def test_multiplier_table(self, criticality, expected):
        assert compute_criticality_multiplier(criticality) == pytest.approx(expected)

    def test_none_defaults_to_neutral(self):
        assert compute_criticality_multiplier(None) == pytest.approx(1.0)

    def test_out_of_range_defaults_to_neutral(self):
        assert compute_criticality_multiplier(0) == pytest.approx(1.0)
        assert compute_criticality_multiplier(6) == pytest.approx(1.0)
        assert compute_criticality_multiplier(-1) == pytest.approx(1.0)


class TestCombineCriticality:
    """max(asset, org) — an unclassified asset (default 3) falls back to the
    org's setting; a specifically-flagged asset can still escalate above an
    otherwise-default org."""

    def test_asset_wins_when_higher(self):
        assert combine_criticality(asset_criticality=5, org_criticality=3) == 5

    def test_org_wins_when_higher(self):
        assert combine_criticality(asset_criticality=3, org_criticality=5) == 5

    def test_both_default_falls_back_to_three(self):
        assert combine_criticality(asset_criticality=None, org_criticality=None) == 3

    def test_asset_none_falls_back_to_org(self):
        assert combine_criticality(asset_criticality=None, org_criticality=5) == 5

    def test_org_none_falls_back_to_asset(self):
        assert combine_criticality(asset_criticality=5, org_criticality=None) == 5

    def test_low_asset_does_not_drag_down_high_org(self):
        """max(), not average — a not-yet-classified low asset shouldn't mute
        an org the platform already knows is critical."""
        assert combine_criticality(asset_criticality=1, org_criticality=5) == 5


class TestParseCvssVector:
    """Stage 2: CVSS 3.x vector -> C/I/A/Scope, observability only (no
    scoring-formula effect this stage — see TestCvssVectorNoScoringEffect)."""

    def test_parses_valid_3_1_vector(self):
        result = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result == CvssImpactMetrics(confidentiality="H", integrity="H", availability="H", scope_changed=False)

    def test_parses_valid_3_0_vector(self):
        result = parse_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N")
        assert result == CvssImpactMetrics(confidentiality="L", integrity="L", availability="N", scope_changed=True)

    def test_scope_changed_true_only_for_c(self):
        assert parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N").scope_changed is True
        assert parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").scope_changed is False

    def test_cvss_2_0_rejected(self):
        # Different C/I/A encoding entirely (N/P/C, not N/L/H) — must not be
        # misinterpreted as 3.x.
        assert parse_cvss_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_cvss_4_0_rejected(self):
        # Different structure (VC/VI/VA + SC/SI/SA, no bare C/I/A keys at all).
        assert parse_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None

    def test_missing_prefix_rejected(self):
        assert parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_quoted_vector_still_parses(self):
        # A handful of real nuclei templates wrap the vector in stray quotes.
        result = parse_cvss_vector('"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')
        assert result == CvssImpactMetrics(confidentiality="H", integrity="H", availability="H", scope_changed=False)

    def test_none_input_returns_none(self):
        assert parse_cvss_vector(None) is None

    def test_empty_string_returns_none(self):
        assert parse_cvss_vector("") is None

    def test_non_string_input_returns_none(self):
        assert parse_cvss_vector(12345) is None  # type: ignore[arg-type]


class TestComputeImpactLevel:
    """Stage 4: CVSS-driven (NVD's own Qualitative Severity Rating Scale
    boundaries), severity-label fallback when no CVSS, shifted by
    criticality_multiplier."""

    def test_cvss_boundary_critical(self):
        assert compute_impact_level("info", 9.0, 1.0) == ImpactLevel.CRITICAL
        assert compute_impact_level("info", 10.0, 1.0) == ImpactLevel.CRITICAL

    def test_cvss_boundary_just_below_critical(self):
        assert compute_impact_level("info", 8.9, 1.0) == ImpactLevel.HIGH

    def test_cvss_boundary_high(self):
        assert compute_impact_level("info", 7.0, 1.0) == ImpactLevel.HIGH

    def test_cvss_boundary_just_below_high(self):
        assert compute_impact_level("info", 6.9, 1.0) == ImpactLevel.MEDIUM

    def test_cvss_boundary_medium(self):
        assert compute_impact_level("info", 4.0, 1.0) == ImpactLevel.MEDIUM

    def test_cvss_boundary_just_below_medium(self):
        assert compute_impact_level("info", 3.9, 1.0) == ImpactLevel.LOW

    def test_no_cvss_falls_back_to_severity(self):
        assert compute_impact_level("critical", None, 1.0) == ImpactLevel.CRITICAL
        assert compute_impact_level("high", None, 1.0) == ImpactLevel.HIGH
        assert compute_impact_level("medium", None, 1.0) == ImpactLevel.MEDIUM
        assert compute_impact_level("low", None, 1.0) == ImpactLevel.LOW
        assert compute_impact_level("info", None, 1.0) == ImpactLevel.LOW

    def test_unknown_severity_with_no_cvss_defaults_low(self):
        assert compute_impact_level("unknown_sev", None, 1.0) == ImpactLevel.LOW

    def test_criticality_shifts_impact_up(self):
        # criticality_multiplier >= 1.15 (asset/org criticality 4 or 5)
        assert compute_impact_level("medium", None, 1.15) == ImpactLevel.HIGH
        assert compute_impact_level("high", None, 1.30) == ImpactLevel.CRITICAL

    def test_criticality_shift_ceilings_at_critical(self):
        # Already-critical impact must not overflow past the top tier.
        assert compute_impact_level("critical", None, 1.30) == ImpactLevel.CRITICAL

    def test_criticality_shifts_impact_down(self):
        # criticality_multiplier <= 0.85 (asset/org criticality 1 or 2)
        assert compute_impact_level("high", None, 0.85) == ImpactLevel.MEDIUM
        assert compute_impact_level("medium", None, 0.70) == ImpactLevel.LOW

    def test_criticality_shift_floors_at_low(self):
        assert compute_impact_level("low", None, 0.70) == ImpactLevel.LOW

    def test_default_criticality_does_not_shift(self):
        assert compute_impact_level("high", None, 1.00) == ImpactLevel.HIGH


class TestComputeLikelihoodLevel:
    """Stage 4: driven by exploit_boost's 6 real possible values
    ({1.0, 1.2, 1.25, 1.3, 1.5, 1.75} from exploit_intel.py/version_cve_intel.py's
    max()-combination in risk_worker.py). Confidence is deliberately not a
    parameter here at all — see module-level docstring for why."""

    def test_no_signal_is_low(self):
        assert compute_likelihood_level(1.0) == LikelihoodLevel.LOW

    def test_high_epss_is_medium(self):
        assert compute_likelihood_level(1.2) == LikelihoodLevel.MEDIUM

    def test_ssvc_poc_is_medium(self):
        assert compute_likelihood_level(1.25) == LikelihoodLevel.MEDIUM

    def test_ssvc_automatable_is_medium(self):
        assert compute_likelihood_level(1.3) == LikelihoodLevel.MEDIUM

    def test_kev_is_high(self):
        assert compute_likelihood_level(1.5) == LikelihoodLevel.HIGH

    def test_kev_ransomware_is_high(self):
        assert compute_likelihood_level(1.75) == LikelihoodLevel.HIGH


class TestRiskMatrix:
    """Literal test of the OWASP-style lookup table — one assertion per cell."""

    @pytest.mark.parametrize("likelihood,impact,expected", [
        (LikelihoodLevel.LOW, ImpactLevel.LOW, MatrixRating.NOTE),
        (LikelihoodLevel.LOW, ImpactLevel.MEDIUM, MatrixRating.LOW),
        (LikelihoodLevel.LOW, ImpactLevel.HIGH, MatrixRating.MEDIUM),
        (LikelihoodLevel.LOW, ImpactLevel.CRITICAL, MatrixRating.HIGH),
        (LikelihoodLevel.MEDIUM, ImpactLevel.LOW, MatrixRating.LOW),
        (LikelihoodLevel.MEDIUM, ImpactLevel.MEDIUM, MatrixRating.MEDIUM),
        (LikelihoodLevel.MEDIUM, ImpactLevel.HIGH, MatrixRating.HIGH),
        (LikelihoodLevel.MEDIUM, ImpactLevel.CRITICAL, MatrixRating.CRITICAL),
        (LikelihoodLevel.HIGH, ImpactLevel.LOW, MatrixRating.MEDIUM),
        (LikelihoodLevel.HIGH, ImpactLevel.MEDIUM, MatrixRating.HIGH),
        (LikelihoodLevel.HIGH, ImpactLevel.HIGH, MatrixRating.CRITICAL),
        (LikelihoodLevel.HIGH, ImpactLevel.CRITICAL, MatrixRating.CRITICAL),
    ])
    def test_matrix_cell(self, likelihood, impact, expected):
        assert compute_matrix_rating(likelihood, impact) == expected


# ── Scoring engine ────────────────────────────────────────────

class TestRiskScoringEngine:
    """Integration-level tests for the full scoring pipeline."""

    def setup_method(self):
        self.engine = RiskScoringEngine()
        self.now = datetime.now(timezone.utc)

    def _make_finding(self, severity="high", category="open_port", status="open",
                      confidence=1.0, exploit_boost=1.0, days_ago=0, criticality=3,
                      cvss_vector=None, cvss_score=None):
        last_seen = self.now - timedelta(days=days_ago)
        return FindingInput(
            id="test-id",
            category=category,
            severity=severity,
            status=status,
            confidence=confidence,
            exploit_boost=exploit_boost,
            last_seen=last_seen,
            criticality=criticality,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
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
        # Stage 4: 4 default-criticality criticals (no CVSS, no exploit intel)
        # -> Impact=CRITICAL (severity fallback), Likelihood=LOW (exploit_boost
        # 1.0) -> matrix rating HIGH -> cap 74 (was 60 under the old ad-hoc cap).
        assert result.overall_score <= 74

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
        """Stage 4: a single "critical" finding's Likelihood x Impact matrix
        rating is driven by severity/cvss/exploit_boost/criticality only —
        deliberately NOT by decay (a stale, still-open Critical-rated
        vulnerability isn't less risky for having sat open 90 days). So the
        new cap applies identically to both variants here, masking decay's
        effect on overall_score exactly the way test_exploit_boost_shifts_
        category_score_through_full_pipeline and test_criticality_shifts_
        category_score_through_full_pipeline above already document for their
        own signals — assert on the (unaffected) category score instead,
        same established technique."""
        recent_finding = [self._make_finding("critical", "open_port", days_ago=0)]
        old_finding    = [self._make_finding("critical", "open_port", days_ago=90)]

        recent_score = self.engine.compute("org-1", recent_finding, now=self.now)
        old_score    = self.engine.compute("org-1", old_finding,    now=self.now)

        network_security = ScoreCategory.NETWORK_SECURITY.value
        assert old_score.score_breakdown[network_security]["score"] > recent_score.score_breakdown[network_security]["score"]

    def test_category_scores_populated(self):
        findings = [self._make_finding("high", "missing_spf")]  # DNS category
        result = self.engine.compute("org-1", findings, now=self.now)

        assert ScoreCategory.DNS_HEALTH.value in result.score_breakdown
        dns_score = result.score_breakdown[ScoreCategory.DNS_HEALTH.value]["score"]
        assert dns_score < 100

    def test_low_confidence_finding_shifts_category_score_less_than_high_confidence(self):
        """Milestone 7: confidence must actually move a *category* score through
        the full compute() pipeline, not just the raw penalty function
        (test_confidence_scales_penalty above only covers compute_severity_penalty
        in isolation) — this is what nuclei_worker.py's CVE-confidence signal is
        for: a low-confidence CVE match should hurt the score less."""
        high_confidence = [self._make_finding("high", "known_cve", confidence=1.0)]
        low_confidence = [self._make_finding("high", "known_cve", confidence=0.5)]

        high_conf_result = self.engine.compute("org-1", high_confidence, now=self.now)
        low_conf_result = self.engine.compute("org-1", low_confidence, now=self.now)

        patch_hygiene = ScoreCategory.PATCH_HYGIENE.value
        high_conf_score = high_conf_result.score_breakdown[patch_hygiene]["score"]
        low_conf_score = low_conf_result.score_breakdown[patch_hygiene]["score"]
        assert low_conf_score > high_conf_score
        # Stage 4: a single "high" finding's matrix rating (like the network_security
        # case above) is driven by severity/cvss/exploit_boost/criticality, not
        # confidence, so both variants here hit the identical cap — this
        # docstring's own stated purpose ("shifts a *category* score") is what
        # the assertion above already proves; no overall_score assertion needed.

    def test_exploit_boost_shifts_category_score_through_full_pipeline(self):
        """Milestone 8: a KEV-boosted CVE finding must hurt its category score
        more than the identical finding with no exploit-intel signal — proven
        through the full compute() pipeline, not just compute_severity_penalty
        in isolation. Uses "critical" severity deliberately avoided here (a
        critical finding triggers risk_engine's own aggregate-severity ceiling
        cap on overall_score, which would mask the boost's effect on the
        blended total — confirmed by manual testing against real EPSS/KEV
        data, see CHANGELOG.md). "high" has no such cap collision."""
        no_boost = [self._make_finding("high", "known_cve", exploit_boost=1.0)]
        kev_boosted = [self._make_finding("high", "known_cve", exploit_boost=1.75)]

        no_boost_result = self.engine.compute("org-1", no_boost, now=self.now)
        kev_result = self.engine.compute("org-1", kev_boosted, now=self.now)

        patch_hygiene = ScoreCategory.PATCH_HYGIENE.value
        no_boost_score = no_boost_result.score_breakdown[patch_hygiene]["score"]
        kev_score = kev_result.score_breakdown[patch_hygiene]["score"]
        assert kev_score < no_boost_score

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
        # Stage 4: default-criticality high, no CVSS, no exploit intel ->
        # Impact=HIGH (severity fallback), Likelihood=LOW -> matrix rating
        # MEDIUM -> cap 89 (was 84 under the old ad-hoc cap).
        assert result.overall_score <= 89
        assert result.grade != "A"

    def test_mediums_only_unaffected_by_high_penalty_cap(self):
        """The new HIGH aggregate cap shouldn't fire when there are no HIGH findings at all."""
        findings = [self._make_finding("medium", "missing_dmarc")]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.grade == "A"

    def test_criticality_shifts_category_score_through_full_pipeline(self):
        """Stage 1: identical findings differing only in criticality (1 vs 5)
        must produce different category/overall scores in the expected
        direction, proven through the full compute() pipeline, not just
        compute_severity_penalty in isolation. "medium"/two findings in the
        highest-weighted category (exposure_mgmt, 0.18) used deliberately: a
        single "high" finding always trips the high_penalty>=15 aggregate cap
        (base penalty is exactly 15.0) regardless of criticality, which would
        mask the multiplier's effect on overall_score — confirmed via a first
        draft of this test that tied at the same capped value."""
        low_criticality = [
            self._make_finding("medium", "exposed_api", criticality=1),
            self._make_finding("medium", "exposed_api", criticality=1),
        ]
        high_criticality = [
            self._make_finding("medium", "exposed_api", criticality=5),
            self._make_finding("medium", "exposed_api", criticality=5),
        ]

        low_result = self.engine.compute("org-1", low_criticality, now=self.now)
        high_result = self.engine.compute("org-1", high_criticality, now=self.now)

        exposure_mgmt = ScoreCategory.EXPOSURE_MGMT.value
        low_score = low_result.score_breakdown[exposure_mgmt]["score"]
        high_score = high_result.score_breakdown[exposure_mgmt]["score"]
        assert low_score > high_score
        assert low_result.overall_score > high_result.overall_score

    def test_default_criticality_matches_pre_stage1_score(self):
        """A finding with no criticality signal (default 3 -> multiplier 1.0)
        must score identically to how it did before criticality existed."""
        finding = [self._make_finding("high", "known_cve", criticality=3)]
        result = self.engine.compute("org-1", finding, now=self.now)
        patch_hygiene = result.score_breakdown[ScoreCategory.PATCH_HYGIENE.value]
        assert patch_hygiene["score"] == 100 - 15  # SEVERITY_PENALTIES["high"], multiplier 1.0

    def test_compute_org_score_passes_through_criticality(self):
        """The dict->FindingInput convenience wrapper must read a
        'criticality' key from raw finding dicts (workers/risk/risk_worker.py's
        _load_findings supplies this via combine_criticality()). Two findings
        in exposure_mgmt (see test above for why one "high" finding or a
        smaller-weight category isn't enough to move the rounded overall_score)."""
        base = {
            "id": "f1", "category": "exposed_api", "severity": "medium", "status": "open",
            "confidence": 1.0, "first_seen": self.now, "last_seen": self.now,
            "is_false_positive": False, "is_risk_accepted": False, "cvss_score": None,
        }
        low = compute_org_score("org-test", [{**base, "criticality": 1}, {**base, "id": "f2", "criticality": 1}], total_assets=5)
        high = compute_org_score("org-test", [{**base, "criticality": 5}, {**base, "id": "f2", "criticality": 5}], total_assets=5)
        assert low.overall_score > high.overall_score

    def test_cvss_vector_presence_has_zero_scoring_effect(self):
        """Stage 2: parse_cvss_vector()'s output is stashed into the per-finding
        penalties audit dict for observability only — compute_severity_penalty()
        takes no cvss_vector-derived parameter at all this stage. Prove it,
        don't just assume it: an otherwise-identical finding with vs. without a
        populated cvss_vector must produce a byte-identical score, including
        one with Scope Changed (S:C) and full C:H/I:H/A:H impact — the
        "worst case" vector that a future stage's formula change would most
        plausibly escalate on."""
        with_vector = [self._make_finding(
            "high", "known_cve",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )]
        without_vector = [self._make_finding("high", "known_cve", cvss_vector=None)]

        with_result = self.engine.compute("org-1", with_vector, now=self.now)
        without_result = self.engine.compute("org-1", without_vector, now=self.now)

        assert with_result.overall_score == without_result.overall_score
        assert with_result.score_breakdown == without_result.score_breakdown

    def test_different_categories_score_independently(self):
        """Finding in DNS category shouldn't affect network security score."""
        dns_finding = [self._make_finding("critical", "missing_spf")]
        result = self.engine.compute("org-1", dns_finding, now=self.now)

        dns_score     = result.score_breakdown.get(ScoreCategory.DNS_HEALTH.value, {}).get("score", 100)
        network_score = result.score_breakdown.get(ScoreCategory.NETWORK_SECURITY.value, {}).get("score", 100)

        assert dns_score     < 100   # DNS affected
        assert network_score == 100  # Network unaffected

    def test_matrix_critical_rating_caps_at_59(self):
        """Stage 4: a confirmed-KEV (Likelihood=HIGH), CVSS>=9 (Impact=CRITICAL)
        finding in a low-weight category (misconfiguration, 0.05) — without a
        cap, weighted_total would land near 100; the matrix-driven cap must
        still force it down to 59, proving the CRITICAL tier fires on its own,
        not just alongside the MEDIUM/HIGH tiers below it."""
        findings = [self._make_finding(
            "critical", "cors_misconfiguration", cvss_score=9.8, exploit_boost=1.5,
        )]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score <= 59

    def test_matrix_high_rating_caps_at_74(self):
        """Likelihood=MEDIUM (high EPSS, exploit_boost=1.2) x Impact=HIGH
        (severity fallback, no CVSS) -> matrix HIGH -> cap 74, distinct from
        the CRITICAL (59) and MEDIUM (89) tiers."""
        findings = [self._make_finding("high", "cors_misconfiguration", exploit_boost=1.2)]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.overall_score <= 74

    def test_matrix_low_rating_does_not_cap(self):
        """Likelihood=LOW x Impact=MEDIUM -> matrix LOW, which is not in
        _RATING_CAPS at all -> no cap applied, org can still reach grade A."""
        findings = [self._make_finding("medium", "missing_dmarc")]
        result = self.engine.compute("org-1", findings, now=self.now)
        assert result.grade == "A"

    def test_penalties_dict_includes_matrix_fields(self):
        findings = [self._make_finding("high", "known_cve", exploit_boost=1.5)]
        result = self.engine.compute("org-1", findings, now=self.now)
        cat = result.category_scores[ScoreCategory.PATCH_HYGIENE.value]
        assert len(cat.penalties) == 1
        p = cat.penalties[0]
        assert p["impact"] == ImpactLevel.HIGH.value
        assert p["likelihood"] == LikelihoodLevel.HIGH.value
        assert p["matrix_rating"] == MatrixRating.CRITICAL.value


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

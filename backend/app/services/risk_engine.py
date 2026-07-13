"""
ASM Platform — Risk Scoring Engine
Computes organization security scores across multiple categories.
Inspired by SecurityScorecard methodology with configurable weights.
"""
import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog

log = structlog.get_logger()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScoreCategory(str, Enum):
    NETWORK_SECURITY = "network_security"
    DNS_HEALTH = "dns_health"
    WEB_SECURITY = "web_security"
    TLS_SECURITY = "tls_security"
    EXPOSURE_MGMT = "exposure_mgmt"
    PATCH_HYGIENE = "patch_hygiene"
    INFO_LEAKAGE = "info_leakage"
    REPUTATION = "reputation"
    MISCONFIGURATION = "misconfiguration"


# Category weights — must sum to 1.0
CATEGORY_WEIGHTS: Dict[ScoreCategory, float] = {
    ScoreCategory.NETWORK_SECURITY: 0.15,
    ScoreCategory.DNS_HEALTH: 0.10,
    ScoreCategory.WEB_SECURITY: 0.15,
    ScoreCategory.TLS_SECURITY: 0.12,
    ScoreCategory.EXPOSURE_MGMT: 0.18,
    ScoreCategory.PATCH_HYGIENE: 0.10,
    ScoreCategory.INFO_LEAKAGE: 0.08,
    ScoreCategory.REPUTATION: 0.07,
    ScoreCategory.MISCONFIGURATION: 0.05,
}

# Severity → raw penalty points
SEVERITY_PENALTIES: Dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

# Asset/org criticality (1-5, same scale as Asset.criticality/Organization.criticality)
# -> penalty multiplier. 3 (the schema default for both) maps to 1.0 so a
# finding with no criticality signal scores exactly as it did before this
# field existed. Symmetric around 1.0, not just an escalation floor like
# exploit_boost — a genuinely low-value asset (e.g. a disposable dev/staging
# host) should see its findings' contribution shrink, not merely fail to grow.
CRITICALITY_MULTIPLIERS: Dict[int, float] = {
    1: 0.70,
    2: 0.85,
    3: 1.00,
    4: 1.15,
    5: 1.30,
}

# Finding category → score category mapping
FINDING_CATEGORY_MAP: Dict[str, ScoreCategory] = {
    # Network
    "open_port": ScoreCategory.NETWORK_SECURITY,
    "exposed_service": ScoreCategory.NETWORK_SECURITY,
    "firewall_bypass": ScoreCategory.NETWORK_SECURITY,
    "rdp_exposed": ScoreCategory.NETWORK_SECURITY,
    "ssh_exposed": ScoreCategory.NETWORK_SECURITY,
    "telnet_exposed": ScoreCategory.NETWORK_SECURITY,
    "smb_exposed": ScoreCategory.NETWORK_SECURITY,
    # DNS
    "missing_spf": ScoreCategory.DNS_HEALTH,
    "missing_dmarc": ScoreCategory.DNS_HEALTH,
    "dmarc_misconfiguration": ScoreCategory.DNS_HEALTH,
    "missing_dnssec": ScoreCategory.DNS_HEALTH,
    "zone_transfer": ScoreCategory.DNS_HEALTH,
    "dangling_dns": ScoreCategory.DNS_HEALTH,
    "subdomain_takeover": ScoreCategory.DNS_HEALTH,
    # Web
    "missing_hsts": ScoreCategory.WEB_SECURITY,
    "missing_csp": ScoreCategory.WEB_SECURITY,
    "missing_xframe": ScoreCategory.WEB_SECURITY,
    "missing_xcto": ScoreCategory.WEB_SECURITY,
    "missing_referrer_policy": ScoreCategory.WEB_SECURITY,
    "http_only": ScoreCategory.WEB_SECURITY,
    "mixed_content": ScoreCategory.WEB_SECURITY,
    # TLS
    "expired_certificate": ScoreCategory.TLS_SECURITY,
    "self_signed_certificate": ScoreCategory.TLS_SECURITY,
    "weak_cipher": ScoreCategory.TLS_SECURITY,
    "old_tls_version": ScoreCategory.TLS_SECURITY,
    "cert_expiring_soon": ScoreCategory.TLS_SECURITY,
    "wildcard_certificate": ScoreCategory.TLS_SECURITY,
    "tls_misconfiguration": ScoreCategory.TLS_SECURITY,
    # Exposure
    "exposed_admin_panel": ScoreCategory.EXPOSURE_MGMT,
    "default_credentials": ScoreCategory.EXPOSURE_MGMT,
    "exposed_database": ScoreCategory.EXPOSURE_MGMT,
    "exposed_storage": ScoreCategory.EXPOSURE_MGMT,
    "exposed_api": ScoreCategory.EXPOSURE_MGMT,
    "open_redirect": ScoreCategory.EXPOSURE_MGMT,
    "cloud_public_exposure": ScoreCategory.EXPOSURE_MGMT,
    # Patch hygiene
    "known_cve": ScoreCategory.PATCH_HYGIENE,
    "outdated_software": ScoreCategory.PATCH_HYGIENE,
    "eol_software": ScoreCategory.PATCH_HYGIENE,
    # Information leakage
    "exposed_git": ScoreCategory.INFO_LEAKAGE,
    "exposed_env_file": ScoreCategory.INFO_LEAKAGE,
    "debug_endpoint": ScoreCategory.INFO_LEAKAGE,
    "stack_trace": ScoreCategory.INFO_LEAKAGE,
    "source_disclosure": ScoreCategory.INFO_LEAKAGE,
    "exposed_backup": ScoreCategory.INFO_LEAKAGE,
    "credential_exposure": ScoreCategory.INFO_LEAKAGE,
    # Reputation
    "malware_detected": ScoreCategory.REPUTATION,
    "phishing_detected": ScoreCategory.REPUTATION,
    "blacklisted_ip": ScoreCategory.REPUTATION,
    "spam_reputation": ScoreCategory.REPUTATION,
    # Misconfiguration
    "cors_misconfiguration": ScoreCategory.MISCONFIGURATION,
    "clickjacking": ScoreCategory.MISCONFIGURATION,
    "insecure_cookie": ScoreCategory.MISCONFIGURATION,
    "directory_listing": ScoreCategory.MISCONFIGURATION,
}

DECAY_LAMBDA = 0.05  # e^(-0.05 * days) → ~14 days to halve penalty


@dataclass
class FindingInput:
    """Input finding for score computation."""
    id: str
    category: str
    severity: str
    status: str
    confidence: float = 1.0
    # Escalation-only multiplier from EPSS/CISA KEV exploit intelligence — a
    # different axis from confidence (trustworthiness of the match vs.
    # urgency of a *real* finding). Never below 1.0.
    exploit_boost: float = 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_false_positive: bool = False
    is_risk_accepted: bool = False
    cvss_score: Optional[float] = None
    # combine_criticality(asset.criticality, org.criticality) — unlike
    # exploit_boost this axis can legitimately reduce a penalty (a low-value
    # asset should be de-prioritized, not just a high-value one escalated),
    # so it's applied unclamped in compute_severity_penalty(). Defaults to 3
    # (CRITICALITY_MULTIPLIERS[3] == 1.0), matching Asset.criticality's own
    # schema default — a finding with no criticality data behaves exactly as
    # it did before this field existed.
    criticality: int = 3
    # Stage 2 of the redesign: raw CVSS 3.x vector string, parsed for
    # observability via parse_cvss_vector() below. Not read by
    # compute_severity_penalty() — the base cvss_score above is already
    # blended into the penalty; storing the parsed C/I/A/Scope breakdown here
    # only feeds the per-finding penalties audit dict, no formula effect yet.
    cvss_vector: Optional[str] = None


@dataclass
class CategoryScore:
    """Score for a single category."""
    category: ScoreCategory
    score: int
    max_score: int = 100
    weight: float = 0.0
    weighted_score: float = 0.0
    finding_count: int = 0
    penalties: List[Dict[str, Any]] = field(default_factory=list)
    factors: List[str] = field(default_factory=list)

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)


@dataclass
class OrgRiskScore:
    """Complete organization risk score."""
    org_id: str
    overall_score: int
    grade: str
    category_scores: Dict[str, CategoryScore]
    total_assets: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    score_breakdown: Dict[str, Any]
    score_factors: List[Dict[str, Any]]
    computed_at: datetime
    # 1.0 -> 1.1: added asset/org criticality as a scoring multiplier (Stage 1).
    # 1.1 -> 1.2: SSVC Automatable/Exploitation=poc escalation (Stage 3;
    # Stage 2 made no formula change, so no bump).
    # 1.2 -> 1.3: ad-hoc critical_penalty/high_penalty global cap replaced by
    # an explicit Likelihood x Impact matrix rating (Stage 4, final stage).
    # Forensic marker for "which formula produced this row," not surfaced in
    # any API response or chart annotation by itself — score_version is now
    # additionally exposed in /scores/history and /{org_id}/score-history so
    # at least the raw value is queryable, though still no visual chart
    # annotation (see CHANGELOG.md).
    score_version: str = "1.3"


def score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def compute_decay_factor(last_seen: Optional[datetime], now: Optional[datetime] = None) -> float:
    """
    Compute time-based decay factor for a finding.
    Newer findings have full weight; older ones decay exponentially.
    Half-life ≈ 14 days with λ=0.05.
    """
    if last_seen is None:
        return 1.0

    if now is None:
        now = datetime.now(timezone.utc)

    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    days_old = max(0, (now - last_seen).days)
    return math.exp(-DECAY_LAMBDA * days_old)


def compute_criticality_multiplier(criticality: Optional[int]) -> float:
    """Asset/org criticality -> penalty multiplier. Falls back to the neutral
    3 (-> 1.0) for anything outside 1-5, rather than raising, since this reads
    a value that ultimately comes from user input (Asset/Organization.criticality)."""
    c = criticality if criticality in CRITICALITY_MULTIPLIERS else 3
    return CRITICALITY_MULTIPLIERS[c]


def combine_criticality(asset_criticality: Optional[int], org_criticality: Optional[int]) -> int:
    """Asset.criticality defaults to 3 until manually set or auto-inferred, so
    max() naturally falls back to the org's own setting for a not-yet-
    classified asset, while still letting a specifically-flagged critical
    asset escalate above an otherwise-default org, and an org-wide bump raise
    every asset's floor."""
    return max(asset_criticality or 3, org_criticality or 3)


@dataclass
class CvssImpactMetrics:
    """Parsed Confidentiality/Integrity/Availability impact + Scope from a
    CVSS 3.x vector string. Observability only for now (Stage 2 of the
    redesign) — not yet read by compute_severity_penalty(); the base CVSS
    score is already blended into the penalty below, and a separate
    Scope-Changed escalation was deliberately deferred (CVSS's own base-score
    formula already partially reflects Scope, so adding another multiplier
    from it would re-emphasize an already-partially-counted signal rather
    than add genuinely new information)."""
    confidentiality: str  # "N" / "L" / "H"
    integrity: str
    availability: str
    scope_changed: bool


def parse_cvss_vector(vector: Optional[str]) -> Optional[CvssImpactMetrics]:
    """CVSS 3.0/3.1 only — covers ~95% of real nuclei template vectors. CVSS
    2.0 (different C/I/A encoding: N/P/C) and CVSS 4.0 (separate VC/VI/VA +
    SC/SI/SA structure) are a different schema entirely and are explicitly
    out of scope: this fails closed (returns None) rather than misparse them.
    Also tolerates a stray wrapping quote character and rejects a vector
    missing the "CVSS:3.x/" prefix outright — both real, if rare, shapes seen
    in the actual nuclei-templates corpus."""
    if not vector or not isinstance(vector, str):
        return None
    v = vector.strip().strip('"').strip("'")
    if not (v.startswith("CVSS:3.0/") or v.startswith("CVSS:3.1/")):
        return None
    parts = dict(seg.partition(":")[::2] for seg in v.split("/")[1:] if ":" in seg)
    c, i, a, s = parts.get("C"), parts.get("I"), parts.get("A"), parts.get("S")
    if c not in ("N", "L", "H") or i not in ("N", "L", "H") or a not in ("N", "L", "H"):
        return None
    return CvssImpactMetrics(confidentiality=c, integrity=i, availability=a, scope_changed=(s == "C"))


class ImpactLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LikelihoodLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MatrixRating(str, Enum):
    NOTE = "note"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_IMPACT_ORDER = [ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL]

# Stage 4 of the redesign: OWASP's own published Risk Rating Methodology 3x3
# table (Low/Medium/High Likelihood x Low/Medium/High Impact -> Note/Low/
# Medium/High/Critical), extended by one Impact column the same monotonic way
# OWASP's own docs describe for a 4th impact tier — each step right/down
# escalates one level, saturating at Critical in the worst corner.
_RISK_MATRIX: Dict[Tuple[LikelihoodLevel, ImpactLevel], MatrixRating] = {
    (LikelihoodLevel.LOW, ImpactLevel.LOW): MatrixRating.NOTE,
    (LikelihoodLevel.LOW, ImpactLevel.MEDIUM): MatrixRating.LOW,
    (LikelihoodLevel.LOW, ImpactLevel.HIGH): MatrixRating.MEDIUM,
    (LikelihoodLevel.LOW, ImpactLevel.CRITICAL): MatrixRating.HIGH,
    (LikelihoodLevel.MEDIUM, ImpactLevel.LOW): MatrixRating.LOW,
    (LikelihoodLevel.MEDIUM, ImpactLevel.MEDIUM): MatrixRating.MEDIUM,
    (LikelihoodLevel.MEDIUM, ImpactLevel.HIGH): MatrixRating.HIGH,
    (LikelihoodLevel.MEDIUM, ImpactLevel.CRITICAL): MatrixRating.CRITICAL,
    (LikelihoodLevel.HIGH, ImpactLevel.LOW): MatrixRating.MEDIUM,
    (LikelihoodLevel.HIGH, ImpactLevel.MEDIUM): MatrixRating.HIGH,
    (LikelihoodLevel.HIGH, ImpactLevel.HIGH): MatrixRating.CRITICAL,
    (LikelihoodLevel.HIGH, ImpactLevel.CRITICAL): MatrixRating.CRITICAL,
}

# score_to_grade's own existing boundaries (90/75/60), minus one — not fresh
# hand-picked numbers like the ad-hoc cap they replace.
_RATING_CAPS: Dict[MatrixRating, int] = {
    MatrixRating.CRITICAL: 59,
    MatrixRating.HIGH: 74,
    MatrixRating.MEDIUM: 89,
}


def compute_impact_level(
    severity: str,
    cvss: Optional[float],
    criticality_multiplier: float = 1.0,
) -> ImpactLevel:
    """CVSS-driven (NVD's own published Qualitative Severity Rating Scale
    boundaries), falling back to severity label when no CVSS score exists
    (43.6% of real findings — non-CVE nuclei/tls/eol checks). Shifted by
    asset/org criticality: a finding on a criticality>=4 asset escalates one
    tier (ceiling Critical), criticality<=2 de-escalates one tier (floor Low)
    — confirmed via real data this correctly rates confirmed-KEV
    medium-severity findings as Critical, at the accepted cost that an
    ordinary high-severity/no-exploit-intel finding on a criticality>=4 asset
    now caps slightly harsher than before this stage (see CHANGELOG.md)."""
    if cvss is not None and 0 <= cvss <= 10:
        if cvss >= 9.0:
            impact = ImpactLevel.CRITICAL
        elif cvss >= 7.0:
            impact = ImpactLevel.HIGH
        elif cvss >= 4.0:
            impact = ImpactLevel.MEDIUM
        else:
            impact = ImpactLevel.LOW
    else:
        try:
            sev = Severity(severity.lower())
        except ValueError:
            sev = Severity.INFO
        impact = {
            Severity.CRITICAL: ImpactLevel.CRITICAL,
            Severity.HIGH: ImpactLevel.HIGH,
            Severity.MEDIUM: ImpactLevel.MEDIUM,
            Severity.LOW: ImpactLevel.LOW,
            Severity.INFO: ImpactLevel.LOW,
        }[sev]

    idx = _IMPACT_ORDER.index(impact)
    if criticality_multiplier >= 1.15:
        idx = min(idx + 1, len(_IMPACT_ORDER) - 1)
    elif criticality_multiplier <= 0.85:
        idx = max(idx - 1, 0)
    return _IMPACT_ORDER[idx]


def compute_likelihood_level(exploit_boost: float) -> LikelihoodLevel:
    """Driven by exploit_boost, which can only take one of 6 discrete values
    today: {1.0, 1.2, 1.25, 1.3, 1.5, 1.75} from exploit_intel.py's KEV/EPSS
    boost and version_cve_intel.py's SSVC boost, max()-combined in
    risk_worker.py. Confidence is deliberately NOT a factor here — a real-data
    check found VERSION_MATCH_CONFIDENCE=0.3 is a fixed per-detection-method
    constant applied to 69% of real non-KEV high-EPSS findings, so a naive
    "low confidence demotes Likelihood" rule would have silently suppressed
    exactly the population Stage 3's exploit-intel work exists to elevate.
    Confidence keeps its existing, separate role in compute_severity_penalty()."""
    if exploit_boost >= 1.5:
        return LikelihoodLevel.HIGH
    if exploit_boost > 1.0:
        return LikelihoodLevel.MEDIUM
    return LikelihoodLevel.LOW


def compute_matrix_rating(likelihood: LikelihoodLevel, impact: ImpactLevel) -> MatrixRating:
    return _RISK_MATRIX[(likelihood, impact)]


def compute_severity_penalty(
    severity: str,
    confidence: float,
    decay: float,
    cvss: Optional[float] = None,
    exploit_boost: float = 1.0,
    criticality_multiplier: float = 1.0,
) -> float:
    """
    Compute penalty points for a single finding.
    Uses CVSS score if available for more precision.
    """
    try:
        sev = Severity(severity.lower())
    except ValueError:
        sev = Severity.INFO

    base_penalty = SEVERITY_PENALTIES[sev]

    # If CVSS available, blend with severity-based penalty
    if cvss is not None and 0 <= cvss <= 10:
        cvss_penalty = (cvss / 10.0) * SEVERITY_PENALTIES[Severity.CRITICAL]
        base_penalty = (base_penalty + cvss_penalty) / 2

    # criticality_multiplier is deliberately NOT floor-clamped like
    # max(1.0, exploit_boost) below — it must be able to go below 1.0 so a
    # low-criticality asset's findings are actually de-prioritized, not just
    # prevented from being escalated further.
    return base_penalty * confidence * decay * max(1.0, exploit_boost) * criticality_multiplier


class RiskScoringEngine:
    """
    Core risk scoring engine for ASM Platform.

    Algorithm:
    1. Group findings by mapped category
    2. For each category, compute penalty sum with decay
    3. Cap each category at max_penalty (100 points of deduction)
    4. category_score = max(0, 100 - total_penalty)
    5. overall_score = Σ(category_score × weight)
    """

    MAX_PENALTY_PER_CATEGORY = 100.0

    def __init__(
        self,
        weights: Optional[Dict[ScoreCategory, float]] = None,
        decay_lambda: float = DECAY_LAMBDA,
        max_penalty: float = MAX_PENALTY_PER_CATEGORY,
    ):
        self.weights = weights or CATEGORY_WEIGHTS
        self.decay_lambda = decay_lambda
        self.max_penalty = max_penalty
        self._validate_weights()

    def _validate_weights(self):
        total = sum(self.weights.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Category weights must sum to 1.0, got {total:.3f}")

    def compute(
        self,
        org_id: str,
        findings: List[FindingInput],
        total_assets: int = 0,
        now: Optional[datetime] = None,
    ) -> OrgRiskScore:
        """
        Compute complete risk score for an organization.

        Args:
            org_id: Organization identifier
            findings: All active findings for the org
            total_assets: Total asset count (for context scoring)
            now: Reference time (defaults to UTC now)
        """
        if now is None:
            now = datetime.now(timezone.utc)

        log.info("computing_risk_score", org_id=org_id, finding_count=len(findings))

        # Filter out excluded findings
        active_findings = [
            f for f in findings
            if not f.is_false_positive
            and not f.is_risk_accepted
            and f.status not in ("resolved", "false_positive")
        ]

        # Initialize category buckets
        category_findings: Dict[ScoreCategory, List[FindingInput]] = {
            cat: [] for cat in ScoreCategory
        }

        # Count by severity
        severity_counts = {s: 0 for s in Severity}
        for finding in active_findings:
            # Map to category
            score_cat = FINDING_CATEGORY_MAP.get(
                finding.category.lower(),
                ScoreCategory.MISCONFIGURATION,  # default bucket
            )
            category_findings[score_cat].append(finding)

            # Count severity
            try:
                sev = Severity(finding.severity.lower())
                severity_counts[sev] += 1
            except ValueError:
                pass

        # Compute per-category scores
        category_scores: Dict[str, CategoryScore] = {}
        weighted_total = 0.0

        for cat, cat_findings in category_findings.items():
            cat_score = self._compute_category_score(cat, cat_findings, now)
            cat_score.weight = self.weights.get(cat, 0.0)
            cat_score.weighted_score = cat_score.score * cat_score.weight
            weighted_total += cat_score.weighted_score
            category_scores[cat.value] = cat_score

        # Stage 4 of the redesign: per-category weighting alone lets a handful
        # of real severe findings spread across otherwise-clean categories
        # average out near 100 — cap the score so that doesn't happen. Driven
        # by the single worst Likelihood x Impact matrix rating across every
        # finding org-wide (an explicit OWASP-style classification, not the
        # ad-hoc critical_penalty/high_penalty sum thresholds this replaced).
        worst_rating: Optional[MatrixRating] = None
        rating_order = [MatrixRating.NOTE, MatrixRating.LOW, MatrixRating.MEDIUM, MatrixRating.HIGH, MatrixRating.CRITICAL]
        for cat_score in category_scores.values():
            for penalty in cat_score.penalties:
                rating = MatrixRating(penalty["matrix_rating"])
                if worst_rating is None or rating_order.index(rating) > rating_order.index(worst_rating):
                    worst_rating = rating

        # Apply bonus for assets with no findings (healthy org)
        if total_assets > 0 and len(active_findings) == 0:
            bonus = min(5, 100 - weighted_total)
            weighted_total = min(100, weighted_total + bonus)

        overall_score = max(0, min(100, round(weighted_total)))
        if worst_rating in _RATING_CAPS:
            overall_score = min(overall_score, _RATING_CAPS[worst_rating])
        grade = score_to_grade(overall_score)

        # Build score factors (human-readable impact statements)
        score_factors = self._generate_score_factors(category_scores, active_findings)

        # Build breakdown for API
        score_breakdown = {
            cat.value: {
                "score": cs.score,
                "grade": cs.grade,
                "weight": cs.weight,
                "weighted_score": round(cs.weighted_score, 2),
                "finding_count": cs.finding_count,
                "factors": cs.factors,
            }
            for cat, cs in [(ScoreCategory(k), v) for k, v in category_scores.items()]
        }

        result = OrgRiskScore(
            org_id=org_id,
            overall_score=overall_score,
            grade=grade,
            category_scores=category_scores,
            total_assets=total_assets,
            total_findings=len(findings),
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
            score_breakdown=score_breakdown,
            score_factors=score_factors,
            computed_at=now,
        )

        log.info(
            "risk_score_computed",
            org_id=org_id,
            score=overall_score,
            grade=grade,
            active_findings=len(active_findings),
        )

        return result

    def _compute_category_score(
        self,
        category: ScoreCategory,
        findings: List[FindingInput],
        now: datetime,
    ) -> CategoryScore:
        """Compute score for a single category."""
        if not findings:
            return CategoryScore(
                category=category,
                score=100,
                finding_count=0,
                factors=["No issues detected"],
            )

        total_penalty = 0.0
        penalties = []
        factors = []

        for f in findings:
            decay = compute_decay_factor(f.last_seen, now)
            criticality_multiplier = compute_criticality_multiplier(f.criticality)
            penalty = compute_severity_penalty(
                f.severity,
                f.confidence,
                decay,
                f.cvss_score,
                f.exploit_boost,
                criticality_multiplier,
            )
            total_penalty += penalty
            cvss_impact = parse_cvss_vector(f.cvss_vector)
            impact_level = compute_impact_level(f.severity, f.cvss_score, criticality_multiplier)
            likelihood_level = compute_likelihood_level(f.exploit_boost)
            matrix_rating = compute_matrix_rating(likelihood_level, impact_level)
            penalties.append({
                "finding_id": f.id,
                "severity": f.severity,
                "penalty": round(penalty, 2),
                "decay": round(decay, 3),
                "confidence": f.confidence,
                "exploit_boost": f.exploit_boost,
                "criticality": f.criticality,
                "criticality_multiplier": criticality_multiplier,
                "cvss_impact": (
                    {
                        "confidentiality": cvss_impact.confidentiality,
                        "integrity": cvss_impact.integrity,
                        "availability": cvss_impact.availability,
                        "scope_changed": cvss_impact.scope_changed,
                    }
                    if cvss_impact
                    else None
                ),
                "impact": impact_level.value,
                "likelihood": likelihood_level.value,
                "matrix_rating": matrix_rating.value,
            })

        # Cap total penalty
        total_penalty = min(self.max_penalty, total_penalty)
        score = max(0, round(100 - total_penalty))

        # Generate human-readable factors
        by_severity = {}
        for f in findings:
            sev = f.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        for sev, count in sorted(by_severity.items(), key=lambda x: list(Severity).index(Severity(x[0])) if x[0] in [s.value for s in Severity] else 99):
            factors.append(f"{count} {sev} issue{'s' if count > 1 else ''}")

        return CategoryScore(
            category=category,
            score=score,
            finding_count=len(findings),
            penalties=penalties,
            factors=factors,
        )

    def _generate_score_factors(
        self,
        category_scores: Dict[str, CategoryScore],
        active_findings: List[FindingInput],
    ) -> List[Dict[str, Any]]:
        """Generate prioritized list of score improvement factors."""
        factors = []

        # Sort categories by impact (lowest score first)
        sorted_cats = sorted(
            category_scores.items(),
            key=lambda x: x[1].weighted_score,
        )

        for cat_name, cat_score in sorted_cats[:5]:  # Top 5 impactful
            if cat_score.score < 100:
                impact = 100 - cat_score.score
                factors.append({
                    "category": cat_name,
                    "score": cat_score.score,
                    "grade": cat_score.grade,
                    "impact": round(impact * cat_score.weight, 2),
                    "finding_count": cat_score.finding_count,
                    "description": f"{cat_name.replace('_', ' ').title()} has {cat_score.finding_count} issue(s)",
                    "factors": cat_score.factors,
                })

        return factors

    def compute_score_delta(
        self,
        previous_score: OrgRiskScore,
        current_score: OrgRiskScore,
    ) -> Dict[str, Any]:
        """Compute delta between two score snapshots."""
        delta = current_score.overall_score - previous_score.overall_score
        category_deltas = {}

        for cat in ScoreCategory:
            prev = previous_score.category_scores.get(cat.value)
            curr = current_score.category_scores.get(cat.value)
            if prev and curr:
                category_deltas[cat.value] = {
                    "previous": prev.score,
                    "current": curr.score,
                    "delta": curr.score - prev.score,
                }

        return {
            "overall_delta": delta,
            "previous_score": previous_score.overall_score,
            "current_score": current_score.overall_score,
            "previous_grade": previous_score.grade,
            "current_grade": current_score.grade,
            "grade_changed": previous_score.grade != current_score.grade,
            "improved": delta > 0,
            "degraded": delta < 0,
            "category_deltas": category_deltas,
            "new_findings": current_score.total_findings - previous_score.total_findings,
            "computed_at": current_score.computed_at.isoformat(),
        }


# ── Convenience function ──────────────────────────────────────
def compute_org_score(
    org_id: str,
    findings: List[Dict[str, Any]],
    total_assets: int = 0,
) -> OrgRiskScore:
    """
    Convenience wrapper: compute org score from raw finding dicts.
    Suitable for calling from workers and API endpoints.
    """
    engine = RiskScoringEngine()

    finding_inputs = []
    for f in findings:
        finding_inputs.append(FindingInput(
            id=str(f.get("id", "")),
            category=f.get("category", "unknown"),
            severity=f.get("severity", "info"),
            status=f.get("status", "open"),
            confidence=float(f.get("confidence", 1.0)),
            exploit_boost=float(f.get("exploit_boost", 1.0)),
            first_seen=f.get("first_seen"),
            last_seen=f.get("last_seen"),
            is_false_positive=bool(f.get("is_false_positive", False)),
            is_risk_accepted=bool(f.get("is_risk_accepted", False)),
            cvss_score=f.get("cvss_score"),
            criticality=int(f.get("criticality", 3)),
            cvss_vector=f.get("cvss_vector"),
        ))

    return engine.compute(org_id, finding_inputs, total_assets)

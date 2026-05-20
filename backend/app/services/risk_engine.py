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
    # Exposure
    "exposed_admin_panel": ScoreCategory.EXPOSURE_MGMT,
    "default_credentials": ScoreCategory.EXPOSURE_MGMT,
    "exposed_database": ScoreCategory.EXPOSURE_MGMT,
    "exposed_storage": ScoreCategory.EXPOSURE_MGMT,
    "exposed_api": ScoreCategory.EXPOSURE_MGMT,
    "open_redirect": ScoreCategory.EXPOSURE_MGMT,
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
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_false_positive: bool = False
    is_risk_accepted: bool = False
    cvss_score: Optional[float] = None


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
    score_version: str = "1.0"


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


def compute_severity_penalty(severity: str, confidence: float, decay: float, cvss: Optional[float] = None) -> float:
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

    return base_penalty * confidence * decay


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

        # Apply bonus for assets with no findings (healthy org)
        if total_assets > 0 and len(active_findings) == 0:
            bonus = min(5, 100 - weighted_total)
            weighted_total = min(100, weighted_total + bonus)

        overall_score = max(0, min(100, round(weighted_total)))
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
            penalty = compute_severity_penalty(
                f.severity,
                f.confidence,
                decay,
                f.cvss_score,
            )
            total_penalty += penalty
            penalties.append({
                "finding_id": f.id,
                "severity": f.severity,
                "penalty": round(penalty, 2),
                "decay": round(decay, 3),
                "confidence": f.confidence,
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
            first_seen=f.get("first_seen"),
            last_seen=f.get("last_seen"),
            is_false_positive=bool(f.get("is_false_positive", False)),
            is_risk_accepted=bool(f.get("is_risk_accepted", False)),
            cvss_score=f.get("cvss_score"),
        ))

    return engine.compute(org_id, finding_inputs, total_assets)

"""
ASM Platform — Report executive narrative.

Deterministic, templated prose synthesizing an already-computed report's
risk score / summary / category data into readable sentences. Not an LLM
call -- every sentence traces directly to a field already present in
report_service.py's report_data, so the narrative is always explainable and
never invents a claim the underlying data doesn't support.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

CATEGORY_LABELS: Dict[str, str] = {
    "network_security": "Network Security",
    "dns_health": "DNS Health",
    "web_security": "Web Security",
    "tls_security": "TLS Security",
    "exposure_mgmt": "Exposure Management",
    "patch_hygiene": "Patch Hygiene",
    "info_leakage": "Information Leakage",
    "reputation": "Reputation",
    "misconfiguration": "Misconfiguration",
}

# Matches risk_engine.py::score_to_grade's own "A" cutoff -- a category at or
# above this is healthy and not worth singling out as a risk driver.
HEALTHY_CATEGORY_THRESHOLD = 90


def build_executive_narrative(
    org_name: str,
    risk_score: Optional[Dict[str, Any]],
    summary: Dict[str, Any],
    findings_by_category: Dict[str, int],
) -> str:
    sentences: list[str] = []

    if risk_score:
        sentences.append(
            f"{org_name}'s overall security posture is rated {risk_score['grade']} "
            f"({risk_score['overall_score']}/100) as of {risk_score['computed_at'][:10]}."
        )
        categories = risk_score.get("categories") or {}
        if categories:
            worst_key = min(categories, key=lambda k: categories[k])
            worst_score = categories[worst_key]
            if worst_score < HEALTHY_CATEGORY_THRESHOLD:
                worst_label = CATEGORY_LABELS.get(worst_key, worst_key.replace("_", " ").title())
                sentences.append(
                    f"The most significant risk driver is {worst_label} ({worst_score}/100), "
                    f"the lowest-scoring category."
                )
    else:
        sentences.append(f"{org_name} does not yet have a computed risk score.")

    total = summary.get("total_findings", 0) or 0
    critical = summary.get("critical", 0) or 0
    high = summary.get("high", 0) or 0

    if total:
        severity_bit = ""
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if high:
            parts.append(f"{high} high")
        if parts:
            severity_bit = f", including {' and '.join(parts)} severity"
        sentences.append(f"There are currently {total} open findings{severity_bit}.")
    else:
        sentences.append("There are no open findings at this time.")

    if findings_by_category:
        top_category, top_count = max(findings_by_category.items(), key=lambda kv: kv[1])
        top_label = top_category.replace("_", " ")
        sentences.append(
            f"{top_label.capitalize()} accounts for the largest share of open findings ({top_count})."
        )

    if critical or high:
        sentences.append(
            "Prioritizing remediation of critical and high severity findings is recommended to "
            "improve the organization's overall risk posture."
        )

    return " ".join(sentences)

"""Asset validation and scan-gating helpers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable


SCANNABLE_SCOPE_STATUSES = {"in_scope", "probable"}
SCANNABLE_LIVENESS_STATUSES = {"alive"}


def normalize_hostname(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def validate_discovered_host(
    *,
    host: str,
    root_domains: Iterable[str],
    dns_info: Dict[str, Any] | None = None,
    http_info: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build deterministic ownership/liveness validation evidence for a host."""
    dns_info = dns_info or {}
    http_info = http_info or {}
    host = normalize_hostname(host)
    roots = [normalize_hostname(root) for root in root_domains if root]
    reasons: list[str] = []
    evidence: Dict[str, Any] = {
        "root_domains": roots,
        "dns": {
            "a": dns_info.get("a", []),
            "aaaa": dns_info.get("aaaa", []),
            "cname": dns_info.get("cname", []),
        },
        "http": {
            "url": http_info.get("url"),
            "status_code": http_info.get("status_code"),
            "status_class": http_info.get("status_class"),
            "title": http_info.get("title"),
            "webserver": http_info.get("webserver"),
            "cdn_name": http_info.get("cdn_name"),
        },
    }

    confidence = 0.0
    matched_root = next((root for root in roots if host == root or host.endswith(f".{root}")), None)
    if matched_root:
        confidence += 0.55
        reasons.append("host_matches_registered_scope")
        evidence["matched_root_domain"] = matched_root
    else:
        reasons.append("host_outside_registered_scope")

    ips = list(dns_info.get("a", []) or []) + list(dns_info.get("aaaa", []) or [])
    if ips:
        confidence += 0.15
        reasons.append("dns_resolved")
    if dns_info.get("cname"):
        confidence += 0.05
        reasons.append("cname_chain_observed")

    status_code = http_info.get("status_code")
    status_class = http_info.get("status_class")
    if status_code:
        confidence += 0.2
        reasons.append("http_probe_alive")
    if http_info.get("url"):
        confidence += 0.05
        reasons.append("http_url_observed")

    tls = http_info.get("tls") or {}
    san_values = [normalize_hostname(value) for value in tls.get("subject_an", []) or []]
    subject_dn = normalize_hostname(tls.get("subject_dn", ""))
    if matched_root and (any(matched_root in san for san in san_values) or matched_root in subject_dn):
        confidence += 0.05
        reasons.append("tls_certificate_matches_scope")
        evidence["tls"] = {
            "subject_an": tls.get("subject_an", [])[:20],
            "subject_dn": tls.get("subject_dn"),
            "issuer": tls.get("issuer"),
        }

    redirects = http_info.get("redirect_chain", []) or []
    if redirects:
        evidence["redirect_chain"] = redirects[:10]
        off_scope = [
            url for url in redirects
            if roots and not any(root in normalize_hostname(url) for root in roots)
        ]
        if off_scope:
            confidence = max(0.0, confidence - 0.15)
            reasons.append("redirect_chain_leaves_scope")

    confidence = min(round(confidence, 2), 1.0)
    if matched_root and confidence >= 0.75:
        scope_status = "in_scope"
        ownership_reason = "matched registered scope with DNS/HTTP evidence"
    elif matched_root and confidence >= 0.55:
        scope_status = "probable"
        ownership_reason = "matched registered scope with limited validation evidence"
    elif matched_root:
        scope_status = "needs_review"
        ownership_reason = "matched registered scope but validation evidence is weak"
    else:
        scope_status = "out_of_scope"
        ownership_reason = "host did not match registered scope"

    if status_code:
        liveness_status = "alive"
    elif ips:
        liveness_status = "dns_only"
    else:
        liveness_status = "unresolved"

    if status_class in {"ok", "redirect", "auth"}:
        exposure_status = "exposed"
    elif status_class in {"client_error", "server_error", "not_found"}:
        exposure_status = "limited"
    elif status_code:
        exposure_status = "unknown_http"
    else:
        exposure_status = "not_exposed"

    return {
        "scope_status": scope_status,
        "ownership_confidence": confidence,
        "ownership_reason": ownership_reason,
        "exposure_status": exposure_status,
        "liveness_status": liveness_status,
        "validation_sources": {
            "method": "discovery_dns_http_tls",
            "reasons": reasons,
            "evidence": evidence,
            "validated_at": datetime.now(timezone.utc).isoformat(),
        },
        "last_verified_at": datetime.now(timezone.utc),
        "is_in_scope": scope_status in {"in_scope", "probable", "needs_review"},
        "confidence": confidence,
    }


def should_scan_validated_asset(validation: Dict[str, Any] | None, *, require_validation: bool = True) -> bool:
    """Return whether active scan phases should target this asset."""
    if not validation:
        return not require_validation
    return (
        validation.get("scope_status") in SCANNABLE_SCOPE_STATUSES
        and validation.get("liveness_status") in SCANNABLE_LIVENESS_STATUSES
    )


def validation_skip_reason(validation: Dict[str, Any] | None) -> str:
    if not validation:
        return "missing_validation"
    if validation.get("scope_status") not in SCANNABLE_SCOPE_STATUSES:
        return f"scope_{validation.get('scope_status') or 'unknown'}"
    if validation.get("liveness_status") not in SCANNABLE_LIVENESS_STATUSES:
        return f"liveness_{validation.get('liveness_status') or 'unknown'}"
    return "eligible"

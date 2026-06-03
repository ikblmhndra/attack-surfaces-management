"""Asset validation and scan-gating helpers."""
from __future__ import annotations

import fnmatch
import ipaddress
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

    if status_class in {"ok", "redirect", "auth", "auth_required"}:
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


def apply_scope_controls(
    validation: Dict[str, Any],
    *,
    target: str,
    allow_patterns: Iterable[str] | None = None,
    deny_patterns: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Apply organization explicit allow/deny patterns to validation evidence."""
    updated = dict(validation or {})
    sources = dict(updated.get("validation_sources") or {})
    reasons = list(sources.get("reasons") or [])
    target_normalized = normalize_hostname(target)

    deny_match = _first_pattern_match(target_normalized, deny_patterns or [])
    allow_match = _first_pattern_match(target_normalized, allow_patterns or [])
    if deny_match:
        updated["scope_status"] = "out_of_scope"
        updated["ownership_confidence"] = min(float(updated.get("ownership_confidence") or 0), 0.2)
        updated["ownership_reason"] = f"matched organization deny pattern: {deny_match}"
        updated["is_in_scope"] = False
        reasons.append("org_deny_pattern_matched")
        sources["matched_deny_pattern"] = deny_match
    elif allow_match and updated.get("scope_status") in {"needs_review", "out_of_scope"}:
        updated["scope_status"] = "probable"
        updated["ownership_confidence"] = max(float(updated.get("ownership_confidence") or 0), 0.65)
        updated["ownership_reason"] = f"matched organization allow pattern: {allow_match}"
        updated["is_in_scope"] = True
        reasons.append("org_allow_pattern_matched")
        sources["matched_allow_pattern"] = allow_match

    sources["reasons"] = list(dict.fromkeys(reasons))
    updated["validation_sources"] = sources
    return updated


def merge_rdap_evidence(
    validation: Dict[str, Any],
    *,
    rdap: Dict[str, Any] | None,
    org_names: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Merge RDAP/ASN ownership evidence into an existing validation result."""
    if not rdap:
        return validation
    updated = dict(validation or {})
    sources = dict(updated.get("validation_sources") or {})
    reasons = list(sources.get("reasons") or [])
    evidence = dict(sources.get("evidence") or {})
    evidence["rdap"] = rdap

    org_haystack = " ".join(
        str(value or "").lower()
        for value in [
            rdap.get("asn_org"),
            rdap.get("registry_org"),
            rdap.get("isp"),
            rdap.get("network_name"),
            rdap.get("network_handle"),
            rdap.get("country"),
        ]
    )
    names = [normalize_hostname(name).replace(".", " ") for name in (org_names or []) if name]
    matched_name = next((name for name in names if name and name in org_haystack), None)
    if matched_name:
        reasons.append("rdap_org_matches_scope")
        updated["ownership_confidence"] = min(max(float(updated.get("ownership_confidence") or 0), 0.8), 1.0)
        if updated.get("scope_status") in {"needs_review", "probable"}:
            updated["scope_status"] = "in_scope"
        updated["ownership_reason"] = "RDAP/ASN ownership matched organization identity"
    elif rdap.get("asn") or rdap.get("asn_org"):
        reasons.append("rdap_asn_observed")
        updated["ownership_confidence"] = max(float(updated.get("ownership_confidence") or 0), 0.55)

    sources["reasons"] = list(dict.fromkeys(reasons))
    sources["evidence"] = evidence
    updated["validation_sources"] = sources
    return updated


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


def _first_pattern_match(target: str, patterns: Iterable[str]) -> str | None:
    for raw_pattern in patterns:
        pattern = normalize_hostname(raw_pattern)
        if not pattern:
            continue
        if _pattern_matches(target, pattern):
            return raw_pattern
    return None


def _pattern_matches(target: str, pattern: str) -> bool:
    if pattern.startswith("*.") and (target.endswith(pattern[1:]) or target == pattern[2:]):
        return True
    if any(char in pattern for char in "*?[]"):
        return fnmatch.fnmatch(target, pattern)
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(target) in network
    except ValueError:
        pass
    return target == pattern or target.endswith(f".{pattern}")

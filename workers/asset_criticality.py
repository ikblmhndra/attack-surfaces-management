"""
ASM Platform — Asset Criticality Inference

Auto-infers a default Asset.criticality (1-5, same scale as Organization.criticality)
from signals the platform already collects (hostname, root-domain membership) —
so wiring criticality into risk scoring doesn't require 100% manual asset-by-asset
tagging to be useful from day one. A human can still override any individual
asset's criticality via PATCH /assets/{id} (stamped with
labels.criticality_source="manual"); this module only ever computes the
*default* a not-yet-classified asset should start at.

Same lightweight regex-table style as web_crawl_worker.py's AUTH_PATH_RE/
ADMIN_PATH_RE/API_PATH_RE (endpoint-path classifiers) — this is the analogous
classifier at the hostname level, not a different mechanism.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

# Environment/disposability keywords — checked first, deliberately: a host
# like "api-staging.foo.com" should still classify as low-value. The
# environment label dominates the functional label, since a staging/dev
# payment box is still disposable infrastructure.
LOW_VALUE_HOST_RE = re.compile(
    r"(^|[.\-])(dev|develop|staging|stage|stg|test|testing|qa|uat|preprod|"
    r"demo|sandbox|sbx|beta|internal|local)([.\-]|$)",
    re.I,
)

# Functionally sensitive keywords — auth/payment/admin-adjacent hosts, absent
# an environment keyword above, are more likely to matter if compromised.
HIGH_VALUE_HOST_RE = re.compile(
    r"(api|payment|pay|checkout|billing|invoice|account|accounts|auth|login|"
    r"sso|oauth|admin|portal|vault|wallet|secure)",
    re.I,
)

PROD_HOST_RE = re.compile(r"(^|[.\-])(prod|production|www)([.\-]|$)", re.I)


def infer_asset_criticality(
    hostname: str,
    is_root_domain: bool = False,
    org_criticality: Optional[int] = None,
) -> Tuple[int, str]:
    """Returns (criticality, reason) — reason is stored for observability/
    debugging, not scored. `org_criticality` sets the baseline an inferred
    value escalates from or de-escalates against, so an org that's already
    marked high-criticality doesn't get every subdomain reset to a generic
    middle value."""
    baseline = max(1, min(5, org_criticality or 3))
    host = (hostname or "").lower()

    if LOW_VALUE_HOST_RE.search(host):
        return min(baseline, 2), "low_value_keyword"
    if HIGH_VALUE_HOST_RE.search(host):
        return max(baseline, 4), "high_value_keyword"
    if is_root_domain:
        return max(baseline, 4), "root_domain"
    if PROD_HOST_RE.search(host):
        return max(baseline, 4), "prod_keyword"
    return baseline, "org_default"

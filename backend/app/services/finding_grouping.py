"""
ASM Platform — Finding Grouping (display-only aggregation)

Collapses repeated instances of the same underlying issue (e.g. one CVE
matched on 25 different hosts running the same outdated software version)
into a single group for triage, without touching detection logic at all —
every Finding row stays exactly as persisted. Motivated by a real scan: 536
version_cve_correlation findings, only 41 distinct CVEs behind them.

Finding.template_id (already indexed) is the grouping key used by the
GET /findings/grouped endpoint (backend/app/api/v1/endpoints/findings.py) —
confirmed a universal, safe key across every scanner (not just
version_cve_correlation), and category/severity are confirmed uniform per
template_id in real data. This module only holds the pure, DB-independent
piece: deriving a human-readable heading/subheading for a group.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _group_heading(
    sample_title: Optional[str],
    cve_ids: List[str],
    template_id: Optional[str],
    finding_count: int,
) -> Dict[str, Any]:
    """Raw `title` is unsafe as a group-level label for CVE-bearing groups —
    it embeds the matched version string and varies per host (one real CVE's
    template_id spans 8 distinct title variants in production data). cve_id/
    template_id do not vary within a group, so they're the stable heading.

    Non-CVE templates (nuclei's cors-misconfiguration, missing-sri, etc.) are
    confirmed single-variant per template_id in real data, so their raw title
    is safe to show as-is. The scanner=''/template_id IS NULL singleton
    fallback rows need no special case here — they arrive with empty cve_ids
    and finding_count == 1, so they naturally take the template branch and
    degrade to just showing their own title with no subheading noise.
    """
    if cve_ids:
        heading = cve_ids[0].upper()
        subheading = f"e.g., {sample_title}" if finding_count > 1 else sample_title
        heading_kind = "cve"
    else:
        heading = sample_title or (template_id or "")
        subheading = template_id
        heading_kind = "template"
    return {"heading": heading, "subheading": subheading, "heading_kind": heading_kind}

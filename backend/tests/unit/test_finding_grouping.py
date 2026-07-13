"""
ASM Platform — Unit Tests: Finding Grouping
Pure-function tests for the group heading/subheading rule.
"""
from app.services.finding_grouping import _group_heading


class TestGroupHeading:
    def test_cve_group_heading_is_uppercased_cve_id(self):
        result = _group_heading(
            sample_title="Potential CVE-2026-42535: Apache HTTP Server 2.4.62 matches a known-affected version range",
            cve_ids=["CVE-2026-42535"],
            template_id="version_cve_cve-2026-42535",
            finding_count=25,
        )
        assert result["heading"] == "CVE-2026-42535"
        assert result["heading_kind"] == "cve"

    def test_cve_group_plural_subheading_is_prefixed(self):
        result = _group_heading(
            sample_title="Potential CVE-2026-42535: Apache HTTP Server 2.4.62 matches a known-affected version range",
            cve_ids=["CVE-2026-42535"],
            template_id="version_cve_cve-2026-42535",
            finding_count=25,
        )
        assert result["subheading"].startswith("e.g., ")

    def test_cve_group_singular_subheading_is_bare(self):
        # finding_count == 1 -> not really a "group" of repeats, no "e.g." framing needed.
        result = _group_heading(
            sample_title="Potential CVE-2026-42535: Apache HTTP Server 2.4.62 matches a known-affected version range",
            cve_ids=["CVE-2026-42535"],
            template_id="version_cve_cve-2026-42535",
            finding_count=1,
        )
        assert result["subheading"] == "Potential CVE-2026-42535: Apache HTTP Server 2.4.62 matches a known-affected version range"

    def test_cve_id_lowercase_input_gets_uppercased(self):
        result = _group_heading(
            sample_title="t", cve_ids=["cve-2026-99999"], template_id="x", finding_count=1,
        )
        assert result["heading"] == "CVE-2026-99999"

    def test_non_cve_group_heading_is_verbatim_title(self):
        # Confirmed in real data: non-CVE templates (nuclei's cors-misconfiguration,
        # missing-sri, etc.) are single-variant per template_id, so raw title is safe.
        result = _group_heading(
            sample_title="CORS Misconfiguration Detected",
            cve_ids=[],
            template_id="cors-misconfig",
            finding_count=6,
        )
        assert result["heading"] == "CORS Misconfiguration Detected"
        assert result["subheading"] == "cors-misconfig"
        assert result["heading_kind"] == "template"

    def test_singleton_fallback_no_scanner_row(self):
        # scanner=''/template_id IS NULL rows (COALESCE'd to a synthetic
        # per-id key upstream) arrive here with empty cve_ids and
        # finding_count == 1 — must degrade cleanly, no special case needed.
        result = _group_heading(
            sample_title="Manually seeded finding",
            cve_ids=[],
            template_id=None,
            finding_count=1,
        )
        assert result["heading"] == "Manually seeded finding"
        assert result["subheading"] is None
        assert result["heading_kind"] == "template"

    def test_missing_title_and_template_id_falls_back_to_empty_string(self):
        # Defensive edge case: never emit a None heading.
        result = _group_heading(sample_title=None, cve_ids=[], template_id=None, finding_count=1)
        assert result["heading"] == ""

"""
ASM Platform — Unit Tests: CIS Controls v8 Compliance Mapping
"""
from app.services.compliance_mapping import CATEGORY_TO_CIS_SAFEGUARD, CIS_CONTROLS, get_cis_mapping
from app.services.risk_engine import FINDING_CATEGORY_MAP


class TestCategoryCoverage:
    def test_every_finding_category_map_key_has_a_cis_mapping(self):
        # FINDING_CATEGORY_MAP is the production-vetted, exhaustive category
        # taxonomy risk_engine.py already relies on -- a past incident found
        # categories silently missing from it, so this test guards the same
        # kind of drift for the CIS mapping.
        missing = set(FINDING_CATEGORY_MAP) - set(CATEGORY_TO_CIS_SAFEGUARD)
        assert missing == set()

    def test_no_extra_categories_beyond_finding_category_map(self):
        extra = set(CATEGORY_TO_CIS_SAFEGUARD) - set(FINDING_CATEGORY_MAP)
        assert extra == set()

    def test_every_mapped_control_id_exists_in_cis_controls(self):
        for control_id, _safeguard_id, _title in CATEGORY_TO_CIS_SAFEGUARD.values():
            assert control_id in CIS_CONTROLS


class TestGetCisMapping:
    def test_known_category_returns_control_safeguard_title(self):
        result = get_cis_mapping("known_cve")
        assert result == ("7", "7.1", "Establish and Maintain a Vulnerability Management Process")

    def test_case_insensitive(self):
        assert get_cis_mapping("Known_CVE") == get_cis_mapping("known_cve")

    def test_unknown_category_returns_none(self):
        assert get_cis_mapping("not_a_real_category") is None

    def test_empty_string_returns_none(self):
        assert get_cis_mapping("") is None

    def test_none_input_returns_none(self):
        assert get_cis_mapping(None) is None

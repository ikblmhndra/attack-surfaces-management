"""
ASM Platform — Unit Tests: Version-to-CVE Correlation (cve.circl.lu)
Pure-function tests plus get_matching_cves's cache-hit/cache-miss branching
with a fake DB session — no real network calls.
"""
import pytest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.version_cve_intel import (
    SSVC_AUTOMATABLE_BOOST,
    SSVC_POC_BOOST,
    VERSION_MATCH_CONFIDENCE,
    _compare_versions,
    _extract_cvss,
    _extract_ssvc,
    _parse_version_tuple,
    _severity_from_cvss,
    compute_ssvc_boost,
    get_matching_cves,
    resolve_vendor_product,
    version_in_range,
)


class TestResolveVendorProduct:
    def test_known_products_resolve(self):
        assert resolve_vendor_product("Apache HTTP Server") == ("apache", "http_server")
        assert resolve_vendor_product("OpenSSL") == ("openssl", "openssl")
        assert resolve_vendor_product("PHP") == ("php", "php")

    def test_case_insensitive(self):
        assert resolve_vendor_product("openssl") == ("openssl", "openssl")
        assert resolve_vendor_product("  Nginx  ") == ("nginx", "nginx")

    def test_unmapped_product_returns_none(self):
        assert resolve_vendor_product("Bootstrap") is None
        assert resolve_vendor_product("") is None
        assert resolve_vendor_product(None) is None


class TestParseVersionTuple:
    def test_dotted_version(self):
        assert _parse_version_tuple("2.4.49") == (2, 4, 49)

    def test_version_with_suffix(self):
        assert _parse_version_tuple("1.0.2k") == (1, 0, 2)

    def test_no_numeric_prefix_returns_none(self):
        assert _parse_version_tuple("unknown") is None


class TestCompareVersions:
    def test_equal_with_padding(self):
        assert _compare_versions((2, 4), (2, 4, 0)) == 0

    def test_less_than(self):
        assert _compare_versions((2, 4, 17), (2, 4, 49)) == -1

    def test_greater_than(self):
        assert _compare_versions((2, 4, 62), (2, 4, 49)) == 1


class TestVersionInRange:
    """Real shape verified against cve.circl.lu/api/search/apache/http_server
    before writing this: {"version": "2.4.17", "lessThanOrEqual": "2.4.67",
    "status": "affected"}."""

    def test_version_within_affected_range(self):
        spec = {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "affected"}
        assert version_in_range("2.4.49", spec) is True

    def test_version_above_range_excluded(self):
        spec = {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "affected"}
        assert version_in_range("2.4.68", spec) is False

    def test_version_below_range_excluded(self):
        spec = {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "affected"}
        assert version_in_range("2.4.10", spec) is False

    def test_less_than_is_exclusive(self):
        spec = {"version": "1.0.0", "lessThan": "2.0.0", "status": "affected"}
        assert version_in_range("2.0.0", spec) is False
        assert version_in_range("1.9.9", spec) is True

    def test_unaffected_status_never_matches(self):
        # "unaffected" describes versions *outside* the vulnerable range, not
        # a green light — must not be treated as a match under any version.
        spec = {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "unaffected"}
        assert version_in_range("2.4.49", spec) is False

    def test_unparseable_version_returns_false(self):
        spec = {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "affected"}
        assert version_in_range("unknown", spec) is False


class TestSeverityFromCvss:
    def test_critical_threshold(self):
        assert _severity_from_cvss(9.8) == "critical"
        assert _severity_from_cvss(9.0) == "critical"

    def test_high_threshold(self):
        assert _severity_from_cvss(7.5) == "high"

    def test_medium_threshold(self):
        assert _severity_from_cvss(5.0) == "medium"

    def test_low_threshold(self):
        assert _severity_from_cvss(2.0) == "low"

    def test_missing_cvss_defaults_medium(self):
        # Conservative middle ground when the record has no CVSS at all,
        # rather than assuming either extreme.
        assert _severity_from_cvss(None) == "medium"


class TestExtractCvss:
    def test_extracts_from_adp_container(self):
        # Real records carry CVSS in containers.adp[].metrics[], not
        # containers.cna — verified against a real cve.circl.lu record before
        # relying on this path (the CNA's own metrics were empty for it).
        record = {
            "containers": {
                "cna": {"metrics": []},
                "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]}],
            }
        }
        assert _extract_cvss(record) == 7.5

    def test_no_cvss_anywhere_returns_none(self):
        record = {"containers": {"cna": {"metrics": []}, "adp": []}}
        assert _extract_cvss(record) is None


class TestExtractSsvc:
    """Stage 3: CISA ADP Vulnrichment's SSVC assessment lives in the same
    containers.adp[].metrics[] list _extract_cvss() walks, under an "other"
    key shaped {"type": "ssvc", "content": {"options": [...]}} — verified
    against 3 real cve.circl.lu records before writing this."""

    def test_extracts_from_real_shaped_record(self):
        record = {
            "containers": {
                "cna": {"metrics": []},
                "adp": [
                    {"title": "CVE Program Container", "metrics": [{"cvssV3_1": {"baseScore": 7.5}}]},
                    {"title": "CISA ADP Vulnrichment", "metrics": [
                        {"other": {"type": "ssvc", "content": {
                            "timestamp": "2026-01-01", "id": "CVE-2026-49975",
                            "options": [
                                {"Exploitation": "poc"},
                                {"Automatable": "yes"},
                                {"Technical Impact": "partial"},
                            ],
                            "role": "CISA Coordinator", "version": "2.0.3",
                        }}}
                    ]},
                ],
            }
        }
        assert _extract_ssvc(record) == ("poc", "yes")

    def test_active_and_no_pass_through_unmodified(self):
        record = {
            "containers": {"adp": [{"metrics": [
                {"other": {"type": "ssvc", "content": {
                    "options": [{"Exploitation": "active"}, {"Automatable": "no"}],
                }}}
            ]}]}
        }
        # Extraction must surface "active" even though scoring ignores it —
        # observability shouldn't silently drop a real CISA-assessed value.
        assert _extract_ssvc(record) == ("active", "no")

    def test_no_ssvc_metric_returns_none_none(self):
        record = {"containers": {"adp": [{"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]}]}}
        assert _extract_ssvc(record) == (None, None)

    def test_non_ssvc_other_metric_ignored(self):
        record = {"containers": {"adp": [{"metrics": [{"other": {"type": "not-ssvc", "content": {}}}]}]}}
        assert _extract_ssvc(record) == (None, None)

    def test_malformed_options_fails_closed(self):
        record = {
            "containers": {"adp": [{"metrics": [
                {"other": {"type": "ssvc", "content": {"options": "not-a-list"}}}
            ]}]}
        }
        assert _extract_ssvc(record) == (None, None)

    def test_missing_containers_returns_none_none(self):
        assert _extract_ssvc({}) == (None, None)
        assert _extract_ssvc({"containers": {}}) == (None, None)


class TestComputeSsvcBoost:
    def test_automatable_yes_escalates(self):
        assert compute_ssvc_boost(exploitation=None, automatable="yes") == SSVC_AUTOMATABLE_BOOST

    def test_exploitation_poc_escalates(self):
        assert compute_ssvc_boost(exploitation="poc", automatable=None) == SSVC_POC_BOOST

    def test_both_present_takes_max_not_sum(self):
        assert compute_ssvc_boost(exploitation="poc", automatable="yes") == max(SSVC_POC_BOOST, SSVC_AUTOMATABLE_BOOST)

    def test_exploitation_active_contributes_nothing(self):
        """Regression guard: CISA KEV already represents "confirmed active
        exploitation" for the same real-world fact — escalating separately on
        SSVC's Exploitation=active would risk double-counting KEV's own
        signal (see CHANGELOG.md). Must stay a deliberate no-op."""
        assert compute_ssvc_boost(exploitation="active", automatable=None) == 1.0
        assert compute_ssvc_boost(exploitation="active", automatable="no") == 1.0

    def test_none_or_garbage_defaults_to_neutral(self):
        assert compute_ssvc_boost(None, None) == 1.0
        assert compute_ssvc_boost("garbage", "garbage") == 1.0

    def test_boost_ordering_below_kev(self):
        # KEV_BOOST/KEV_RANSOMWARE_BOOST live in exploit_intel.py (1.5/1.75) —
        # a CISA-confirmed KEV entry must never lose to an SSVC-only status.
        from app.services.exploit_intel import KEV_BOOST
        assert SSVC_POC_BOOST < KEV_BOOST
        assert SSVC_AUTOMATABLE_BOOST < KEV_BOOST


class _FakeCacheRow:
    def __init__(self, cves, cached_at):
        self.cves = cves
        self.cached_at = cached_at


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeDB:
    """Only ever needs to answer the initial cache-row SELECT — every test
    below either expects no refetch (monkeypatches _cache_product to raise if
    called) or replaces _cache_product outright (so it never issues its own
    INSERT through this fake)."""

    def __init__(self, row):
        self._row = row

    async def execute(self, stmt):
        return _FakeScalarResult(self._row)

    async def commit(self):
        pass


class TestGetMatchingCves:
    @pytest.mark.asyncio
    async def test_unmapped_product_returns_empty_without_db_query(self):
        db = _FakeDB(None)
        result = await get_matching_cves(db, "Bootstrap", "5.3.3")
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_version_returns_empty(self):
        db = _FakeDB(None)
        result = await get_matching_cves(db, "PHP", "")
        assert result == []

    @pytest.mark.asyncio
    async def test_fresh_cache_hit_matches_without_refetch(self, monkeypatch):
        cached_cves = [{
            "cve_id": "CVE-2026-44631",
            "cvss_score": 9.8,
            "description": "test",
            "versions": [{"version": "2.4.0", "lessThanOrEqual": "2.4.67", "status": "affected"}],
        }]
        row = _FakeCacheRow(cached_cves, datetime.now(timezone.utc))
        db = _FakeDB(row)

        async def fail_if_called(*a, **kw):
            raise AssertionError("should not re-fetch when cache is fresh")
        monkeypatch.setattr("app.services.version_cve_intel._cache_product", fail_if_called)

        result = await get_matching_cves(db, "Apache HTTP Server", "2.4.49")
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2026-44631"

    @pytest.mark.asyncio
    async def test_stale_cache_triggers_refetch(self, monkeypatch):
        old_row = _FakeCacheRow([], datetime.now(timezone.utc) - timedelta(days=30))
        db = _FakeDB(old_row)

        called = {"count": 0}
        async def fake_cache_product(db, product_key, vendor, product):
            called["count"] += 1
            return [{
                "cve_id": "CVE-2026-99999",
                "cvss_score": 5.0,
                "description": "fresh",
                "versions": [{"version": "1.0.0", "lessThanOrEqual": "9.9.9", "status": "affected"}],
            }]
        monkeypatch.setattr("app.services.version_cve_intel._cache_product", fake_cache_product)

        result = await get_matching_cves(db, "PHP", "7.4.33")
        assert called["count"] == 1
        assert len(result) == 1

    def test_confidence_is_lower_than_nucleis_own_low_tier(self):
        # nuclei_worker.py's own low-confidence CVE tier is 0.5 — this
        # version-inferred-only signal must be lower still, since it has no
        # template/response confirmation of any kind.
        assert VERSION_MATCH_CONFIDENCE < 0.5

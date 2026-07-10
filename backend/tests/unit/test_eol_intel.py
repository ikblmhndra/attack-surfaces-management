"""
ASM Platform — Unit Tests: End-of-Life Intelligence (endoflife.date)
Pure-function tests plus get_eol_status's cache-hit/cache-miss branching with a
fake DB session — no real network calls (verified against the live API
manually during development, not re-verified here on every test run).
"""
from datetime import date, datetime, timezone, timedelta
from types import SimpleNamespace

import pytest

from app.services.eol_intel import (
    PRODUCT_SLUG_MAP,
    _default_cycle,
    _is_past,
    _openssl_cycle,
    _parse_eol_date,
    get_eol_status,
    normalize_cycle,
    resolve_product_slug,
)


class TestResolveProductSlug:
    def test_known_products_resolve(self):
        assert resolve_product_slug("PHP") == "php"
        assert resolve_product_slug("Apache HTTP Server") == "apache-http-server"
        assert resolve_product_slug("WordPress") == "wordpress"

    def test_case_and_whitespace_insensitive(self):
        assert resolve_product_slug("  OpenSSL  ") == "openssl"
        assert resolve_product_slug("openssl") == "openssl"

    def test_unmapped_product_returns_none(self):
        assert resolve_product_slug("Bootstrap") is None
        assert resolve_product_slug("IIS") is None

    def test_empty_input_returns_none(self):
        assert resolve_product_slug("") is None
        assert resolve_product_slug(None) is None


class TestNormalizeCycle:
    """Cases verified against the real endoflife.date API responses during
    development (see Milestone 15 CHANGELOG entry)."""

    def test_default_cycle_takes_major_minor(self):
        assert _default_cycle("2.4.62") == "2.4"
        assert _default_cycle("7.4.33") == "7.4"
        assert _default_cycle("1.14.1") == "1.14"

    def test_default_cycle_single_component_version(self):
        assert _default_cycle("7") == "7"
        assert _default_cycle("8") == "8"

    def test_openssl_1x_keeps_full_patch_component(self):
        assert _openssl_cycle("1.0.2k") == "1.0.2"
        assert _openssl_cycle("1.1.1p") == "1.1.1"
        assert _openssl_cycle("1.1.1k") == "1.1.1"

    def test_openssl_3x_uses_major_minor_only(self):
        assert _openssl_cycle("3.5.7") == "3.5"
        assert _openssl_cycle("3.1.3") == "3.1"

    def test_normalize_cycle_dispatches_openssl_rule(self):
        assert normalize_cycle("openssl", "1.0.2k") == "1.0.2"
        assert normalize_cycle("openssl", "3.5.7") == "3.5"

    def test_normalize_cycle_uses_default_for_other_products(self):
        assert normalize_cycle("php", "7.4.33") == "7.4"
        assert normalize_cycle("apache-http-server", "2.4.62") == "2.4"
        assert normalize_cycle("drupal", "7") == "7"


class TestParseEolDate:
    def test_false_means_not_eol(self):
        assert _parse_eol_date(False) is None

    def test_date_string_parses(self):
        assert _parse_eol_date("2022-11-28") == date(2022, 11, 28)

    def test_none_returns_none(self):
        assert _parse_eol_date(None) is None


class TestIsPast:
    def test_none_is_not_past(self):
        assert _is_past(None) is False

    def test_yesterday_is_past(self):
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        assert _is_past(yesterday) is True

    def test_future_date_is_not_past(self):
        future = (datetime.now(timezone.utc) + timedelta(days=365)).date()
        assert _is_past(future) is False

    def test_today_counts_as_past(self):
        assert _is_past(datetime.now(timezone.utc).date()) is True


def _eol_row(product, cycle, eol_date, latest_version="9.9.9"):
    return SimpleNamespace(
        product=product, cycle=cycle, eol_date=eol_date,
        is_eol=eol_date is not None, latest_version=latest_version,
    )


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _QueueFakeDB:
    """Returns each queued result in order, one per db.execute() call —
    matches get_eol_status's exact call sequence for each branch."""

    def __init__(self, results):
        self._results = list(results)

    async def execute(self, stmt):
        return self._results.pop(0)


class TestGetEolStatus:
    @pytest.mark.asyncio
    async def test_cache_hit_recomputes_is_eol_from_date_not_stored_column(self):
        # Regression: a cycle cached while its eol_date was still in the future
        # (e.g. PHP 8.3, eol 2027-12-31 at cache time) must not be trusted via
        # its stored `is_eol` column once that date is now in the past —
        # get_eol_status must recompute from eol_date freshly every call.
        past_date = date(2020, 1, 1)
        row = _eol_row("php", "7.4", past_date)
        row.is_eol = False  # deliberately wrong stored value
        db = _QueueFakeDB([_FakeScalarResult(row)])
        result = await get_eol_status(db, "PHP", "7.4.33")
        assert result["is_eol"] is True
        assert result["eol_date"] == past_date

    @pytest.mark.asyncio
    async def test_future_eol_date_is_not_eol(self):
        future_date = (datetime.now(timezone.utc) + timedelta(days=500)).date()
        row = _eol_row("php", "8.3", future_date)
        db = _QueueFakeDB([_FakeScalarResult(row)])
        result = await get_eol_status(db, "PHP", "8.3.28")
        assert result["is_eol"] is False

    @pytest.mark.asyncio
    async def test_not_eol_cycle_returns_none_eol_date(self):
        row = _eol_row("apache-http-server", "2.4", None)
        db = _QueueFakeDB([_FakeScalarResult(row)])
        result = await get_eol_status(db, "Apache HTTP Server", "2.4.62")
        assert result["is_eol"] is False
        assert result["eol_date"] is None

    @pytest.mark.asyncio
    async def test_unmapped_product_returns_none_without_any_query(self):
        db = _QueueFakeDB([])  # would raise IndexError if a query were attempted
        assert await get_eol_status(db, "Bootstrap", "5.3.3") is None

    @pytest.mark.asyncio
    async def test_empty_version_returns_none(self):
        db = _QueueFakeDB([])
        assert await get_eol_status(db, "PHP", "") is None

    @pytest.mark.asyncio
    async def test_cache_miss_but_product_already_cached_does_not_refetch(self):
        # First query (exact cycle) misses, second query (any row for this
        # product) hits — must NOT trigger a network fetch in this case.
        db = _QueueFakeDB([
            _FakeScalarResult(None),          # exact (product, cycle) miss
            _FakeScalarResult("some-uuid"),   # any_cached hit
        ])
        result = await get_eol_status(db, "PHP", "9.9.9")
        assert result is None  # genuinely no data for this specific cycle


class TestProductSlugMapCoverage:
    def test_all_slugs_are_lowercase_hyphenated(self):
        for slug in PRODUCT_SLUG_MAP.values():
            assert slug == slug.lower()
            assert " " not in slug

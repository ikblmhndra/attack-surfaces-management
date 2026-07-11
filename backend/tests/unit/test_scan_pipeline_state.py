"""
Unit tests for scan lifecycle and port persistence safety.

NOTE: this file imports from `workers.*`, which isn't mounted into the `api`
container (only `backend/app` is) — it fails to collect there, so it's excluded
from the standard `pytest tests/unit --ignore=tests/unit/test_scan_pipeline_state.py`
regression command and doesn't run in routine CI-style checks. No worker container
has pytest installed either. Run it by installing pytest transiently inside a
worker container (e.g. `worker-nuclei`) and pointing it at a copy of this file.
"""
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from workers import scan_state
from workers.crawler.web_crawl_worker import WebCrawlWorker
from workers.scanner.discovery_worker import DiscoveryWorker, normalize_technology
from workers.scanner.nuclei_worker import NucleiWorker
from workers.scanner.port_worker import PortWorker
from workers.scanner.scanner_common import make_finding


class FakeResult:
    def __init__(self, scalar=None, row=None):
        self._scalar = scalar
        self._row = row

    def scalar_one_or_none(self):
        return self._scalar

    def scalar_one(self):
        return self._scalar

    def fetchone(self):
        return self._row


class FakeDB:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.statements = []
        self.commits = 0

    async def execute(self, stmt):
        self.statements.append(stmt)
        if self.results:
            return self.results.pop(0)
        return FakeResult()

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_mark_scan_running_updates_active_scan(monkeypatch):
    events = []
    row = SimpleNamespace(
        id="scan-1",
        workspace_id="ws-1",
        org_id="org-1",
        progress_pct=25,
    )
    db = FakeDB([FakeResult(row=row)])

    async def fake_publish(*args):
        events.append(args)

    monkeypatch.setattr(scan_state, "_publish_scan_event", fake_publish)

    assert await scan_state.mark_scan_running(db, "scan-1", progress_floor=25) is True
    assert db.commits == 1
    assert events == [("ws-1", "org-1", "scan-1", "running", 25.0)]


@pytest.mark.asyncio
async def test_mark_scan_completed_does_not_publish_when_scan_not_active(monkeypatch):
    events = []
    db = FakeDB([FakeResult(row=None)])

    async def fake_publish(*args):
        events.append(args)

    monkeypatch.setattr(scan_state, "_publish_scan_event", fake_publish)

    assert await scan_state.mark_scan_completed(db, "scan-1") is False
    assert db.commits == 1
    assert events == []


@pytest.mark.asyncio
async def test_mark_scan_failed_records_error_and_event(monkeypatch):
    events = []
    row = SimpleNamespace(workspace_id="ws-1", org_id="org-1", progress_pct=50)
    db = FakeDB([FakeResult(row=row)])

    async def fake_publish(*args):
        events.append(args)

    monkeypatch.setattr(scan_state, "_publish_scan_event", fake_publish)

    await scan_state.mark_scan_failed(db, "scan-1", "boom")

    assert db.commits == 1
    assert events == [("ws-1", "org-1", "scan-1", "failed", 50.0, "boom")]


@pytest.mark.asyncio
async def test_port_worker_uses_ip_address_id_for_ports(monkeypatch):
    calls = []
    worker = PortWorker()
    db = FakeDB([
        FakeResult(scalar="asset-id"),
        FakeResult(scalar="ip-address-id"),
        FakeResult(),
        FakeResult(),
    ])

    class FakeInsert:
        def __init__(self, table):
            self.table = table
            self.values_payload = None

        def values(self, **kwargs):
            self.values_payload = kwargs
            calls.append((self.table.name, kwargs))
            return self

        def on_conflict_do_update(self, **kwargs):
            return self

        def returning(self, *args):
            return self

    monkeypatch.setattr("sqlalchemy.dialects.postgresql.insert", lambda table: FakeInsert(table))

    ip_ids = await worker._persist_ip_assets(
        db,
        org_id="org-1",
        workspace_id="ws-1",
        ips=["192.0.2.10"],
    )
    await worker._persist_results(
        db,
        org_id="org-1",
        workspace_id="ws-1",
        scan_id="scan-1",
        results={"192.0.2.10": [{"port": 443, "protocol": "tcp", "service": "https"}]},
        ip_ids=ip_ids,
    )

    # Full expected payload — kept in sync with port_worker.py::_persist_ip_assets's
    # asset_values dict, which grew ownership/scope-confidence fields after this test
    # was first written; the mismatch was invisible because this file can't be
    # collected in the api container (see module-level note) so it never ran in CI.
    assert ("assets", {
        "org_id": "org-1",
        "workspace_id": "ws-1",
        "asset_type": "ip",
        "value": "192.0.2.10",
        "status": "active",
        "discovery_method": "dns_resolution",
        "confidence": 0.65,
        "is_in_scope": True,
        "scope_status": "probable",
        "ownership_confidence": 0.65,
        "ownership_reason": "resolved from validated in-scope host",
        "exposure_status": "exposed",
        "liveness_status": "alive",
        "validation_sources": calls[0][1]["validation_sources"],
        "last_verified_at": calls[0][1]["last_verified_at"],
        "last_seen": calls[0][1]["last_seen"],
        "metadata": {
            "source": "port_worker",
            "validation": {
                "method": "dns_resolution_port_scan",
                "reasons": ["resolved_from_validated_host", "port_scan_target"],
            },
        },
    }) in calls
    assert ("ip_addresses", {
        "asset_id": "asset-id",
        "org_id": "org-1",
        "ip": "192.0.2.10",
        "version": 4,
        "is_private": True,
        "last_seen": calls[1][1]["last_seen"],
    }) in calls

    port_call = next(payload for table, payload in calls if table == "ports")
    assert port_call["ip_id"] == "ip-address-id"
    assert port_call["port_number"] == 443


def test_normalize_technology_extracts_name_and_version():
    assert normalize_technology("Next.js:14.2.3") == {
        "name": "Next.js",
        "version": "14.2.3",
    }
    assert normalize_technology("React") == {"name": "React", "version": ""}
    assert normalize_technology("") is None


def test_nuclei_tech_tags_are_curated():
    worker = NucleiWorker()

    assert set(worker._tech_tags(["Next.js:14.2.3", "React", "Unknown CMS"])) == {
        "nextjs",
        "react",
    }


def test_map_category_does_not_let_http_prefix_shadow_keyword_match():
    # Regression: CATEGORY_MAP's "http" key models nuclei's tag taxonomy, not a
    # template-ID prefix. "http-missing-security-headers" (and every other
    # http-*/dns-*/ssl-*/network-*/misconfiguration-* template ID) used to get
    # swallowed into CATEGORY_MAP["http"]="exposed_admin_panel" before the more
    # specific keyword matching below it ever ran.
    worker = NucleiWorker()

    assert worker._map_category(
        "http-missing-security-headers", ["misconfig", "headers", "generic", "vuln"]
    ) == "missing_hsts"
    assert worker._map_category("iis-shortname-detect", ["iis", "edb", "vuln"]) == "cors_misconfiguration"


def test_map_category_still_resolves_known_cve_via_tag():
    worker = NucleiWorker()

    assert worker._map_category(
        "CVE-2025-55184", ["cve", "cve2025", "react", "nextjs", "vuln", "vkev"]
    ) == "known_cve"


def test_map_category_resolves_eol_templates():
    # nuclei's own generic *-eol templates (e.g. php-eol, tags ["tech","php","eol"])
    # used to fall through to the cors_misconfiguration default since "eol" wasn't
    # a CATEGORY_MAP tag key or a keyword bucket — found while wiring the new
    # endoflife.date-based eol_software enrichment (Milestone 15), which made this
    # category actually meaningful for the first time.
    worker = NucleiWorker()

    assert worker._map_category("php-eol", ["tech", "php", "eol"]) == "eol_software"
    assert worker._map_category("php-eol", []) == "eol_software"
    assert worker._map_category("wordpress-outdated-version", []) == "eol_software"


class _FakeScalarsResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _FakeSessionDB:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt):
        return _FakeScalarsResult(self._rows)


def _patch_get_session(monkeypatch, fake_db):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_get_session():
        yield fake_db

    monkeypatch.setattr("workers.scanner.discovery_worker.get_session", _fake_get_session)


def test_tls_san_mining_discards_unrelated_third_party_sans():
    # Regression: a shared-hosting cert's SAN list can carry hundreds of
    # unrelated third-party hostnames alongside the org's own (verified against
    # real pasarjaya.co.id data: mail.*.com/correo.*.com noise from a shared
    # mail server cert) — _add_discovery_candidate's own domain-suffix check
    # is what filters this, so lock in that it actually does for SAN-sourced
    # candidates specifically.
    worker = DiscoveryWorker.__new__(DiscoveryWorker)
    candidates: dict = {}
    for san in ["ciptakarya.pu.go.id", "*.pu.go.id", "pu.go.id", "mail.unrelated-thirdparty.com"]:
        worker._add_discovery_candidate(
            candidates, san, "pu.go.id", "tls_san_mining", generated=False,
            evidence={"source": "tls_san_mining"},
        )
    assert set(candidates.keys()) == {"ciptakarya.pu.go.id", "pu.go.id"}
    assert "tls_san_mining" in candidates["ciptakarya.pu.go.id"]["sources"]


@pytest.mark.asyncio
async def test_fetch_known_tls_sans_flattens_and_dedupes(monkeypatch):
    worker = DiscoveryWorker.__new__(DiscoveryWorker)
    fake_db = _FakeSessionDB([
        ["ciptakarya.pu.go.id", "*.pu.go.id"],
        ["ciptakarya.pu.go.id", None],
        None,
    ])
    _patch_get_session(monkeypatch, fake_db)
    sans = await worker._fetch_known_tls_sans("org-1")
    assert sans == sorted({"ciptakarya.pu.go.id", "*.pu.go.id"})


@pytest.mark.asyncio
async def test_fetch_known_ip_assets_returns_asset_values(monkeypatch):
    worker = DiscoveryWorker.__new__(DiscoveryWorker)
    fake_db = _FakeSessionDB(["223.27.156.68", "223.27.156.69"])
    _patch_get_session(monkeypatch, fake_db)
    ips = await worker._fetch_known_ip_assets("org-1")
    assert ips == ["223.27.156.68", "223.27.156.69"]


@pytest.mark.asyncio
async def test_reverse_dns_merges_known_ips_with_manual_ranges(monkeypatch):
    # Regression: reverse-DNS used to only look at manually-declared
    # org.ip_ranges (always empty for every real org in this platform so far),
    # so it never ran. It should also draw from this org's own already-
    # confirmed IP Asset rows — no new scope, since those IPs were already
    # validated from a prior in-scope subdomain resolution.
    worker = DiscoveryWorker.__new__(DiscoveryWorker)

    async def fake_fetch_known_ips(org_id):
        return ["203.0.113.5"]

    monkeypatch.setattr(worker, "_fetch_known_ip_assets", fake_fetch_known_ips)

    async def fake_getnameinfo(addr, flags):
        return ("host.pu.go.id", None) if addr[0] == "203.0.113.5" else ("", None)

    # Patch getnameinfo on the *real* running loop rather than replacing
    # asyncio.get_running_loop() itself — the code under test wraps this call
    # in asyncio.wait_for(), which needs the genuine loop's timer machinery to
    # keep working.
    monkeypatch.setattr(asyncio.get_running_loop(), "getnameinfo", fake_getnameinfo)

    source_health: dict = {}
    discoveries = await worker._discover_reverse_dns_targets(
        "org-1", {"domains": ["pu.go.id"], "ip_ranges": []}, {}, source_health,
    )
    assert any(d["value"] == "host.pu.go.id" and d["evidence"]["scope_match"] for d in discoveries)
    # Also confirm the safety posture is unchanged: still not auto-scanned.
    assert all(d["selected"] is False for d in discoveries)


class _FakeHttpResponse:
    def __init__(self, json_body=None, content_bytes=b"{}"):
        self._json_body = json_body
        self._content_bytes = content_bytes
        self.content = SimpleNamespace(read=self._read)

    async def _read(self, n):
        return self._content_bytes

    async def json(self, content_type=None):
        return self._json_body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeHttpSession:
    def __init__(self, responses: dict):
        self._responses = responses

    def get(self, url, **kwargs):
        return self._responses.get(url, _FakeHttpResponse())

    def post(self, url, **kwargs):
        return self._responses.get(url, _FakeHttpResponse())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch_aiohttp_session(monkeypatch, responses: dict):
    monkeypatch.setattr(
        "workers.crawler.web_crawl_worker.aiohttp.ClientSession",
        lambda *a, **kw: _FakeHttpSession(responses),
    )


@pytest.mark.asyncio
async def test_analyze_api_specs_rejects_real_world_false_positive(monkeypatch):
    # Regression: a URL matching /swagger|openapi/ isn't proof of a real spec.
    # pasarjaya.co.id's own /api-docs and /api/swagger.json both returned this
    # exact generic app-level error shape during manual verification — no
    # "swagger"/"openapi"/"paths" key, just an unrelated JSON error envelope.
    worker = WebCrawlWorker.__new__(WebCrawlWorker)
    url = "https://admin-sirupa.pasarjaya.co.id/api/swagger.json"
    body = b'{"status":400,"message":"Gagal akses ke server.","error_code":"error_0102832","data":{}}'
    _patch_aiohttp_session(monkeypatch, {url: _FakeHttpResponse(content_bytes=body)})

    validated = [{"url": url, "http_status": 200, "status_class": "ok"}]
    result = await worker._analyze_api_specs(validated, "org-1", "ws-1", {})

    assert result["findings"] == []
    assert result["extracted_endpoints"] == []


@pytest.mark.asyncio
async def test_analyze_api_specs_extracts_routes_from_genuine_spec(monkeypatch):
    url = "https://target.example/swagger.json"
    spec = {
        "openapi": "3.0.0",
        "paths": {"/users": {}, "/users/{id}": {}, "/orders": {}},
    }
    import json as _json
    _patch_aiohttp_session(monkeypatch, {url: _FakeHttpResponse(content_bytes=_json.dumps(spec).encode())})
    worker = WebCrawlWorker.__new__(WebCrawlWorker)

    validated = [{"url": url, "http_status": 200, "status_class": "ok"}]
    result = await worker._analyze_api_specs(validated, "org-1", "ws-1", {})

    assert len(result["findings"]) == 1
    assert result["findings"][0]["category"] == "exposed_api"
    assert set(result["extracted_endpoints"]) == {
        "https://target.example/users",
        "https://target.example/users/{id}",
        "https://target.example/orders",
    }


@pytest.mark.asyncio
async def test_analyze_graphql_endpoints_flags_introspection_enabled(monkeypatch):
    url = "https://target.example/graphql"
    body = {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
    _patch_aiohttp_session(monkeypatch, {url: _FakeHttpResponse(json_body=body)})
    worker = WebCrawlWorker.__new__(WebCrawlWorker)

    validated = [{"url": url, "http_status": 200, "status_class": "ok"}]
    result = await worker._analyze_graphql_endpoints(validated, "org-1", "ws-1", {})

    assert len(result["findings"]) == 1
    assert result["findings"][0]["template_id"] == "graphql_introspection_enabled"
    assert result["findings"][0]["proof"]["type_count"] == 2


@pytest.mark.asyncio
async def test_analyze_graphql_endpoints_no_finding_when_disabled(monkeypatch):
    url = "https://target.example/graphql"
    # A real GraphQL server with introspection disabled returns an error body,
    # no "__schema" key at all.
    body = {"errors": [{"message": "introspection is disabled"}]}
    _patch_aiohttp_session(monkeypatch, {url: _FakeHttpResponse(json_body=body)})
    worker = WebCrawlWorker.__new__(WebCrawlWorker)

    validated = [{"url": url, "http_status": 200, "status_class": "ok"}]
    result = await worker._analyze_graphql_endpoints(validated, "org-1", "ws-1", {})

    assert result["findings"] == []


def test_make_finding_threads_cve_ids_through():
    # Regression: make_finding() never accepted/produced a cve_ids field at
    # all, and persist_findings() separately hardcoded cve_ids=[] regardless
    # — harmless while only nuclei_worker.py's own, different persistence path
    # populated Finding.cve_ids, but version_cve_intel-based findings (M21)
    # are the first coverage_worker.py-style source that needs this populated
    # so M14's EPSS/KEV lookup and cve_id-based filtering apply to them too.
    finding = make_finding(
        org_id="org-1", workspace_id="ws-1", scanner="version_cve_correlation",
        check_id="version_cve_cve-2026-44631", target="host.example",
        title="t", severity="critical", category="known_cve",
        description="d", evidence="e", cve_ids=["CVE-2026-44631"],
    )
    assert finding["cve_ids"] == ["CVE-2026-44631"]


def test_make_finding_defaults_cve_ids_to_empty_list():
    finding = make_finding(
        org_id="org-1", workspace_id="ws-1", scanner="eol_scanner",
        check_id="eol_php_7.4", target="host.example",
        title="t", severity="high", category="eol_software",
        description="d", evidence="e",
    )
    assert finding["cve_ids"] == []

"""
Unit tests for scan lifecycle and port persistence safety.

NOTE: this file imports from `workers.*`, which isn't mounted into the `api`
container (only `backend/app` is) — it fails to collect there, so it's excluded
from the standard `pytest tests/unit --ignore=tests/unit/test_scan_pipeline_state.py`
regression command and doesn't run in routine CI-style checks. No worker container
has pytest installed either. Run it by installing pytest transiently inside a
worker container (e.g. `worker-nuclei`) and pointing it at a copy of this file.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from workers import scan_state
from workers.scanner.discovery_worker import normalize_technology
from workers.scanner.nuclei_worker import NucleiWorker
from workers.scanner.port_worker import PortWorker


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

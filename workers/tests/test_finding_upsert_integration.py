"""Integration test for Milestone 7 / A1: a rediscovered Finding must not have
its triage status silently reset to "open" on every rescan. Requires a real
Postgres connection (workers.db.get_session()) since the fix is expressed as
SQLAlchemy `case()` SET-clause fragments in an ON CONFLICT upsert — this can't
be meaningfully verified by calling the helper function in isolation, only by
observing what Postgres actually persists (the same lesson Milestone 6 learned
the hard way about config resolution).

Run inside a worker container (workers/ isn't mounted into the api container,
so this can't run via `docker compose exec api pytest`):
    docker compose exec worker-crawl python3 -m pytest workers/tests/test_finding_upsert_integration.py -v

Note: run one test at a time (-k <name> or ::<name>), not the whole file in one
pytest invocation. workers/db.py's async engine is a module-level singleton
bound to whichever event loop first opens a connection; pytest-asyncio's
per-test event loop then conflicts with it on the second test in the same
process ("Event loop is closed" / "attached to a different loop" at teardown).
This is a test-harness/event-loop-scoping artifact, not a bug in the upsert
logic itself — each test passes cleanly in isolation, which is what actually
proves the fix.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from workers.db import get_session
from workers.db_models import Asset, Finding, Scan
from workers.scanner.scanner_common import make_finding, persist_findings

ORG_ID = "8f19fa82-9215-400e-bad7-a929cff9018c"
WORKSPACE_ID = "00000000-0000-0000-0000-000000000000"
TEST_HOST = "m7-upsert-test.internal.invalid"
TEST_TARGET = f"https://{TEST_HOST}/"


@pytest_asyncio.fixture
async def test_asset():
    async with get_session() as db:
        org_row = (await db.execute(select(Asset.workspace_id).where(Asset.org_id == ORG_ID).limit(1))).first()
        workspace_id = str(org_row[0]) if org_row else WORKSPACE_ID
        asset = Asset(
            id=uuid.uuid4(),
            org_id=ORG_ID,
            workspace_id=workspace_id,
            asset_type="url",
            value=TEST_TARGET,
        )
        scan_1 = Scan(id=uuid.uuid4(), org_id=ORG_ID, workspace_id=workspace_id, scan_type="vuln", status="running")
        scan_2 = Scan(id=uuid.uuid4(), org_id=ORG_ID, workspace_id=workspace_id, scan_type="vuln", status="running")
        db.add_all([asset, scan_1, scan_2])
        await db.commit()
        asset_id, scan_id_1, scan_id_2 = asset.id, scan_1.id, scan_2.id
    yield {"workspace_id": workspace_id, "scan_id_1": str(scan_id_1), "scan_id_2": str(scan_id_2)}
    async with get_session() as db:
        await db.execute(Finding.__table__.delete().where(Finding.asset_id == asset_id))
        await db.execute(Asset.__table__.delete().where(Asset.id == asset_id))
        await db.execute(Scan.__table__.delete().where(Scan.id.in_([scan_id_1, scan_id_2])))
        await db.commit()


def _finding_dict(workspace_id: str, check_id: str = "m7_upsert_test"):
    return make_finding(
        org_id=ORG_ID,
        workspace_id=workspace_id,
        scanner="test",
        check_id=check_id,
        target=TEST_TARGET,
        title="M7 upsert integration test finding",
        severity="high",
        category="open_port",
        description="test",
        evidence="test",
    )


async def _get_finding(fingerprint: str):
    async with get_session() as db:
        result = await db.execute(select(Finding).where(Finding.fingerprint == fingerprint))
        return result.scalar_one_or_none()


@pytest.mark.asyncio
async def test_false_positive_survives_rescan(test_asset):
    workspace_id = test_asset["workspace_id"]
    finding_dict = _finding_dict(workspace_id, "m7_fp_test")

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_1"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    assert finding.status == "open"

    async with get_session() as db:
        await db.execute(
            Finding.__table__.update()
            .where(Finding.id == finding.id)
            .values(status="false_positive", is_false_positive=True)
        )
        await db.commit()

    before_rescan = datetime.now(timezone.utc)
    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_2"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    assert finding.status == "false_positive"
    assert finding.last_seen >= before_rescan - timedelta(seconds=5)


@pytest.mark.asyncio
async def test_active_risk_acceptance_survives_rescan(test_asset):
    workspace_id = test_asset["workspace_id"]
    finding_dict = _finding_dict(workspace_id, "m7_accepted_active_test")

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_1"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    async with get_session() as db:
        await db.execute(
            Finding.__table__.update()
            .where(Finding.id == finding.id)
            .values(
                status="accepted",
                is_risk_accepted=True,
                risk_accepted_until=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        await db.commit()

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_2"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    assert finding.status == "accepted"
    assert finding.is_risk_accepted is True


@pytest.mark.asyncio
async def test_expired_risk_acceptance_reopens_on_rescan(test_asset):
    workspace_id = test_asset["workspace_id"]
    finding_dict = _finding_dict(workspace_id, "m7_accepted_expired_test")

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_1"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    async with get_session() as db:
        await db.execute(
            Finding.__table__.update()
            .where(Finding.id == finding.id)
            .values(
                status="accepted",
                is_risk_accepted=True,
                risk_accepted_until=datetime.now(timezone.utc) - timedelta(days=1),
            )
        )
        await db.commit()

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_2"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    assert finding.status == "open"
    assert finding.is_risk_accepted is False


@pytest.mark.asyncio
async def test_resolved_finding_reopens_on_rescan(test_asset):
    workspace_id = test_asset["workspace_id"]
    finding_dict = _finding_dict(workspace_id, "m7_resolved_test")

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_1"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    async with get_session() as db:
        await db.execute(
            Finding.__table__.update()
            .where(Finding.id == finding.id)
            .values(status="resolved", resolved_at=datetime.now(timezone.utc))
        )
        await db.commit()

    async with get_session() as db:
        await persist_findings(db, test_asset["scan_id_2"], [finding_dict])
        await db.commit()

    finding = await _get_finding(finding_dict["fingerprint"])
    assert finding.status == "open"
    assert finding.resolved_at is None

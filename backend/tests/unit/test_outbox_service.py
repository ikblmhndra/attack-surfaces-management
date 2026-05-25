"""
Unit tests for transactional outbox helpers.
"""
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.services.outbox_service import _prepare_event, create_queue_event


def test_create_queue_event_defaults():
    event = create_queue_event(
        routing_key="scan.discovery",
        payload={"scan_id": "scan-1"},
        aggregate_type="scan",
        aggregate_id="scan-1",
    )

    assert event.event_type == "queue.publish"
    assert event.status is None or event.status == "pending"
    assert event.routing_key == "scan.discovery"
    assert event.payload == {"scan_id": "scan-1"}
    assert event.priority == 5
    assert event.aggregate_type == "scan"
    assert event.aggregate_id == "scan-1"


def test_create_queue_event_preserves_headers_and_priority():
    event = create_queue_event(
        routing_key="scan.nuclei",
        payload={"scan_id": "scan-1"},
        priority=8,
        headers={"coordinator": {"nuclei_expected": 1}},
    )

    assert event.priority == 8
    assert event.headers == {"coordinator": {"nuclei_expected": 1}}


@pytest.mark.asyncio
async def test_prepare_event_is_idempotent_for_coordinator(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.values = {}
            self.increments = {}

        async def set(self, key, value, ex=None, nx=False):
            if nx and key in self.values:
                return False
            self.values[key] = value
            return True

        async def incrby(self, key, amount):
            self.increments[key] = self.increments.get(key, 0) + amount
            return self.increments[key]

        async def expire(self, key, ttl):
            return True

        async def setex(self, key, ttl, value):
            self.values[key] = value
            return True

        async def aclose(self):
            return None

    fake_redis = FakeRedis()

    import redis.asyncio as aioredis

    monkeypatch.setattr(aioredis, "from_url", lambda *args, **kwargs: fake_redis)

    event = create_queue_event(
        routing_key="scan.nuclei",
        payload={"scan_id": "scan-1"},
        headers={"coordinator": {"nuclei_expected": 1, "screenshot_done": True}},
    )
    event.id = uuid.uuid4()

    await _prepare_event(event)
    await _prepare_event(event)

    assert fake_redis.increments["scan:scan-1:nuclei_expected"] == 1
    assert fake_redis.values["scan:scan-1:screenshot_done"] == 1

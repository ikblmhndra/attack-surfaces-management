"""
Transactional outbox dispatcher for reliable queue publishing.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import structlog
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import database
from app.core.queue_client import QueueClient
from app.db.models.models import OutboxEvent, Scan

log = structlog.get_logger()

_dispatcher_task: Optional[asyncio.Task] = None
_stop_event: Optional[asyncio.Event] = None


def create_queue_event(
    *,
    routing_key: str,
    payload: Dict[str, Any],
    priority: int = 5,
    headers: Optional[Dict[str, Any]] = None,
    aggregate_type: Optional[str] = None,
    aggregate_id: Optional[str] = None,
) -> OutboxEvent:
    return OutboxEvent(
        event_type="queue.publish",
        routing_key=routing_key,
        payload=payload,
        headers=headers or {},
        priority=priority,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
    )


async def dispatch_pending_outbox_once(limit: int = 25) -> int:
    if database.AsyncSessionLocal is None:
        return 0

    async with database.AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)
        stale_publishing_before = now - timedelta(minutes=5)
        result = await db.execute(
            select(OutboxEvent)
            .where(
                or_(
                    OutboxEvent.status.in_(["pending", "failed"]),
                    (
                        (OutboxEvent.status == "publishing")
                        & (OutboxEvent.updated_at <= stale_publishing_before)
                    ),
                ),
                OutboxEvent.attempt_count < OutboxEvent.max_attempts,
                OutboxEvent.next_attempt_at <= now,
            )
            .order_by(OutboxEvent.created_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        events = result.scalars().all()
        count = 0
        for event in events:
            await _dispatch_event(db, event)
            count += 1
        return count


async def _dispatch_event(db: AsyncSession, event: OutboxEvent) -> None:
    event.status = "publishing"
    event.attempt_count += 1
    await db.commit()

    try:
        if event.event_type != "queue.publish" or not event.routing_key:
            raise ValueError(f"Unsupported outbox event: {event.event_type}")

        await _prepare_event(event)

        queue = QueueClient()
        try:
            await queue.connect()
            await queue.publish(
                routing_key=event.routing_key,
                message=event.payload,
                priority=event.priority,
                headers=event.headers,
            )
        finally:
            await queue.close()

        event.status = "published"
        event.published_at = datetime.now(timezone.utc)
        event.last_error = None
        await db.commit()
        log.info("outbox_event_published", event_id=str(event.id), routing_key=event.routing_key)
    except Exception as exc:
        delay = min(300, 2 ** min(event.attempt_count, 8))
        event.status = "failed"
        event.last_error = str(exc)[:4000]
        event.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
        await db.commit()

        if event.attempt_count >= event.max_attempts and event.aggregate_type == "scan" and event.aggregate_id:
            await db.execute(
                update(Scan)
                .where(Scan.id == event.aggregate_id, Scan.status.in_(["queued", "pending"]))
                .values(status="failed", error_message=f"Outbox publish failed: {event.last_error}")
            )
            await db.commit()
        log.warning("outbox_event_publish_failed", event_id=str(event.id), error=str(exc))


async def _prepare_event(event: OutboxEvent) -> None:
    coordinator = (event.headers or {}).get("coordinator")
    if not coordinator:
        return

    import redis.asyncio as aioredis
    import os

    scan_id = coordinator.get("scan_id") or event.payload.get("scan_id")
    if not scan_id:
        return

    ttl = int(coordinator.get("ttl", 86400))
    redis = aioredis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
    try:
        prepared_key = f"scan:{scan_id}:outbox:{event.id}:prepared"
        if not await redis.set(prepared_key, "1", ex=ttl, nx=True):
            return

        if coordinator.get("nuclei_expected"):
            key = f"scan:{scan_id}:nuclei_expected"
            await redis.incrby(key, int(coordinator["nuclei_expected"]))
            await redis.expire(key, ttl)
        if coordinator.get("port_expected"):
            key = f"scan:{scan_id}:port_expected"
            await redis.incrby(key, int(coordinator["port_expected"]))
            await redis.expire(key, ttl)
        if coordinator.get("screenshot_done"):
            await redis.setex(f"scan:{scan_id}:screenshot_done", ttl, 1)
    finally:
        await redis.aclose()


async def start_outbox_dispatcher(interval_seconds: float = 2.0) -> None:
    global _dispatcher_task, _stop_event
    if _dispatcher_task and not _dispatcher_task.done():
        return
    _stop_event = asyncio.Event()
    _dispatcher_task = asyncio.create_task(_run_dispatcher(interval_seconds))


async def stop_outbox_dispatcher() -> None:
    global _dispatcher_task, _stop_event
    if _stop_event:
        _stop_event.set()
    if _dispatcher_task:
        _dispatcher_task.cancel()
        try:
            await _dispatcher_task
        except asyncio.CancelledError:
            pass
    _dispatcher_task = None
    _stop_event = None


async def _run_dispatcher(interval_seconds: float) -> None:
    assert _stop_event is not None
    while not _stop_event.is_set():
        try:
            await dispatch_pending_outbox_once()
        except Exception as exc:
            log.warning("outbox_dispatcher_error", error=str(exc))
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass

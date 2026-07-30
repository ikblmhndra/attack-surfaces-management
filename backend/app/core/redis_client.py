"""
ASM Platform — Redis Client
Async Redis connection with typed cache helpers and pub/sub support.
"""
import asyncio
import json
from typing import Any, Optional, Union

import redis.asyncio as aioredis
import structlog

from app.core.config import settings

log = structlog.get_logger()

redis_client: aioredis.Redis | None = None


async def init_redis() -> None:
    """Initialize async Redis connection pool."""
    global redis_client

    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
        socket_timeout=5,
        socket_connect_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30,
    )

    # Verify connection. Retried the same way workers/base_worker.py retries
    # its RabbitMQ connect: on a host/daemon restart, Docker starts all
    # `restart: unless-stopped` containers natively and doesn't honor
    # compose's `depends_on: condition: service_healthy` ordering, so this
    # can race Redis's own boot. A lost race here would otherwise kill the
    # whole ASGI lifespan with no self-recovery (see rabbitmq.py::init_rabbitmq).
    for attempt in range(1, 6):
        try:
            await redis_client.ping()
            break
        except Exception as e:
            if attempt == 5:
                raise
            wait = attempt * 3
            log.warning("redis_connect_retry", attempt=attempt, wait=wait, error=str(e))
            await asyncio.sleep(wait)
    log.info("redis_initialized", url=settings.REDIS_URL.split("@")[-1])


async def close_redis() -> None:
    """Close Redis connection pool."""
    global redis_client
    if redis_client:
        await redis_client.aclose()
        redis_client = None
        log.info("redis_closed")


def get_redis() -> aioredis.Redis:
    if redis_client is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    return redis_client


# ── Cache helpers ──────────────────────────────────────────────

class CacheManager:
    """High-level cache operations with JSON serialization."""

    def __init__(self, prefix: str = "asm", default_ttl: int = 300):
        self.prefix = prefix
        self.default_ttl = default_ttl

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"

    async def get(self, key: str) -> Optional[Any]:
        """Get a cached value (auto JSON decode)."""
        raw = await get_redis().get(self._key(key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """Set a cached value with TTL (auto JSON encode)."""
        serialized = json.dumps(value, default=str)
        await get_redis().setex(
            self._key(key),
            ttl or self.default_ttl,
            serialized,
        )

    async def delete(self, key: str) -> None:
        await get_redis().delete(self._key(key))

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern. Use sparingly."""
        full_pattern = self._key(pattern)
        keys = await get_redis().keys(full_pattern)
        if keys:
            return await get_redis().delete(*keys)
        return 0

    async def exists(self, key: str) -> bool:
        return bool(await get_redis().exists(self._key(key)))

    async def increment(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        r = get_redis()
        val = await r.incr(self._key(key), amount)
        if ttl and val == amount:  # Just created
            await r.expire(self._key(key), ttl)
        return val

    async def get_or_set(
        self,
        key: str,
        factory,
        ttl: Optional[int] = None,
    ) -> Any:
        """Get from cache or compute and store value."""
        cached = await self.get(key)
        if cached is not None:
            return cached
        value = await factory() if callable(factory) else factory
        await self.set(key, value, ttl)
        return value


# ── Pub/Sub ───────────────────────────────────────────────────

class PubSubManager:
    """Redis Pub/Sub for real-time WebSocket events."""

    CHANNEL_PREFIX = "asm:events"

    async def publish(self, workspace_id: str, event_type: str, data: dict) -> None:
        channel = f"{self.CHANNEL_PREFIX}:{workspace_id}"
        message = json.dumps({"type": event_type, "data": data}, default=str)
        await get_redis().publish(channel, message)

    async def subscribe(self, workspace_id: str):
        """Return a pubsub object subscribed to workspace channel."""
        pubsub = get_redis().pubsub()
        channel = f"{self.CHANNEL_PREFIX}:{workspace_id}"
        await pubsub.subscribe(channel)
        return pubsub


# ── Distributed lock ──────────────────────────────────────────

class DistributedLock:
    """
    Simple Redis-based distributed lock.
    Prevents concurrent scan execution for same org.
    """

    def __init__(self, name: str, timeout: int = 3600):
        self.key = f"asm:lock:{name}"
        self.timeout = timeout
        self._acquired = False

    async def acquire(self) -> bool:
        result = await get_redis().set(
            self.key, "1",
            nx=True,
            ex=self.timeout,
        )
        self._acquired = result is True
        return self._acquired

    async def release(self) -> None:
        if self._acquired:
            await get_redis().delete(self.key)
            self._acquired = False

    async def __aenter__(self):
        if not await self.acquire():
            raise RuntimeError(f"Could not acquire lock: {self.key}")
        return self

    async def __aexit__(self, *args):
        await self.release()

    async def is_locked(self) -> bool:
        return bool(await get_redis().exists(self.key))


# ── Singletons ────────────────────────────────────────────────
cache = CacheManager(prefix="asm", default_ttl=settings.REDIS_CACHE_TTL)
pubsub = PubSubManager()

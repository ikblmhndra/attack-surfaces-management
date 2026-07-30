"""
ASM Platform — RabbitMQ Connection for API
"""
import asyncio

import structlog
import aio_pika
from app.core.config import settings

log = structlog.get_logger()
_connection: aio_pika.RobustConnection | None = None
_channel: aio_pika.Channel | None = None


async def init_rabbitmq() -> None:
    global _connection, _channel

    # connect_robust only auto-retries *after* an initial connection succeeds
    # (it fails fast on the first attempt). On a host/daemon restart, Docker
    # starts all `restart: unless-stopped` containers natively and does not
    # honor compose's `depends_on: condition: service_healthy` ordering, so
    # RabbitMQ (Erlang/Mnesia boot) can still be coming up when this runs.
    # Retry the initial connect the same way workers/base_worker.py does, or
    # a lost race here kills the whole ASGI lifespan and the API never
    # recovers on its own (its process doesn't exit, so `restart:
    # unless-stopped` never re-triggers).
    for attempt in range(1, 6):
        try:
            _connection = await aio_pika.connect_robust(
                settings.RABBITMQ_URL,
                reconnect_interval=5,
            )
            break
        except Exception as e:
            if attempt == 5:
                raise
            wait = attempt * 3
            log.warning("rabbitmq_connect_retry", attempt=attempt, wait=wait, error=str(e))
            await asyncio.sleep(wait)

    _channel = await _connection.channel()
    await _channel.set_qos(prefetch_count=1)
    log.info("rabbitmq_initialized")


async def close_rabbitmq() -> None:
    global _connection
    if _connection and not _connection.is_closed:
        await _connection.close()
        _connection = None
        log.info("rabbitmq_closed")


def get_rabbitmq_channel() -> aio_pika.Channel:
    if _channel is None:
        raise RuntimeError("RabbitMQ not initialized.")
    return _channel

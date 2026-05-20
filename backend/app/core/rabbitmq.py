"""
ASM Platform — RabbitMQ Connection for API
"""
import structlog
import aio_pika
from app.core.config import settings

log = structlog.get_logger()
_connection: aio_pika.RobustConnection | None = None
_channel: aio_pika.Channel | None = None


async def init_rabbitmq() -> None:
    global _connection, _channel
    _connection = await aio_pika.connect_robust(
        settings.RABBITMQ_URL,
        reconnect_interval=5,
    )
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

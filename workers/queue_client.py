"""
ASM Platform — Queue Client
Publishes messages to RabbitMQ from API and workers.
Supports priority, routing keys, and connection pooling.
"""
import json
import os
from typing import Any, Dict, Optional

import aio_pika
import structlog

log = structlog.get_logger()

# Exchange → routing key → queue mappings
ROUTING_CONFIG = {
    "scan.discovery":      {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "scan.crawl":          {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "scan.port":           {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "scan.nuclei":         {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "scan.scanner":        {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "scan.screenshot":     {"exchange": "asm.scan",         "type": aio_pika.ExchangeType.TOPIC},
    "correlation.process": {"exchange": "asm.correlation",  "type": aio_pika.ExchangeType.FANOUT},
    "risk.compute":        {"exchange": "asm.risk",         "type": aio_pika.ExchangeType.DIRECT},
    "notify.send":         {"exchange": "asm.notify",       "type": aio_pika.ExchangeType.TOPIC},
    "enrich.assets":       {"exchange": "asm.enrich",       "type": aio_pika.ExchangeType.DIRECT},
    "asset.validate":      {"exchange": "asm.asset",        "type": aio_pika.ExchangeType.DIRECT},
}

QUEUE_CONFIG = {
    routing_key: {
        "exchange": config["exchange"],
        "type": config["type"],
        "binding_key": routing_key,
    }
    for routing_key, config in ROUTING_CONFIG.items()
}


class QueueClient:
    """Async RabbitMQ publisher with connection management."""

    def __init__(self, url: Optional[str] = None):
        self.url = url or os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self.connection: Optional[aio_pika.RobustConnection] = None
        self.channel: Optional[aio_pika.Channel] = None
        self._exchanges: Dict[str, aio_pika.Exchange] = {}

    async def connect(self) -> None:
        """Establish connection to RabbitMQ."""
        self.connection = await aio_pika.connect_robust(
            self.url,
            reconnect_interval=5,
        )
        self.channel = await self.connection.channel()
        await self.channel.set_qos(prefetch_count=1)

        # Pre-declare all known exchanges
        for routing_key, config in ROUTING_CONFIG.items():
            exchange_name = config["exchange"]
            if exchange_name not in self._exchanges:
                exchange = await self.channel.declare_exchange(
                    exchange_name,
                    config["type"],
                    durable=True,
                )
                self._exchanges[exchange_name] = exchange

        await self._declare_queues()

        log.info("queue_client_connected")

    async def _declare_queues(self) -> None:
        dlx = await self.channel.declare_exchange(
            "asm.dlx",
            aio_pika.ExchangeType.DIRECT,
            durable=True,
        )

        for queue_name, config in QUEUE_CONFIG.items():
            dlq = await self.channel.declare_queue(
                f"{queue_name}.dlq",
                durable=True,
                arguments={
                    "x-message-ttl": 7 * 24 * 60 * 60 * 1000,
                    "x-max-length": 10_000,
                },
            )
            await dlq.bind(dlx, routing_key=queue_name)

            queue = await self.channel.declare_queue(
                queue_name,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": "asm.dlx",
                    "x-dead-letter-routing-key": queue_name,
                    "x-max-priority": 10,
                    "x-message-ttl": 24 * 60 * 60 * 1000,
                },
            )
            exchange = self._exchanges[config["exchange"]]
            await queue.bind(exchange, routing_key=config["binding_key"])

    async def publish(
        self,
        routing_key: str,
        message: Dict[str, Any],
        priority: int = 5,
        expiration: Optional[int] = None,
        headers: Optional[Dict] = None,
    ) -> None:
        """
        Publish a message to the appropriate exchange.

        Args:
            routing_key: Queue routing key (e.g., "scan.discovery")
            message: Message payload (will be JSON-encoded)
            priority: Message priority 1-10 (10 = highest)
            expiration: TTL in milliseconds
            headers: Optional message headers
        """
        if not self.channel or self.channel.is_closed:
            await self.connect()

        config = ROUTING_CONFIG.get(routing_key)
        if not config:
            # Use default exchange (direct to queue)
            exchange = self.channel.default_exchange
        else:
            exchange = self._exchanges.get(config["exchange"])
            if not exchange:
                await self.connect()
                exchange = self._exchanges[config["exchange"]]

        body = json.dumps(message, default=str).encode("utf-8")

        msg = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            priority=max(0, min(10, priority)),
            headers=headers or {},
            content_type="application/json",
        )

        if expiration:
            msg.expiration = expiration

        await exchange.publish(msg, routing_key=routing_key)

        log.debug(
            "message_published",
            routing_key=routing_key,
            priority=priority,
            size_bytes=len(body),
        )

    async def close(self) -> None:
        """Close the connection."""
        if self.connection and not self.connection.is_closed:
            await self.connection.close()
        self._exchanges.clear()

    @property
    def is_connected(self) -> bool:
        return (
            self.connection is not None
            and not self.connection.is_closed
        )

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()

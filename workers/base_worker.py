"""
ASM Platform — Base Worker
Abstract base class for all queue-consuming workers.
Provides: connection management, message acknowledgment, retry logic,
dead-letter handling, Prometheus metrics, graceful shutdown.
"""
import asyncio
import json
import os
import signal
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import aio_pika
import structlog
from aiormq.exceptions import ChannelInvalidStateError
from prometheus_client import Counter, Gauge, Histogram, start_http_server

log = structlog.get_logger()

# ── Prometheus metrics ────────────────────────────────────────
MESSAGES_PROCESSED = Counter(
    "asm_worker_messages_processed_total",
    "Total messages processed",
    ["worker_type", "status"],
)
MESSAGES_FAILED = Counter(
    "asm_worker_messages_failed_total",
    "Total messages failed",
    ["worker_type", "reason"],
)
PROCESSING_TIME = Histogram(
    "asm_worker_processing_seconds",
    "Message processing time in seconds",
    ["worker_type"],
    buckets=[0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600],
)
ACTIVE_WORKERS = Gauge(
    "asm_worker_active",
    "Number of active worker instances",
    ["worker_type"],
)
QUEUE_DEPTH = Gauge(
    "asm_worker_queue_depth",
    "Estimated queue depth",
    ["queue_name"],
)


class BaseWorker(ABC):
    """
    Abstract base for all ASM Platform workers.

    Subclasses must implement:
        - QUEUE (class attribute): RabbitMQ queue name
        - process(message: dict) -> None: Message handler

    Optionally override:
        - setup() -> None: Called once before consuming
        - teardown() -> None: Called on shutdown
        - CONCURRENCY: Max concurrent messages
        - MAX_RETRIES: Retry attempts before DLQ
        - RETRY_DELAY: Seconds between retries (exponential backoff)
    """

    QUEUE: str = ""
    CONCURRENCY: int = 3
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 5.0
    PREFETCH_COUNT: int = 10

    # Exchange mapping: queue name → (exchange_name, type)
    EXCHANGE_MAP: Dict[str, tuple] = {
        "scan.discovery":      ("asm.scan", aio_pika.ExchangeType.TOPIC),
        "scan.port":           ("asm.scan", aio_pika.ExchangeType.TOPIC),
        "scan.nuclei":         ("asm.scan", aio_pika.ExchangeType.TOPIC),
        "scan.screenshot":     ("asm.scan", aio_pika.ExchangeType.TOPIC),
        "correlation.process": ("asm.correlation", aio_pika.ExchangeType.FANOUT),
        "risk.compute":        ("asm.risk", aio_pika.ExchangeType.DIRECT),
        "notify.send":         ("asm.notify", aio_pika.ExchangeType.TOPIC),
    }

    def __init__(self):
        self.worker_type = self.__class__.__name__
        self.connection: Optional[aio_pika.RobustConnection] = None
        self.channel: Optional[aio_pika.Channel] = None
        self._shutdown = asyncio.Event()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_tasks: set = set()

    # ── Entry point ───────────────────────────────────────────

    async def run(self) -> None:
        """Main entry point. Sets up connections and starts consuming."""
        self._semaphore = asyncio.Semaphore(self.CONCURRENCY)

        # Start Prometheus metrics server
        metrics_port = int(os.getenv("METRICS_PORT", "8001"))
        try:
            start_http_server(metrics_port)
            log.info("metrics_server_started", port=metrics_port)
        except Exception:
            pass  # Port already in use (multiple workers)

        # Register signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        ACTIVE_WORKERS.labels(worker_type=self.worker_type).inc()

        try:
            await self._connect()
            await self.setup()
            log.info(
                "worker_started",
                worker=self.worker_type,
                queue=self.QUEUE,
                concurrency=self.CONCURRENCY,
            )
            await self._consume()
        except Exception as e:
            log.error("worker_fatal_error", worker=self.worker_type, error=str(e), exc_info=True)
            raise
        finally:
            await self.teardown()
            await self._disconnect()
            ACTIVE_WORKERS.labels(worker_type=self.worker_type).dec()
            log.info("worker_stopped", worker=self.worker_type)

    # ── Connection management ─────────────────────────────────

    async def _connect(self) -> None:
        """Establish RabbitMQ connection with retry."""
        rabbitmq_url = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")

        for attempt in range(1, 6):
            try:
                heartbeat = int(os.getenv("RABBITMQ_HEARTBEAT", "1200"))
                self.connection = await aio_pika.connect_robust(
                    rabbitmq_url,
                    reconnect_interval=5,
                    heartbeat=heartbeat,
                )
                self.channel = await self.connection.channel()
                prefetch_count = min(self.PREFETCH_COUNT, max(1, self.CONCURRENCY))
                await self.channel.set_qos(prefetch_count=prefetch_count)

                # Declare all required exchanges and queues
                await self._declare_topology()

                log.info(
                    "rabbitmq_connected",
                    queue=self.QUEUE,
                    attempt=attempt,
                    prefetch_count=prefetch_count,
                )
                return
            except Exception as e:
                if attempt == 5:
                    raise
                wait = attempt * 3
                log.warning("rabbitmq_connect_retry", attempt=attempt, wait=wait, error=str(e))
                await asyncio.sleep(wait)

    async def _declare_topology(self) -> None:
        """Declare exchanges, queues, and bindings."""
        # Dead-letter exchange
        dlx = await self.channel.declare_exchange(
            "asm.dlx",
            aio_pika.ExchangeType.DIRECT,
            durable=True,
        )

        # Dead-letter queue (per queue)
        dlq = await self.channel.declare_queue(
            f"{self.QUEUE}.dlq",
            durable=True,
            arguments={
                "x-message-ttl": 7 * 24 * 60 * 60 * 1000,  # 7 days
                "x-max-length": 10_000,
            },
        )
        await dlq.bind(dlx, routing_key=self.QUEUE)

        # Main queue with DLX routing
        queue = await self.channel.declare_queue(
            self.QUEUE,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "asm.dlx",
                "x-dead-letter-routing-key": self.QUEUE,
                "x-max-priority": 10,
                "x-message-ttl": 24 * 60 * 60 * 1000,  # 24 hours max TTL
            },
        )

        # Bind queue to the appropriate exchange for this worker
        exchange_config = self.EXCHANGE_MAP.get(self.QUEUE)
        if exchange_config:
            exchange_name, exchange_type = exchange_config
            exchange = await self.channel.declare_exchange(
                exchange_name, exchange_type, durable=True,
            )
            await queue.bind(exchange, routing_key=self.QUEUE)
            log.info("queue_bound", queue=self.QUEUE, exchange=exchange_name)

    async def _disconnect(self) -> None:
        """Gracefully close connection."""
        if self.connection and not self.connection.is_closed:
            await self.connection.close()

    # ── Consuming ─────────────────────────────────────────────

    async def _consume(self) -> None:
        """Start consuming messages from the queue."""
        queue = await self.channel.declare_queue(
            self.QUEUE,
            durable=True,
            passive=True,  # Don't recreate, just get reference
        )

        async with queue.iterator() as q_iter:
            async for message in q_iter:
                if self._shutdown.is_set():
                    log.info("worker_shutdown_consuming", worker=self.worker_type)
                    break

                await self._semaphore.acquire()
                task = asyncio.create_task(self._handle_message_limited(message))
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)

        # Wait for in-flight tasks
        if self._active_tasks:
            log.info("worker_draining", pending=len(self._active_tasks))
            await asyncio.gather(*self._active_tasks, return_exceptions=True)

    async def _handle_message(self, message: aio_pika.IncomingMessage) -> None:
        """Wrapper: decode, process, ack/nack with retry logic."""
        start = time.monotonic()
        retry_count = 0

        # Extract retry count from headers
        headers = message.headers or {}
        retry_count = int(headers.get("x-retry-count", 0))

        body = None

        try:
            # Decode JSON body
            body = json.loads(message.body.decode("utf-8"))

            log.info(
                "message_received",
                worker=self.worker_type,
                queue=self.QUEUE,
                retry=retry_count,
                message_id=getattr(message, "message_id", None),
            )

            # Process message
            await self.process(body)

            # Acknowledge success
            await message.ack()

            elapsed = time.monotonic() - start
            MESSAGES_PROCESSED.labels(worker_type=self.worker_type, status="success").inc()
            PROCESSING_TIME.labels(worker_type=self.worker_type).observe(elapsed)

            log.info(
                "message_processed",
                worker=self.worker_type,
                elapsed_s=round(elapsed, 3),
            )

        except json.JSONDecodeError as e:
            log.error("message_decode_error", error=str(e), worker=self.worker_type)
            try:
                await message.reject(requeue=False)
            except Exception:
                pass
            MESSAGES_FAILED.labels(worker_type=self.worker_type, reason="decode_error").inc()

        except ChannelInvalidStateError as e:
            log.warning(
                "message_channel_closed",
                worker=self.worker_type,
                error=str(e),
                elapsed_s=round(time.monotonic() - start, 1),
            )

        except Exception as e:
            elapsed = time.monotonic() - start
            log.error(
                "message_processing_error",
                worker=self.worker_type,
                error=str(e),
                retry=retry_count,
                exc_info=True,
            )
            MESSAGES_FAILED.labels(worker_type=self.worker_type, reason="processing_error").inc()

            if retry_count < self.MAX_RETRIES:
                # Republish with incremented retry count and backoff
                delay = self.RETRY_DELAY * (2 ** retry_count)  # Exponential backoff
                await asyncio.sleep(min(delay, 60))

                try:
                    await self.channel.default_exchange.publish(
                        aio_pika.Message(
                            body=message.body,
                            headers={
                                **headers,
                                "x-retry-count": retry_count + 1,
                                "x-last-error": str(e)[:500],
                                "x-original-queue": self.QUEUE,
                            },
                            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                        ),
                        routing_key=self.QUEUE,
                    )
                    await message.ack()
                    log.info(
                        "message_requeued",
                        retry=retry_count + 1,
                        delay=delay,
                        worker=self.worker_type,
                    )
                except ChannelInvalidStateError:
                    pass
                except Exception as retry_err:
                    log.error("retry_publish_failed", error=str(retry_err))
                    try:
                        await message.reject(requeue=False)
                    except Exception:
                        pass
            else:
                # Max retries exceeded → send to DLQ
                log.error(
                    "message_dead_lettered",
                    worker=self.worker_type,
                    retries=retry_count,
                    error=str(e),
                )
                scan_id = body.get("scan_id") if isinstance(body, dict) else None
                if scan_id:
                    try:
                        from workers.db import get_session
                        from workers.scan_state import mark_scan_failed

                        async with get_session() as db:
                            await mark_scan_failed(
                                db,
                                scan_id,
                                f"{self.worker_type} failed after {self.MAX_RETRIES} retries: {str(e)}",
                            )
                    except Exception as state_err:
                        log.warning(
                            "scan_failed_state_update_failed",
                            worker=self.worker_type,
                            scan_id=scan_id,
                            error=str(state_err),
                        )
                try:
                    await message.reject(requeue=False)
                except Exception:
                    pass
                MESSAGES_FAILED.labels(worker_type=self.worker_type, reason="max_retries").inc()

    async def _handle_message_limited(self, message: aio_pika.IncomingMessage) -> None:
        """Process one message and release the worker concurrency slot."""
        try:
            await self._handle_message(message)
        finally:
            self._semaphore.release()

    # ── Abstract interface ─────────────────────────────────────

    @abstractmethod
    async def process(self, message: Dict[str, Any]) -> None:
        """Process a single message. Must be implemented by subclasses."""

    async def setup(self) -> None:
        """Called once before consuming starts. Override for initialization."""

    async def teardown(self) -> None:
        """Called on shutdown. Override for cleanup."""

    # ── Shutdown handling ─────────────────────────────────────

    def _handle_shutdown(self) -> None:
        """Signal handler for graceful shutdown."""
        log.info("shutdown_signal_received", worker=self.worker_type)
        self._shutdown.set()

    # ── Health properties ─────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return (
            self.connection is not None
            and not self.connection.is_closed
            and self.channel is not None
            and not self.channel.is_closed
        )

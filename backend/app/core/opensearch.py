"""
ASM Platform — OpenSearch Client Initialization
"""
import asyncio

from opensearchpy import AsyncOpenSearch, RequestsHttpConnection
import structlog
from app.core.config import settings

log = structlog.get_logger()
_opensearch_client: AsyncOpenSearch | None = None


async def init_opensearch() -> None:
    global _opensearch_client
    hosts = [{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}]
    kwargs = dict(
        hosts=hosts,
        use_ssl=False,
        verify_certs=False,
        http_compress=True,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )
    if settings.OPENSEARCH_USER:
        kwargs["http_auth"] = (settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD)
    _opensearch_client = AsyncOpenSearch(**kwargs)

    # OpenSearch's own max_retries/retry_on_timeout only cover per-request
    # timeouts against an already-listening server, not "server not up yet"
    # -- and it's the slowest-booting service in the stack (JVM start), so
    # it's the most likely to lose the depends_on-bypassing startup race
    # described in rabbitmq.py::init_rabbitmq. Retry the initial info() call
    # with backoff for the same reason.
    for attempt in range(1, 6):
        try:
            info = await _opensearch_client.info()
            break
        except Exception as e:
            if attempt == 5:
                raise
            wait = attempt * 3
            log.warning("opensearch_connect_retry", attempt=attempt, wait=wait, error=str(e))
            await asyncio.sleep(wait)
    log.info("opensearch_initialized", version=info.get("version", {}).get("number"))


async def close_opensearch() -> None:
    global _opensearch_client
    if _opensearch_client:
        await _opensearch_client.close()
        _opensearch_client = None
        log.info("opensearch_closed")


def get_opensearch() -> AsyncOpenSearch:
    if _opensearch_client is None:
        raise RuntimeError("OpenSearch not initialized.")
    return _opensearch_client

"""
ASM Platform — OpenSearch Client Initialization
"""
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
    info = await _opensearch_client.info()
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

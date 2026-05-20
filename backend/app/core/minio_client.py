"""
ASM Platform — MinIO Client Initialization
"""
import asyncio
import structlog
from minio import Minio
from minio.error import S3Error
from app.core.config import settings

log = structlog.get_logger()
_minio_client: Minio | None = None

BUCKETS = [
    settings.MINIO_BUCKET_SCREENSHOTS,
    settings.MINIO_BUCKET_EVIDENCE,
    settings.MINIO_BUCKET_REPORTS,
    settings.MINIO_BUCKET_EXPORTS,
]


async def init_minio() -> None:
    global _minio_client
    _minio_client = Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )
    loop = asyncio.get_event_loop()
    for bucket in BUCKETS:
        try:
            exists = await loop.run_in_executor(None, _minio_client.bucket_exists, bucket)
            if not exists:
                await loop.run_in_executor(None, _minio_client.make_bucket, bucket)
                log.info("minio_bucket_created", bucket=bucket)
        except S3Error as e:
            log.warning("minio_bucket_init_error", bucket=bucket, error=str(e))
    log.info("minio_initialized", endpoint=settings.MINIO_ENDPOINT)


def get_minio() -> Minio:
    if _minio_client is None:
        raise RuntimeError("MinIO not initialized.")
    return _minio_client

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

    # Connectivity probe, retried with backoff for the same reason as
    # rabbitmq.py::init_rabbitmq (depends_on health-gating is bypassed on a
    # native container restart, e.g. after a host reboot). Only a raw
    # connection failure needs retrying here -- the per-bucket loop below
    # already has its own S3Error handling for real S3-level errors once
    # MinIO is confirmed reachable.
    for attempt in range(1, 6):
        try:
            await loop.run_in_executor(None, _minio_client.bucket_exists, BUCKETS[0])
            break
        except S3Error:
            break
        except Exception as e:
            if attempt == 5:
                raise
            wait = attempt * 3
            log.warning("minio_connect_retry", attempt=attempt, wait=wait, error=str(e))
            await asyncio.sleep(wait)

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

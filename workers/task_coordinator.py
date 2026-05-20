"""
ASM Platform — Task Coordinator (Redis-based)
Coordinates scan task completion across distributed workers.
Tracks nuclei batches and screenshot status so the terminal
correlation message is only sent when ALL work is done.
"""
import os
from typing import Optional

import structlog

log = structlog.get_logger()


class TaskCoordinator:
    """
    Uses Redis counters to track per-scan task progress.

    Keys:
      scan:{scan_id}:nuclei_expected   — total nuclei batches published
      scan:{scan_id}:nuclei_done       — nuclei batches completed
      scan:{scan_id}:screenshot_done   — 0/1 flag
    """

    def __init__(self):
        self._redis: Optional = None

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                os.getenv("REDIS_URL", "redis://redis:6379/0"),
                decode_responses=True,
            )
        return self._redis

    async def close(self):
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    async def add_nuclei_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        val = await r.incrby(f"scan:{scan_id}:nuclei_expected", count)
        return val

    async def incr_nuclei_done(self, scan_id: str) -> int:
        r = await self._get_redis()
        val = await r.incr(f"scan:{scan_id}:nuclei_done")
        return val

    async def set_screenshot_done(self, scan_id: str) -> None:
        r = await self._get_redis()
        await r.set(f"scan:{scan_id}:screenshot_done", 1)

    async def is_all_done(self, scan_id: str) -> bool:
        r = await self._get_redis()
        expected = int(await r.get(f"scan:{scan_id}:nuclei_expected") or 0)
        done = int(await r.get(f"scan:{scan_id}:nuclei_done") or 0)
        screenshot = int(await r.get(f"scan:{scan_id}:screenshot_done") or 0)
        return done >= expected and screenshot == 1

    async def cleanup(self, scan_id: str) -> None:
        r = await self._get_redis()
        await r.delete(
            f"scan:{scan_id}:nuclei_expected",
            f"scan:{scan_id}:nuclei_done",
            f"scan:{scan_id}:screenshot_done",
        )

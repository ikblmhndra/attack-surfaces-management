"""
ASM Platform — Task Coordinator (Redis-based)
Coordinates scan task completion across distributed workers.
Tracks nuclei batches and screenshot status so the terminal
correlation message is only sent when ALL work is done.

Uses atomic Lua script to prevent double-finalization race
between workers finishing near-simultaneously.
"""
import os
from typing import Optional

import structlog

log = structlog.get_logger()

REDIS_KEY_TTL = 86400  # 24 hours — keys auto-expire if scan fails mid-pipeline

# Lua script: atomically check if all work is done AND claim the terminal slot.
# Returns 1 if caller should send terminal correlation, 0 otherwise.
_LUA_MARK_TERMINAL = """
local nuclei_expected = redis.call('GET', KEYS[1]) or 0
local nuclei_done = redis.call('GET', KEYS[2]) or 0
local port_expected = redis.call('GET', KEYS[3]) or 0
local port_done = redis.call('GET', KEYS[4]) or 0
local crawl_expected = redis.call('GET', KEYS[5]) or 0
local crawl_done = redis.call('GET', KEYS[6]) or 0
local screenshot_done = redis.call('GET', KEYS[7]) or 0
local enrich_expected = redis.call('GET', KEYS[8]) or 0
local enrich_done = redis.call('GET', KEYS[9]) or 0
local scanner_expected = redis.call('GET', KEYS[10]) or 0
local scanner_done = redis.call('GET', KEYS[11]) or 0
local terminal_marked = redis.call('GET', KEYS[12])
if terminal_marked == '1' then
    return 0
end
if tonumber(nuclei_done) >= tonumber(nuclei_expected) and tonumber(port_done) >= tonumber(port_expected) and tonumber(crawl_done) >= tonumber(crawl_expected) and tonumber(enrich_done) >= tonumber(enrich_expected) and tonumber(scanner_done) >= tonumber(scanner_expected) and tonumber(screenshot_done) == 1 then
    redis.call('SETEX', KEYS[12], 300, '1')
    return 1
end
return 0
"""


class TaskCoordinator:
    """
    Uses Redis counters to track per-scan task progress.

    Keys:
      scan:{scan_id}:nuclei_expected   — total nuclei batches published
      scan:{scan_id}:nuclei_done       — nuclei batches completed
      scan:{scan_id}:port_expected     — total port batches published
      scan:{scan_id}:port_done         — port batches completed
      scan:{scan_id}:crawl_expected    — total crawl batches published
      scan:{scan_id}:crawl_done        — crawl batches completed
      scan:{scan_id}:enrich_expected   — total enrichment batches published
      scan:{scan_id}:enrich_done       — enrichment batches completed
      scan:{scan_id}:scanner_expected  — total scanner-family batches published
      scan:{scan_id}:scanner_done      — scanner-family batches completed
      scan:{scan_id}:screenshot_done   — 0/1 flag
      scan:{scan_id}:terminal_marked   — 0/1 flag (atomic guard)
    """

    def __init__(self):
        self._redis: Optional = None
        self._mark_terminal_script: Optional = None

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                os.getenv("REDIS_URL", "redis://redis:6379/0"),
                decode_responses=True,
            )
        return self._redis

    async def _load_script(self):
        if self._mark_terminal_script is not None:
            return self._mark_terminal_script
        r = await self._get_redis()
        self._mark_terminal_script = r.register_script(_LUA_MARK_TERMINAL)
        return self._mark_terminal_script

    async def close(self):
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    async def add_nuclei_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:nuclei_expected"
        val = await r.incrby(key, count)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def incr_nuclei_done(self, scan_id: str, targets_scanned: int = 0, findings_found: int = 0) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:nuclei_done"
        val = await r.incr(key)
        await r.expire(key, REDIS_KEY_TTL)
        if targets_scanned:
            targets_key = f"scan:{scan_id}:nuclei_targets_scanned"
            await r.incrby(targets_key, int(targets_scanned))
            await r.expire(targets_key, REDIS_KEY_TTL)
        if findings_found:
            findings_key = f"scan:{scan_id}:nuclei_findings_found"
            await r.incrby(findings_key, int(findings_found))
            await r.expire(findings_key, REDIS_KEY_TTL)
        return val

    async def get_counts(self, scan_id: str) -> dict:
        r = await self._get_redis()
        keys = {
            "nuclei_expected": f"scan:{scan_id}:nuclei_expected",
            "nuclei_done": f"scan:{scan_id}:nuclei_done",
            "nuclei_targets_scanned": f"scan:{scan_id}:nuclei_targets_scanned",
            "nuclei_findings_found": f"scan:{scan_id}:nuclei_findings_found",
            "port_expected": f"scan:{scan_id}:port_expected",
            "port_done": f"scan:{scan_id}:port_done",
            "crawl_expected": f"scan:{scan_id}:crawl_expected",
            "crawl_done": f"scan:{scan_id}:crawl_done",
            "enrich_expected": f"scan:{scan_id}:enrich_expected",
            "enrich_done": f"scan:{scan_id}:enrich_done",
            "scanner_expected": f"scan:{scan_id}:scanner_expected",
            "scanner_done": f"scan:{scan_id}:scanner_done",
            "screenshot_done": f"scan:{scan_id}:screenshot_done",
        }
        values = await r.mget(list(keys.values()))
        return {name: int(value or 0) for name, value in zip(keys, values)}

    async def add_port_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:port_expected"
        val = await r.incrby(key, count)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def incr_port_done(self, scan_id: str) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:port_done"
        val = await r.incr(key)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def add_crawl_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:crawl_expected"
        val = await r.incrby(key, count)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def incr_crawl_done(self, scan_id: str) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:crawl_done"
        val = await r.incr(key)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def set_screenshot_done(self, scan_id: str) -> None:
        r = await self._get_redis()
        key = f"scan:{scan_id}:screenshot_done"
        await r.setex(key, REDIS_KEY_TTL, 1)

    async def add_enrich_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:enrich_expected"
        val = await r.incrby(key, count)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def incr_enrich_done(self, scan_id: str) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:enrich_done"
        val = await r.incr(key)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def add_scanner_expected(self, scan_id: str, count: int = 1) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:scanner_expected"
        val = await r.incrby(key, count)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def incr_scanner_done(self, scan_id: str) -> int:
        r = await self._get_redis()
        key = f"scan:{scan_id}:scanner_done"
        val = await r.incr(key)
        await r.expire(key, REDIS_KEY_TTL)
        return val

    async def mark_terminal_if_all_done(self, scan_id: str) -> bool:
        """Atomically check AND claim the terminal slot. Returns True if caller should send terminal correlation."""
        script = await self._load_script()
        r = await self._get_redis()
        result = await script(
            keys=[
                f"scan:{scan_id}:nuclei_expected",
                f"scan:{scan_id}:nuclei_done",
                f"scan:{scan_id}:port_expected",
                f"scan:{scan_id}:port_done",
                f"scan:{scan_id}:crawl_expected",
                f"scan:{scan_id}:crawl_done",
                f"scan:{scan_id}:screenshot_done",
                f"scan:{scan_id}:enrich_expected",
                f"scan:{scan_id}:enrich_done",
                f"scan:{scan_id}:scanner_expected",
                f"scan:{scan_id}:scanner_done",
                f"scan:{scan_id}:terminal_marked",
            ],
        )
        return result == 1

    async def is_all_done(self, scan_id: str) -> bool:
        """Non-atomic check — kept for backward compatibility. Prefer mark_terminal_if_all_done()."""
        r = await self._get_redis()
        expected = int(await r.get(f"scan:{scan_id}:nuclei_expected") or 0)
        done = int(await r.get(f"scan:{scan_id}:nuclei_done") or 0)
        port_expected = int(await r.get(f"scan:{scan_id}:port_expected") or 0)
        port_done = int(await r.get(f"scan:{scan_id}:port_done") or 0)
        crawl_expected = int(await r.get(f"scan:{scan_id}:crawl_expected") or 0)
        crawl_done = int(await r.get(f"scan:{scan_id}:crawl_done") or 0)
        enrich_expected = int(await r.get(f"scan:{scan_id}:enrich_expected") or 0)
        enrich_done = int(await r.get(f"scan:{scan_id}:enrich_done") or 0)
        scanner_expected = int(await r.get(f"scan:{scan_id}:scanner_expected") or 0)
        scanner_done = int(await r.get(f"scan:{scan_id}:scanner_done") or 0)
        screenshot = int(await r.get(f"scan:{scan_id}:screenshot_done") or 0)
        return (
            done >= expected
            and port_done >= port_expected
            and crawl_done >= crawl_expected
            and enrich_done >= enrich_expected
            and scanner_done >= scanner_expected
            and screenshot == 1
        )

    async def cleanup(self, scan_id: str) -> None:
        r = await self._get_redis()
        await r.delete(
            f"scan:{scan_id}:nuclei_expected",
            f"scan:{scan_id}:nuclei_done",
            f"scan:{scan_id}:port_expected",
            f"scan:{scan_id}:port_done",
            f"scan:{scan_id}:crawl_expected",
            f"scan:{scan_id}:crawl_done",
            f"scan:{scan_id}:enrich_expected",
            f"scan:{scan_id}:enrich_done",
            f"scan:{scan_id}:scanner_expected",
            f"scan:{scan_id}:scanner_done",
            f"scan:{scan_id}:nuclei_targets_scanned",
            f"scan:{scan_id}:nuclei_findings_found",
            f"scan:{scan_id}:screenshot_done",
            f"scan:{scan_id}:terminal_marked",
        )

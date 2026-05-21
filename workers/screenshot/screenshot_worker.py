"""
ASM Platform — Screenshot Worker
Captures screenshots of discovered web assets using Playwright.
Stores images in MinIO object storage with thumbnails.
"""
import asyncio
import io
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from minio import Minio
from minio.error import S3Error
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient

log = structlog.get_logger()

SCREENSHOT_TIMEOUT = int(os.getenv("SCREENSHOT_TIMEOUT", "30"))
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 800
THUMBNAIL_WIDTH = 400
THUMBNAIL_HEIGHT = 250
MAX_CONCURRENT_BROWSERS = 3


class ScreenshotWorker(BaseWorker):
    """
    Captures screenshots of alive HTTP/HTTPS services.

    Features:
    - Headless Chromium via Playwright
    - Full-page screenshots with viewport normalization
    - WebP conversion for storage efficiency
    - Thumbnail generation
    - MinIO storage with presigned URLs
    - Per-asset screenshot history (tracks changes)
    """

    QUEUE = "scan.screenshot"
    CONCURRENCY = 1  # Browser management is internal
    _browser_semaphore: asyncio.Semaphore = None

    def __init__(self):
        super().__init__()
        self.playwright = None
        self.browser = None
        self.minio_client: Optional[Minio] = None
        self.bucket = os.getenv("MINIO_BUCKET", "screenshots")
        self._browser_semaphore = asyncio.Semaphore(MAX_CONCURRENT_BROWSERS)

    async def setup(self) -> None:
        """Initialize Playwright browser and MinIO client."""
        # Initialize Playwright
        from playwright.async_api import async_playwright
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-first-run",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-translate",
                "--hide-scrollbars",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-default-browser-check",
                "--safebrowsing-disable-auto-update",
            ],
        )

        # Initialize MinIO
        self.minio_client = Minio(
            os.getenv("MINIO_ENDPOINT", "minio:9000"),
            access_key=os.getenv("MINIO_ACCESS_KEY", ""),
            secret_key=os.getenv("MINIO_SECRET_KEY", ""),
            secure=os.getenv("MINIO_SECURE", "false").lower() == "true",
        )

        # Ensure bucket exists
        if not self.minio_client.bucket_exists(self.bucket):
            self.minio_client.make_bucket(self.bucket)

        log.info("screenshot_worker_initialized", bucket=self.bucket)

    async def teardown(self) -> None:
        """Clean up browser resources."""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message["scan_id"]
        org_id = message["org_id"]
        workspace_id = message["workspace_id"]
        targets = message.get("targets", [])

        if not targets:
            log.info("screenshot_no_targets", scan_id=scan_id)
        else:
            log.info("screenshot_batch_started", scan_id=scan_id, targets=len(targets))

            # Process in parallel with concurrency limit
            tasks = [
                self._capture_with_semaphore(url, org_id, workspace_id)
                for url in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success = sum(1 for r in results if r is True)
            failed = len(results) - success

            log.info(
                "screenshot_batch_complete",
                scan_id=scan_id,
                success=success,
                failed=failed,
            )

        # Always update progress
        async with get_session() as db:
            await self._update_scan_progress(db, scan_id)

        # Flag screenshot as done. Atomically claim terminal slot —
        # only one worker (screenshot or nuclei) will send the terminal
        # correlation message.
        from workers.task_coordinator import TaskCoordinator
        coord = TaskCoordinator()
        await coord.set_screenshot_done(scan_id)
        if await coord.mark_terminal_if_all_done(scan_id):
            queue = QueueClient()
            await queue.connect()
            await queue.publish(
                routing_key="correlation.process",
                message={
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "workspace_id": workspace_id,
                    "is_terminal": True,
                },
            )
            await queue.close()
            await coord.cleanup(scan_id)
        await coord.close()

    async def _capture_with_semaphore(
        self,
        url: str,
        org_id: str,
        workspace_id: str,
    ) -> bool:
        async with self._browser_semaphore:
            return await self._capture_screenshot(url, org_id, workspace_id)

    async def _capture_screenshot(
        self,
        url: str,
        org_id: str,
        workspace_id: str,
    ) -> bool:
        """Capture a screenshot for a single URL."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Extract hostname for asset lookup
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or url

        context = None
        page = None

        try:
            context = await self.browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                ignore_https_errors=True,
                java_script_enabled=True,
                bypass_csp=True,
                user_agent="Mozilla/5.0 (compatible; ASM-Platform/1.0; +https://asm-platform.local)",
            )

            page = await context.new_page()

            # Block unnecessary resources
            await page.route("**/*.{woff,woff2,ttf,eot,otf}", lambda r: r.abort())
            await page.route("**/analytics*", lambda r: r.abort())
            await page.route("**/tracking*", lambda r: r.abort())

            # Navigate with timeout
            response = await page.goto(
                url,
                timeout=SCREENSHOT_TIMEOUT * 1000,
                wait_until="domcontentloaded",
            )

            # Brief wait for JS rendering
            await asyncio.sleep(1.5)

            http_status = response.status if response else None

            # Capture full page screenshot as PNG
            screenshot_bytes = await page.screenshot(
                type="png",
                full_page=False,
                clip={"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            )

            if not screenshot_bytes:
                return False

            # Convert to WebP for efficiency
            webp_bytes = await self._convert_to_webp(screenshot_bytes)
            thumbnail_bytes = await self._generate_thumbnail(screenshot_bytes)

            # Upload to MinIO
            screenshot_path, thumbnail_path = await self._upload_to_minio(
                org_id=org_id,
                hostname=hostname,
                webp_bytes=webp_bytes,
                thumbnail_bytes=thumbnail_bytes,
            )

            # Persist to database
            async with get_session() as db:
                asset_id = await self._find_asset_id(db, org_id, hostname)
                if asset_id:
                    await self._save_screenshot(
                        db=db,
                        asset_id=asset_id,
                        org_id=org_id,
                        url=url,
                        storage_path=screenshot_path,
                        thumbnail_path=thumbnail_path,
                        http_status=http_status,
                        file_size=len(webp_bytes),
                    )

            log.info("screenshot_captured", url=url, size=len(webp_bytes))
            return True

        except asyncio.TimeoutError:
            log.warning("screenshot_timeout", url=url)
            return False
        except Exception as e:
            log.warning("screenshot_error", url=url, error=str(e))
            return False
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            if context:
                try:
                    await context.close()
                except Exception:
                    pass

    async def _convert_to_webp(self, png_bytes: bytes) -> bytes:
        """Convert PNG screenshot to WebP for ~30% size reduction."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(png_bytes))
            output = io.BytesIO()
            img.save(output, format="WebP", quality=85, optimize=True)
            return output.getvalue()
        except Exception:
            return png_bytes  # Fall back to PNG

    async def _generate_thumbnail(self, png_bytes: bytes) -> bytes:
        """Generate a small thumbnail for preview display."""
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(png_bytes))
            img.thumbnail((THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT), Image.LANCZOS)
            output = io.BytesIO()
            img.save(output, format="WebP", quality=70, optimize=True)
            return output.getvalue()
        except Exception:
            return png_bytes

    async def _upload_to_minio(
        self,
        org_id: str,
        hostname: str,
        webp_bytes: bytes,
        thumbnail_bytes: bytes,
    ) -> tuple[str, str]:
        """Upload screenshot and thumbnail to MinIO."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        safe_hostname = hostname.replace(".", "_").replace(":", "_")[:100]

        screenshot_key = f"orgs/{org_id}/{safe_hostname}/{timestamp}.webp"
        thumbnail_key = f"orgs/{org_id}/{safe_hostname}/{timestamp}_thumb.webp"

        loop = asyncio.get_event_loop()

        # Upload main screenshot
        await loop.run_in_executor(
            None,
            lambda: self.minio_client.put_object(
                self.bucket,
                screenshot_key,
                io.BytesIO(webp_bytes),
                length=len(webp_bytes),
                content_type="image/webp",
                metadata={
                    "hostname": hostname,
                    "org_id": org_id,
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                },
            ),
        )

        # Upload thumbnail
        await loop.run_in_executor(
            None,
            lambda: self.minio_client.put_object(
                self.bucket,
                thumbnail_key,
                io.BytesIO(thumbnail_bytes),
                length=len(thumbnail_bytes),
                content_type="image/webp",
            ),
        )

        return screenshot_key, thumbnail_key

    async def _find_asset_id(self, db, org_id: str, hostname: str) -> Optional[str]:
        from workers.db_models import Asset
        result = await db.execute(
            select(Asset.id).where(
                Asset.org_id == org_id,
                Asset.value == hostname,
                Asset.deleted_at.is_(None),
            ).limit(1)
        )
        row = result.scalar_one_or_none()
        return str(row) if row else None

    async def _save_screenshot(
        self,
        db,
        asset_id: str,
        org_id: str,
        url: str,
        storage_path: str,
        thumbnail_path: str,
        http_status: Optional[int],
        file_size: int,
    ) -> None:
        from workers.db_models import Screenshot

        # Mark previous screenshots as not current
        await db.execute(
            update(Screenshot)
            .where(Screenshot.asset_id == asset_id, Screenshot.is_current == True)
            .values(is_current=False)
        )

        # Insert new screenshot
        await db.execute(
            pg_insert(Screenshot.__table__).values(
                asset_id=asset_id,
                org_id=org_id,
                url=url,
                storage_path=storage_path,
                thumbnail_path=thumbnail_path,
                storage_bucket=self.bucket,
                width=VIEWPORT_WIDTH,
                height=VIEWPORT_HEIGHT,
                file_size=file_size,
                format="webp",
                http_status=http_status,
                is_current=True,
            )
        )
        await db.commit()


    async def _update_scan_progress(self, db, scan_id: str) -> None:
        from sqlalchemy import update, func
        from workers.db_models import Scan
        from datetime import datetime, timezone
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                completed_tasks=Scan.completed_tasks + 1,
                progress_pct=func.greatest(Scan.progress_pct, 90),
            )
        )
        await db.commit()

if __name__ == "__main__":
    worker = ScreenshotWorker()
    asyncio.run(worker.run())

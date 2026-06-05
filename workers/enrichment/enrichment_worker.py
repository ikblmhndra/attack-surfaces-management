"""
ASM Platform - Asset Enrichment Worker
Adds no-key network baseline data.
"""
import asyncio
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import aiohttp
import structlog
from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.queue_client import QueueClient
from workers.scan_observability import record_target_selections
from workers.scan_phase import update_scan_phase
from workers.scan_state import mark_scan_running

log = structlog.get_logger()


class EnrichmentWorker(BaseWorker):
    QUEUE = "enrich.assets"
    CONCURRENCY = int(os.getenv("ENRICHMENT_CONCURRENCY", "2"))
    PREFETCH_COUNT = int(os.getenv("ENRICHMENT_PREFETCH", "2"))

    async def process(self, message: Dict[str, Any]) -> None:
        scan_id = message.get("scan_id")
        org_id = message.get("org_id")
        workspace_id = message.get("workspace_id")
        assets = message.get("assets") or []
        config = message.get("config") or {}

        if scan_id:
            async with get_session() as db:
                if not await mark_scan_running(db, scan_id, progress_floor=55):
                    log.info("enrichment_skipped_inactive_scan", scan_id=scan_id)
                    return
                await record_target_selections(
                    db,
                    scan_id=scan_id,
                    phase="enrich",
                    targets=[
                        {
                            "target": asset.get("value"),
                            "target_type": asset.get("asset_type") or "asset",
                            "asset_id": asset.get("asset_id"),
                            "profile": "enrichment",
                            "selected": True,
                            "reasons": ["enrichment_target"],
                            "metadata": {
                                "provider_mode": "baseline",
                            },
                        }
                        for asset in assets
                    ],
                )
                await update_scan_phase(db, scan_id, "enrich", "running", targets_total=len(assets))

        processed = 0
        failed = 0
        for asset in assets:
            try:
                await self._enrich_asset(asset, org_id or asset.get("org_id"), config)
                processed += 1
            except Exception as exc:
                failed += 1
                log.warning(
                    "asset_enrichment_failed",
                    asset_id=asset.get("asset_id"),
                    value=asset.get("value"),
                    error=str(exc),
                )

        if scan_id:
            async with get_session() as db:
                await update_scan_phase(
                    db,
                    scan_id,
                    "enrich",
                    "completed",
                    targets_total=len(assets),
                    completed=processed,
                    failed=failed,
                )
                await self._update_scan_progress(db, scan_id)
            await self._mark_enrich_done(scan_id, org_id, workspace_id)

        log.info("enrichment_completed", scan_id=scan_id, assets=len(assets), processed=processed)

    async def _enrich_asset(self, asset: Dict[str, Any], org_id: str, config: Dict[str, Any]) -> None:
        asset_id = asset.get("asset_id")
        value = asset.get("value")
        asset_type = asset.get("asset_type")
        org_id = org_id or asset.get("org_id")
        if not asset_id or not value or not org_id:
            return

        indicator_type = "ip" if asset_type == "ip" else "domain"
        async with get_session() as db:
            if indicator_type == "ip" and config.get("enrichment_baseline", True):
                baseline = await self._network_baseline(value)
                if baseline:
                    await self._persist_ip_baseline(db, asset_id, baseline)
                    await self._persist_intel(
                        db,
                        asset_id,
                        org_id,
                        source="network_baseline",
                        indicator_type="ip",
                        data=baseline,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=14),
                    )

            await db.commit()

    async def _network_baseline(self, ip: str) -> Dict[str, Any]:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return {"ip": ip, "is_private": parsed.is_private, "found": False}

        cymru, rdap = await asyncio.gather(
            self._team_cymru(ip),
            self._rdap_ip(ip),
            return_exceptions=True,
        )
        if isinstance(cymru, Exception):
            cymru = {}
        if isinstance(rdap, Exception):
            rdap = {}

        data = {"ip": ip, "found": bool(cymru or rdap), **(rdap or {}), **(cymru or {})}
        provider = self._classify_provider(data.get("asn_org") or data.get("name") or "")
        data.update(provider)
        return data

    async def _team_cymru(self, ip: str) -> Dict[str, Any]:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("whois.cymru.com", 43), timeout=10)
        try:
            writer.write(f"begin\nverbose\n{ip}\nend\n".encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=10)
        finally:
            writer.close()
            await writer.wait_closed()

        lines = [line.strip() for line in raw.decode(errors="ignore").splitlines() if line.strip()]
        if len(lines) < 2:
            return {}
        parts = [part.strip() for part in lines[1].split("|")]
        if len(parts) < 5 or parts[0].upper() in {"NA", "AS"}:
            return {}
        as_name = parts[-1]
        return {
            "asn": parts[0],
            "bgp_prefix": parts[2],
            "asn_country": parts[3],
            "asn_org": as_name,
            "isp": as_name,
        }

    async def _rdap_ip(self, ip: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
            async with session.get(f"https://rdap.org/ip/{ip}") as resp:
                if resp.status != 200:
                    return {}
                raw = await resp.json()

        org = None
        for entity in raw.get("entities", []) or []:
            vcard = entity.get("vcardArray") or []
            if len(vcard) < 2:
                continue
            for item in vcard[1]:
                if item and item[0] in {"fn", "org"} and len(item) >= 4:
                    org = item[3]
                    break
            if org:
                break
        return {
            "name": raw.get("name"),
            "country_code": raw.get("country"),
            "country_name": raw.get("country"),
            "rdap_handle": raw.get("handle"),
            "network_start": raw.get("startAddress"),
            "network_end": raw.get("endAddress"),
            "registry_org": org,
        }

    def _classify_provider(self, text: str) -> Dict[str, Any]:
        lower = text.lower()
        provider = None
        is_cdn = False
        is_hosting = False
        if "cloudflare" in lower:
            provider, is_cdn, is_hosting = "cloudflare", True, True
        elif "akamai" in lower:
            provider, is_cdn, is_hosting = "akamai", True, True
        elif "fastly" in lower:
            provider, is_cdn, is_hosting = "fastly", True, True
        elif "amazon" in lower or "aws" in lower:
            provider, is_hosting = "aws", True
        elif "google" in lower:
            provider, is_hosting = "gcp", True
        elif "microsoft" in lower or "azure" in lower:
            provider, is_hosting = "azure", True
        elif "digitalocean" in lower:
            provider, is_hosting = "digitalocean", True
        return {"cloud_provider": provider, "is_cdn": is_cdn, "is_hosting": is_hosting}

    async def _persist_ip_baseline(self, db, asset_id: str, data: Dict[str, Any]) -> None:
        from workers.db_models import IPAddress

        values = {
            "asn": str(data.get("asn")) if data.get("asn") else None,
            "asn_org": data.get("asn_org") or data.get("registry_org") or data.get("name"),
            "asn_country": data.get("asn_country") or data.get("country_code"),
            "country_code": data.get("country_code") or data.get("asn_country"),
            "country_name": data.get("country_name") or data.get("country_code") or data.get("asn_country"),
            "isp": data.get("isp") or data.get("asn_org") or data.get("registry_org"),
            "cloud_provider": data.get("cloud_provider"),
            "is_cdn": bool(data.get("is_cdn", False)),
            "is_hosting": bool(data.get("is_hosting", False)),
            "last_seen": datetime.now(timezone.utc),
        }
        await db.execute(
            update(IPAddress)
            .where(IPAddress.asset_id == asset_id)
            .values(**{key: value for key, value in values.items() if value is not None})
        )

    async def _persist_intel(
        self,
        db,
        asset_id: str,
        org_id: str,
        source: str,
        indicator_type: str,
        data: Dict[str, Any],
        risk_score: int | None = None,
        is_malicious: bool = False,
        tags: List[str] | None = None,
        categories: List[str] | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        from workers.db_models import ThreatIntel

        now = datetime.now(timezone.utc)
        values = {
            "asset_id": asset_id,
            "org_id": org_id,
            "source": source,
            "indicator_type": indicator_type,
            "data": data or {},
            "risk_score": risk_score,
            "is_malicious": bool(is_malicious),
            "tags": tags or [],
            "categories": categories or [],
            "enriched_at": now,
            "expires_at": expires_at,
        }
        stmt = pg_insert(ThreatIntel.__table__).values(**values)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_intel_asset_source",
            set_={
                "data": values["data"],
                "risk_score": values["risk_score"],
                "is_malicious": values["is_malicious"],
                "tags": values["tags"],
                "categories": values["categories"],
                "enriched_at": values["enriched_at"],
                "expires_at": values["expires_at"],
            },
        )
        await db.execute(stmt)

    async def _mark_enrich_done(self, scan_id: str, org_id: str, workspace_id: str) -> None:
        from workers.task_coordinator import TaskCoordinator

        coord = TaskCoordinator()
        await coord.incr_enrich_done(scan_id)
        if await coord.mark_terminal_if_all_done(scan_id):
            queue = QueueClient()
            await queue.connect()
            try:
                await queue.publish(
                    routing_key="correlation.process",
                    message={
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "workspace_id": workspace_id,
                        "is_terminal": True,
                    },
                )
            finally:
                await queue.close()
            await coord.cleanup(scan_id)
        await coord.close()

    async def _update_scan_progress(self, db, scan_id: str) -> None:
        from sqlalchemy import func, update
        from workers.db_models import Scan

        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                completed_tasks=Scan.completed_tasks + 1,
                progress_pct=func.greatest(Scan.progress_pct, 65),
            )
        )
        await db.commit()


if __name__ == "__main__":
    worker = EnrichmentWorker()
    asyncio.run(worker.run())

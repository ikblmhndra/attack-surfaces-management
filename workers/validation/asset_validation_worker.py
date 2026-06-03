"""
ASM Platform — Asset Validation Worker
Periodically refreshes scope, ownership, liveness, and network evidence.
"""
import asyncio
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional
from uuid import UUID

import aiohttp
import structlog
from sqlalchemy import or_, select, update

from app.services.asset_validation import (
    apply_scope_controls,
    merge_rdap_evidence,
    validate_discovered_host,
)
from workers.base_worker import BaseWorker
from workers.db import get_session

log = structlog.get_logger()


class AssetValidationWorker(BaseWorker):
    QUEUE = "asset.validate"
    CONCURRENCY = int(os.getenv("VALIDATION_CONCURRENCY", "2"))
    PREFETCH_COUNT = int(os.getenv("VALIDATION_PREFETCH", "2"))

    async def process(self, message: Dict[str, Any]) -> None:
        from workers.db_models import Asset, IPAddress, Organization, Subdomain

        org_id = message.get("org_id")
        workspace_id = message.get("workspace_id")
        asset_ids = self._parse_asset_ids(message.get("asset_ids") or [])
        limit = max(1, min(int(message.get("limit", 200)), 1000))
        stale_hours = int(message.get("stale_hours") or os.getenv("VALIDATION_STALE_HOURS", "24"))
        cutoff = datetime.now(timezone.utc) - timedelta(hours=stale_hours)

        async with get_session() as db:
            query = (
                select(Asset, Organization, Subdomain, IPAddress)
                .join(Organization, Organization.id == Asset.org_id)
                .outerjoin(Subdomain, Subdomain.asset_id == Asset.id)
                .outerjoin(IPAddress, IPAddress.asset_id == Asset.id)
                .where(
                    Asset.deleted_at.is_(None),
                    Asset.status == "active",
                    Asset.asset_type.in_(["subdomain", "ip"]),
                    Organization.deleted_at.is_(None),
                )
                .limit(limit)
            )
            if org_id:
                query = query.where(Asset.org_id == org_id)
            if workspace_id:
                query = query.where(Asset.workspace_id == workspace_id)
            if asset_ids:
                query = query.where(Asset.id.in_(asset_ids))
            else:
                query = query.where(or_(Asset.last_verified_at.is_(None), Asset.last_verified_at < cutoff))

            rows = (await db.execute(query)).all()

        processed = 0
        failed = 0
        for asset, org, subdomain, ip_row in rows:
            try:
                await self._validate_asset(asset, org, subdomain, ip_row)
                processed += 1
            except Exception as exc:
                failed += 1
                log.warning(
                    "asset_validation_failed",
                    asset_id=str(asset.id),
                    value=asset.value,
                    error=str(exc),
                )

        log.info(
            "asset_validation_completed",
            org_id=str(org_id) if org_id else None,
            processed=processed,
            failed=failed,
        )

    async def _validate_asset(self, asset, org, subdomain=None, ip_row=None) -> None:
        now = datetime.now(timezone.utc)
        org_names = [org.name, org.company_name, *(org.domains or []), *(org.root_domains or [])]
        allow_patterns = org.scope_allow_patterns or []
        deny_patterns = org.scope_deny_patterns or []

        if asset.asset_type == "subdomain":
            validation = self._validate_subdomain(asset, org, subdomain)
            public_ips = [
                value for value in (subdomain.ip_addresses if subdomain else [])
                if self._is_public_ip(value)
            ]
            if public_ips:
                baseline = await self._network_baseline(public_ips[0])
                validation = merge_rdap_evidence(validation, rdap=baseline, org_names=org_names)
        elif asset.asset_type == "ip":
            validation = await self._validate_ip_asset(asset, org, ip_row)
            if ip_row:
                baseline = (validation.get("validation_sources") or {}).get("evidence", {}).get("rdap") or {}
                await self._persist_ip_baseline(asset.id, baseline)
        else:
            return

        validation = apply_scope_controls(
            validation,
            target=asset.value,
            allow_patterns=allow_patterns,
            deny_patterns=deny_patterns,
        )
        validation = self._apply_org_asn_match(validation, org.asns or [])
        validation = self._preserve_review_decision(asset, validation)
        validation["last_verified_at"] = now

        async with get_session() as db:
            await db.execute(
                update(type(asset))
                .where(type(asset).id == asset.id)
                .values(
                    is_in_scope=validation.get("is_in_scope", True),
                    scope_status=validation.get("scope_status", "needs_review"),
                    ownership_confidence=validation.get("ownership_confidence", 0.0),
                    ownership_reason=validation.get("ownership_reason"),
                    exposure_status=validation.get("exposure_status", "unknown"),
                    liveness_status=validation.get("liveness_status", "unknown"),
                    validation_sources=validation.get("validation_sources", {}),
                    last_verified_at=now,
                    review_status=validation.get("review_status", asset.review_status or "none"),
                )
            )
            await db.commit()

    def _validate_subdomain(self, asset, org, subdomain) -> Dict[str, Any]:
        dns_records = dict(subdomain.dns_records or {}) if subdomain else {}
        dns_info = {
            "a": (subdomain.ip_addresses or dns_records.get("a", [])) if subdomain else [],
            "aaaa": dns_records.get("aaaa", []),
            "cname": (subdomain.cname_chain or dns_records.get("cname", [])) if subdomain else [],
        }
        http_info = {
            "url": f"https://{asset.value}",
            "status_code": subdomain.http_status if subdomain else None,
            "status_class": self._status_class(subdomain.http_status if subdomain else None),
            "title": subdomain.http_title if subdomain else None,
            "webserver": subdomain.http_server if subdomain else None,
            "cdn_name": subdomain.cdn_provider if subdomain else None,
            "tls": (subdomain.tls_info or {}) if subdomain else {},
            "redirect_chain": (subdomain.redirect_chain or []) if subdomain else [],
        }
        return validate_discovered_host(
            host=asset.value,
            root_domains=(org.root_domains or []) + (org.domains or []),
            dns_info=dns_info,
            http_info=http_info,
        )

    async def _validate_ip_asset(self, asset, org, ip_row) -> Dict[str, Any]:
        open_ports = int(getattr(ip_row, "open_ports_count", 0) or 0)
        baseline = await self._network_baseline(asset.value)
        confidence = 0.45
        reasons = ["ip_asset_registered"]
        if baseline.get("found"):
            confidence = 0.6
            reasons.append("network_registry_observed")
        if open_ports > 0:
            reasons.append("open_ports_observed")

        validation = {
            "scope_status": "probable",
            "ownership_confidence": confidence,
            "ownership_reason": "IP asset has network registry evidence" if baseline else "IP asset requires ownership review",
            "exposure_status": "exposed" if open_ports > 0 else "not_exposed",
            "liveness_status": "alive" if open_ports > 0 else "unknown",
            "validation_sources": {
                "method": "asset_revalidation_ip_rdap_asn",
                "reasons": reasons,
                "evidence": {"rdap": baseline, "open_ports_count": open_ports},
                "validated_at": datetime.now(timezone.utc).isoformat(),
            },
            "is_in_scope": True,
            "confidence": confidence,
        }
        return merge_rdap_evidence(validation, rdap=baseline, org_names=[org.name, org.company_name])

    async def _network_baseline(self, ip: str) -> Dict[str, Any]:
        if not self._is_public_ip(ip):
            return {"ip": ip, "found": False, "is_private": True}

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
        return {key: value for key, value in data.items() if value not in (None, "", [])}

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
        return {
            "asn": parts[0],
            "bgp_prefix": parts[2],
            "asn_country": parts[3],
            "asn_org": parts[-1],
            "isp": parts[-1],
            "source": "team_cymru",
        }

    async def _rdap_ip(self, ip: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as session:
            async with session.get(f"https://rdap.org/ip/{ip}") as resp:
                if resp.status != 200:
                    return {}
                raw = await resp.json()

        registry_org = self._extract_rdap_org(raw)
        return {
            "network_name": raw.get("name"),
            "network_handle": raw.get("handle"),
            "country": raw.get("country"),
            "country_code": raw.get("country"),
            "network_start": raw.get("startAddress"),
            "network_end": raw.get("endAddress"),
            "registry_org": registry_org,
            "rdap_source": "rdap.org",
        }

    async def _persist_ip_baseline(self, asset_id: UUID, baseline: Dict[str, Any]) -> None:
        if not baseline:
            return
        from workers.db_models import IPAddress

        values = {
            "asn": str(baseline.get("asn")) if baseline.get("asn") else None,
            "asn_org": baseline.get("asn_org") or baseline.get("registry_org") or baseline.get("network_name"),
            "asn_country": baseline.get("asn_country") or baseline.get("country_code") or baseline.get("country"),
            "country_code": baseline.get("country_code") or baseline.get("country"),
            "country_name": baseline.get("country") or baseline.get("country_code"),
            "isp": baseline.get("isp") or baseline.get("asn_org") or baseline.get("registry_org"),
            "last_seen": datetime.now(timezone.utc),
        }
        async with get_session() as db:
            await db.execute(
                update(IPAddress)
                .where(IPAddress.asset_id == asset_id)
                .values(**{key: value for key, value in values.items() if value is not None})
            )
            await db.commit()

    def _parse_asset_ids(self, values: Iterable[Any]) -> list[UUID]:
        parsed = []
        for value in values:
            try:
                parsed.append(UUID(str(value)))
            except (TypeError, ValueError):
                log.warning("asset_validation_invalid_asset_id", value=str(value))
        return parsed

    def _preserve_review_decision(self, asset, validation: Dict[str, Any]) -> Dict[str, Any]:
        updated = dict(validation or {})
        review_status = asset.review_status or "none"
        sources = dict(updated.get("validation_sources") or {})
        reasons = list(sources.get("reasons") or [])

        if review_status == "approved":
            updated["scope_status"] = "in_scope"
            updated["is_in_scope"] = True
            updated["review_status"] = "approved"
            updated["ownership_confidence"] = max(float(updated.get("ownership_confidence") or 0), 0.9)
            updated["ownership_reason"] = "approved by analyst"
            reasons.append("analyst_approved_scope")
        elif review_status == "rejected":
            updated["scope_status"] = "out_of_scope"
            updated["is_in_scope"] = False
            updated["review_status"] = "rejected"
            updated["ownership_confidence"] = min(float(updated.get("ownership_confidence") or 0), 0.2)
            updated["ownership_reason"] = "rejected by analyst"
            reasons.append("analyst_rejected_scope")
        elif updated.get("scope_status") == "needs_review":
            updated["review_status"] = "pending"
        elif updated.get("scope_status") == "out_of_scope":
            updated["review_status"] = "rejected" if sources.get("matched_deny_pattern") else "pending"
        else:
            updated["review_status"] = "none"

        sources["reasons"] = list(dict.fromkeys(reasons))
        updated["validation_sources"] = sources
        return updated

    def _apply_org_asn_match(self, validation: Dict[str, Any], org_asns: Iterable[str]) -> Dict[str, Any]:
        normalized_org_asns = {str(asn).upper().replace("AS", "").strip() for asn in org_asns if asn}
        if not normalized_org_asns:
            return validation
        sources = dict((validation or {}).get("validation_sources") or {})
        rdap = dict((sources.get("evidence") or {}).get("rdap") or {})
        observed = str(rdap.get("asn") or "").upper().replace("AS", "").strip()
        if not observed or observed not in normalized_org_asns:
            return validation

        updated = dict(validation)
        reasons = list(sources.get("reasons") or [])
        reasons.append("asn_matches_registered_scope")
        sources["reasons"] = list(dict.fromkeys(reasons))
        updated["validation_sources"] = sources
        updated["scope_status"] = "in_scope"
        updated["is_in_scope"] = True
        updated["ownership_confidence"] = max(float(updated.get("ownership_confidence") or 0), 0.9)
        updated["ownership_reason"] = "ASN matched registered organization scope"
        return updated

    def _extract_rdap_org(self, raw: Dict[str, Any]) -> Optional[str]:
        for entity in raw.get("entities", []) or []:
            vcard = entity.get("vcardArray") or []
            if len(vcard) < 2:
                continue
            for item in vcard[1]:
                if item and item[0] in {"fn", "org"} and len(item) >= 4:
                    return item[3]
        return None

    def _status_class(self, status_code: Optional[int]) -> str:
        if status_code is None:
            return "probe_failed"
        if 200 <= int(status_code) < 300:
            return "ok"
        if 300 <= int(status_code) < 400:
            return "redirect"
        if int(status_code) in {401, 403}:
            return "auth_required"
        if int(status_code) == 404:
            return "not_found"
        if int(status_code) == 429:
            return "rate_limited"
        if int(status_code) >= 500:
            return "server_error"
        return "other"

    def _is_public_ip(self, value: str) -> bool:
        try:
            parsed = ipaddress.ip_address(value)
            return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local)
        except ValueError:
            return False


if __name__ == "__main__":
    worker = AssetValidationWorker()
    asyncio.run(worker.run())

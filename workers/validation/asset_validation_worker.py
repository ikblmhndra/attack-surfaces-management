"""
ASM Platform — Asset Validation Worker
Periodically refreshes scope, ownership, liveness, and network evidence.
"""
import asyncio
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import UUID

import aiohttp
import structlog
from sqlalchemy import func, or_, select, update

from app.services.asset_validation import (
    apply_scope_controls,
    merge_rdap_evidence,
    validate_discovered_host,
)
from workers.base_worker import BaseWorker
from workers.db import get_session
from workers.scanner.discovery_worker import tool_path

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

        # Real re-probe, not just a re-score of stale cached fields: batch all
        # subdomain hostnames in this cycle through one dnsx + one httpx pass
        # (same tool/pattern as discovery_worker.py's _run_dnsx/_probe_http,
        # kept as an independent, slimmed-down copy here rather than shared,
        # so this worker's probing can't regress the far-more-heavily-used
        # discovery pipeline). A tool failure/timeout for a given host simply
        # means that host is missing from these dicts -- _validate_subdomain
        # falls back to the existing stale columns for it rather than wrongly
        # demoting a genuinely-alive asset from a transient probe hiccup.
        subdomain_hosts = [
            asset.value for asset, _org, _subdomain, _ip_row in rows
            if asset.asset_type == "subdomain"
        ]
        fresh_dns: Dict[str, Dict[str, Any]] = {}
        fresh_http: Dict[str, Dict[str, Any]] = {}
        if subdomain_hosts:
            with tempfile.TemporaryDirectory(prefix="asm-revalidate-") as tmpdir_str:
                tmpdir = Path(tmpdir_str)
                fresh_dns, fresh_http = await asyncio.gather(
                    self._resolve_dns_batch(subdomain_hosts, tmpdir),
                    self._probe_http_batch(subdomain_hosts, tmpdir),
                )

        dup_counts: Dict[str, int] = {}
        hashes = list({data["hash"] for data in fresh_http.values() if data.get("hash")})
        if hashes:
            async with get_session() as db:
                dup_counts = await self._duplicate_hash_counts(db, hashes)

        processed = 0
        failed = 0
        for asset, org, subdomain, ip_row in rows:
            try:
                http_for_host = fresh_http.get(asset.value)
                duplicate_hash_count = dup_counts.get(http_for_host["hash"], 0) if http_for_host and http_for_host.get("hash") else 0
                await self._validate_asset(
                    asset, org, subdomain, ip_row,
                    fresh_dns=fresh_dns.get(asset.value),
                    fresh_http=http_for_host,
                    duplicate_hash_count=duplicate_hash_count,
                )
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
            reprobed_hosts=len(subdomain_hosts),
        )

    async def _resolve_dns_batch(self, hosts: List[str], tmpdir: Path) -> Dict[str, Dict[str, Any]]:
        """Batched dnsx re-resolution for re-validation -- a-record/cname only,
        no mx/txt/ns (kept lean; those aren't used by validate_discovered_host
        and this worker doesn't touch Subdomain.dns_records to avoid clobbering
        the fuller record set a real discovery scan already collected)."""
        dnsx_path = tool_path("dnsx")
        if not hosts or not dnsx_path:
            return {}

        input_file = tmpdir / "revalidate_hosts.txt"
        input_file.write_text("\n".join(hosts))
        output_file = tmpdir / "revalidate_dnsx.json"

        cmd = [
            dnsx_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-a", "-aaaa", "-cname",
            "-silent",
            "-t", "100",
            "-retry", "3",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            log.warning("revalidation_dnsx_timeout", hosts=len(hosts))
        except Exception as e:
            log.error("revalidation_dnsx_error", error=str(e))

        resolved: Dict[str, Dict[str, Any]] = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = data.get("host", "")
                if host:
                    resolved[host] = {
                        "a": data.get("a", []),
                        "aaaa": data.get("aaaa", []),
                        "cname": data.get("cname", []),
                    }
        return resolved

    async def _probe_http_batch(self, hosts: List[str], tmpdir: Path) -> Dict[str, Dict[str, Any]]:
        """Batched httpx re-probe for re-validation -- a smaller flag set than
        discovery_worker.py's own _probe_http (no tech-detect/cpe/jarm/favicon/
        cdn/asn/websocket/pipeline/http2): this is a liveness/content recheck,
        not a fresh discovery run."""
        httpx_path = tool_path("httpx")
        if not hosts or not httpx_path:
            return {}

        input_file = tmpdir / "revalidate_probe.txt"
        input_file.write_text("\n".join(hosts))
        output_file = tmpdir / "revalidate_httpx.json"

        cmd = [
            httpx_path,
            "-l", str(input_file),
            "-json",
            "-o", str(output_file),
            "-silent",
            "-follow-redirects",
            "-max-redirects", "5",
            "-title",
            "-web-server",
            "-status-code",
            "-tls-grab",
            "-content-length",
            "-hash", "sha256",
            "-location",
            "-t", "50",
            "-rl", "150",
            "-timeout", "10",
            "-no-color",
            "-duc",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            log.warning("revalidation_httpx_timeout", hosts=len(hosts))
        except Exception as e:
            log.error("revalidation_httpx_error", error=str(e))

        probed: Dict[str, Dict[str, Any]] = {}
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if data.get("failed"):
                    continue
                url = data.get("url", "")
                host = data.get("host") or (url.split("//")[-1].split("/")[0] if "//" in url else url)
                if not host:
                    continue
                hash_data = data.get("hash") or {}
                body_hash = hash_data.get("body_sha256", "") if isinstance(hash_data, dict) else str(hash_data)
                probed[host] = {
                    "url": url,
                    "status_code": data.get("status_code"),
                    "status_class": self._status_class(data.get("status_code")),
                    "title": data.get("title", ""),
                    "webserver": data.get("webserver", ""),
                    "content_length": data.get("content_length"),
                    "hash": body_hash,
                    "tls": data.get("tls", {}),
                    "redirect_chain": [r.get("url") for r in data.get("chain", [])],
                }
        return probed

    async def _duplicate_hash_counts(self, db, hashes: List[str]) -> Dict[str, int]:
        """How many Subdomain rows platform-wide already carry each of these
        response hashes -- the signal classify_liveness_content() uses to spot
        a shared default/placeholder page. Batched into one query rather than
        one per host."""
        from workers.db_models import Subdomain

        result = await db.execute(
            select(Subdomain.response_hash, func.count(Subdomain.id))
            .where(Subdomain.response_hash.in_(hashes))
            .group_by(Subdomain.response_hash)
        )
        return {row[0]: row[1] for row in result.all() if row[0]}

    async def _validate_asset(
        self, asset, org, subdomain=None, ip_row=None,
        fresh_dns: Optional[Dict[str, Any]] = None,
        fresh_http: Optional[Dict[str, Any]] = None,
        duplicate_hash_count: int = 0,
    ) -> None:
        now = datetime.now(timezone.utc)
        org_names = [org.name, org.company_name, *(org.domains or []), *(org.root_domains or [])]
        allow_patterns = org.scope_allow_patterns or []
        deny_patterns = org.scope_deny_patterns or []

        if asset.asset_type == "subdomain":
            validation = self._validate_subdomain(
                asset, org, subdomain,
                fresh_dns=fresh_dns, fresh_http=fresh_http,
                duplicate_hash_count=duplicate_hash_count,
            )
            ips_for_ownership = (fresh_dns or {}).get("a", []) or (subdomain.ip_addresses if subdomain else [])
            public_ips = [value for value in ips_for_ownership if self._is_public_ip(value)]
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
            # Refresh the cached Subdomain columns too, not just the derived
            # validation score -- otherwise every other page/feature reading
            # these columns directly stays stuck on the pre-revalidation
            # snapshot even though the score itself is now current.
            # dns_records (mx/txt/ns) is deliberately left untouched -- this
            # worker only re-fetches a/aaaa/cname, and overwriting it with an
            # incomplete snapshot would clobber a real discovery scan's fuller
            # record set.
            if asset.asset_type == "subdomain" and subdomain and fresh_http is not None:
                from workers.db_models import Subdomain

                await db.execute(
                    update(Subdomain)
                    .where(Subdomain.id == subdomain.id)
                    .values(
                        ip_addresses=(fresh_dns or {}).get("a", []) + (fresh_dns or {}).get("aaaa", []),
                        cname_chain=(fresh_dns or {}).get("cname", []),
                        http_status=fresh_http.get("status_code"),
                        http_title=(fresh_http.get("title") or "")[:500],
                        http_server=(fresh_http.get("webserver") or "")[:255],
                        content_length=fresh_http.get("content_length"),
                        response_hash=(fresh_http.get("hash") or "")[:64],
                        tls_info=fresh_http.get("tls") or None,
                        redirect_chain=fresh_http.get("redirect_chain") or [],
                        last_probed=now,
                    )
                )
            await db.commit()

    def _validate_subdomain(
        self, asset, org, subdomain,
        fresh_dns: Optional[Dict[str, Any]] = None,
        fresh_http: Optional[Dict[str, Any]] = None,
        duplicate_hash_count: int = 0,
    ) -> Dict[str, Any]:
        dns_records = dict(subdomain.dns_records or {}) if subdomain else {}
        if fresh_dns is not None:
            dns_info = {
                "a": fresh_dns.get("a", []),
                "aaaa": fresh_dns.get("aaaa", []),
                "cname": fresh_dns.get("cname", []),
            }
        else:
            dns_info = {
                "a": (subdomain.ip_addresses or dns_records.get("a", [])) if subdomain else [],
                "aaaa": dns_records.get("aaaa", []),
                "cname": (subdomain.cname_chain or dns_records.get("cname", [])) if subdomain else [],
            }

        if fresh_http is not None:
            http_info = {
                "url": fresh_http.get("url") or f"https://{asset.value}",
                "status_code": fresh_http.get("status_code"),
                "status_class": fresh_http.get("status_class"),
                "title": fresh_http.get("title"),
                "webserver": fresh_http.get("webserver"),
                "cdn_name": subdomain.cdn_provider if subdomain else None,
                "tls": fresh_http.get("tls") or {},
                "redirect_chain": fresh_http.get("redirect_chain") or [],
            }
        else:
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
        http_info["duplicate_hash_count"] = duplicate_hash_count

        return validate_discovered_host(
            host=asset.value,
            root_domains=(org.root_domains or []) + (org.domains or []),
            dns_info=dns_info,
            http_info=http_info,
        )

    async def _validate_ip_asset(self, asset, org, ip_row) -> Dict[str, Any]:
        open_ports = int(getattr(ip_row, "open_ports_count", 0) or 0)
        async with get_session() as db:
            liveness_status, reachable_count, checked_count = await self._check_ip_liveness(db, asset.value, ip_row)
        baseline = await self._network_baseline(asset.value)
        confidence = 0.45
        reasons = ["ip_asset_registered"]
        if baseline.get("found"):
            confidence = 0.6
            reasons.append("network_registry_observed")
        if reachable_count > 0:
            reasons.append("tcp_port_reachable")
            confidence = max(confidence, 0.6)
        elif checked_count > 0:
            reasons.append("previously_open_ports_now_unreachable")
        elif open_ports > 0:
            # No Port rows to recheck against yet (open_ports_count set by a
            # port scan that predates this worker's Port-row-based recheck) --
            # don't downgrade liveness on a signal we simply can't verify yet.
            reasons.append("open_ports_observed")
            liveness_status = "alive"

        # is_cdn/is_hosting/cloud_provider are already computed and persisted
        # by enrichment_worker.py::_classify_provider -- previously never read
        # by any validation/scoring logic. Only is_cdn (Cloudflare/Akamai/
        # Fastly -- genuinely shared anycast edges) down-weights confidence;
        # is_hosting alone (AWS/GCP/Azure/DigitalOcean) doesn't, since a
        # dedicated cloud VM IP is still reasonably exclusive to whoever's
        # running that instance, unlike a CDN edge shared across thousands of
        # unrelated customers.
        is_cdn = bool(getattr(ip_row, "is_cdn", False))
        is_hosting = bool(getattr(ip_row, "is_hosting", False))
        cloud_provider = getattr(ip_row, "cloud_provider", None)
        ownership_reason = "IP asset has network registry evidence" if baseline.get("found") else "IP asset requires ownership review"
        if is_cdn:
            reasons.append("shared_cdn_provider_ip")
            ownership_reason = f"IP belongs to a shared CDN provider ({cloud_provider or 'unknown'}) -- ownership is not exclusive"

        validation = {
            "scope_status": "probable",
            "ownership_confidence": confidence,
            "ownership_reason": ownership_reason,
            "exposure_status": "exposed" if (reachable_count > 0 or (checked_count == 0 and open_ports > 0)) else "not_exposed",
            "liveness_status": liveness_status,
            "validation_sources": {
                "method": "asset_revalidation_ip_rdap_asn_tcp",
                "reasons": reasons,
                "evidence": {
                    "rdap": baseline,
                    "open_ports_count": open_ports,
                    "tcp_reachable_ports": reachable_count,
                    "tcp_ports_checked": checked_count,
                    "is_cdn": is_cdn,
                    "is_hosting": is_hosting,
                    "cloud_provider": cloud_provider,
                },
                "validated_at": datetime.now(timezone.utc).isoformat(),
            },
            "is_in_scope": True,
            "confidence": confidence,
        }
        validation = merge_rdap_evidence(validation, rdap=baseline, org_names=[org.name, org.company_name])
        if is_cdn:
            # Applied *after* merge_rdap_evidence, not before: that helper
            # raises ownership_confidence to >=0.55 whenever *any* ASN/
            # registry data exists (true of nearly every real IP, CDN or
            # not) -- a shared anycast edge's confidence must not get
            # re-inflated by that generic bump.
            validation["ownership_confidence"] = min(float(validation.get("ownership_confidence") or 0), 0.35)
            validation["confidence"] = validation["ownership_confidence"]
            validation["ownership_reason"] = ownership_reason
        return validation

    async def _check_ip_liveness(self, db, ip: str, ip_row) -> tuple[str, int, int]:
        """Bounded, real TCP connectivity recheck against up to 5 previously-
        recorded open ports for this IP -- not a full naabu rescan (that's the
        port-scanning pipeline's job), just enough of a live check that
        "alive" stops being purely inherited from open_ports_count, a field
        this worker never updates. Returns (liveness_status, reachable_count,
        checked_count)."""
        from workers.db_models import Port

        if not ip_row:
            return "unknown", 0, 0

        result = await db.execute(
            select(Port.port_number)
            .where(Port.ip_id == ip_row.id, Port.state == "open")
            .limit(5)
        )
        ports = [row[0] for row in result.all()]
        if not ports:
            return "unknown", 0, 0

        async def _try_connect(port: int) -> bool:
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=3,
                )
            except Exception:
                return False
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True

        results = await asyncio.gather(*(_try_connect(p) for p in ports))
        reachable = sum(1 for ok in results if ok)
        return ("alive" if reachable > 0 else "unresolved"), reachable, len(ports)

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

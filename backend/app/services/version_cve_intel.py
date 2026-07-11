"""
ASM Platform — Version-to-CVE Correlation (cve.circl.lu)

Keyless, publicly-published product/version CVE data (CIRCL's CVE Search,
backed by NVD/CVE Program records). Cross-references already-detected
Technology rows (name + version) against known CVE affected-version ranges to
catch vulnerabilities nuclei has no template for at all — a materially
different, broader gap than the confidence-scored CVE matching nuclei_worker.py
already does for its *own* template hits (risk_engine.py::FindingInput.confidence,
Milestone 7's A2).

This is inherently the least certain signal in the platform: a version falling
inside a CVE's published affected range is not proof of exploitability (the
vendor may have backported a fix without bumping the version, the feature may
not be reachable, etc.) — every finding this produces is explicitly framed as
"potential" in its title/description and carries a low `confidence_score` in
its `proof` (already-existing risk_engine.py mechanism, not a new one) so it
measurably dampens the risk-score impact rather than being trusted at face
value like a real nuclei template match.

Different refresh model from eol_intel.py's fetch-once-forever: a product's
CVE list genuinely grows over time (unlike a fixed EOL date), so a cached
product entry is refreshed if older than CACHE_MAX_AGE_DAYS, not held forever.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

log = structlog.get_logger()

CIRCL_SEARCH_URL = "https://cve.circl.lu/api/search/{vendor}/{product}"
MAX_PAGES_PER_PRODUCT = 2  # ~20 most recent CVEs — bounded; recent CVEs are
                            # what a nuclei-template gap is most likely to be,
                            # not a product's full multi-hundred-CVE history.
CACHE_MAX_AGE_DAYS = 7

# Technology.name (lowercased) -> (vendor, product) for cve.circl.lu's URL path.
# Deliberately narrow: only products this platform has actually detected with
# real version data, not an attempt to cover every product in the CVE corpus.
PRODUCT_VENDOR_MAP: Dict[str, Tuple[str, str]] = {
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "nginx": ("nginx", "nginx"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "tomcat": ("apache", "tomcat"),
    "apache tomcat": ("apache", "tomcat"),
    "jenkins": ("jenkins", "jenkins"),
    "grafana": ("grafana", "grafana"),
    "elasticsearch": ("elastic", "elasticsearch"),
}

# Low, fixed confidence for every version-inferred finding — this is a
# structurally weaker signal than even nuclei's own "low" CVE-confidence tier
# (0.5, see nuclei_worker.py::_cve_confidence), since there's no template
# match/response confirmation of any kind, purely a version-range comparison.
VERSION_MATCH_CONFIDENCE = 0.3


def resolve_vendor_product(tech_name: str) -> Optional[Tuple[str, str]]:
    if not tech_name:
        return None
    return PRODUCT_VENDOR_MAP.get(tech_name.strip().lower())


def _parse_version_tuple(version: str) -> Optional[Tuple[int, ...]]:
    """Best-effort numeric version parse for comparison — "2.4.49" -> (2,4,49).
    Returns None for versions with no leading numeric component at all."""
    match = re.match(r"^(\d+(?:\.\d+)*)", version.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b — pads the shorter tuple with zeros so
    (2, 4) compares equal to (2, 4, 0)."""
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def version_in_range(version: str, version_spec: Dict[str, Any]) -> bool:
    """Check a detected version against one CIRCL "versions[]" entry, e.g.
    {"version": "2.4.17", "lessThanOrEqual": "2.4.67", "status": "affected"}.
    Only "affected" entries are ever checked (an "unaffected" entry describes
    versions *outside* the vulnerable range, not a green light)."""
    if version_spec.get("status") != "affected":
        return False
    target = _parse_version_tuple(version)
    if target is None:
        return False

    floor = _parse_version_tuple(str(version_spec.get("version", "")))
    if floor is not None and _compare_versions(target, floor) < 0:
        return False

    less_than = version_spec.get("lessThan")
    if less_than is not None:
        bound = _parse_version_tuple(str(less_than))
        if bound is not None and _compare_versions(target, bound) >= 0:
            return False

    less_than_eq = version_spec.get("lessThanOrEqual")
    if less_than_eq is not None:
        bound = _parse_version_tuple(str(less_than_eq))
        if bound is not None and _compare_versions(target, bound) > 0:
            return False

    return True


def _extract_cvss(record: Dict[str, Any]) -> Optional[float]:
    """CVSS commonly lives in containers.adp[].metrics[], not containers.cna
    — verified against real cve.circl.lu records before relying on this path
    (the CNA's own metrics were empty; ADP — an NVD-side "additional data
    provider" — carried the actual score)."""
    containers = record.get("containers", {}) if isinstance(record, dict) else {}
    for adp in containers.get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            for key, value in metric.items():
                if key.lower().startswith("cvssv") and isinstance(value, dict):
                    score = value.get("baseScore")
                    if isinstance(score, (int, float)):
                        return float(score)
    return None


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_record(cve_id: str, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    containers = record.get("containers", {}) if isinstance(record, dict) else {}
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    affected = cna.get("affected", []) if isinstance(cna, dict) else []
    versions: List[Dict[str, Any]] = []
    for item in affected:
        for v in item.get("versions", []) or []:
            if isinstance(v, dict):
                versions.append(v)
    if not versions:
        return None

    descriptions = cna.get("descriptions", []) if isinstance(cna, dict) else []
    description = ""
    for d in descriptions:
        if isinstance(d, dict) and d.get("value"):
            description = str(d["value"])[:1000]
            break

    return {
        "cve_id": str(cve_id).upper(),
        "description": description,
        "cvss_score": _extract_cvss(record),
        "versions": versions,
    }


async def _fetch_product_cves(vendor: str, product: str) -> List[Dict[str, Any]]:
    cves: List[Dict[str, Any]] = []
    async with aiohttp.ClientSession() as session:
        for page in range(1, MAX_PAGES_PER_PRODUCT + 1):
            url = CIRCL_SEARCH_URL.format(vendor=vendor, product=product)
            try:
                async with session.get(
                    url, params={"page": page}, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 404:
                        break
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
            except Exception as exc:
                log.warning("version_cve_fetch_failed", vendor=vendor, product=product, page=page, error=str(exc)[:300])
                break

            results = (data.get("results") or {}).get("nvd") or []
            if not results:
                break
            for entry in results:
                if not isinstance(entry, list) or len(entry) != 2:
                    continue
                parsed = _extract_record(entry[0], entry[1])
                if parsed:
                    cves.append(parsed)
            if len(results) < 10:
                break
    return cves


async def _cache_product(db, product_key: str, vendor: str, product: str) -> List[Dict[str, Any]]:
    from app.db.models.models import VersionCveCache

    cves = await _fetch_product_cves(vendor, product)
    now = datetime.now(timezone.utc)
    stmt = pg_insert(VersionCveCache.__table__).values(
        id=uuid.uuid4(), product=product_key, cves=cves, cached_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["product"],
        set_={"cves": stmt.excluded.cves, "cached_at": stmt.excluded.cached_at},
    )
    await db.execute(stmt)
    await db.commit()
    log.info("version_cve_cached", product=product_key, cves=len(cves))
    return cves


async def get_matching_cves(db, tech_name: str, version: str) -> List[Dict[str, Any]]:
    """Cache-first (refreshed if stale) lookup of CVEs whose affected-version
    range actually includes this detected version. Returns [] if the product
    isn't mapped, has no cached/fetchable data, or no cached CVE's range
    actually covers this version."""
    from app.db.models.models import VersionCveCache

    if not version:
        return []
    mapping = resolve_vendor_product(tech_name)
    if not mapping:
        return []
    vendor, product = mapping
    product_key = f"{vendor}/{product}"

    result = await db.execute(select(VersionCveCache).where(VersionCveCache.product == product_key))
    row = result.scalar_one_or_none()

    stale = row is None or (
        datetime.now(timezone.utc) - row.cached_at.replace(tzinfo=timezone.utc)
        > timedelta(days=CACHE_MAX_AGE_DAYS)
    )
    if stale:
        cves = await _cache_product(db, product_key, vendor, product)
    else:
        cves = row.cves or []

    matches = []
    for cve in cves:
        if any(version_in_range(version, spec) for spec in cve.get("versions", [])):
            matches.append(cve)
    return matches

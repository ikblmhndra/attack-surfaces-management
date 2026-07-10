"""
ASM Platform — End-of-Life Intelligence (endoflife.date)

Keyless, publicly-published end-of-life data per product cycle. Cross-references
already-detected Technology rows (name + version) against real EOL dates so the
existing (previously unused) `eol_software` risk_engine.py scoring category
actually gets fed real signal.

Different refresh model from exploit_intel.py's EPSS (which shifts daily): a
cycle's EOL date is fixed once a product publishes it, so there's no scheduled
bulk refresh — a product's cycle list is fetched from endoflife.date exactly
once (the first time any of its cycles is looked up) and cached in `eol_intel`
forever. This keeps the platform's no-key-enrichment posture (see CLAUDE.md)
while still being materially useful: real, aged-out software (an unpatched
OpenSSL 1.0.2, an EOL WordPress) is a genuine, non-speculative security signal.
"""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

log = structlog.get_logger()

ENDOFLIFE_API = "https://endoflife.date/api/{product}.json"

# Technology.name (as detected by httpx/nuclei tech-detect) -> endoflife.date
# product slug. Only products we've actually seen detected, or are common
# enough to be worth covering pre-emptively — not an attempt to cover
# endoflife.date's full catalog (400+ products).
PRODUCT_SLUG_MAP: Dict[str, str] = {
    "php": "php",
    "openssl": "openssl",
    "nginx": "nginx",
    "apache http server": "apache-http-server",
    "apache": "apache-http-server",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "centos": "centos",
    "ubuntu": "ubuntu",
    "laravel": "laravel",
    "windows server": "windows-server",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "mongodb": "mongodb",
    "redis": "redis",
    "django": "django",
    "ruby on rails": "rails",
    "rails": "rails",
    "python": "python",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "grafana": "grafana",
    "elasticsearch": "elasticsearch",
    "jenkins": "jenkins",
    "docker": "docker-engine",
    "joomla": "joomla",
    "magento": "magento",
    "moodle": "moodle",
}


def resolve_product_slug(tech_name: str) -> Optional[str]:
    """Map a detected Technology.name to an endoflife.date product slug."""
    if not tech_name:
        return None
    return PRODUCT_SLUG_MAP.get(tech_name.strip().lower())


def _default_cycle(version: str) -> str:
    """major.minor, taken from the first two dot-separated numeric components
    (endoflife.date's convention for most products: php "7.4.33" -> "7.4",
    nginx "1.24.0" -> "1.24", apache-http-server "2.4.62" -> "2.4"). Falls
    back to whatever numeric prefix is available for version strings with
    fewer than two components (e.g. drupal "7" -> "7")."""
    parts = re.split(r"[.\-]", version.strip())
    numeric_parts: List[str] = []
    for part in parts:
        match = re.match(r"^(\d+)", part)
        if not match:
            break
        numeric_parts.append(match.group(1))
        if len(numeric_parts) >= 2:
            break
    return ".".join(numeric_parts) if numeric_parts else version.strip()


def _openssl_cycle(version: str) -> str:
    """OpenSSL's own cycle convention differs by era: 1.0.x/1.1.x track a full
    major.minor.patch cycle (patch-letter suffix stripped: "1.0.2k" -> "1.0.2",
    "1.1.1p" -> "1.1.1"), but 3.x tracks major.minor only ("3.5.7" -> "3.5") —
    verified against the real endoflife.date/api/openssl.json response."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version.strip())
    if not match:
        return _default_cycle(version)
    major, minor, patch = match.groups()
    if major == "1":
        return f"{major}.{minor}.{patch}"
    return f"{major}.{minor}"


PRODUCT_CYCLE_RULES: Dict[str, Callable[[str], str]] = {
    "openssl": _openssl_cycle,
}


def normalize_cycle(product_slug: str, version: str) -> str:
    rule = PRODUCT_CYCLE_RULES.get(product_slug, _default_cycle)
    return rule(version)


def _is_past(d: Optional[date]) -> bool:
    return d is not None and d <= datetime.now(timezone.utc).date()


def _parse_eol_date(eol: Any) -> Optional[date]:
    """endoflife.date's `eol` field is either the boolean `false` (not EOL yet)
    or an ISO date string (EOL'd on that date) — two different JSON types for
    the same field, confirmed against real API responses."""
    if not eol or eol is True:
        return None
    try:
        return datetime.strptime(str(eol)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


async def _fetch_product_cycles(product_slug: str) -> List[Dict[str, Any]]:
    url = ENDOFLIFE_API.format(product=product_slug)
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 404:
                return []
            resp.raise_for_status()
            data = await resp.json(content_type=None)
    return data if isinstance(data, list) else []


async def _cache_product_cycles(db, product_slug: str) -> None:
    """Fetch a product's full cycle list from endoflife.date once and cache
    every cycle row — a single API call covers the product's entire history,
    so there's no reason to fetch per-cycle."""
    from app.db.models.models import EolIntel

    try:
        cycles = await _fetch_product_cycles(product_slug)
    except Exception as exc:
        log.warning("eol_intel_fetch_failed", product=product_slug, error=str(exc)[:300])
        return

    if not cycles:
        return

    now = datetime.now(timezone.utc)
    rows = []
    for row in cycles:
        if row.get("cycle") is None:
            continue
        eol_date = _parse_eol_date(row.get("eol"))
        rows.append({
            "id": uuid.uuid4(),
            "product": product_slug,
            "cycle": str(row.get("cycle")),
            "eol_date": eol_date,
            "is_eol": _is_past(eol_date),
            "latest_version": row.get("latest"),
            "checked_at": now,
        })
    if not rows:
        return

    stmt = pg_insert(EolIntel.__table__).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["product", "cycle"],
        set_={
            "eol_date": stmt.excluded.eol_date,
            "is_eol": stmt.excluded.is_eol,
            "latest_version": stmt.excluded.latest_version,
            "checked_at": stmt.excluded.checked_at,
        },
    )
    await db.execute(stmt)
    await db.commit()
    log.info("eol_intel_product_cached", product=product_slug, cycles=len(rows))


async def get_eol_status(db, tech_name: str, version: str) -> Optional[Dict[str, Any]]:
    """Cache-first EOL lookup for a detected Technology (name, version). Returns
    None if the product isn't mapped to a known slug, the version can't be
    parsed into a cycle, or endoflife.date has no data for that cycle.
    Returns {"product": ..., "cycle": ..., "is_eol": bool, "eol_date": date|None,
    "latest_version": str|None} otherwise.
    """
    from app.db.models.models import EolIntel

    if not version:
        return None
    product_slug = resolve_product_slug(tech_name)
    if not product_slug:
        return None
    cycle = normalize_cycle(product_slug, version)

    result = await db.execute(
        select(EolIntel).where(EolIntel.product == product_slug, EolIntel.cycle == cycle)
    )
    row = result.scalar_one_or_none()

    if row is None:
        # Cache miss for this cycle — but we may already have *other* cycles
        # of this product cached (i.e. genuinely no data for this specific
        # cycle) vs. never having fetched this product at all. Only hit the
        # network in the latter case.
        any_cached = await db.execute(
            select(EolIntel.id).where(EolIntel.product == product_slug).limit(1)
        )
        if any_cached.scalar_one_or_none() is None:
            await _cache_product_cycles(db, product_slug)
            result = await db.execute(
                select(EolIntel).where(EolIntel.product == product_slug, EolIntel.cycle == cycle)
            )
            row = result.scalar_one_or_none()

    if row is None:
        return None

    # Recompute from eol_date rather than trusting the stored is_eol column:
    # a cycle cached while its eol_date was still in the future (e.g. PHP 8.3,
    # eol 2027-12-31) must correctly flip to EOL once that date passes, even
    # though this product's cycle list is never re-fetched (fetch-once design
    # — see module docstring). The stored column is kept for direct-SQL/
    # reporting convenience only, not treated as the source of truth here.
    return {
        "product": row.product,
        "cycle": row.cycle,
        "is_eol": _is_past(row.eol_date),
        "eol_date": row.eol_date,
        "latest_version": row.latest_version,
    }

"""
ASM Platform — Bug Bounty Recon Worker
Modules 1-4: subdomain enumeration, URL collection, JS analysis, path/endpoint
discovery. Populates BountyAsset only -- a suggestion list a human reviews and
explicitly promotes to BountyTarget. Never touches BountyTarget itself:
discovery silently expanding what's testable is the exact failure mode this
pipeline's schema separation exists to prevent. See CHANGELOG.md.
"""
import asyncio
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.bounty_scope import is_target_in_scope
from workers.bounty.bounty_stage import BountyStageWorker
from workers.bounty.browser_crawl import browser_crawl
from workers.bounty.tools import (
    analyze_js_file,
    discover_js_files,
    in_domain,
    login_and_get_session,
    normalize_host,
    run_assetfinder,
    run_crtsh,
    run_dnsx,
    run_ffuf,
    run_gau,
    run_httpx,
    run_katana,
    run_subfinder,
    run_waybackurls,
)
from workers.bounty.recon_ext import (
    classify_url,
    run_alterx,
    run_hackertarget,
    run_hakrawler,
    run_rapiddns,
    run_uro,
    run_urlscan_subs,
    run_waymore,
)
from workers.bounty.detect import (
    discover_api_specs,
    graphql_introspection,
    run_feroxbuster,
)
from workers.db import get_session
from workers.db_models import BountyAsset, BountyProgram, BountyTarget
from workers.fuzz_wordlist import resolve_fuzz_wordlist

log = structlog.get_logger()

# Bounds to keep a single recon run finite regardless of how wide a
# program's scope is -- these are recon budgets, not scope restrictions.
MAX_DOMAINS_PER_RUN = 10
# Domains within one recon run used to process strictly sequentially -- a
# real 10-domain program could take 1.5h+ wall-clock even after the timeout/
# ceiling fixes below made that *safe* rather than infinite. Bounded (not
# unbounded) concurrency: each domain already fans out many subprocess tools
# (subfinder/httpx/katana/ffuf/feroxbuster/browser_crawl) internally, so
# running all MAX_DOMAINS_PER_RUN at once would both hammer the worker
# container's CPU/subprocess budget and multiply live request volume against
# the real target by up to 10x simultaneously -- not a good bug-bounty
# citizen. 3 is a middle ground: a real speedup without that multiplier.
MAX_CONCURRENT_DOMAINS = int(os.getenv("BOUNTY_RECON_DOMAIN_CONCURRENCY", "3"))
MAX_KATANA_SEED_HOSTS = 20
MAX_JS_FILES_ANALYZED = 25
MAX_FFUF_HOSTS = 5
MAX_FEROX_HOSTS = 2          # feroxbuster is heavier (recursive) -> fewer hosts
MAX_API_DISCOVERY_HOSTS = 10  # OpenAPI/GraphQL probing (cheap HTTP)
MAX_BROWSER_CRAWL_HOSTS = 2   # real browser navigation -- by far the heaviest source
# URL collection can return tens of thousands from wayback/waymore; cap what we
# persist (gf-classified URLs prioritized, since those drive exploit routing).
MAX_URLS_PERSISTED = 5000
# Full-auto only: how many in-scope subdomains one recon run may auto-promote
# into testable targets. A bound on blast radius, not a scope restriction.
MAX_AUTO_PROMOTE = 50
# _persist()'s bulk-insert chunk size -- see the comment at its call site;
# keeps every batch safely under Postgres/asyncpg's 32767-bind-parameter cap
# (5 columns/row here).
_PERSIST_BATCH_SIZE = 1000

# Punctuation that never appears in a real URL path a browser would request,
# but does appear verbatim when a JS-content crawler (katana's -jc mode, or
# tools.py::analyze_js_file's own ENDPOINT_PATTERN, whose char class allows
# "{}") lifts a template-expression or string-concatenation fragment out of
# bundled script source -- e.g. "/'+L(i[8])+'" or the percent-decoded form of
# "/%7B%7Bhref%7D%7D" ("/{{href}}"). Verified live against a real target:
# these fragments get crawled as if they were routes and then re-tested by
# every downstream module, wasting budget on non-existent endpoints.
_JS_EXPR_PUNCT_RE = re.compile(r"[+(){}\[\]]")


def _looks_like_real_path(value: str) -> bool:
    """Reject a candidate whose path (raw OR percent-decoded) contains
    JS-expression punctuation -- see _JS_EXPR_PUNCT_RE above. Checked on both
    forms since the punctuation can arrive already percent-encoded."""
    try:
        path = urlparse(value if "://" in value else f"//{value}").path or value
    except Exception:
        path = value
    if _JS_EXPR_PUNCT_RE.search(path):
        return False
    try:
        if _JS_EXPR_PUNCT_RE.search(unquote(path)):
            return False
    except Exception:
        pass
    return True


def _scope_seed_domains(scope_rules: List[Dict[str, Any]]) -> List[str]:
    """Concrete recon seed domains derived from a program's in-scope domain
    scope rules (wildcards stripped: '*.acme.com' -> 'acme.com'). Patterns
    carrying other glob chars aren't clean seeds and are skipped -- they only
    refine scope, they don't name a root to enumerate from."""
    seeds: List[str] = []
    for rule in scope_rules or []:
        if not isinstance(rule, dict) or not rule.get("in_scope"):
            continue
        if str(rule.get("type", "domain")) != "domain":
            continue
        host = normalize_host(str(rule.get("pattern", "")))
        if host and not any(c in host for c in "*?[]"):
            seeds.append(host)
    return seeds


class BountyReconWorker(BountyStageWorker):
    QUEUE = "bounty.recon"
    STAGE = "recon"
    CONCURRENCY = int(os.getenv("BOUNTY_RECON_CONCURRENCY", "2"))

    async def run_stage(self, message: Dict[str, Any]):
        program_id = message["program_id"]

        async with get_session() as db:
            program = (await db.execute(
                select(BountyProgram).where(BountyProgram.id == program_id)
            )).scalar_one_or_none()

            if not program:
                log.warning("bounty_recon_program_missing", program_id=program_id)
                return {"skipped": "program_missing"}
            if program.status != "active":
                log.info("bounty_recon_skipped_inactive", program_id=program_id, status=program.status)
                return {"skipped": "program_not_active"}

            domain_targets = (await db.execute(
                select(BountyTarget).where(
                    BountyTarget.program_id == program.id,
                    BountyTarget.target_type == "domain",
                )
            )).scalars().all()

        scope_rules = program.scope_rules or []
        roe = program.rules_of_engagement or {}

        # Optional single-identity auth (see exploit_worker.py for the full
        # rationale): without this, the crawl only ever sees the slice of the
        # app that doesn't require a session, which for most real targets is
        # a small fraction of the actual surface. Off by default. Uses
        # login_and_get_session (not just login_and_get_token) because the
        # browser crawl below needs more than the bearer token to make an SPA
        # actually render its logged-in state -- see browser_crawl.py.
        extra_headers: Dict[str, str] = {}
        auth_token: Optional[str] = None
        session_fields: Dict[str, str] = {}
        auth_login_url = roe.get("auth_login_url")
        auth_email = roe.get("auth_email")
        auth_password = roe.get("auth_password")
        if auth_login_url and auth_email and auth_password:
            auth_token, session_fields = await login_and_get_session(
                auth_login_url, auth_email, auth_password,
                email_field=roe.get("auth_email_field", "email"),
                password_field=roe.get("auth_password_field", "password"),
            )
            if auth_token:
                extra_headers = {"Authorization": f"Bearer {auth_token}"}
            log.info("bounty_recon_auth", program_id=program_id, authenticated=bool(auth_token))

        # Seed recon from BOTH explicit domain targets AND the in-scope domain
        # scope rules (wildcard-stripped) -- so a program only needs its scope
        # defined to run recon; no separate manual target entry required. Recon
        # only produces suggestions (BountyAsset) and never tests anything, so
        # seeding from scope doesn't touch the recon->promote human gate.
        seed_candidates = list(dict.fromkeys(
            [normalize_host(t.value) for t in domain_targets]
            + _scope_seed_domains(scope_rules)
        ))
        domains = [
            d for d in seed_candidates
            if d and is_target_in_scope(d, scope_rules)
        ][:MAX_DOMAINS_PER_RUN]

        if not domains:
            log.info("bounty_recon_no_in_scope_domains", program_id=program_id)
            return {"skipped": "no_in_scope_domain_seeds"}

        log.info("bounty_recon_started", program_id=program_id, domains=domains)

        with tempfile.TemporaryDirectory(prefix="asm-bounty-recon-") as tmpdir_raw:
            tmpdir = Path(tmpdir_raw)
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOMAINS)
            results = await asyncio.gather(
                *(self._process_domain(domain, tmpdir, program_id, extra_headers, auth_token, session_fields, semaphore)
                  for domain in domains),
                return_exceptions=True,
            )
            total_persisted = 0
            for domain, result in zip(domains, results):
                if isinstance(result, Exception):
                    log.warning("bounty_recon_domain_failed", domain=domain, error=str(result)[:300])
                    continue
                total_persisted += result

        # Full-auto: promote in-scope discovered subdomains to testable targets
        # so the chained probe/vulnscan/exploit stages have something to run
        # against without a manual review step. Manual runs skip this entirely.
        promoted = 0
        if message.get("auto_chain"):
            async with get_session() as db:
                promoted = await self._auto_promote_in_scope(db, program_id, scope_rules)

        authenticated = bool(extra_headers)
        log.info(
            "bounty_recon_completed",
            program_id=program_id, domains=len(domains),
            assets_persisted=total_persisted, auto_promoted=promoted, authenticated=authenticated,
        )
        return {
            "domains": len(domains), "assets_found": total_persisted,
            "auto_promoted": promoted, "authenticated": authenticated,
        }

    async def _process_domain(
        self,
        domain: str,
        tmpdir_root: Path,
        program_id: str,
        extra_headers: Dict[str, str],
        auth_token: Optional[str],
        session_fields: Dict[str, str],
        semaphore: asyncio.Semaphore,
    ) -> int:
        """Run every recon module for one domain and persist its findings.
        Returns the number of rows persisted. Runs under `semaphore` so at
        most MAX_CONCURRENT_DOMAINS domains are in flight at once.

        Each domain gets its own subdirectory under the shared tmpdir root,
        not the root itself -- several tools in tools.py (run_dnsx, run_katana,
        run_httpx) write to fixed filenames (e.g. "bounty_dnsx_output.json")
        rather than domain-scoped ones, since they were written assuming one
        domain runs at a time. Two domains sharing tmpdir directly would race
        on those files and silently corrupt/cross-contaminate each other's
        results -- not crash, just return wrong data. A per-domain
        subdirectory sidesteps that without touching every tool function.
        """
        async with semaphore:
            tmpdir = tmpdir_root / domain
            tmpdir.mkdir(parents=True, exist_ok=True)
            entries: List[Tuple[str, str, str, Dict[str, Any]]] = []

            subdomains = await self._enumerate_subdomains(domain, tmpdir, entries)
            base_urls = await self._resolve_base_urls(subdomains, tmpdir, extra_headers)
            await self._collect_urls(domain, subdomains, base_urls, tmpdir, entries, extra_headers)
            await self._analyze_js(entries)
            await self._discover_paths(subdomains, base_urls, tmpdir, entries, extra_headers)
            await self._discover_apis(subdomains, base_urls, entries, extra_headers)
            await self._browser_crawl_urls(subdomains, base_urls, entries, extra_headers, auth_token, session_fields)

            async with get_session() as db:
                return await self._persist(db, program_id, entries)

    async def _auto_promote_in_scope(self, db: AsyncSession, program_id: str, scope_rules) -> int:
        """Promote in-scope subdomain assets to domain targets (full-auto only).

        Mirrors endpoints/bounty.py::promote_asset -- scope re-check + dedup
        against existing targets -- and re-validates is_target_in_scope so an
        out-of-scope asset can never become testable. Promoting the hosts is
        enough: exploit pulls its candidate URLs from in-scope BountyAssets
        that are owned by an approved target, so the URLs come along for free.
        """
        existing = set((await db.execute(
            select(BountyTarget.value).where(BountyTarget.program_id == program_id)
        )).scalars().all())

        assets = (await db.execute(
            select(BountyAsset).where(
                BountyAsset.program_id == program_id,
                BountyAsset.asset_type == "subdomain",
                BountyAsset.promoted.is_(False),
            )
        )).scalars().all()

        promoted = 0
        for asset in assets:
            if promoted >= MAX_AUTO_PROMOTE:
                break
            if asset.value in existing:
                asset.promoted = True
                continue
            if not is_target_in_scope(asset.value, scope_rules):
                continue
            db.add(BountyTarget(
                program_id=program_id, value=asset.value, target_type="domain", added_by=None,
            ))
            asset.promoted = True
            existing.add(asset.value)
            promoted += 1

        await db.commit()
        return promoted

    # ── Module 1: Subdomain Enumeration ────────────────────────

    async def _enumerate_subdomains(
        self,
        domain: str,
        tmpdir: Path,
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
    ) -> List[str]:
        results = await asyncio.gather(
            run_subfinder(domain, tmpdir),
            run_assetfinder(domain),
            run_crtsh(domain),
            run_urlscan_subs(domain),
            run_hackertarget(domain),
            run_rapiddns(domain),
            return_exceptions=True,
        )
        candidates: Set[str] = {domain}
        for result in results:
            if isinstance(result, Exception):
                log.warning("bounty_subdomain_source_failed", domain=domain, error=str(result)[:200])
                continue
            candidates.update(h for h in result if in_domain(h, domain))

        # Permutation expansion (alterx) on what we found, then resolve the
        # permuted candidates -- only DNS-confirmed ones are kept as real.
        # BUT under wildcard DNS every guess "resolves", so permutations become
        # pure noise there -- drop them entirely for wildcard domains (the
        # real OSINT sources above stay; only the generated guesses are unsafe).
        permuted = await run_alterx(sorted(candidates), tmpdir)
        permuted = {h for h in permuted if in_domain(h, domain)} - candidates
        if permuted and await self._is_wildcard(domain, tmpdir):
            log.info("bounty_recon_wildcard_dropped_permutations", domain=domain, dropped=len(permuted))
            permuted = set()

        resolved = await run_dnsx(sorted(candidates | permuted), tmpdir)
        confirmed = [h for h in candidates if resolved.get(h)] or sorted(candidates)
        confirmed += [h for h in permuted if resolved.get(h)]  # permutations must resolve

        # NOTE: BountyAsset.source is String(50) -- keep this label short. The
        # candidate set is a merge of all sources, so a single per-host label
        # can't name which one found it anyway.
        for host in dict.fromkeys(confirmed):
            entries.append((host, "subdomain", "subdomain_enum", {}))

        log.info(
            "bounty_recon_subdomains", domain=domain,
            candidates=len(candidates), permuted=len(permuted), confirmed=len(set(confirmed)),
        )
        return list(dict.fromkeys(confirmed))

    async def _is_wildcard(self, domain: str, tmpdir: Path) -> bool:
        """Wildcard DNS check: if random non-existent subdomains resolve, the
        domain accepts anything -- so generated/permuted guesses can't be
        trusted as real."""
        import random
        import string
        probes = [
            "".join(random.choices(string.ascii_lowercase + string.digits, k=16)) + f".{domain}"
            for _ in range(3)
        ]
        resolved = await run_dnsx(probes, tmpdir)
        return sum(1 for p in probes if resolved.get(p)) >= 2

    # ── Module 2: URL Collection ───────────────────────────────

    async def _resolve_base_urls(
        self, subdomains: List[str], tmpdir: Path, extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Live scheme per host (httpx auto-negotiates https/http), so downstream
        crawl/fuzz/API-discovery steps don't hardcode https:// -- some in-scope
        targets (internal/staging hosts, local test envs) are http-only and would
        silently yield zero results otherwise. Falls back to https:// as a guess
        for any host httpx couldn't confirm (tool missing, target down)."""
        hosts = subdomains[:MAX_KATANA_SEED_HOSTS]
        if not hosts:
            return {}
        alive = await run_httpx(hosts, tmpdir, extra_headers=extra_headers)
        return {host: (alive.get(host) or {}).get("url") or f"https://{host}" for host in hosts}

    async def _collect_urls(
        self,
        domain: str,
        subdomains: List[str],
        base_urls: Dict[str, str],
        tmpdir: Path,
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        # Historical sources.
        wayback_urls, gau_urls, waymore_urls = await asyncio.gather(
            run_waybackurls(domain), run_gau(domain), run_waymore(domain, tmpdir),
            return_exceptions=True,
        )
        url_source: Dict[str, str] = {}
        for source, result in (("waybackurls", wayback_urls), ("gau", gau_urls), ("waymore", waymore_urls)):
            if isinstance(result, Exception):
                log.warning("bounty_url_source_failed", domain=domain, source=source, error=str(result)[:200])
                continue
            for url in result:
                host = normalize_host(urlparse(url if "://" in url else f"https://{url}").hostname or "")
                if in_domain(host, domain):
                    url_source.setdefault(url, source)

        # Live crawl: katana + hakrawler on seed hosts.
        seed_urls = [base_urls.get(h, f"https://{h}") for h in subdomains[:MAX_KATANA_SEED_HOSTS]]
        katana_result, hakrawler_urls = await asyncio.gather(
            run_katana(seed_urls, tmpdir, extra_headers=extra_headers),
            run_hakrawler(seed_urls, extra_headers=extra_headers),
            return_exceptions=True,
        )
        js_files: Set[str] = set()
        if not isinstance(katana_result, Exception):
            for url in katana_result.get("urls", set()):
                url_source.setdefault(url, "katana")
            js_files = katana_result.get("js_files", set())
        if not isinstance(hakrawler_urls, Exception):
            for url in hakrawler_urls:
                host = normalize_host(urlparse(url).hostname or "")
                if in_domain(host, domain):
                    url_source.setdefault(url, "hakrawler")

        # Dedup near-identical URLs (uro), tag each with its gf bucket(s), and
        # persist gf-classified ones first (they drive exploit routing).
        deduped = await run_uro(list(url_source.keys()), tmpdir)
        classified = [(u, classify_url(u)) for u in deduped]
        classified.sort(key=lambda x: (len(x[1]) == 0, x[0]))
        for url, buckets in classified[:MAX_URLS_PERSISTED]:
            entries.append((url, "url", url_source.get(url, "url"), {"gf": buckets} if buckets else {}))

        for js_url in js_files:
            entries.append((js_url, "url", "katana", {"kind": "js_file"}))

        log.info(
            "bounty_recon_urls", domain=domain,
            collected=len(url_source), deduped=len(deduped),
            classified=sum(1 for _, b in classified if b), js_files=len(js_files),
        )

    # ── Module 3: JS Analysis ──────────────────────────────────

    async def _analyze_js(self, entries: List[Tuple[str, str, str, Dict[str, Any]]]) -> None:
        js_urls = {value for value, asset_type, _, meta in entries if meta.get("kind") == "js_file"}
        page_urls = [value for value, asset_type, _, meta in entries if asset_type == "url" and not meta.get("kind")]
        if page_urls:
            js_urls.update(await discover_js_files(page_urls))

        for js_url in list(js_urls)[:MAX_JS_FILES_ANALYZED]:
            analysis = await analyze_js_file(js_url)
            for endpoint in analysis.get("endpoints", []):
                entries.append((endpoint, "js_endpoint", "js_analysis", {"js_file": js_url}))
            for secret_label in analysis.get("secrets", []):
                entries.append((f"{secret_label}@{js_url}", "secret", "js_analysis", {
                    "js_file": js_url, "secret_label": secret_label,
                }))
            # DOM-XSS sinks + declared API base URLs -- informational intel per
            # JS file (points a human where to look), recorded once.
            extras: Dict[str, Any] = {}
            if analysis.get("dom_xss_sinks"):
                extras["dom_xss_sinks"] = analysis["dom_xss_sinks"]
            if analysis.get("api_base_urls"):
                extras["api_base_urls"] = analysis["api_base_urls"][:20]
            if extras:
                entries.append((f"js_intel@{js_url}", "js_finding", "js_analysis", {"js_file": js_url, **extras}))

    # ── Module 4: Path & Endpoint Discovery ────────────────────

    async def _discover_paths(
        self,
        subdomains: List[str],
        base_urls: Dict[str, str],
        tmpdir: Path,
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        wordlist = resolve_fuzz_wordlist(tmpdir, {})
        for host in subdomains[:MAX_FFUF_HOSTS]:
            discovered = await run_ffuf(base_urls.get(host, f"https://{host}"), tmpdir, wordlist, extra_headers=extra_headers)
            for url in discovered:
                entries.append((url, "url", "ffuf", {"gf": classify_url(url)} if classify_url(url) else {}))
        # feroxbuster (recursive, backup/extension collection) on fewer hosts.
        for host in subdomains[:MAX_FEROX_HOSTS]:
            discovered = await run_feroxbuster(base_urls.get(host, f"https://{host}"), tmpdir, wordlist, extra_headers=extra_headers)
            for url in discovered:
                entries.append((url, "url", "feroxbuster", {"gf": classify_url(url)} if classify_url(url) else {}))

    # ── Module 7: API / GraphQL discovery ──────────────────────

    async def _discover_apis(
        self,
        subdomains: List[str],
        base_urls: Dict[str, str],
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """OpenAPI/Swagger spec hunting + GraphQL introspection on a bounded
        set of hosts. Specs/GraphQL endpoints are recorded as recon assets."""
        for host in subdomains[:MAX_API_DISCOVERY_HOSTS]:
            base = base_urls.get(host, f"https://{host}")
            for spec in await discover_api_specs(base, extra_headers=extra_headers):
                entries.append((spec["value"], "api_spec", "api_discovery", {"kind": spec.get("kind")}))
            for gql in await graphql_introspection(base, extra_headers=extra_headers):
                entries.append((gql["value"], "graphql", "api_discovery", {
                    "introspection_open": gql.get("introspection_open"),
                }))

    # ── Module 8: Browser-driven crawl (real SPA execution) ────

    async def _browser_crawl_urls(
        self,
        subdomains: List[str],
        base_urls: Dict[str, str],
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
        extra_headers: Optional[Dict[str, str]],
        auth_token: Optional[str],
        session_fields: Dict[str, str],
    ) -> None:
        """katana/hakrawler/ffuf/feroxbuster all parse static HTML/JS text or
        brute-force paths -- none of them execute JavaScript, so a modern SPA's
        real routes/API calls (constructed client-side, often only once
        logged in) are invisible to every one of them. Bounded to the first
        couple of hosts -- a real browser navigation is by far the most
        expensive source in this file."""
        for host in subdomains[:MAX_BROWSER_CRAWL_HOSTS]:
            base = base_urls.get(host, f"https://{host}")
            discovered = await browser_crawl(
                base, extra_headers=extra_headers, auth_token=auth_token, session_fields=session_fields,
            )
            for url in discovered:
                entries.append((url, "url", "browser_crawl", {"gf": classify_url(url)} if classify_url(url) else {}))

    # ── Persistence ─────────────────────────────────────────────

    async def _persist(
        self,
        db: AsyncSession,
        program_id: str,
        entries: List[Tuple[str, str, str, Dict[str, Any]]],
    ) -> int:
        if not entries:
            return 0
        seen: Set[Tuple[str, str]] = set()
        rejected = 0
        rows = []
        for value, asset_type, source, meta in entries:
            value = str(value)[:1000]
            if asset_type in ("url", "js_endpoint") and not _looks_like_real_path(value):
                rejected += 1
                continue
            key = (value, asset_type)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "program_id": program_id,
                "value": value,
                "asset_type": asset_type,
                "source": source,
                "metadata": meta or None,
            })
        if rejected:
            log.info("bounty_recon_rejected_nonroute_assets", program_id=program_id, rejected=rejected)
        if not rows:
            return 0

        # Postgres/asyncpg hard-caps bind parameters at 32767 per query -- 5
        # columns per row here, so one all-in-one INSERT tops out around 6553
        # rows. Confirmed live against a real, long-lived multi-domain
        # program: a single domain's collected entries (subdomains + URLs +
        # JS endpoints/secrets/findings) exceeded that and crashed the whole
        # call with asyncpg.exceptions._base.InterfaceError, losing every
        # entry for that domain, not just the overflow. Batched in chunks
        # safely under the limit instead.
        total = 0
        for i in range(0, len(rows), _PERSIST_BATCH_SIZE):
            batch = rows[i:i + _PERSIST_BATCH_SIZE]
            stmt = pg_insert(BountyAsset.__table__).values(batch)
            stmt = stmt.on_conflict_do_nothing(index_elements=["program_id", "value", "asset_type"])
            result = await db.execute(stmt)
            total += result.rowcount or 0
        await db.commit()
        return total


if __name__ == "__main__":
    worker = BountyReconWorker()
    asyncio.run(worker.run())

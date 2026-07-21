"""
ASM Platform — Bug Bounty pipeline: extended recon (breadth + classification).

Phase 1 of aligning the pipeline to a full bug-bounty framework:
- gf-style URL classification (xss/sqli/ssrf/lfi/idor/redirect/rce/ssti buckets)
  done in Python from the well-known gf parameter lists -- no gf binary or
  pattern-repo dependency. Downstream exploit modules route off these buckets.
- Extra keyless subdomain sources (urlscan.io, hackertarget, rapiddns) that
  complement the subfinder/assetfinder/crt.sh set already in tools.py.
- alterx permutation expansion, waymore/hakrawler extra URL sources, uro dedup.

Stateless wrappers, no persistence -- the recon worker calls these and persists
BountyAssets (with gf buckets in metadata). See CHANGELOG.md.
"""
import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

import aiohttp
import structlog

from workers.bounty.tools import in_domain, normalize_host
from workers.scanner.discovery_worker import tool_path

log = structlog.get_logger()


# ── gf-style URL classification ────────────────────────────────
# Condensed from the canonical gf/1ndianl33t param lists. A URL is tagged with
# a bucket if any of its query-parameter names appears in that bucket's set.
GF_PARAM_PATTERNS: Dict[str, Set[str]] = {
    "xss": {"q", "s", "search", "id", "action", "keyword", "query", "page", "keywords",
            "url", "view", "cat", "name", "key", "p", "callback", "return", "redirect", "r"},
    "sqli": {"id", "page", "dir", "search", "category", "file", "class", "url", "news",
             "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread",
             "type", "date", "form", "join", "main", "nav", "region", "order", "sort",
             "where", "select", "report", "row", "results", "table", "from", "sel", "field"},
    "ssrf": {"url", "uri", "path", "dest", "redirect", "redir", "return", "next", "site",
             "html", "val", "validate", "domain", "callback", "return_to", "continue",
             "feed", "host", "port", "to", "out", "show", "file", "document", "folder",
             "page", "pg", "template", "doc", "img", "image", "load", "open", "fetch"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template",
            "php_path", "doc", "page", "name", "cat", "dir", "action", "board", "date",
            "detail", "download", "prefix", "include", "inc", "locate", "show", "site",
            "type", "view", "content", "layout", "mod", "conf", "read", "filename"},
    "redirect": {"url", "redirect", "next", "dest", "destination", "redir", "redirurl",
                 "return", "returnurl", "go", "goto", "target", "link", "checkout_url",
                 "continue", "return_path", "returnto", "rurl", "forward", "r", "u", "out"},
    "rce": {"cmd", "exec", "command", "execute", "ping", "count", "do", "func", "arg",
            "option", "load", "process", "step", "read", "function", "req", "feature",
            "exe", "module", "payload", "run", "print", "daemon", "upload", "log", "ip", "cli"},
    "idor": {"id", "uid", "user", "userid", "account", "acct", "number", "order", "no",
             "doc", "key", "email", "group", "profile", "edit", "report", "gid", "pid",
             "oid", "aid", "invoice", "ticket", "customer", "member", "record"},
    "ssti": {"id", "page", "name", "q", "search", "query", "message", "content", "view",
             "template", "preview", "body", "subject", "title", "description", "input", "text"},
}


def classify_url(url: str) -> List[str]:
    """Return the gf buckets a URL matches, based on its query-parameter names."""
    params = {k.lower() for k in parse_qs(urlparse(url).query, keep_blank_values=True)}
    if not params:
        return []
    return sorted(bucket for bucket, names in GF_PARAM_PATTERNS.items() if params & names)


# ── Extra keyless subdomain sources ────────────────────────────

async def run_urlscan_subs(domain: str, timeout: int = 25) -> Set[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    hosts: Set[str] = set()
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return set()
                data = await r.json(content_type=None)
    except Exception as exc:
        log.warning("bounty_urlscan_error", domain=domain, error=str(exc)[:150])
        return set()
    for res in (data.get("results") or []):
        for path in (("page", "domain"), ("task", "domain")):
            v = res.get(path[0], {}).get(path[1])
            h = normalize_host(v or "")
            if h and in_domain(h, domain):
                hosts.add(h)
    return hosts


async def run_hackertarget(domain: str, timeout: int = 25) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return set()
                text = await r.text()
    except Exception as exc:
        log.warning("bounty_hackertarget_error", domain=domain, error=str(exc)[:150])
        return set()
    if "API count exceeded" in text or "error" in text.lower():
        return set()
    hosts = set()
    for line in text.splitlines():
        h = normalize_host(line.split(",")[0])
        if h and in_domain(h, domain):
            hosts.add(h)
    return hosts


async def run_rapiddns(domain: str, timeout: int = 25) -> Set[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0"},
        ) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return set()
                html = await r.text(errors="ignore")
    except Exception as exc:
        log.warning("bounty_rapiddns_error", domain=domain, error=str(exc)[:150])
        return set()
    hosts = set()
    for m in re.findall(r"<td>([a-zA-Z0-9._-]+\.%s)</td>" % re.escape(domain), html):
        h = normalize_host(m)
        if h and in_domain(h, domain):
            hosts.add(h)
    return hosts


async def run_alterx(hosts: List[str], tmpdir: Path, timeout: int = 60, max_out: int = 2000) -> Set[str]:
    """Generate permutation candidates from known hosts (needs dnsx resolution
    afterwards, done by the caller). No-op if alterx isn't installed."""
    path = tool_path("alterx")
    if not path or not hosts:
        return set()
    infile = tmpdir / "alterx_in.txt"
    infile.write_text("\n".join(hosts[:500]))
    outfile = tmpdir / "alterx_out.txt"
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "-l", str(infile), "-o", str(outfile), "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("bounty_alterx_timeout")
    except Exception as exc:
        log.warning("bounty_alterx_error", error=str(exc)[:150])
    if not outfile.exists():
        return set()
    return {normalize_host(h) for h in outfile.read_text().splitlines()[:max_out] if h.strip()}


# ── Extra URL sources ──────────────────────────────────────────

async def run_waymore(domain: str, tmpdir: Path, timeout: int = 180) -> Set[str]:
    """waymore URL mode (keyless historical sources). No-op if not installed."""
    import shutil
    path = shutil.which("waymore")
    if not path:
        return set()
    outfile = tmpdir / f"waymore_{domain}.txt"
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "-i", domain, "-mode", "U", "-f", "-oU", str(outfile),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("bounty_waymore_timeout", domain=domain)
    except Exception as exc:
        log.warning("bounty_waymore_error", domain=domain, error=str(exc)[:150])
    if not outfile.exists():
        return set()
    return {u.strip() for u in outfile.read_text().splitlines() if u.strip().startswith("http")}


async def run_hakrawler(
    urls: List[str], timeout: int = 120, extra_headers: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Crawl live URLs for more endpoints (reads seeds from stdin)."""
    path = tool_path("hakrawler")
    if not path or not urls:
        return set()
    cmd = [path, "-d", "2", "-subs", "-u"]
    if extra_headers:
        cmd += ["-h", ";;".join(f"{k}: {v}" for k, v in extra_headers.items())]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate("\n".join(urls[:50]).encode()), timeout=timeout,
        )
    except asyncio.TimeoutError:
        log.warning("bounty_hakrawler_timeout")
        return set()
    except Exception as exc:
        log.warning("bounty_hakrawler_error", error=str(exc)[:150])
        return set()
    return {u.strip() for u in stdout.decode(errors="ignore").splitlines() if u.strip().startswith("http")}


async def run_uro(urls: List[str], tmpdir: Path, timeout: int = 60) -> List[str]:
    """Deduplicate near-identical URLs (uro). Falls back to plain dedup if
    uro isn't installed."""
    import shutil
    if not urls:
        return []
    deduped = list(dict.fromkeys(urls))
    path = shutil.which("uro")
    if not path:
        return deduped
    infile = tmpdir / "uro_in.txt"
    infile.write_text("\n".join(deduped))
    outfile = tmpdir / "uro_out.txt"
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "-i", str(infile), "-o", str(outfile),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except Exception as exc:
        log.warning("bounty_uro_error", error=str(exc)[:150])
        return deduped
    if outfile.exists():
        return [u.strip() for u in outfile.read_text().splitlines() if u.strip()]
    return deduped

"""
ASM Platform — Bug Bounty pipeline: Phase 2 detection modules.

High-signal, mostly-detection checks that sit between recon and active exploit:
- WAF fingerprint (wafw00f) -- run by the probe stage, stored on the target.
- API/GraphQL schema discovery (OpenAPI/Swagger hunt + GraphQL introspection)
  -- run by recon, produces BountyAssets.
- Sensitive-file exposure, CORS misconfiguration, 403 bypass -- run by vulnscan,
  produce ExploitAttempt findings.

Stateless wrappers; the workers persist. Everything here is a bounded GET/POST
against explicitly in-scope targets (scope re-validated by the worker first).
See CHANGELOG.md.
"""
import asyncio
import json
import random
import re
import shutil
import string
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import structlog

log = structlog.get_logger()

_UA = {"User-Agent": "Mozilla/5.0 (compatible; ASM-Bounty/1.0)"}


async def _is_catch_all_200(session: aiohttp.ClientSession, base_url: str) -> bool:
    """True if a definitely-nonexistent path still returns 200 -- i.e. the
    server answers 200 for everything (SPA / catch-all). Without this guard,
    signature-less sensitive-file checks and path-mutation 403 bypasses fire
    on every such host (a very common false-positive source in the wild)."""
    nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    try:
        async with session.get(f"{base_url.rstrip('/')}/asm-probe-{nonce}", allow_redirects=False) as r:
            return r.status == 200
    except Exception:
        return False


# ── WAF fingerprint (probe stage) ──────────────────────────────

async def run_wafw00f(url: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    path = shutil.which("wafw00f")
    if not path:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            path, url, "-a", "-f", "json", "-o", "-",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        log.warning("bounty_wafw00f_error", url=url, error=str(exc)[:150])
        return None
    try:
        data = json.loads(stdout.decode(errors="ignore") or "[]")
    except json.JSONDecodeError:
        return None
    for entry in (data if isinstance(data, list) else [data]):
        if entry.get("detected") or entry.get("firewall") not in (None, "None", "Generic"):
            return {"detected": True, "firewall": entry.get("firewall"), "manufacturer": entry.get("manufacturer")}
    return {"detected": False, "firewall": None}


# ── Sensitive-file exposure (vulnscan stage) ───────────────────

# path -> (regex-ish signature that must appear in the body to confirm)
SENSITIVE_FILES: Dict[str, Optional[str]] = {
    "/.env": "=",
    "/.git/config": "[core]",
    "/.git/HEAD": "ref:",
    "/.svn/entries": None,
    "/config.php": None,
    "/wp-config.php": "DB_",
    "/.aws/credentials": "aws_access_key",
    "/.aws/config": "region",
    "/actuator": "_links",
    "/actuator/env": "propertySources",
    "/actuator/health": "status",
    "/server-status": "Apache Server Status",
    "/phpinfo.php": "phpinfo()",
    "/.htpasswd": ":",
    "/docker-compose.yml": "services:",
    "/backup.sql": "INSERT INTO",
    "/.DS_Store": "Bud1",
    "/debug/vars": "cmdline",
    "/.travis.yml": None,
    "/id_rsa": "PRIVATE KEY",
}


async def check_sensitive_files(
    base_url: str, timeout: int = 20, max_bytes: int = 20000, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = base_url.rstrip("/")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            catch_all = await _is_catch_all_200(s, base)
            for path, signature in SENSITIVE_FILES.items():
                url = base + path
                try:
                    async with s.get(url, allow_redirects=False) as r:
                        if r.status != 200:
                            continue
                        body = (await r.content.read(max_bytes)).decode(errors="ignore")
                except Exception:
                    continue
                if len(body) < 5:
                    continue
                # Weak signatures like "=" (.env) or ":" (.htpasswd) trivially match any HTML
                # page's markup, so this must run before the signature check, not instead of it.
                if catch_all and ("<html" in body.lower() or "<!doctype" in body.lower()):
                    continue  # SPA/catch-all shell page, not the real file
                if signature and signature.lower() not in body.lower():
                    continue  # signature required -> avoids generic-200/SPA false positives
                if not signature and catch_all:
                    continue  # bare 200 on a catch-all server proves nothing
                findings.append({
                    "technique": f"sensitive-file{path}",
                    "severity": "high" if any(k in path for k in (".env", ".git", "credentials", "id_rsa", "wp-config")) else "medium",
                    "evidence": {"url": url, "matched_signature": signature, "excerpt": body[:300]},
                })
    except Exception as exc:
        log.warning("bounty_sensitive_files_error", base=base_url, error=str(exc)[:150])
    return findings


# ── CORS misconfiguration (vulnscan stage) ─────────────────────

async def check_cors(
    url: str, timeout: int = 15, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    host = urlparse(url).hostname or ""
    origins = [
        ("reflected", "https://evil.example.org"),
        ("null", "null"),
        ("subdomain_evil", f"https://{host}.evil.example.org"),
        ("prefix_evil", f"https://evil{host}"),
    ]
    findings: List[Dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            for label, origin in origins:
                try:
                    async with s.get(url, headers={"Origin": origin}, allow_redirects=False) as r:
                        acao = r.headers.get("Access-Control-Allow-Origin")
                        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
                except Exception:
                    continue
                if not acao:
                    continue
                # A bare "*" ACAO is a standard, safe config for public/no-auth
                # resources -- browsers refuse to honor it on credentialed
                # requests, so it's only worth flagging combined with ACAC, or
                # when the server actually reflects our specific origin back
                # (proof there's no allowlist at all, not just a public wildcard).
                exact_reflect = acao == origin
                wildcard_with_creds = acao == "*" and acac
                if not exact_reflect and not wildcard_with_creds:
                    continue
                if exact_reflect and acac:
                    severity, note = "high", "Reflects attacker origin with credentials allowed"
                elif exact_reflect:
                    severity, note = "medium", "Reflects arbitrary Origin with no allowlist"
                else:
                    severity, note = "low", "Wildcard ACAO combined with Allow-Credentials (spec-invalid)"
                findings.append({
                    "technique": f"cors-{label}",
                    "severity": severity,
                    "evidence": {
                        "url": url, "origin_sent": origin,
                        "acao": acao, "acac_true": acac, "note": note,
                    },
                })
                break  # one representative CORS finding per URL
    except Exception as exc:
        log.warning("bounty_cors_error", url=url, error=str(exc)[:150])
    return findings


# ── 403 bypass (vulnscan stage) ────────────────────────────────

_403_PATH_TRICKS = ["/%2e/{p}", "/{p}/.", "//{p}//", "/./{p}", "/{p}%20", "/{p}%09", "/{p}?", "/{p}#", "/{p}/..;/"]
_403_HEADER_TRICKS = [
    {"X-Original-URL": "/{p}"}, {"X-Rewrite-URL": "/{p}"},
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"}, {"X-Host": "127.0.0.1"},
]


async def check_403_bypass(url: str, timeout: int = 15) -> List[Dict[str, Any]]:
    parsed = urlparse(url)
    path = parsed.path.lstrip("/")
    base = f"{parsed.scheme}://{parsed.netloc}"
    if not path:
        return []
    findings: List[Dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=_UA) as s:
            # confirm it's actually 403 first
            try:
                async with s.get(url, allow_redirects=False) as r:
                    if r.status not in (401, 403):
                        return []
            except Exception:
                return []
            # Path mutations returning 200 are meaningless on a catch-all-200
            # server -- only try them when a random path does NOT 200. Header
            # bypasses keep the exact path, so they stay reliable either way.
            catch_all = await _is_catch_all_200(s, base)
            if not catch_all:
                for trick in _403_PATH_TRICKS:
                    test = base + "/" + trick.format(p=path).lstrip("/")
                    try:
                        async with s.get(test, allow_redirects=False) as r:
                            if r.status == 200:
                                findings.append({"technique": "403-bypass-path", "severity": "medium",
                                                 "evidence": {"original": url, "bypass_url": test, "status": 200}})
                                return findings
                    except Exception:
                        continue
            for header in _403_HEADER_TRICKS:
                h = {k: v.format(p=path) for k, v in header.items()}
                try:
                    async with s.get(url, headers=h, allow_redirects=False) as r:
                        if r.status == 200:
                            findings.append({"technique": "403-bypass-header", "severity": "medium",
                                             "evidence": {"original": url, "header": h, "status": 200}})
                            return findings
                except Exception:
                    continue
    except Exception as exc:
        log.warning("bounty_403bypass_error", url=url, error=str(exc)[:150])
    return findings


# ── API / GraphQL discovery (recon stage) ──────────────────────

OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json", "/api/openapi.json",
    "/api-docs/swagger.json", "/redoc", "/swagger-ui.html", "/api/v1/swagger.json",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query"]


async def discover_api_specs(
    base_url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Return discovered OpenAPI/Swagger spec URLs (as recon assets)."""
    base = base_url.rstrip("/")
    found: List[Dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            for path in OPENAPI_PATHS:
                url = base + path
                try:
                    async with s.get(url, allow_redirects=False) as r:
                        if r.status != 200:
                            continue
                        text = (await r.content.read(50000)).decode(errors="ignore")
                except Exception:
                    continue
                if any(k in text for k in ('"swagger"', '"openapi"', '"paths"')):
                    found.append({"value": url, "kind": "openapi_spec"})
    except Exception as exc:
        log.warning("bounty_apispec_error", base=base_url, error=str(exc)[:150])
    return found


async def graphql_introspection(
    base_url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Probe GraphQL endpoints; flag ones with introspection enabled."""
    base = base_url.rstrip("/")
    results: List[Dict[str, Any]] = []
    q_type = {"query": "{__typename}"}
    q_introspect = {"query": "{__schema{types{name}}}"}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            for path in GRAPHQL_PATHS:
                url = base + path
                try:
                    async with s.post(url, json=q_type, allow_redirects=False) as r:
                        if r.status not in (200, 400):
                            continue
                        body = await r.text(errors="ignore")
                except Exception:
                    continue
                if "__typename" not in body and "errors" not in body and "data" not in body:
                    continue
                # looks like GraphQL; test introspection
                introspection_open = False
                try:
                    async with s.post(url, json=q_introspect, allow_redirects=False) as r2:
                        b2 = await r2.text(errors="ignore")
                        introspection_open = "__schema" in b2 and '"types"' in b2
                except Exception:
                    pass
                results.append({"value": url, "kind": "graphql", "introspection_open": introspection_open})
    except Exception as exc:
        log.warning("bounty_graphql_error", base=base_url, error=str(exc)[:150])
    return results


_SENSITIVE_NAME_RE = re.compile(
    r"(password|secret|token|apikey|api_key|admin|internal|private[_-]?key|ssn|creditcard|credit_card|salt|hash)",
    re.IGNORECASE,
)


async def graphql_schema_scan(url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """A confirmed-open GraphQL endpoint's introspection result can be walked
    for type/field *names* that suggest the schema exposes more than a
    frontend actually needs (a `password`/`resetToken`/`internalNotes`-shaped
    field reachable via a generic query) -- a common, real over-exposure
    class distinct from "is introspection on at all". Only field/type names
    are inspected, never actual query results -- this never calls a query
    that would return real data, only the schema's own self-description."""
    query = {"query": "{__schema{types{name fields{name}}}}"}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            async with s.post(url, json=query, allow_redirects=False) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
    except Exception as exc:
        log.warning("bounty_graphql_schema_error", url=url, error=str(exc)[:150])
        return []

    types = (((data or {}).get("data") or {}).get("__schema") or {}).get("types") or []
    hits: List[str] = []
    for t in types:
        type_name = t.get("name") or ""
        if _SENSITIVE_NAME_RE.search(type_name):
            hits.append(type_name)
        for f in t.get("fields") or []:
            field_name = f.get("name") or ""
            if _SENSITIVE_NAME_RE.search(field_name):
                hits.append(f"{type_name}.{field_name}")
    if not hits:
        return []
    return [{
        "technique": "graphql-sensitive-schema-field",
        "severity": "medium",
        "status": "inconclusive",
        "evidence": {
            "target_url": url, "fields": sorted(set(hits))[:25],
            "note": (
                "Introspection exposes type/field names suggesting sensitive data is reachable "
                "through this schema. Confirm manually whether a normal query can actually read them."
            ),
        },
    }]


async def check_graphql_batching(url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """POST a small (5-query) GraphQL batch and check whether the server
    processes all of them in one request. Not itself a vulnerability -- it's
    a candidate signal for rate-limit/brute-force-bypass risk (batching lets
    many logical requests hide behind one HTTP-level rate-limit check), so
    this stays a small, bounded probe rather than trying to push toward an
    actual abuse volume."""
    batch = [{"query": "{__typename}"}] * 5
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            async with s.post(url, json=batch, allow_redirects=False) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
    except Exception:
        return []
    if not isinstance(data, list) or len(data) < len(batch):
        return []
    return [{
        "technique": "graphql-batching-accepted",
        "severity": "low",
        "status": "inconclusive",
        "evidence": {
            "target_url": url, "batch_size": len(batch),
            "note": (
                "The endpoint processed a batched array of queries in one request. If no "
                "per-query cost/rate limit applies, batching can bypass a per-request rate limit "
                "(e.g. on login/OTP-style resolvers) -- confirm whether any sensitive resolver is reachable this way."
            ),
        },
    }]


# ── feroxbuster content discovery (recon stage) ────────────────

async def run_feroxbuster(
    base_url: str, tmpdir: Path, wordlist: str, timeout: int = 120,
    extra_headers: Optional[Dict[str, str]] = None,
) -> set:
    path = shutil.which("feroxbuster")
    if not path:
        return set()
    outfile = tmpdir / f"ferox_{abs(hash(base_url))}.json"
    cmd = [
        path, "-u", base_url.rstrip("/"), "-w", wordlist,
        "--json", "-o", str(outfile), "-q", "--no-state",
        "-d", "2", "-t", "40", "--time-limit", f"{timeout}s",
        "-s", "200,204,301,302,307,401,403,405,500",
        "-C", "404",
    ]
    for key, value in (extra_headers or {}).items():
        cmd += ["-H", f"{key}:{value}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout + 30)
    except asyncio.TimeoutError:
        log.warning("bounty_feroxbuster_timeout", url=base_url)
    except Exception as exc:
        log.warning("bounty_feroxbuster_error", url=base_url, error=str(exc)[:150])
    discovered = set()
    if outfile.exists():
        for line in outfile.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") == "response" and rec.get("url"):
                discovered.add(rec["url"])
    return discovered

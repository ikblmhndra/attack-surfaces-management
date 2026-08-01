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
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
import structlog

log = structlog.get_logger()

_UA = {"User-Agent": "Mozilla/5.0 (compatible; ASM-Bounty/1.0)"}

CatchAllCache = Dict[str, Tuple[bool, str]]


async def _is_catch_all_200(
    session: aiohttp.ClientSession, base_url: str, cache: Optional[CatchAllCache] = None,
) -> Tuple[bool, str]:
    """(is_catch_all, baseline_body) for this exact base_url -- a nonexistent
    path either 404s normally, or the server answers 200 for everything under
    this base (SPA / catch-all route), in which case baseline_body is that
    catch-all's own content. Catch-all is a property of the specific base, not
    necessarily the whole origin: a site's root can 200 with its SPA shell
    while a deeper base (e.g. a static-file route matched by prefix) 200s with
    different, non-HTML content for any suffix under it -- so this must be
    re-checked per base, not assumed from the origin alone.
    Without this guard, signature-less sensitive-file checks and path-mutation
    403 bypasses fire on every such host (a very common false-positive source
    in the wild). `cache`, if given, is a dict the caller owns for one worker
    run, keyed by the exact base string, so repeat callers asking about the
    same base within a run issue the nonce probe once."""
    base = base_url.rstrip("/")
    if cache is not None and base in cache:
        return cache[base]
    nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    result: Tuple[bool, str] = (False, "")
    try:
        async with session.get(f"{base}/asm-probe-{nonce}", allow_redirects=False) as r:
            if r.status == 200:
                result = (True, (await r.content.read(20000)).decode(errors="ignore"))
    except Exception:
        pass
    if cache is not None:
        cache[base] = result
    return result


def _bodies_match(candidate: str, baseline: str) -> bool:
    """Exact match, or whitespace-collapsed match (defends against a catch-all
    page injecting a per-request timestamp/nonce into otherwise-identical
    markup). An empty baseline (probe errored / wasn't itself 200) never
    counts as a match."""
    if not baseline:
        return False
    if candidate == baseline:
        return True
    return " ".join(candidate.split()) == " ".join(baseline.split())


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
    catch_all_cache: Optional[CatchAllCache] = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base = base_url.rstrip("/")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            catch_all, baseline_body = await _is_catch_all_200(s, base, cache=catch_all_cache)
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
                # Weak signatures like "=" (.env) or ":" (.htpasswd) trivially match any
                # catch-all page's content (HTML shell OR plain text -- e.g. a base whose
                # own catch-all is a non-HTML page like a security.txt-style route matched
                # by prefix), so this must run before the signature check, not instead of it.
                if catch_all and _bodies_match(body, baseline_body):
                    continue  # this base's own catch-all content, not the real file
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


# ── Security headers (vulnscan stage) ──────────────────────────
# Single-GET, header-only checks -- confirmed the moment a header is absent/
# misconfigured, since a server either sends it or it doesn't (no baseline-
# diff needed the way a body-content check like check_sensitive_files needs
# the catch-all-200 guard). One of the most commonly-accepted "quick win"
# bug bounty report categories, and previously entirely uncovered.

async def check_security_headers(
    url: str, timeout: int = 15, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})}) as s:
            async with s.get(url, allow_redirects=True) as r:
                headers = r.headers
                content_type = headers.get("Content-Type", "")
    except Exception as exc:
        log.warning("bounty_security_headers_error", url=url, error=str(exc)[:150])
        return []

    findings: List[Dict[str, Any]] = []

    # Clickjacking (XFO/CSP frame-ancestors) only matters for an actual
    # renderable page -- an API/JSON endpoint being frameable isn't a real
    # clickjacking concern, and flagging it there would just be noise.
    if "html" in content_type.lower():
        xfo = (headers.get("X-Frame-Options") or "").strip().upper()
        csp = headers.get("Content-Security-Policy") or ""
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        if xfo not in ("DENY", "SAMEORIGIN") and not has_frame_ancestors:
            findings.append({
                "technique": "missing-clickjacking-protection",
                "severity": "medium",
                "evidence": {
                    "url": url,
                    "x_frame_options": headers.get("X-Frame-Options"),
                    "csp": csp[:300] or None,
                    "note": "No X-Frame-Options (DENY/SAMEORIGIN) and no CSP frame-ancestors directive -- "
                            "this page can be embedded in a hostile iframe (clickjacking).",
                },
            })

    if url.lower().startswith("https://") and not headers.get("Strict-Transport-Security"):
        findings.append({
            "technique": "missing-hsts",
            "severity": "low",
            "evidence": {
                "url": url,
                "note": "No Strict-Transport-Security header on an HTTPS response -- a user's first "
                        "visit (or any plain-HTTP link to this site) isn't protected against an "
                        "SSL-stripping downgrade.",
            },
        })

    xcto = (headers.get("X-Content-Type-Options") or "").strip().lower()
    if xcto != "nosniff":
        findings.append({
            "technique": "missing-x-content-type-options",
            "severity": "low",
            "evidence": {
                "url": url,
                "value": headers.get("X-Content-Type-Options"),
                "note": "No 'X-Content-Type-Options: nosniff' -- browsers may MIME-sniff the response "
                        "body, which can enable content-type-confusion attacks (e.g. an uploaded file "
                        "served without nosniff being interpreted and executed as HTML/JS).",
            },
        })

    return findings


# ── 403 bypass (vulnscan stage) ────────────────────────────────

_403_PATH_TRICKS = ["/%2e/{p}", "/{p}/.", "//{p}//", "/./{p}", "/{p}%20", "/{p}%09", "/{p}?", "/{p}#", "/{p}/..;/"]
_403_HEADER_TRICKS = [
    {"X-Original-URL": "/{p}"}, {"X-Rewrite-URL": "/{p}"},
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"}, {"X-Host": "127.0.0.1"},
]


async def check_403_bypass(
    url: str, timeout: int = 15, catch_all_cache: Optional[CatchAllCache] = None,
) -> List[Dict[str, Any]]:
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
            catch_all, _ = await _is_catch_all_200(s, base, cache=catch_all_cache)
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


# ── Vulnerable/outdated frontend JS component detection (vulnscan stage) ──
# retire.js-style: most bundlers/minifiers still preserve a library's own
# `/*! Name vX.Y.Z */`-style banner comment even when everything else is
# minified -- match that against a small, curated table of known-vulnerable
# version thresholds. Deliberately a SMALL, high-confidence starting set
# (widely-cited, extremely well-documented CVEs only) rather than a full
# retire.js-scale database -- easy to extend with more (name, pattern,
# ranges) tuples later without touching the check logic itself.
def _parse_version(s: str) -> Optional[Tuple[int, int, int]]:
    parts = s.split(".")[:3]
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


# (library_name, banner_pattern (must capture version in group 1), ranges)
# ranges: list of (max_vulnerable_version, cve_ids, severity, description,
# same_major_only), ordered highest-value/most-recent fix first -- the first
# range the detected version fails to meet is reported (avoids piling up
# every historical advisory for one old copy of a library into a wall of
# findings). same_major_only=True restricts a range to installs on that same
# major version -- required for a project like Bootstrap that maintains
# parallel major branches with their own separate backported fix (a 3.x site
# should be told to reach 3.4.1, never "upgrade to 4.3.1", a different major
# entirely). False (jQuery/AngularJS here) means the advisory is cumulative
# across the whole version line -- there's one continuously-maintained
# series, so "upgrade to the latest fixed version" is correct regardless of
# how old the detected copy is.
LIBRARY_VERSION_SIGNATURES: List[Tuple[str, "re.Pattern", List[Tuple[Tuple[int, int, int], List[str], str, str, bool]]]] = [
    ("jquery", re.compile(r"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)"), [
        ((3, 5, 0), ["CVE-2020-11022", "CVE-2020-11023"], "medium",
         "jQuery < 3.5.0: untrusted HTML passed to .html()/.append()/etc. containing <option> or "
         "style attributes can execute injected JS (jQuery.htmlPrefilter regex XSS).", False),
        ((3, 4, 0), ["CVE-2019-11358"], "medium",
         "jQuery < 3.4.0: $.extend(true, {}, ...) on untrusted JSON can pollute Object.prototype.", False),
        ((1, 9, 0), ["CVE-2015-9251"], "medium",
         "jQuery < 1.9.0: cross-domain Ajax responses are executed as script even for non-script "
         "dataType, allowing a compromised/MITM'd third-party endpoint to run arbitrary JS.", False),
    ]),
    ("bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+)"), [
        ((4, 3, 1), ["CVE-2019-8331"], "medium",
         "Bootstrap < 4.3.1: tooltip/popover data-template/title/content options aren't sanitized "
         "-> XSS if any of those ever come from untrusted input.", True),
        ((3, 4, 1), ["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"], "medium",
         "Bootstrap < 3.4.1: XSS via tooltip/popover data-viewport, scrollspy/affix href, and "
         "collapse data-target attributes when sourced from untrusted input.", True),
    ]),
    ("angularjs", re.compile(r"AngularJS v(\d+\.\d+\.\d+)"), [
        ((1, 6, 0), [], "high",
         "AngularJS (1.x) < 1.6.0: predates the 1.6 removal of the $parse expression sandbox, which "
         "had a long-running series of documented bypasses (client-side template-injection-style "
         "RCE-in-the-browser) that the AngularJS team ultimately deemed unfixable -- see NVD/GHSA "
         "for the specific AngularJS sandbox-bypass advisories.", False),
    ]),
]


async def check_vulnerable_components(js_url: str, timeout: int = 15, max_bytes: int = 60000) -> List[Dict[str, Any]]:
    """Fetch a JS asset (bounded to its first max_bytes -- library version
    banners are always at the very top of a bundle, never worth reading a
    multi-MB file for this) and match it against LIBRARY_VERSION_SIGNATURES.
    Confirmed -- a version number is either below the documented fixed-in
    threshold or it isn't, no judgement call needed. Skips anything that
    isn't actually JS content (an HTML catch-all/SPA-shell served at a URL
    that merely looks like a .js path would otherwise never match a library
    banner regex in practice, but checking explicitly is cheap and avoids
    ever wasting a finding slot on a misclassified target)."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=_UA) as s:
            async with s.get(js_url, allow_redirects=False) as r:
                if r.status != 200:
                    return []
                text = (await r.content.read(max_bytes)).decode(errors="ignore")
    except Exception as exc:
        log.warning("bounty_vulnerable_components_error", url=js_url, error=str(exc)[:150])
        return []
    if not text or text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return []

    findings: List[Dict[str, Any]] = []
    for lib_name, pattern, ranges in LIBRARY_VERSION_SIGNATURES:
        m = pattern.search(text)
        if not m:
            continue
        version = _parse_version(m.group(1))
        if version is None:
            continue
        for max_vulnerable, cve_ids, severity, description, same_major_only in ranges:
            if same_major_only and version[0] != max_vulnerable[0]:
                continue
            if version < max_vulnerable:
                findings.append({
                    "technique": f"vulnerable-component/{lib_name}",
                    "severity": severity,
                    "status": "confirmed",
                    "evidence": {
                        "url": js_url, "library": lib_name, "version": m.group(1),
                        "fixed_in": ".".join(str(p) for p in max_vulnerable),
                        "cve_ids": cve_ids, "note": description,
                    },
                })
                break  # most relevant (first/highest) matching threshold is enough per library
    return findings

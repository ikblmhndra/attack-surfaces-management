"""
ASM Platform — Bug Bounty pipeline: recon/probe/vulnscan tool wrappers.

Standalone, stateless CLI/HTTP wrappers -- no BountyAsset/BountyTarget/
ExploitAttempt persistence here, that belongs to the workers that call
these. Reuses tool-availability detection from the ASM discovery worker (a
pure filesystem lookup, not tied to the ASM Asset schema) rather than
duplicating it.
"""
import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import aiohttp
import structlog

from workers.scanner.discovery_worker import tool_path

log = structlog.get_logger()

_UA = {"User-Agent": "Mozilla/5.0 (compatible; ASM-Bounty/1.0)"}


# ── Authenticated session (optional, per-program rules_of_engagement) ──
# Shared by every stage (recon/probe/vulnscan/exploit): most of a real app's
# attack surface (profile, basket, orders, admin-after-creds...) sits behind
# a login wall, so without this the pipeline only ever sees the slice of an
# app that doesn't require a session. Single test identity only: this logs in
# as ONE account and carries its token everywhere, it does not create/hold a
# second identity, so IDOR/BAC confirmation is unaffected -- that still needs
# an authorized human with two accounts to compare against.
_TOKEN_JSON_PATHS = (
    ("authentication", "token"), ("token",), ("data", "token"), ("jwt",), ("access_token",),
)


def _extract_token(data: Any) -> Optional[str]:
    if not isinstance(data, dict):
        return None
    for path in _TOKEN_JSON_PATHS:
        node = data
        for key in path:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if isinstance(node, str) and len(node) > 8:
            return node
    return None


def _flatten_scalars(node: Any, out: Dict[str, str]) -> None:
    """Every scalar leaf of a JSON structure, keyed by its own field name
    (not a dotted path) -- e.g. Juice Shop's login response nests a `bid`
    (basket id) field the app's own client-side JS reads back out of
    localStorage under that exact name, separately from the token. There's
    no way to know an arbitrary app's session-state field names in advance,
    but mirroring whatever its own login response already used is a
    reasonable, generic stand-in for actually knowing them."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                _flatten_scalars(v, out)
            elif isinstance(v, (str, int, float, bool)) and v is not None:
                out[k] = str(v)
    elif isinstance(node, list):
        for item in node:
            _flatten_scalars(item, out)


async def login_and_get_session(
    login_url: str, email: str, password: str,
    email_field: str = "email", password_field: str = "password",
    timeout: int = 20,
) -> tuple[Optional[str], Dict[str, str]]:
    """POST real test credentials to the program's configured login endpoint.
    Returns (token, flattened_scalar_fields) -- the second is every scalar
    field name/value pair found anywhere in the response, for callers (the
    browser-driven crawl) that need to seed more of an app's own client-side
    session state than just the bearer token. Returns (None, {}) on any
    failure -- callers proceed unauthenticated rather than raise, since auth
    is an optional enhancement, not a hard requirement."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=_UA) as s:
            async with s.post(
                login_url, json={email_field: email, password_field: password}, allow_redirects=False,
            ) as r:
                if r.status != 200:
                    log.warning("bounty_auth_login_failed", login_url=login_url, status=r.status)
                    return None, {}
                try:
                    data = json.loads(await r.text(errors="ignore"))
                except json.JSONDecodeError:
                    log.warning("bounty_auth_login_non_json", login_url=login_url)
                    return None, {}
    except Exception as exc:
        log.warning("bounty_auth_login_error", login_url=login_url, error=str(exc)[:200])
        return None, {}
    token = _extract_token(data)
    if not token:
        log.warning("bounty_auth_login_no_token", login_url=login_url)
        return None, {}
    fields: Dict[str, str] = {}
    _flatten_scalars(data, fields)
    return token, fields


async def login_and_get_token(
    login_url: str, email: str, password: str,
    email_field: str = "email", password_field: str = "password",
    timeout: int = 20,
) -> Optional[str]:
    """POST real test credentials to the program's configured login endpoint
    and pull a bearer token out of the JSON response. Thin wrapper over
    login_and_get_session() for the (much more common) callers that only
    need the token itself."""
    token, _ = await login_and_get_session(
        login_url, email, password, email_field=email_field, password_field=password_field, timeout=timeout,
    )
    return token


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".").lstrip("*.")


def in_domain(host: str, domain: str) -> bool:
    host = normalize_host(host)
    domain = normalize_host(domain)
    return bool(host) and (host == domain or host.endswith(f".{domain}"))


# ── Module 1: Subdomain Enumeration ────────────────────────────

async def run_subfinder(domain: str, tmpdir: Path, timeout: int = 120) -> Set[str]:
    path = tool_path("subfinder")
    if not path:
        return set()
    outfile = tmpdir / f"bounty_subfinder_{domain}.txt"
    cmd = [path, "-d", domain, "-o", str(outfile), "-silent", "-duc"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if outfile.exists():
            return {normalize_host(h) for h in outfile.read_text().splitlines() if h.strip()}
    except asyncio.TimeoutError:
        log.warning("bounty_subfinder_timeout", domain=domain)
    except Exception as exc:
        log.warning("bounty_subfinder_error", domain=domain, error=str(exc)[:200])
    return set()


async def run_assetfinder(domain: str, timeout: int = 60) -> Set[str]:
    path = tool_path("assetfinder")
    if not path:
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(
            path, "--subs-only", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {normalize_host(h) for h in stdout.decode(errors="ignore").splitlines() if h.strip()}
    except asyncio.TimeoutError:
        log.warning("bounty_assetfinder_timeout", domain=domain)
    except Exception as exc:
        log.warning("bounty_assetfinder_error", domain=domain, error=str(exc)[:200])
    return set()


async def run_crtsh(domain: str, timeout: int = 30) -> Set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    log.warning("bounty_crtsh_http_error", domain=domain, status=resp.status)
                    return set()
                data = await resp.json(content_type=None)
    except Exception as exc:
        log.warning("bounty_crtsh_error", domain=domain, error=str(exc)[:200])
        return set()

    hosts: Set[str] = set()
    for entry in data or []:
        for name in str(entry.get("name_value", "")).splitlines():
            name = normalize_host(name)
            if name and in_domain(name, domain):
                hosts.add(name)
    return hosts


async def run_dnsx(hosts: List[str], tmpdir: Path, timeout: int = 180) -> Dict[str, Dict[str, Any]]:
    """Resolve hosts and return only DNS-confirmed evidence -- recon should
    surface real assets, not raw unconfirmed name guesses. If dnsx itself
    isn't installed, every host is passed through unresolved rather than
    silently dropped, so a missing tool degrades confidence, not coverage."""
    if not hosts:
        return {}
    path = tool_path("dnsx")
    if not path:
        return {h: {} for h in hosts}

    input_file = tmpdir / "bounty_dnsx_hosts.txt"
    input_file.write_text("\n".join(hosts))
    output_file = tmpdir / "bounty_dnsx_output.json"
    cmd = [
        path, "-l", str(input_file), "-json", "-o", str(output_file),
        "-a", "-aaaa", "-cname", "-silent", "-t", "100", "-retry", "2",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("bounty_dnsx_timeout")
    except Exception as exc:
        log.warning("bounty_dnsx_error", error=str(exc)[:200])

    resolved: Dict[str, Dict[str, Any]] = {}
    if output_file.exists():
        for line in output_file.read_text().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host")
            if host:
                resolved[normalize_host(host)] = {
                    "a": data.get("a", []),
                    "aaaa": data.get("aaaa", []),
                    "cname": data.get("cname", []),
                }
    return resolved


async def run_subzy(hosts: List[str], tmpdir: Path, timeout: int = 120) -> Dict[str, Dict[str, Any]]:
    """Subdomain takeover check -- subzy tracks ~75+ actively-maintained
    provider fingerprints, so this reuses it rather than a hand-rolled
    marker-string dict (same tool the main ASM pipeline's coverage_worker.py
    already uses; already installed in this image). subzy resolves CNAMEs
    itself, so a plain host list is all it needs.

    Note: this subzy build's JSON `"vulnerable"` boolean field is unreliable
    (observed `false` even when `"status"` says `"vulnerable"`) -- `status`
    is the field actually trusted here, same lesson coverage_worker.py
    already learned the hard way."""
    if not hosts:
        return {}
    path = shutil.which("subzy")
    if not path:
        return {}

    targets_file = tmpdir / "bounty_subzy_targets.txt"
    output_file = tmpdir / "bounty_subzy_output.json"
    targets_file.write_text("\n".join(hosts))
    cmd = [
        path, "run",
        "--targets", str(targets_file),
        "--output", str(output_file),
        "--https", "--hide_fails",
        "--timeout", "10", "--concurrency", "10",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except Exception as exc:
        log.warning("bounty_subzy_error", error=str(exc)[:200])
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    if output_file.exists():
        try:
            # --hide_fails makes subzy write the literal JSON `null`, not
            # `[]`, when nothing is vulnerable (the overwhelmingly common
            # case), which json.loads()s to None.
            records = json.loads(output_file.read_text(errors="ignore") or "[]") or []
        except json.JSONDecodeError:
            records = []
        for record in records:
            host = record.get("subdomain")
            if not host:
                continue
            results[host] = {
                "vulnerable": record.get("status") == "vulnerable",
                "engine": record.get("engine"),
                "cname": record.get("cname"),
                "documentation": record.get("documentation"),
            }
    return results


# ── Module 2: URL Collection ───────────────────────────────────

async def run_waybackurls(domain: str, timeout: int = 60) -> Set[str]:
    path = tool_path("waybackurls")
    if path:
        try:
            proc = await asyncio.create_subprocess_exec(
                path, domain,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {u.strip() for u in stdout.decode(errors="ignore").splitlines() if u.strip()}
        except asyncio.TimeoutError:
            log.warning("bounty_waybackurls_timeout", domain=domain)
            return set()
        except Exception as exc:
            log.warning("bounty_waybackurls_error", domain=domain, error=str(exc)[:200])
            return set()

    # Fallback: the same Wayback CDX API waybackurls itself wraps, used
    # directly when the binary isn't installed in this image.
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        "&output=json&fl=original&collapse=urlkey&limit=1000"
    )
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return set()
                rows = await resp.json(content_type=None)
    except Exception as exc:
        log.warning("bounty_wayback_cdx_error", domain=domain, error=str(exc)[:200])
        return set()
    return {row[0] for row in (rows[1:] if isinstance(rows, list) else []) if isinstance(row, list) and row}


async def run_gau(domain: str, timeout: int = 90) -> Set[str]:
    path = tool_path("gau")
    if not path:
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(
            path, domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {u.strip() for u in stdout.decode(errors="ignore").splitlines() if u.strip()}
    except asyncio.TimeoutError:
        log.warning("bounty_gau_timeout", domain=domain)
    except Exception as exc:
        log.warning("bounty_gau_error", domain=domain, error=str(exc)[:200])
    return set()


async def run_katana(
    urls: List[str], tmpdir: Path, timeout: int = 120, extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Set[str]]:
    """Crawl for endpoints; `-jc` additionally surfaces endpoints referenced
    inside JS files without needing to fetch/parse them separately."""
    path = tool_path("katana")
    if not urls or not path:
        return {"urls": set(), "js_files": set()}

    input_file = tmpdir / "bounty_katana_targets.txt"
    input_file.write_text("\n".join(urls))
    output_file = tmpdir / "bounty_katana_output.txt"
    cmd = [
        path, "-list", str(input_file), "-o", str(output_file), "-silent",
        "-depth", "2", "-rate-limit", "40", "-host-rate-limit", "15",
        "-timeout", "10", "-retry", "1", "-concurrency", "10",
        "-fs", "fqdn", "-mdp", "150", "-disable-update-check", "-jc",
    ]
    for key, value in (extra_headers or {}).items():
        cmd += ["-H", f"{key}: {value}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            # A bad flag or other CLI-parse failure exits fast with no output
            # file, which the check below would otherwise swallow silently as
            # "found nothing" instead of "never ran".
            log.warning("bounty_katana_nonzero_exit", code=proc.returncode, stderr=stderr.decode(errors="ignore")[:300])
    except asyncio.TimeoutError:
        log.warning("bounty_katana_timeout")
    except Exception as exc:
        log.warning("bounty_katana_error", error=str(exc)[:200])

    found_urls: Set[str] = set()
    js_files: Set[str] = set()
    if output_file.exists():
        for line in output_file.read_text().splitlines():
            # -jc pulls links out of embedded JS-string content too (e.g. a
            # credits list or a JSON blob with escaped quotes), which can leave
            # a stray raw or percent-encoded backslash/quote in the URL --
            # never a legitimate character in this position.
            line = line.strip()
            for artifact in ("\\", "%5C", "%22"):
                line = line.replace(artifact, "")
            if not line.startswith("http"):
                continue
            if line.split("?")[0].endswith(".js"):
                js_files.add(line)
            else:
                found_urls.add(line)
    return {"urls": found_urls, "js_files": js_files}


# ── Module 3: JS Analysis ──────────────────────────────────────

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)

# LinkFinder-style: quoted path-like strings, filtered down in analyze_js_file.
ENDPOINT_PATTERN = re.compile(r'''["'](/[a-zA-Z0-9_\-/{}.]{2,120}?)["']''')
_ENDPOINT_ASSET_EXTENSIONS = (".png", ".jpg", ".jpeg", ".css", ".svg", ".woff", ".woff2", ".gif", ".ico")

# SecretFinder-style. Only the matched *label* is ever kept (see
# analyze_js_file) -- never the matched text, since this is recon evidence,
# not a place to persist live credentials.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "gcp_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "google_oauth_token": re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"),
    "github_token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "stripe_secret_key": re.compile(r"sk_live_[0-9A-Za-z]{24,}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    "twilio_sid": re.compile(r"AC[a-z0-9]{32}", re.IGNORECASE),
    "mailgun_key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "generic_api_key": re.compile(r"""['"]?(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""", re.IGNORECASE),
    "s3_bucket_url": re.compile(r"[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com", re.IGNORECASE),
    "firebase_url": re.compile(r"[a-z0-9\-]+\.firebaseio\.com", re.IGNORECASE),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
}

# DOM-XSS sink usage worth flagging in JS (informational -- points a human at
# where to look, not a confirmed vuln).
DOM_XSS_SINK_RE = re.compile(
    r"\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval|setTimeout|"
    r"setInterval|location\.(?:href|hash|search)|\.src\s*=|dangerouslySetInnerHTML)\b"
)
# API base URLs declared in JS (baseURL/apiUrl = "...").
API_BASE_URL_RE = re.compile(
    r"""['"](https?://[a-zA-Z0-9.\-]+(?:/[a-zA-Z0-9._\-/]*)?)['"]""")


async def discover_js_files(urls: List[str], timeout: int = 15, max_pages: int = 30) -> Set[str]:
    """subjs if installed; otherwise a direct <script src> scrape -- both are
    just "find JS file URLs referenced by this page," so the fallback isn't a
    lesser feature, just a different implementation of the same module."""
    path = tool_path("subjs")
    if path and urls:
        try:
            proc = await asyncio.create_subprocess_exec(
                path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(("\n".join(urls)).encode()),
                timeout=timeout * max(1, len(urls) // 10),
            )
            found = {u.strip() for u in stdout.decode(errors="ignore").splitlines() if u.strip()}
            if found:
                return found
        except Exception as exc:
            log.warning("bounty_subjs_error", error=str(exc)[:200])

    js_files: Set[str] = set()
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            for page_url in urls[:max_pages]:
                try:
                    async with session.get(page_url) as resp:
                        if resp.status != 200:
                            continue
                        html = await resp.text(errors="ignore")
                except Exception:
                    continue
                for match in _SCRIPT_SRC_RE.findall(html):
                    js_files.add(urljoin(page_url, match))
    except Exception as exc:
        log.warning("bounty_js_scrape_error", error=str(exc)[:200])
    return js_files


async def analyze_js_file(js_url: str, timeout: int = 15, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    """Fetch a JS file and run lightweight LinkFinder/SecretFinder-style regex
    passes over it -- passive content analysis on an already-served, public
    asset, not active exploitation."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(js_url) as resp:
                if resp.status != 200:
                    return {"endpoints": [], "secrets": []}
                body = await resp.content.read(max_bytes)
                text = body.decode(errors="ignore")
    except Exception as exc:
        log.warning("bounty_js_fetch_error", url=js_url, error=str(exc)[:200])
        return {"endpoints": [], "secrets": []}

    endpoints = sorted({
        m for m in ENDPOINT_PATTERN.findall(text)
        if not m.lower().endswith(_ENDPOINT_ASSET_EXTENSIONS)
    })[:200]
    secrets = sorted(label for label, pattern in SECRET_PATTERNS.items() if pattern.search(text))
    dom_xss_sinks = sorted(set(DOM_XSS_SINK_RE.findall(text)))[:20]
    api_base_urls = sorted({
        u for u in API_BASE_URL_RE.findall(text)
        if not u.lower().rsplit("?", 1)[0].endswith(_ENDPOINT_ASSET_EXTENSIONS)
    })[:50]
    return {
        "endpoints": endpoints,
        "secrets": secrets,
        "dom_xss_sinks": dom_xss_sinks,
        "api_base_urls": api_base_urls,
    }


# ── Module 4: Path & Endpoint Discovery ────────────────────────

async def run_ffuf(
    base_url: str, tmpdir: Path, wordlist: str, timeout: int = 90,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Set[str]:
    path = tool_path("ffuf")
    if not path:
        return set()

    target = base_url.rstrip("/")
    outfile = tmpdir / f"bounty_ffuf_{abs(hash(target))}.json"
    cmd = [
        path,
        "-u", f"{target}/FUZZ",
        "-w", wordlist,
        "-o", str(outfile),
        "-of", "json",
        "-mc", "200-299,301,302,307,308,401,403,405,500",
        "-fc", "404",
        "-fs", "0",
        "-t", "20",
        "-rate", "40",
        "-timeout", "10",
        "-maxtime", str(timeout),
        "-noninteractive",
        "-ac", "-ach",
    ]
    for key, value in (extra_headers or {}).items():
        cmd += ["-H", f"{key}: {value}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout + 30)
    except asyncio.TimeoutError:
        log.warning("bounty_ffuf_timeout", url=target)
        return set()
    except Exception as exc:
        log.warning("bounty_ffuf_error", url=target, error=str(exc)[:200])
        return set()

    discovered: Set[str] = set()
    if outfile.exists():
        try:
            data = json.loads(outfile.read_text())
            for result in data.get("results", []):
                url = result.get("url", "")
                if url:
                    discovered.add(url)
        except (json.JSONDecodeError, KeyError):
            pass
    return discovered


# ── Module 5: Live Host Probing ────────────────────────────────

async def run_httpx(
    targets: List[str], tmpdir: Path, timeout: int = 300, extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Probe explicit, human-approved targets only -- callers are
    responsible for passing exactly the values that should be touched."""
    path = tool_path("httpx")
    if not targets or not path:
        return {}

    input_file = tmpdir / "bounty_httpx_targets.txt"
    input_file.write_text("\n".join(targets))
    output_file = tmpdir / "bounty_httpx_output.json"
    cmd = [
        path, "-l", str(input_file), "-json", "-o", str(output_file), "-silent",
        "-follow-redirects", "-max-redirects", "5",
        "-title", "-web-server", "-status-code", "-tech-detect", "-tls-grab",
        "-ip", "-cname", "-content-length", "-content-type", "-response-time",
        "-t", "30", "-rl", "100", "-timeout", "12", "-max-host-error", "10",
        "-no-color", "-duc",
    ]
    for key, value in (extra_headers or {}).items():
        cmd += ["-H", f"{key}: {value}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("bounty_httpx_timeout")
    except Exception as exc:
        log.warning("bounty_httpx_error", error=str(exc)[:200])

    alive: Dict[str, Dict[str, Any]] = {}
    if output_file.exists():
        for line in output_file.read_text().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("failed"):
                continue
            input_value = data.get("input") or data.get("host") or data.get("url", "")
            alive[input_value] = {
                "url": data.get("url", ""),
                "status_code": data.get("status_code"),
                "title": data.get("title", ""),
                "webserver": data.get("webserver", ""),
                "content_length": data.get("content_length"),
                "content_type": data.get("content_type", ""),
                "response_time": data.get("response_time", ""),
                "ip": data.get("ip", ""),
                "cname": data.get("cname", []),
                "technologies": data.get("tech", []),
                "tls": data.get("tls", {}),
            }
    return alive


# ── Module 6: Nuclei Vulnerability Scan ────────────────────────

async def run_nuclei(
    targets: List[str],
    tmpdir: Path,
    *,
    templates_path: str,
    template_dirs: List[str],
    severities: List[str],
    exclude_tags: List[str],
    rate_limit: int = 100,
    bulk_size: int = 10,
    concurrency: int = 10,
    template_timeout: int = 8,
    scan_timeout: int = 600,
    extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Execute nuclei and return raw parsed JSONL results -- mapping a result
    back to a specific BountyTarget/ExploitAttempt row is the caller's job,
    same division of responsibility as every other tool wrapper here."""
    if not targets:
        return []
    nuclei_path = shutil.which("nuclei") or "/go/bin/nuclei"

    input_file = tmpdir / "bounty_nuclei_targets.txt"
    input_file.write_text("\n".join(targets))
    output_file = tmpdir / "bounty_nuclei_output.jsonl"

    cmd = [
        nuclei_path,
        "-l", str(input_file),
        "-jsonl",
        "-o", str(output_file),
        "-silent", "-no-color", "-stream",
        "-rate-limit", str(rate_limit),
        "-bulk-size", str(bulk_size),
        "-c", str(concurrency),
        "-timeout", str(template_timeout),
        "-retries", "0",
        "-max-redirects", "3",
        "-follow-host-redirects",
        "-redact", "authorization,token,password,secret,api_key,apikey,access_token,refresh_token",
        "-disable-update-check",
        "-no-stdin",
        "-H", "X-ASM-Bounty-Scanner: ASM-Platform-Bounty/1.0",
    ]
    for key, value in (extra_headers or {}).items():
        cmd += ["-H", f"{key}: {value}"]
    if severities:
        cmd.extend(["-severity", ",".join(severities)])
    for tmpl_dir in template_dirs:
        tmpl_path = Path(templates_path) / str(tmpl_dir)
        if tmpl_path.exists():
            cmd.extend(["-t", str(tmpl_path)])
    if exclude_tags:
        cmd.extend(["-etags", ",".join(exclude_tags)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ},
        )
        await asyncio.wait_for(proc.communicate(), timeout=scan_timeout)
    except asyncio.TimeoutError:
        log.warning("bounty_nuclei_timeout", scan_timeout=scan_timeout)
    except FileNotFoundError:
        log.error("bounty_nuclei_not_found")
        return []
    except Exception as exc:
        log.error("bounty_nuclei_error", error=str(exc)[:200])
        return []

    results: List[Dict[str, Any]] = []
    if output_file.exists():
        for line in output_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                results.append(parsed)
            elif isinstance(parsed, list):
                results.extend(r for r in parsed if isinstance(r, dict))
    return results

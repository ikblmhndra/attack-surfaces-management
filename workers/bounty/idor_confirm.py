"""
ASM Platform — Bug Bounty pipeline: two-identity IDOR/BAC confirmation.

Everything else in this pipeline that flags an object-reference-looking
param or path segment (exploit_tools.py::idor_candidates) stops at "candidate"
by design -- proving IDOR needs a second identity with no legitimate claim on
the resource to compare against, which the pipeline has never held until now.

This module is opt-in per-program (rules_of_engagement.idor_registration_url +
idor_registration_fields must both be set) and does exactly two things:
1. Register a second, brand-new, disposable test identity via the program's
   own public registration endpoint (a template the operator configures once,
   same pattern as auth_login_url/auth_email_field for the first identity).
2. For a path-shaped object-reference URL, fetch it as the primary identity
   and as this second identity. The second identity is *freshly created* and
   has no legitimate relationship to any pre-existing resource -- if it still
   gets a full, resource-shaped response, that's a missing ownership check,
   confirmed. This only ever compares status codes and a coarse "does this
   look like real resource data" shape check -- the actual resource content
   is never parsed, extracted, or stored, by construction (there is no field-
   extraction code path here, mirroring exploit_tools.py::idor_candidates'
   own "stop at first confirmation, never enumerate" discipline).
"""
import re
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import structlog

from workers.bounty.exploit_tools import PATH_ID_RE

log = structlog.get_logger()

_ID_FIELD_RE = re.compile(r"(?:^|[_-])(id|uid|bid|pid|gid|oid|aid|cid)$", re.IGNORECASE)
_NUMERIC_ID_RE = re.compile(r"^\d{1,15}$")
_UUID_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def derive_id_candidates(session_fields: Dict[str, str]) -> List[str]:
    """Numeric/UUID-looking values from fields whose *name* suggests an
    object reference (id/bid/uid/...), pulled from the primary identity's own
    login response (tools.py::login_and_get_session collects every scalar
    field, not just the token). These are the identity's own real resource
    ids (e.g. Juice Shop's `bid` is the user's own basket id) -- exactly the
    ground truth needed to construct a genuine, testable IDOR candidate
    instead of waiting for recon to discover one by chance."""
    out: List[str] = []
    for key, value in session_fields.items():
        if not _ID_FIELD_RE.search(key):
            continue
        if _NUMERIC_ID_RE.match(value) or _UUID_ID_RE.match(value):
            out.append(value)
    return out


def derive_session_id_urls(candidate_urls: List[str], id_values: List[str]) -> List[str]:
    """For bare resource paths among `candidate_urls` (no query string, no
    id segment of their own yet), construct `{path}/{id}` for each derived id
    value -- e.g. a discovered `/rest/basket` plus a `bid` of `6` yields
    `/rest/basket/6`, a URL no static crawler could construct on its own.
    Bounded implicitly by the caller's own MAX_* limits on both inputs."""
    out: List[str] = []
    seen: set = set()
    for url in candidate_urls:
        parsed = urlparse(url)
        if parsed.query or PATH_ID_RE.search(parsed.path):
            continue
        for id_value in id_values:
            derived = url.rstrip("/") + "/" + id_value
            if derived not in seen:
                seen.add(derived)
                out.append(derived)
    return out

_UA = {"User-Agent": "Mozilla/5.0 (compatible; ASM-Bounty/1.0)"}


def _fill_template(node: Any, email: str, password: str) -> Any:
    """Recursively substitute the literal strings '{email}'/'{password}'
    anywhere in a JSON-shaped template (dicts/lists/strings), so an operator
    can describe an arbitrary registration payload shape (Juice Shop needs a
    nested securityQuestion/securityAnswer, most apps don't) without this
    module needing to know any app-specific schema."""
    if isinstance(node, dict):
        return {k: _fill_template(v, email, password) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill_template(v, email, password) for v in node]
    if isinstance(node, str):
        return node.replace("{email}", email).replace("{password}", password)
    return node


def generate_test_identity(reference_email: str) -> tuple[str, str]:
    """A brand-new disposable email/password pair for the second identity,
    reusing the primary test identity's domain so registration validation
    (if any) behaves consistently with what the operator already knows works."""
    domain = reference_email.split("@")[-1] if "@" in reference_email else "example.com"
    token = secrets.token_hex(6)
    return f"asm-bounty-2-{token}@{domain}", secrets.token_urlsafe(16)


async def register_test_identity(
    registration_url: str, fields_template: Dict[str, Any], email: str, password: str, timeout: int = 20,
    extra_headers: Optional[Dict[str, str]] = None,
) -> bool:
    """POST a program-configured registration payload shape. Returns whether
    it looked like it succeeded (2xx) -- callers proceed to attempt login
    regardless, since some apps 201 without a body or vice versa, and the
    login attempt itself is the real confirmation this identity is usable."""
    payload = _fill_template(fields_template, email, password)
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout), headers={**_UA, **(extra_headers or {})},
        ) as s:
            async with s.post(registration_url, json=payload, allow_redirects=False) as r:
                ok = 200 <= r.status < 300
                if not ok:
                    log.warning("bounty_idor_registration_failed", registration_url=registration_url, status=r.status)
                return ok
    except Exception as exc:
        log.warning("bounty_idor_registration_error", registration_url=registration_url, error=str(exc)[:200])
        return False


def looks_like_resource(status: int, body: str) -> bool:
    """Coarse shape check only -- 200 status and a non-trivial JSON-looking
    body. Deliberately not parsed further: this module never extracts or
    stores what the resource actually contains."""
    stripped = body.strip()
    if status != 200 or len(stripped) <= 20 or stripped[:1] not in ("{", "["):
        return False
    # A common REST wrapper convention -- {"status":"success","data":null} --
    # is a coincidental empty resource (e.g. an unused basket ID), not proof
    # either identity actually reached real content. Reject it specifically
    # rather than relying on length alone, which that envelope can still pass.
    compact = stripped.replace(" ", "").replace("\n", "")
    if '"data":null' in compact or '"data":{}' in compact or '"data":[]' in compact:
        return False
    return True


async def confirm_idor_cross_identity(
    url: str, token_a: str, token_b: str, timeout: int = 15,
) -> List[Dict[str, Any]]:
    """Fetch the same URL as two independent identities. Identity B was just
    created and owns nothing yet, so it has no legitimate claim on any
    pre-existing numbered/UUID resource -- if it still gets a full response
    where a real resource would be, that's a missing ownership check."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=_UA) as s:
            async with s.get(url, headers={"Authorization": f"Bearer {token_a}"}, allow_redirects=False) as ra:
                status_a, body_a = ra.status, await ra.text(errors="ignore")
            async with s.get(url, headers={"Authorization": f"Bearer {token_b}"}, allow_redirects=False) as rb:
                status_b, body_b = rb.status, await rb.text(errors="ignore")
    except Exception as exc:
        log.warning("bounty_idor_confirm_error", url=url, error=str(exc)[:200])
        return []

    if looks_like_resource(status_a, body_a) and looks_like_resource(status_b, body_b):
        return [{
            "technique": "idor-cross-identity-confirmed",
            "severity": "critical",
            "status": "confirmed",
            "evidence": {
                "target_url": url,
                "status_identity_a": status_a,
                "status_identity_b": status_b,
                "note": (
                    "A second, brand-new test identity with no legitimate relationship to this "
                    "resource received the same successful response as the primary identity -- "
                    "missing ownership check. Resource content was never parsed, extracted, or stored."
                ),
            },
        }]
    return []

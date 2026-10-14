"""
ASM Platform — Bug Bounty pipeline: evidence redaction.

Findings store a snippet of the target's real response body as proof
(`evidence.excerpt`), and bounty_report_templates.py drops that snippet
verbatim into the generated draft under "Response excerpt confirming the
issue". Until this module those snippets were captured raw, which meant the
platform could persist -- and hand a researcher a report containing -- real
citizens' personal data or the target's own live credentials.

That is not hypothetical for this deployment: the programs run here are
Indonesian public sector, and the host-prioritisation work in
bounty_priority.py deliberately steers testing toward `disdukcapil` (civil
registry -> NIK), `simpeg`/`bkpsdm` (HR), and `rsud`/`simrs` (medical) --
i.e. precisely the systems whose responses carry the most sensitive data.
A `.env` exposure finding is the sharpest case: the whole point is that the
file leaked, and the proof is the key names being present -- storing the
target's actual DB password alongside them adds nothing to the report and
creates a real secondary liability.

Design follows the evidence-hygiene principle "prove the bug, not the user":
redact the *value*, keep the *structure*. A triager needs to see that
`"nik"` came back in the response and what shape it had; they never need the
digits. Keys, JSON shape, status codes, trace IDs and response ordering are
all deliberately preserved.

Deliberately NOT attempted: detecting personal names. There is no reliable
pattern for them, and a heuristic aggressive enough to catch Indonesian
names would shred ordinary response text, destroying the evidence value the
excerpt exists for. Name redaction stays a human step at submission time
(see the evidence-hygiene skill's black-bar protocol).
"""
import re
from typing import Optional

_MASK = "<REDACTED>"

# ── Sensitive key/value pairs ──────────────────────────────────
# Matches JSON ("key": "value"), form (key=value) and env (KEY=value) shapes.
# The key itself is preserved -- it is the part that proves the finding.
_SENSITIVE_KEYS = (
    # secrets / auth material. Bare "key" is included on purpose: `APP_KEY`
    # (Laravel's app encryption key), `SECRET_KEY`, `ENCRYPTION_KEY` are the
    # single most common real secret in a leaked .env, and an `api_key`-only
    # list misses every one of them. It over-matches a benign JSON `"key"`
    # field occasionally -- an acceptable trade against persisting a target's
    # live encryption key.
    "password", "passwd", "pass", "passphrase", "secret", "token", "key",
    "api_key", "apikey", "access_token", "refresh_token", "authorization",
    "auth", "credential", "private_key", "client_secret", "session", "cookie",
    "salt", "pin", "otp", "dsn",
    # Indonesian government / personal identifiers
    "nik", "no_ktp", "noktp", "ktp", "npwp", "nip", "nisn", "kk", "no_kk",
    # contact / location / demographic PII
    "email", "mail", "phone", "telepon", "telp", "hp", "no_hp", "handphone",
    "alamat", "address", "tgl_lahir", "tanggal_lahir", "birth", "dob",
    "nama_ibu", "ibu_kandung",
    # financial
    "rekening", "no_rekening", "account_number", "card", "cvv", "credit_card",
)

_KEY_ALT = "|".join(sorted((re.escape(k) for k in set(_SENSITIVE_KEYS)), key=len, reverse=True))

# A sensitive key is rarely bare in real data -- `.env` files and JSON APIs
# overwhelmingly prefix it (`DB_PASSWORD`, `MAIL_PASSWORD`, `APP_SECRET`,
# `user_email`, `no_hp_ortu`). So the key may carry a leading identifier
# fragment, but must END at the token: `[\w.]*password` matches `DB_PASSWORD`
# while `"passwordish"` / `passwords_count=` still don't, because the closing
# quote / delimiter has to follow immediately.
_KEY_PREFIXED = rf'[\w.]*(?:{_KEY_ALT})'

# "key": "value"  /  "key":"value"  (JSON)
# Value class is `(?:\\.|[^"\\])*`, not `[^"]*` -- a value containing an
# escaped quote (`"password":"ab\"cd"`) would otherwise truncate the match at
# that `\"`, leaving the `cd"` fragment after it emitted unredacted. `\\.`
# consumes any backslash-escaped character (so the escaped `"` itself is
# consumed, not treated as the closing quote) before falling through to
# "any non-quote, non-backslash character."
_JSON_KV_RE = re.compile(
    rf'("{_KEY_PREFIXED}"\s*:\s*)"(?:\\.|[^"\\])*"',
    re.IGNORECASE,
)
# key=value up to a delimiter (env files, form bodies, query strings)
_PLAIN_KV_RE = re.compile(
    rf'({_KEY_PREFIXED}\s*[=:]\s*)(?!\s)([^\s&,;"\'<>\n\r]+)',
    re.IGNORECASE,
)

# ── Standalone value patterns (no key needed) ──────────────────
# Email: keep the domain (non-identifying, and useful to a triager for
# telling an internal address apart from a citizen's), mask the local part.
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')

# JWT / bearer-shaped token appearing loose in a body.
_JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b')

# Indonesian mobile numbers: +628xx / 628xx / 08xx.
_ID_PHONE_RE = re.compile(r'(?<![\d/])(?:\+?62|0)8[1-9]\d{6,10}(?![\d/])')

# NIK is exactly 16 digits, NPWP 15. Bounded deliberately to those two
# lengths rather than a generic "long digit run": a 13-digit millisecond
# epoch timestamp is extremely common in these responses and redacting it
# would be a pure false positive that damages the evidence.
_ID_NUMBER_RE = re.compile(r'(?<![\d.-])\d{15,16}(?![\d.-])')

# NPWP in its formatted form: 12.345.678.9-012.345
_NPWP_FMT_RE = re.compile(r'\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b')

# NIK/NPWP grouped with separators for readability -- e.g. "3201 0101 0101
# 0001" or "3201-0101-0101-0001" -- which _ID_NUMBER_RE's contiguous-run
# requirement misses (the separators break it into shorter runs) and which,
# inside a keyed field ("nik": "3201 0101 0101 0001"), _JSON_KV_RE/
# _PLAIN_KV_RE can't fully mask either: _PLAIN_KV_RE's value class stops at
# the first space, masking only the first group and leaving the rest exposed
# right after it. Structurally matches any space/dot/dash-grouped digit
# sequence (so it also still works when it's wrapped in a JSON array value,
# where no keyed pattern applies at all -- quotes/brackets don't block the
# lookarounds below); _redact_grouped_id_number() then only actually masks it
# if the digits, with separators stripped, total exactly 15 or 16 -- same
# length discipline as _ID_NUMBER_RE, so a grouped date, IP address or money
# amount is left alone. Must run before the keyed passes in redact_evidence()
# so they never get a chance to partially consume it first.
_ID_NUMBER_GROUPED_RE = re.compile(r'(?<![\d.-])\d{1,4}(?:[ .-]\d{1,4}){1,6}(?![\d.-])')


def _redact_grouped_id_number(m: "re.Match") -> str:
    digits = re.sub(r'\D', '', m.group(0))
    return _MASK if len(digits) in (15, 16) else m.group(0)


def redact_evidence(text: Optional[str], limit: Optional[int] = None) -> Optional[str]:
    """Mask secrets/PII values in a captured response snippet, preserving the
    surrounding structure so the excerpt still proves what it was captured to
    prove. Order matters: keyed pairs are handled before the standalone
    patterns so a value already masked as `"password": "<REDACTED>"` isn't
    re-processed.

    `limit` truncates AFTER redaction -- truncating first could otherwise cut
    a value mid-token and leave a partial secret that no pattern matches.
    """
    if not text:
        return text

    # Must run before the keyed passes: a space/dot/dash-grouped NIK/NPWP
    # inside a keyed field would otherwise get partially consumed by
    # _PLAIN_KV_RE (which stops at the first space) before this ever sees it.
    out = _ID_NUMBER_GROUPED_RE.sub(_redact_grouped_id_number, text)

    out = _JSON_KV_RE.sub(lambda m: f'{m.group(1)}"{_MASK}"', out)
    out = _PLAIN_KV_RE.sub(lambda m: f"{m.group(1)}{_MASK}", out)

    out = _NPWP_FMT_RE.sub(_MASK, out)
    out = _JWT_RE.sub(_MASK, out)
    out = _EMAIL_RE.sub(lambda m: f"{_MASK}{m.group(1)}", out)
    out = _ID_PHONE_RE.sub(_MASK, out)
    out = _ID_NUMBER_RE.sub(_MASK, out)

    if limit is not None and len(out) > limit:
        out = out[:limit]
    return out

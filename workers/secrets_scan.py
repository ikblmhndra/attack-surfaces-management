"""Shared secrets/endpoint/subdomain extraction for content fetched during scans
(exposed .git files, crawled JavaScript). Kept in one place — alongside
scan_phase.py/scan_state.py's "shared worker-side helper" convention documented
in CLAUDE.md — rather than duplicating the regex set per caller.

Secrets are never returned in full: only a masked value (first 4 + last 4 chars)
plus a SHA-256 hash for correlation. Finding.evidence/proof are returned over the
API to anyone with finding-read access — storing a live credential verbatim would
itself create a new secret-sprawl point in this platform's own database.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List
from urllib.parse import urljoin

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=]{16,64})[\"']"
    ),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "pem_private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,64}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
}

# Adversarial near-misses seen in real markup/JS that a naive regex would flag —
# excluded explicitly rather than tightened patterns that would also miss real hits.
_PLACEHOLDER_MARKERS = ("xxxx", "example", "changeme", "your_api_key", "<key>", "{{", "${")

ENDPOINT_PATTERN = re.compile(r"""["'](/[a-zA-Z0-9_\-/.]{2,200}?)["']""")
SUBDOMAIN_PATTERN = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{1,63}){1,}")


def mask_secret(value: str) -> Dict[str, str]:
    value = value.strip()
    if len(value) <= 8:
        masked = "*" * len(value)
    else:
        masked = f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
    return {
        "masked": masked,
        "sha256": hashlib.sha256(value.encode()).hexdigest(),
    }


def find_secrets(text: str, *, limit: int = 20) -> List[Dict[str, str]]:
    if not text:
        return []
    hits: List[Dict[str, str]] = []
    seen_hashes = set()
    for kind, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            raw = match.group(1) if match.groups() else match.group(0)
            if not raw or any(marker in raw.lower() for marker in _PLACEHOLDER_MARKERS):
                continue
            info = mask_secret(raw)
            if info["sha256"] in seen_hashes:
                continue
            seen_hashes.add(info["sha256"])
            hits.append({"type": kind, **info})
            if len(hits) >= limit:
                return hits
    return hits


def find_endpoints(text: str, base_url: str, *, limit: int = 50) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    seen = set()
    for match in ENDPOINT_PATTERN.finditer(text):
        path = match.group(1)
        if path in seen or path in ("/", "//"):
            continue
        seen.add(path)
        try:
            resolved = urljoin(base_url, path)
        except ValueError:
            continue
        found.append(resolved)
        if len(found) >= limit:
            break
    return found


def find_subdomains(text: str, root_domain: str, *, limit: int = 50) -> List[str]:
    if not text or not root_domain:
        return []
    root_domain = root_domain.lower().strip(".")
    found: List[str] = []
    seen = set()
    for match in SUBDOMAIN_PATTERN.finditer(text):
        candidate = match.group(0).lower().strip(".")
        if candidate == root_domain or not candidate.endswith(f".{root_domain}"):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        found.append(candidate)
        if len(found) >= limit:
            break
    return found

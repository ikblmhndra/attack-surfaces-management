"""Bounded DNS candidate generation for discovery scans."""
from __future__ import annotations

from typing import Iterable


DEFAULT_DNS_WORDS = [
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "login",
    "sso",
    "mail",
    "smtp",
    "vpn",
    "portal",
    "dev",
    "staging",
    "test",
    "uat",
    "qa",
    "beta",
    "cdn",
    "static",
    "assets",
    "files",
    "docs",
    "status",
    "monitor",
    "grafana",
    "jenkins",
    "git",
    "repo",
    "blog",
    "shop",
]

PERMUTATION_PREFIXES = ["dev", "staging", "test", "uat", "qa", "api", "admin"]


def normalize_host(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def generate_bruteforce_hosts(
    domain: str,
    *,
    words: Iterable[str] | None = None,
    max_hosts: int = 100,
) -> list[str]:
    """Generate a bounded wordlist of direct subdomain candidates."""
    domain = normalize_host(domain)
    results: list[str] = []
    seen = set()
    for raw_word in words or DEFAULT_DNS_WORDS:
        word = normalize_host(raw_word).replace(" ", "")
        if not word or "." in word:
            continue
        host = f"{word}.{domain}"
        if host in seen:
            continue
        seen.add(host)
        results.append(host)
        if len(results) >= max_hosts:
            break
    return results


def generate_permutation_hosts(
    domain: str,
    known_hosts: Iterable[str],
    *,
    max_hosts: int = 100,
) -> list[str]:
    """Generate conservative env-style permutations from known host labels."""
    domain = normalize_host(domain)
    suffix = f".{domain}"
    results: list[str] = []
    seen = set()

    for host in known_hosts:
        host = normalize_host(host)
        if not host.endswith(suffix):
            continue
        label = host[: -len(suffix)].split(".")[0]
        if not label or len(label) > 40:
            continue
        for prefix in PERMUTATION_PREFIXES:
            candidates = [f"{prefix}-{label}.{domain}", f"{label}-{prefix}.{domain}"]
            for candidate in candidates:
                if candidate in seen or candidate == host:
                    continue
                seen.add(candidate)
                results.append(candidate)
                if len(results) >= max_hosts:
                    return results
    return results


def dns_fingerprint(record: dict) -> tuple[str, ...]:
    """Stable fingerprint for wildcard DNS comparison."""
    values: list[str] = []
    for key in ("a", "aaaa", "cname"):
        raw = record.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        values.extend(normalize_host(value) for value in raw if value)
    return tuple(sorted(set(values)))

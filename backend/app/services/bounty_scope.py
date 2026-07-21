"""
Bug Bounty pipeline -- scope enforcement.

is_target_in_scope is the single most safety-critical function in this
feature: it gates every module from bounty.probe onward. Workers
re-validate every target against it at execution time, never trusting that
an earlier stage or the API layer already checked -- see CHANGELOG.md for
the full design rationale behind the bug bounty pipeline.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from typing import Any, Iterable
from urllib.parse import urlsplit


def _extract_host(value: str) -> str:
    """Best-effort hostname/IP extraction from a domain, IP, or URL value."""
    if "://" in value:
        host = urlsplit(value).hostname
        return (host or "").lower()
    host = value.split("/", 1)[0].split(":", 1)[0]
    return host.lower().rstrip(".")


def _matches_domain_pattern(host: str, pattern: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    if any(ch in pattern for ch in "*?[]"):
        return fnmatch.fnmatch(host, pattern)
    return host == pattern or host.endswith(f".{pattern}")


def _matches_ip_pattern(host: str, pattern: str) -> bool:
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address in network


def _matches_url_pattern(value: str, pattern: str) -> bool:
    return fnmatch.fnmatch(value, pattern)


def _rule_matches(value: str, host: str, rule: dict[str, Any]) -> bool:
    pattern = str(rule.get("pattern") or "").strip()
    if not pattern:
        return False
    rule_type = str(rule.get("type") or "domain").lower()
    if rule_type == "ip":
        return _matches_ip_pattern(host, pattern)
    if rule_type == "url":
        return _matches_url_pattern(value, pattern)
    return _matches_domain_pattern(host, pattern)


def is_target_in_scope(value: str, scope_rules: Iterable[dict[str, Any]] | None) -> bool:
    """
    Fail-closed scope check for the bug bounty pipeline.

    - No rules defined -> not in scope. Nothing executes against a program
      that hasn't had scope explicitly entered.
    - Explicit out-of-scope rules (in_scope: false) always win over any
      in-scope match, mirroring how real bug bounty programs document carve-
      outs (e.g. "*.example.com in scope, except payments.example.com").
    - Otherwise, in scope only if at least one in_scope: true rule matches.
    """
    value = (value or "").strip()
    rules = [r for r in (scope_rules or []) if isinstance(r, dict)]
    if not value or not rules:
        return False

    host = _extract_host(value)

    for rule in rules:
        if rule.get("in_scope") is False and _rule_matches(value, host, rule):
            return False

    for rule in rules:
        if rule.get("in_scope") is True and _rule_matches(value, host, rule):
            return True

    return False

"""Bounded DNS candidate generation for discovery scans."""
from __future__ import annotations

from typing import Iterable


# 30 words caught only the most obvious cases; max_hosts (default 100) already
# bounds how many of these ever get queried per scan, so it's safe to give it a
# much larger candidate pool to draw the top matches from. Ordered roughly by
# how commonly these appear in real enterprise DNS — most likely hits first,
# since a capped run takes candidates in list order.
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
    # Remote access / infra management
    "remote",
    "ssh",
    "rdp",
    "citrix",
    "cpanel",
    "webdisk",
    "webmail",
    "autodiscover",
    "owa",
    "exchange",
    "ns1",
    "ns2",
    "ns3",
    "mx",
    "mx1",
    "mx2",
    "ftp",
    "sftp",
    "proxy",
    "gateway",
    "gw",
    "lb",
    "firewall",
    "router",
    "switch",
    # Internal / dev tooling commonly exposed by accident
    "internal",
    "intranet",
    "corp",
    "office",
    "vault",
    "consul",
    "nomad",
    "prometheus",
    "kibana",
    "elastic",
    "elasticsearch",
    "logstash",
    "kafka",
    "rabbitmq",
    "redis",
    "db",
    "database",
    "mysql",
    "postgres",
    "mongo",
    "sql",
    "phpmyadmin",
    "adminer",
    "gitlab",
    "github",
    "bitbucket",
    "svn",
    "ci",
    "cd",
    "cicd",
    "build",
    "artifactory",
    "nexus",
    "registry",
    "docker",
    "k8s",
    "kubernetes",
    "rancher",
    "argocd",
    "airflow",
    "jira",
    "confluence",
    "wiki",
    "helpdesk",
    "support",
    "kb",
    "servicedesk",
    # API / gateway / versioning patterns
    "api2",
    "apiv1",
    "apiv2",
    "api-v1",
    "api-v2",
    "graphql",
    "rest",
    "ws",
    "websocket",
    "socket",
    "rpc",
    "grpc",
    "gw-api",
    "public-api",
    "internal-api",
    "partner",
    "partners",
    "integration",
    "webhook",
    "webhooks",
    # Environment / lifecycle variants
    "sandbox",
    "demo",
    "preview",
    "preprod",
    "prod",
    "production",
    "live",
    "old",
    "legacy",
    "new",
    "v1",
    "v2",
    "canary",
    "edge",
    "next",
    # Business / customer-facing
    "store",
    "checkout",
    "payments",
    "pay",
    "billing",
    "invoice",
    "account",
    "accounts",
    "customer",
    "customers",
    "client",
    "clients",
    "partner-portal",
    "my",
    "dashboard",
    "console",
    "manage",
    "manager",
    "cms",
    "cpanel2",
    "m",
    "mobile",
    "web",
    "www2",
    "secure",
    "ssl",
    "cert",
    "id",
    "identity",
    "accounts2",
    "signin",
    "signup",
    "register",
    "forum",
    "community",
    "chat",
    "news",
    "media",
    "images",
    "img",
    "video",
    "download",
    "downloads",
    "upload",
    "uploads",
    "backup",
    "backups",
    "archive",
    "data",
    "analytics",
    "metrics",
    "stats",
    "report",
    "reports",
    "search",
    "smtp2",
    "mail2",
    "email",
    "newsletter",
    "notify",
    "notifications",
    "alerts",
    "cron",
    "jobs",
    "worker",
    "workers",
    "queue",
    "cache",
]

PERMUTATION_PREFIXES = ["dev", "staging", "test", "uat", "qa", "api", "admin"]

# Speculative guess sources: dns_bruteforce (wordlist) and dns_permutation
# (env-prefix variants of already-known labels) have a near-zero real-world hit
# rate (confirmed 0% and ~3.5% respectively across production scan data) unlike
# passive/observed sources (crt.sh, subfinder, wayback, tls_san_mining), where a
# miss can still be a dangling-CNAME/takeover signal worth keeping. A host is
# only pruned when EVERY source that found it is one of these two.
GENERATED_ONLY_SOURCES = frozenset({"dns_bruteforce", "dns_permutation"})


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


def is_unconfirmed_generated_guess(sources: Iterable[str], liveness_status: str | None) -> bool:
    """True when a discovered host should not be promoted to a persistent Asset row.

    Applies only to hosts whose entire discovery evidence is speculative guesses
    (dns_bruteforce/dns_permutation) that never resolved to anything real. A host
    corroborated by any passive/observed source is always kept, regardless of
    liveness, since a miss there can still be takeover-relevant evidence.
    """
    source_set = set(sources or [])
    if not source_set:
        return False
    return source_set <= GENERATED_ONLY_SOURCES and liveness_status == "unresolved"


def dns_fingerprint(record: dict) -> tuple[str, ...]:
    """Stable fingerprint for wildcard DNS comparison."""
    values: list[str] = []
    for key in ("a", "aaaa", "cname"):
        raw = record.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        values.extend(normalize_host(value) for value in raw if value)
    return tuple(sorted(set(values)))

"""
ASM Platform — Bug Bounty pipeline: host-level triage priority.

Every stage of the pipeline is bounded (recon deep-crawls N hosts, auto-promote
approves N subdomains, vulnscan scans N targets) because an unbounded run
against a wide program never finishes. Those bounds are fine; what wasn't fine
is *which* N survived them -- before this module they were plain list slices
over set-derived / unordered-query results, i.e. an arbitrary draw. Confirmed
live against a real 307-subdomain government program: the 50 auto-promoted
targets included three PPDB (school-registration) sites and a veterinary queue
app, while `rootwebadmin`, `pajak`/`bapenda`/`bphtb`/`e-sptpd` (six tax
systems), `lpse` (procurement), `simpeg`/`bkpsdm` (HR), `disdukcapil` (civil
registry), `vpn`, `owncloud` and ~15 `api.*` hosts were never tested at all.

This scores a bare hostname so those bounds keep the most promising hosts
instead of a random subset. Deliberately a coarse tier function, not a
precise ranking: the goal is "don't drop rootwebadmin in favour of
ppdbsmpn13", not to claim tier 1 is empirically worth more than tier 2.
PRIORITY_BUCKETS in bounty_report.py stays the URL-*path* equivalent used by
exploit_worker.py -- these tokens match host labels instead, which is why
this isn't just a reuse of that table.

Two deliberate design choices, both forced by testing against real data:

1. Indonesian public-sector vocabulary sits alongside the English tokens
   (pajak = tax, simpeg/kepegawaian = HR, dukcapil = civil registry,
   lpse = e-procurement). This pipeline's actual programs are Indonesian
   government; an English-only token set scored every one of those "generic".

2. A token matches at the START or the END of a host label, not only as a
   whole label. Real hostnames here glue words together -- `apisimpeg`,
   `disdukcapil`, `cpanel1`, `lasiksso` are all live examples that a
   whole-label-only rule missed. The tradeoff is occasional over-scoring
   (Indonesian `terapi` ends in "api"), which is cheap: a false positive
   only tests a host sooner than ideal, while a false negative drops a real
   admin panel from the run entirely.
"""
import re
from typing import Iterable, Optional

# Tier 0 -- direct-compromise surface: admin panels, identity/SSO, remote
# access, devops tooling. A finding here tends to be game-over rather than
# incremental.
_TIER0_TOKENS = (
    "admin", "administrator", "webadmin", "root", "manage", "manager", "panel",
    "dashboard", "backend", "console",
    "sso", "login", "auth", "oauth", "oidc", "idp", "account", "identity",
    "vpn", "remote", "rdp", "citrix", "ssh", "ftp", "sftp",
    "cpanel", "whm", "plesk", "webdisk", "phpmyadmin", "pma", "adminer",
    "git", "gitlab", "gitea", "jenkins", "sonar", "nexus", "registry",
    "argocd", "rancher", "portainer", "kubernetes", "k8s",
    "grafana", "kibana", "prometheus", "zabbix", "nagios",
    "webmail", "owncloud", "nextcloud",
    "internal", "intranet", "corp", "staff",
)

# Tier 1 -- sensitive business systems (money + personal data). For a
# government program these ARE the crown jewels, so they rank directly below
# the direct-compromise surface.
#
# Ordering note: an earlier revision put dev/staging and api/* above this
# tier. Validated against the real 307-host program that motivated this
# module, that ordering filled 49 of the 50 promotion slots with tier-0/dev/
# api hosts and admitted exactly ONE business system -- `pajak`, `bapenda`,
# `bphtb`, `lpse`, `simpeg` and `disdukcapil` all still missed the cut, i.e.
# it barely improved on the arbitrary draw it replaced. `apithumbnailer` is
# not plausibly worth more than a tax system, so impact wins here.
_TIER1_TOKENS = (
    "pajak", "bapenda", "bphtb", "sptpd", "sppt", "pbb", "retribusi",
    "pendapatan", "keuangan", "bkad", "bpkad",
    "payment", "billing", "invoice", "checkout", "finance",
    "lpse", "eproc", "procurement", "lelang", "tender",
    "simpeg", "kepegawaian", "bkpsdm", "bkpp", "hris", "payroll",
    "dukcapil", "capil", "siak", "kependudukan",
    "simrs", "rsud", "rekammedis", "medical",
)

# Tier 2 -- non-production environments. Classic bug bounty ground: same code
# as prod, routinely weaker auth/config, sometimes seeded with real data.
_TIER2_TOKENS = (
    "dev", "devel", "development", "staging", "stg", "test", "testing",
    "uat", "qa", "demo", "sandbox", "beta", "preprod", "lab",
)

# Tier 3 -- API/service endpoints. Broad surface and where IDOR/authz bugs
# live, but a program's APIs are also reachable via the URLs recon collects
# for the hosts above, so a bare `api.*` host ranks last of the scored tiers.
_TIER3_TOKENS = (
    "api", "apis", "rest", "graphql", "gateway", "svc", "service", "services",
    "rpc", "mobile",
)

_DEFAULT_TIER = 4


def _compile(tokens: Iterable[str]) -> re.Pattern:
    """One alternation matching any token at the start or the end of a host
    label. Trailing digits are tolerated on the end-anchored form so
    `cpanel1`/`owncloud2`/`webhost1`-style numbered hosts still match."""
    alts = []
    for tok in sorted(set(tokens), key=len, reverse=True):
        t = re.escape(tok)
        alts.append(rf"(?:^|[.\-]){t}")        # label-prefix: apisimpeg, cpanel1, devproject
        alts.append(rf"{t}\d*(?:$|[.\-])")     # label-suffix: disdukcapil, lasiksso
    return re.compile("|".join(alts), re.IGNORECASE)


_TIER_PATTERNS = (
    (0, _compile(_TIER0_TOKENS)),
    (1, _compile(_TIER1_TOKENS)),
    (2, _compile(_TIER2_TOKENS)),
    (3, _compile(_TIER3_TOKENS)),
)


def seed_domains_from_scope(scope_rules) -> list:
    """The program's own root domains, derived from its in-scope domain rules
    (`*.example.com` -> `example.com`). Callers that have scope_rules but not
    the recon seed list (vulnscan) use this to get the same seed-stripping
    behaviour host_priority_score expects. Patterns carrying other glob
    characters aren't clean roots and are skipped, matching
    recon_worker.py::_scope_seed_domains."""
    seeds = []
    for rule in scope_rules or []:
        if not isinstance(rule, dict) or not rule.get("in_scope"):
            continue
        if str(rule.get("type", "domain")).lower() != "domain":
            continue
        pattern = str(rule.get("pattern") or "").strip().lower().rstrip(".")
        if pattern.startswith("*."):
            pattern = pattern[2:]
        if pattern and not any(c in pattern for c in "*?[]"):
            seeds.append(pattern)
    return seeds


def _matching_seed(host: str, seeds: Optional[Iterable[str]]) -> Optional[str]:
    """The program seed domain this host belongs to, if any. Longest match
    wins so a program seeded with both `example.com` and `sub.example.com`
    strips the more specific one."""
    if not seeds:
        return None
    if isinstance(seeds, str):
        seeds = (seeds,)  # a bare string would otherwise iterate per-character
    best = None
    for raw in seeds:
        seed = (raw or "").strip().lower().rstrip(".")
        if not seed:
            continue
        if host == seed or host.endswith(f".{seed}"):
            if best is None or len(seed) > len(best):
                best = seed
    return best


def host_priority_score(host: str, seed_domains: Optional[Iterable[str]] = None) -> int:
    """Triage tier for a hostname -- LOWER sorts first, matching the
    `0 = high value` convention exploit_worker.py::_priority_score already
    uses for URLs.

    `seed_domains` (the program's own root domains) does two things: it pins
    a seed itself and its `www.` form to tier 0 (the main site is the one
    host that should never be silently dropped from a bounded run, and it
    rarely matches a keyword on its own -- `tangerangselatankota.go.id` looks
    generic), and it strips the registrable part before matching so a keyword
    inside the organisation's own domain can't score every host in the
    program identically.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return _DEFAULT_TIER

    label_part = host
    seed = _matching_seed(host, seed_domains)
    if seed:
        if host == seed or host == f"www.{seed}":
            return 0
        label_part = host[: -(len(seed) + 1)]

    for tier, pattern in _TIER_PATTERNS:
        if pattern.search(label_part):
            return tier
    return _DEFAULT_TIER


def host_sort_key(host: str, seed_domains: Optional[Iterable[str]] = None):
    """Sort key for bounded host selection: priority tier first, then the
    hostname itself. The tiebreak is what makes a truncated run *reproducible*
    -- previously the surviving subset came out of set iteration / an
    unordered query, so two runs over identical data could test different
    hosts with no way to tell why."""
    return (host_priority_score(host, seed_domains), (host or "").lower())

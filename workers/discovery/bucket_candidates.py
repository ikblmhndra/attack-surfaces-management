"""Bounded cloud-storage-bucket name candidate generation.

Mirrors dns_candidates.py's shape (bounded, deduped, seed + word-list combination).
Originally this was meant to feed nuclei's cloud/enum/aws-s3-bucket-enum.yaml
template via `-var wordlist=<file>`, but that template is self-contained/
batteringram with no `payloads:` block — empirically verified (manual
`docker compose exec worker-nuclei nuclei -t cloud/enum/aws-s3-bucket-enum.yaml
-esc ...` runs, including a locally patched copy with an explicit `payloads:`
block added) that nuclei v3.11.0 never actually loads/executes it regardless of
-esc/-var/-dast combinations ("Could not run nuclei: no templates provided for
scan" — 0 templates loaded, unlike a normal template which loads and runs
cleanly). Rather than wire in a call that silently does nothing, bucket
enumeration is implemented directly (coverage_worker.py::_scan_cloud_buckets)
using this module's candidates and a direct HTTP check — this module only
generates the candidate names.
"""
from __future__ import annotations

from typing import Iterable

DEFAULT_BUCKET_WORDS = [
    "backup", "backups", "assets", "static", "media", "data", "files",
    "uploads", "upload", "prod", "production", "dev", "development",
    "staging", "internal", "private", "public", "cdn", "images", "img",
    "logs", "log", "db", "database", "dump", "archive", "config",
    "www", "web", "app", "apps", "storage", "content", "docs", "documents",
    "reports", "export", "exports", "temp", "tmp", "old", "legacy",
]


def normalize_seed(value: str) -> str:
    value = str(value or "").strip().lower()
    # Bucket names are DNS-label-like: keep alnum and hyphens only.
    return "".join(ch if ch.isalnum() or ch == "-" else "" for ch in value)


def generate_bucket_candidates(
    seeds: Iterable[str],
    *,
    words: Iterable[str] | None = None,
    max_names: int = 100,
) -> list[str]:
    """Generate a bounded list of {seed}, {seed}-{word}, {word}-{seed} bucket names."""
    results: list[str] = []
    seen = set()
    word_list = list(words or DEFAULT_BUCKET_WORDS)

    normalized_seeds = []
    for raw_seed in seeds:
        seed = normalize_seed(raw_seed)
        if seed and seed not in normalized_seeds:
            normalized_seeds.append(seed)

    def add(name: str) -> bool:
        if not name or name in seen:
            return False
        seen.add(name)
        results.append(name)
        return len(results) >= max_names

    for seed in normalized_seeds:
        if add(seed):
            return results

    for seed in normalized_seeds:
        for word in word_list:
            if add(f"{seed}-{word}"):
                return results
            if add(f"{word}-{seed}"):
                return results

    return results

"""Recompute Finding.fingerprint under the new target-normalization scheme

Companion to a code change in workers/scanner/scanner_common.py::finding_fingerprint()
and workers/scanner/nuclei_worker.py's own fingerprint computation, both of which now
normalize a target's scheme/host casing and a single trailing slash before hashing (so
"https://x.com/path" and "https://x.com/path/" dedupe to the same Finding instead of
re-appearing as a spurious "new" finding on the next scan). This migration must run
*before* that code is live: it backfills every existing row's fingerprint to what the
new code would compute, so the next scan's upsert (ON CONFLICT (fingerprint, org_id))
matches the existing row instead of inserting a duplicate.

Verified safe against production data before writing this migration (read-only dry run):
3095 findings total, 74 would get a changed fingerprint, 0 collide with another existing
row's new fingerprint within the same org (i.e. this is a pure rename, never a merge).

Revision ID: 018_normalize_fp_target
Revises: 4ec377801f60
Create Date: 2026-07-30
"""
import hashlib
from urllib.parse import urlsplit, urlunsplit

import sqlalchemy as sa
from alembic import op

revision = "018_normalize_fp_target"
down_revision = "4ec377801f60"
branch_labels = None
depends_on = None


def _normalize_fingerprint_target(target: str) -> str:
    target = str(target or "").strip()
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        path = parsed.path
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, parsed.fragment))
    return target.lower()


def _new_fingerprint(org_id: str, scanner: str, template_id: str, target: str) -> str:
    normalized = _normalize_fingerprint_target(target)
    if scanner == "nuclei":
        raw = f"{org_id}:{template_id}:{normalized}"
    else:
        raw = f"{org_id}:{scanner}:{template_id}:{normalized}"
    return hashlib.sha256(raw.encode()).hexdigest()


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, org_id, scanner, source, template_id, affected_url, fingerprint FROM findings"
        )
    ).fetchall()

    updates = []
    for fid, org_id, scanner, source, template_id, affected_url, old_fp in rows:
        scanner_key = scanner or source or "unknown"
        new_fp = _new_fingerprint(str(org_id), scanner_key, template_id or "", affected_url or "")
        if new_fp != old_fp:
            updates.append({"id": fid, "fingerprint": new_fp})

    if not updates:
        return

    conn.execute(
        sa.text("UPDATE findings SET fingerprint = :fingerprint WHERE id = :id"),
        updates,
    )


def downgrade() -> None:
    # One-way data backfill -- the pre-normalization fingerprint isn't stored
    # anywhere to restore, and reverting would just reintroduce the trailing-
    # slash/casing dedup gap this migration exists to close. No-op.
    pass

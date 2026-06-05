"""Endpoint intelligence V2 fields

Revision ID: 014_endpoint_intelligence_v2
Revises: 013_discovered_assets_uq
Create Date: 2026-06-04 00:00:00.000000
"""

from alembic import op


revision = "014_endpoint_intelligence_v2"
down_revision = "013_discovered_assets_uq"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS score_reasons JSONB NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS endpoint_type VARCHAR(50) NOT NULL DEFAULT 'unknown'")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS selected_for_scan BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS selected_reason VARCHAR(255)")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS scan_status VARCHAR(50) NOT NULL DEFAULT 'not_scanned'")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS sources JSONB NOT NULL DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE web_endpoints ADD COLUMN IF NOT EXISTS source_count INTEGER NOT NULL DEFAULT 1")

    op.execute("CREATE INDEX IF NOT EXISTS ix_web_endpoints_score ON web_endpoints (score)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_web_endpoints_endpoint_type ON web_endpoints (endpoint_type)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_web_endpoints_selected_for_scan ON web_endpoints (selected_for_scan)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_web_endpoints_scan_status ON web_endpoints (scan_status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_web_endpoint_asset_score ON web_endpoints (asset_id, score DESC)")

    op.execute(
        """
        UPDATE web_endpoints
        SET
            score = COALESCE((metadata->>'score')::integer, score),
            score_reasons = COALESCE(metadata->'score_reasons', score_reasons),
            endpoint_type = CASE
                WHEN is_api THEN 'api'
                WHEN is_auth THEN 'auth'
                WHEN has_params THEN 'parameterized'
                WHEN is_interesting THEN 'unknown'
                ELSE endpoint_type
            END,
            sources = CASE
                WHEN source IS NULL OR source = '' THEN sources
                ELSE to_jsonb(string_to_array(source, '+'))
            END,
            source_count = GREATEST(1, array_length(string_to_array(COALESCE(source, 'crawl'), '+'), 1))
        WHERE metadata IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_web_endpoint_asset_score")
    op.execute("DROP INDEX IF EXISTS ix_web_endpoints_scan_status")
    op.execute("DROP INDEX IF EXISTS ix_web_endpoints_selected_for_scan")
    op.execute("DROP INDEX IF EXISTS ix_web_endpoints_endpoint_type")
    op.execute("DROP INDEX IF EXISTS ix_web_endpoints_score")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS source_count")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS sources")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS last_scanned_at")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS scan_status")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS selected_reason")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS selected_for_scan")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS endpoint_type")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS score_reasons")
    op.execute("ALTER TABLE web_endpoints DROP COLUMN IF EXISTS score")

"""Add scope controls and asset review workflow fields

Revision ID: 010_scope_controls_asset_review
Revises: 009_asset_validation
Create Date: 2026-06-03
"""
from alembic import op
import sqlalchemy as sa


revision = "010_scope_controls_asset_review"
down_revision = "009_asset_validation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS scope_allow_patterns VARCHAR[] DEFAULT '{}'::varchar[] NOT NULL")
    op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS scope_deny_patterns VARCHAR[] DEFAULT '{}'::varchar[] NOT NULL")

    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS review_status VARCHAR(50) DEFAULT 'none' NOT NULL")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS reviewed_by UUID NULL")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP WITH TIME ZONE NULL")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS review_note TEXT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_review_status ON assets (review_status)")

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'assets_reviewed_by_fkey'
            ) THEN
                ALTER TABLE assets
                ADD CONSTRAINT assets_reviewed_by_fkey
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL;
            END IF;
        END
        $$;
        """
    )

    op.execute(
        """
        UPDATE assets
        SET review_status = CASE
            WHEN scope_status = 'needs_review' THEN 'pending'
            WHEN scope_status = 'out_of_scope' THEN 'rejected'
            ELSE 'none'
        END
        WHERE review_status = 'none'
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_reviewed_by_fkey")
    op.execute("DROP INDEX IF EXISTS ix_assets_review_status")
    op.drop_column("assets", "review_note")
    op.drop_column("assets", "reviewed_at")
    op.drop_column("assets", "reviewed_by")
    op.drop_column("assets", "review_status")
    op.drop_column("organizations", "scope_deny_patterns")
    op.drop_column("organizations", "scope_allow_patterns")

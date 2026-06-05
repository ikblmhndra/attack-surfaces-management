"""Add unique scan finding association

Revision ID: 011_unique_scan_findings
Revises: 010_scope_controls_asset_review
Create Date: 2026-06-04
"""
from alembic import op


revision = "011_unique_scan_findings"
down_revision = "010_scope_controls_asset_review"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        WITH ranked AS (
            SELECT
                id,
                row_number() OVER (
                    PARTITION BY scan_id, finding_id
                    ORDER BY created_at ASC, id ASC
                ) AS row_num
            FROM scan_findings
        )
        DELETE FROM scan_findings sf
        USING ranked r
        WHERE sf.id = r.id
          AND r.row_num > 1
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_scan_findings_scan_finding'
            ) THEN
                ALTER TABLE scan_findings
                ADD CONSTRAINT uq_scan_findings_scan_finding
                UNIQUE (scan_id, finding_id);
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scan_findings DROP CONSTRAINT IF EXISTS uq_scan_findings_scan_finding")

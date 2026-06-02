"""Add organization auto scan setting

Revision ID: 005_org_auto_scan
Revises: 004_unique_finding_fp
Create Date: 2026-06-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "005_org_auto_scan"
down_revision = "004_unique_finding_fp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE organizations "
        "ADD COLUMN IF NOT EXISTS auto_scan_enabled BOOLEAN DEFAULT true"
    )
    op.execute("UPDATE organizations SET auto_scan_enabled = true WHERE auto_scan_enabled IS NULL")
    op.alter_column("organizations", "auto_scan_enabled", nullable=False, server_default=None)


def downgrade() -> None:
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS auto_scan_enabled")

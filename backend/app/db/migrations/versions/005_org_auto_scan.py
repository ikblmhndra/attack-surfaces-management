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
    op.add_column(
        "organizations",
        sa.Column("auto_scan_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.alter_column("organizations", "auto_scan_enabled", server_default=None)


def downgrade() -> None:
    op.drop_column("organizations", "auto_scan_enabled")

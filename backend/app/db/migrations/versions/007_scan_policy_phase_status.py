"""Add scan policy and phase status fields

Revision ID: 007_scan_policy_phase_status
Revises: 006_web_endpoints
Create Date: 2026-06-02 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "007_scan_policy_phase_status"
down_revision = "006_web_endpoints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE organizations "
        "ADD COLUMN IF NOT EXISTS scan_policy JSONB DEFAULT '{}'::jsonb"
    )
    op.execute("UPDATE organizations SET scan_policy = '{}'::jsonb WHERE scan_policy IS NULL")
    op.alter_column("organizations", "scan_policy", nullable=False, server_default=None)

    op.execute(
        "ALTER TABLE scans "
        "ADD COLUMN IF NOT EXISTS phase_status JSONB DEFAULT '{}'::jsonb"
    )
    op.execute("UPDATE scans SET phase_status = '{}'::jsonb WHERE phase_status IS NULL")
    op.alter_column("scans", "phase_status", nullable=False, server_default=None)


def downgrade() -> None:
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS phase_status")
    op.execute("ALTER TABLE organizations DROP COLUMN IF EXISTS scan_policy")

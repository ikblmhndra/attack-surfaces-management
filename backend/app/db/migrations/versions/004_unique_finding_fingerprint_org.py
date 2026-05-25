"""Add unique finding fingerprint per organization

Revision ID: 004_unique_finding_fp
Revises: 003_outbox_events
Create Date: 2026-05-25 00:00:00.000000
"""
from alembic import op


revision = "004_unique_finding_fp"
down_revision = "003_outbox_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_finding_fingerprint", table_name="findings")
    op.create_unique_constraint(
        "uq_finding_fingerprint_org",
        "findings",
        ["fingerprint", "org_id"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_finding_fingerprint_org", "findings", type_="unique")
    op.create_index("ix_finding_fingerprint", "findings", ["fingerprint", "org_id"])

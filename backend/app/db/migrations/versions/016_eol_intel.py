"""Add eol_intel table (endoflife.date product/cycle EOL cache)

Revision ID: 016_eol_intel
Revises: 015_exploit_intel
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "016_eol_intel"
down_revision = "015_exploit_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "eol_intel",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("product", sa.String(length=100), nullable=False),
        sa.Column("cycle", sa.String(length=50), nullable=False),
        sa.Column("eol_date", sa.Date(), nullable=True),
        sa.Column("is_eol", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("latest_version", sa.String(length=50), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("product", "cycle", name="uq_eol_intel_product_cycle"),
    )
    op.create_index("ix_eol_intel_product", "eol_intel", ["product"])


def downgrade() -> None:
    op.drop_index("ix_eol_intel_product", table_name="eol_intel")
    op.drop_table("eol_intel")

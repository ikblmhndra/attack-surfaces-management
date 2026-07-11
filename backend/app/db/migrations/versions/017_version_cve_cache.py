"""Add version_cve_cache table (CIRCL cve.circl.lu product/version CVE cache)

Revision ID: 017_version_cve_cache
Revises: 016_eol_intel
Create Date: 2026-07-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "017_version_cve_cache"
down_revision = "016_eol_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "version_cve_cache",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("product", sa.String(length=100), nullable=False),
        sa.Column("cves", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cached_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("product", name="uq_version_cve_cache_product"),
    )


def downgrade() -> None:
    op.drop_table("version_cve_cache")

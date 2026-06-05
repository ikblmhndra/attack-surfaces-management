"""Add normalized discovered assets inventory

Revision ID: 012_discovered_assets
Revises: 011_unique_scan_findings
Create Date: 2026-06-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "012_discovered_assets"
down_revision = "011_unique_scan_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discovered_assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("value", sa.String(length=2000), nullable=False),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="candidate"),
        sa.Column("selected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("skip_reason", sa.String(length=255), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "asset_type", "value", "source", name="uq_discovered_asset_source"),
    )
    op.create_index("ix_discovered_assets_asset_id", "discovered_assets", ["asset_id"])
    op.create_index("ix_discovered_assets_org_id", "discovered_assets", ["org_id"])
    op.create_index("ix_discovered_assets_scan_id", "discovered_assets", ["scan_id"])
    op.create_index("ix_discovered_assets_scan_source", "discovered_assets", ["scan_id", "source"])
    op.create_index("ix_discovered_assets_workspace_id", "discovered_assets", ["workspace_id"])
    op.create_index("ix_discovered_assets_org_type_status", "discovered_assets", ["org_id", "asset_type", "status"])


def downgrade() -> None:
    op.drop_index("ix_discovered_assets_org_type_status", table_name="discovered_assets")
    op.drop_index("ix_discovered_assets_workspace_id", table_name="discovered_assets")
    op.drop_index("ix_discovered_assets_scan_source", table_name="discovered_assets")
    op.drop_index("ix_discovered_assets_scan_id", table_name="discovered_assets")
    op.drop_index("ix_discovered_assets_org_id", table_name="discovered_assets")
    op.drop_index("ix_discovered_assets_asset_id", table_name="discovered_assets")
    op.drop_table("discovered_assets")

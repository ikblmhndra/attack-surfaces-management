"""Add web endpoints table

Revision ID: 006_web_endpoints
Revises: 005_org_auto_scan
Create Date: 2026-06-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "006_web_endpoints"
down_revision = "005_org_auto_scan"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(2000), nullable=False),
        sa.Column("host", sa.String(500), nullable=False),
        sa.Column("path", sa.String(1500), nullable=False, server_default="/"),
        sa.Column("source", sa.String(50), nullable=False, server_default="katana"),
        sa.Column("http_status", sa.Integer()),
        sa.Column("status_class", sa.String(50), nullable=False, server_default="probe_failed"),
        sa.Column("content_type", sa.String(255)),
        sa.Column("content_length", sa.Integer()),
        sa.Column("title", sa.String(500)),
        sa.Column("has_params", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_api", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_auth", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_interesting", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "url", name="uq_web_endpoint_org_url"),
    )
    op.create_index("ix_web_endpoints_asset_id", "web_endpoints", ["asset_id"])
    op.create_index("ix_web_endpoints_org_id", "web_endpoints", ["org_id"])
    op.create_index("ix_web_endpoints_workspace_id", "web_endpoints", ["workspace_id"])
    op.create_index("ix_web_endpoints_host", "web_endpoints", ["host"])
    op.create_index("ix_web_endpoints_status_class", "web_endpoints", ["status_class"])
    op.create_index("ix_web_endpoints_has_params", "web_endpoints", ["has_params"])
    op.create_index("ix_web_endpoints_is_api", "web_endpoints", ["is_api"])
    op.create_index("ix_web_endpoints_is_auth", "web_endpoints", ["is_auth"])
    op.create_index("ix_web_endpoints_is_interesting", "web_endpoints", ["is_interesting"])
    op.create_index("ix_web_endpoint_asset_interesting", "web_endpoints", ["asset_id", "is_interesting"])
    op.create_index("ix_web_endpoint_org_source", "web_endpoints", ["org_id", "source"])


def downgrade() -> None:
    op.drop_table("web_endpoints")

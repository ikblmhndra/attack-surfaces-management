"""Add scan_templates and reports tables

Revision ID: 002_scan_templates_reports
Revises: 001_initial_schema
Create Date: 2024-06-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_scan_templates_reports"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── scan_templates ──────────────────────────────────────────
    op.create_table(
        "scan_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("scan_type", sa.String(50), nullable=False, server_default="full"),
        sa.Column("modules", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("severities", postgresql.ARRAY(sa.String), nullable=False, server_default='{critical,high,medium,low}'),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("is_default", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_templates_workspace", "scan_templates", ["workspace_id"])

    # ── reports ─────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("format", sa.String(20), nullable=False, server_default="json"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("data", postgresql.JSONB),
        sa.Column("file_path", sa.String(500)),
        sa.Column("stats", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("date_range_start", sa.DateTime(timezone=True)),
        sa.Column("date_range_end", sa.DateTime(timezone=True)),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column("error_message", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_report_org_generated", "reports", ["org_id", "generated_at"])
    op.create_index("ix_report_workspace", "reports", ["workspace_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("scan_templates")

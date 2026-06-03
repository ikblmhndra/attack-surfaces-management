"""Add durable scan observability tables

Revision ID: 008_scan_observability
Revises: 007_scan_policy_phase_status
Create Date: 2026-06-03 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "008_scan_observability"
down_revision = "007_scan_policy_phase_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_phase_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("expected_tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed_tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_tasks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("targets_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("targets_selected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("targets_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warnings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scan_id", "phase", name="uq_scan_phase_runs_scan_phase"),
    )
    op.create_index("ix_scan_phase_runs_scan", "scan_phase_runs", ["scan_id"])
    op.create_index("ix_scan_phase_runs_workspace", "scan_phase_runs", ["workspace_id"])

    op.create_table(
        "scan_target_selections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target", sa.String(2000), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("profile", sa.String(100), nullable=False, server_default=""),
        sa.Column("selected", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("reasons", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("skip_reason", sa.String(255), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scan_id", "phase", "target", "target_type", "profile", name="uq_scan_target_selection"),
    )
    op.create_index("ix_scan_target_selections_scan", "scan_target_selections", ["scan_id"])
    op.create_index("ix_scan_target_selections_workspace", "scan_target_selections", ["workspace_id"])
    op.create_index("ix_scan_target_selections_phase_selected", "scan_target_selections", ["phase", "selected"])


def downgrade() -> None:
    op.drop_index("ix_scan_target_selections_phase_selected", table_name="scan_target_selections")
    op.drop_index("ix_scan_target_selections_workspace", table_name="scan_target_selections")
    op.drop_index("ix_scan_target_selections_scan", table_name="scan_target_selections")
    op.drop_table("scan_target_selections")
    op.drop_index("ix_scan_phase_runs_workspace", table_name="scan_phase_runs")
    op.drop_index("ix_scan_phase_runs_scan", table_name="scan_phase_runs")
    op.drop_table("scan_phase_runs")

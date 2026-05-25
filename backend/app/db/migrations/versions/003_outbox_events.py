"""Add outbox_events table

Revision ID: 003_outbox_events
Revises: 002_scan_templates_reports
Create Date: 2026-05-25 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003_outbox_events"
down_revision = "002_scan_templates_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "outbox_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("headers", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("routing_key", sa.String(255), nullable=True),
        sa.Column("priority", sa.Integer, nullable=False, server_default="5"),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="10"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("aggregate_type", sa.String(100), nullable=True),
        sa.Column("aggregate_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_outbox_events_event_type", "outbox_events", ["event_type"])
    op.create_index("ix_outbox_events_status", "outbox_events", ["status"])
    op.create_index("ix_outbox_events_routing_key", "outbox_events", ["routing_key"])
    op.create_index("ix_outbox_events_next_attempt_at", "outbox_events", ["next_attempt_at"])
    op.create_index("ix_outbox_pending", "outbox_events", ["status", "next_attempt_at"])
    op.create_index("ix_outbox_events_aggregate_type", "outbox_events", ["aggregate_type"])
    op.create_index("ix_outbox_events_aggregate_id", "outbox_events", ["aggregate_id"])


def downgrade() -> None:
    op.drop_table("outbox_events")

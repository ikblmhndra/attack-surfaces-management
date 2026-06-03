"""Add asset validation and scope confidence fields

Revision ID: 009_asset_validation
Revises: 008_scan_observability
Create Date: 2026-06-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "009_asset_validation"
down_revision = "008_scan_observability"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("scope_status", sa.String(50), nullable=False, server_default="in_scope"))
    op.add_column("assets", sa.Column("ownership_confidence", sa.Float(), nullable=False, server_default="1.0"))
    op.add_column("assets", sa.Column("ownership_reason", sa.String(255), nullable=True))
    op.add_column("assets", sa.Column("exposure_status", sa.String(50), nullable=False, server_default="unknown"))
    op.add_column("assets", sa.Column("liveness_status", sa.String(50), nullable=False, server_default="unknown"))
    op.add_column("assets", sa.Column("validation_sources", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"))
    op.add_column("assets", sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_scope_status", "assets", ["scope_status"])
    op.create_index("ix_assets_liveness_status", "assets", ["liveness_status"])
    op.create_index("ix_assets_last_verified", "assets", ["last_verified_at"])
    op.execute(
        """
        UPDATE assets a
        SET
            scope_status = CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM organizations o, unnest(coalesce(o.root_domains, '{}') || coalesce(o.domains, '{}')) root
                    WHERE o.id = a.org_id
                    AND (lower(a.value) = lower(root) OR lower(a.value) LIKE '%.' || lower(root))
                ) THEN 'in_scope'
                ELSE 'needs_review'
            END,
            ownership_confidence = CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM organizations o, unnest(coalesce(o.root_domains, '{}') || coalesce(o.domains, '{}')) root
                    WHERE o.id = a.org_id
                    AND (lower(a.value) = lower(root) OR lower(a.value) LIKE '%.' || lower(root))
                ) THEN 0.9
                ELSE 0.45
            END,
            ownership_reason = 'historical subdomain asset backfilled from organization scope',
            liveness_status = CASE
                WHEN s.http_status IS NOT NULL THEN 'alive'
                WHEN array_length(s.ip_addresses, 1) > 0 THEN 'dns_only'
                ELSE 'unknown'
            END,
            exposure_status = CASE
                WHEN s.http_status BETWEEN 200 AND 399 OR s.http_status IN (401, 403) THEN 'exposed'
                WHEN s.http_status IS NOT NULL THEN 'limited'
                ELSE 'unknown'
            END,
            validation_sources = jsonb_build_object(
                'method', 'historical_backfill',
                'reasons', jsonb_build_array('backfilled_from_existing_subdomain_state'),
                'validated_at', now()
            ),
            last_verified_at = now()
        FROM subdomains s
        WHERE a.id = s.asset_id
        """
    )
    op.execute(
        """
        UPDATE assets a
        SET
            scope_status = 'probable',
            ownership_confidence = 0.65,
            ownership_reason = 'historical IP asset discovered from DNS or port scan',
            liveness_status = CASE WHEN ip.open_ports_count > 0 THEN 'alive' ELSE 'dns_only' END,
            exposure_status = CASE WHEN ip.open_ports_count > 0 THEN 'exposed' ELSE 'unknown' END,
            validation_sources = jsonb_build_object(
                'method', 'historical_backfill',
                'reasons', jsonb_build_array('backfilled_from_existing_ip_state'),
                'validated_at', now()
            ),
            last_verified_at = now()
        FROM ip_addresses ip
        WHERE a.id = ip.asset_id
        """
    )


def downgrade() -> None:
    op.drop_index("ix_assets_last_verified", table_name="assets")
    op.drop_index("ix_assets_liveness_status", table_name="assets")
    op.drop_index("ix_assets_scope_status", table_name="assets")
    op.drop_column("assets", "last_verified_at")
    op.drop_column("assets", "validation_sources")
    op.drop_column("assets", "liveness_status")
    op.drop_column("assets", "exposure_status")
    op.drop_column("assets", "ownership_reason")
    op.drop_column("assets", "ownership_confidence")
    op.drop_column("assets", "scope_status")

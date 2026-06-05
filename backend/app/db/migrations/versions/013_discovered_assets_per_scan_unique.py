"""Scope discovered asset uniqueness to each scan

Revision ID: 013_discovered_assets_uq
Revises: 012_discovered_assets
Create Date: 2026-06-04
"""
from alembic import op


revision = "013_discovered_assets_uq"
down_revision = "012_discovered_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("uq_discovered_asset_source", "discovered_assets", type_="unique")
    op.create_unique_constraint(
        "uq_discovered_asset_scan_source",
        "discovered_assets",
        ["scan_id", "asset_type", "value", "source"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_discovered_asset_scan_source", "discovered_assets", type_="unique")
    op.create_unique_constraint(
        "uq_discovered_asset_source",
        "discovered_assets",
        ["org_id", "asset_type", "value", "source"],
    )

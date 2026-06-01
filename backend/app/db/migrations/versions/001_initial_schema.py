"""Initial schema - all tables

Revision ID: 001_initial_schema
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── workspaces ────────────────────────────────────────────
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("plan", sa.String(50), nullable=False, default="free"),
        sa.Column("settings", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("max_organizations", sa.Integer, nullable=False, default=5),
        sa.Column("max_assets", sa.Integer, nullable=False, default=1000),
        sa.Column("max_scans_per_day", sa.Integer, nullable=False, default=10),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index("ix_workspaces_slug", "workspaces", ["slug"])

    # ── users ─────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, default="viewer"),
        sa.Column("avatar_url", sa.String(500)),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("is_verified", sa.Boolean, nullable=False, default=False),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, default=False),
        sa.Column("mfa_secret", sa.String(255)),
        sa.Column("mfa_backup_codes", postgresql.ARRAY(sa.String)),
        sa.Column("last_login", sa.DateTime(timezone=True)),
        sa.Column("last_login_ip", sa.String(45)),
        sa.Column("refresh_token_hash", sa.String(255)),
        sa.Column("refresh_token_expires", sa.DateTime(timezone=True)),
        sa.Column("preferences", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("workspace_id", "email", name="uq_user_workspace_email"),
    )
    op.create_index("ix_users_workspace_id", "users", ["workspace_id"])
    op.create_index("ix_users_email", "users", ["email"])

    # ── api_keys ──────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_ip", sa.String(45)),
        sa.Column("usage_count", sa.Integer, nullable=False, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── audit_logs ────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_id", sa.String(255)),
        sa.Column("changes", postgresql.JSONB),
        sa.Column("metadata", postgresql.JSONB),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("user_agent", sa.String(500)),
        sa.Column("severity", sa.String(20), nullable=False, default="info"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_workspace_created", "audit_logs", ["workspace_id", "created_at"])
    op.create_index("ix_audit_action", "audit_logs", ["action"])

    # ── organizations ─────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("domains", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("root_domains", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("ip_ranges", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("asns", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("company_name", sa.String(255)),
        sa.Column("industry", sa.String(100)),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("labels", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("criticality", sa.Integer, nullable=False, default=3),
        sa.Column("environment", sa.String(50), nullable=False, default="production"),
        sa.Column("total_assets", sa.Integer, nullable=False, default=0),
        sa.Column("total_findings", sa.Integer, nullable=False, default=0),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("is_monitoring_active", sa.Boolean, nullable=False, default=True),
        sa.Column("auto_scan_enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("workspace_id", "slug", name="uq_org_workspace_slug"),
    )
    op.create_index("ix_org_workspace_active", "organizations", ["workspace_id", "deleted_at"])

    # ── assets ────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="active"),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("labels", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("criticality", sa.Integer, nullable=False, default=3),
        sa.Column("environment", sa.String(50)),
        sa.Column("is_in_scope", sa.Boolean, nullable=False, default=True),
        sa.Column("discovery_method", sa.String(100)),
        sa.Column("confidence", sa.Float, nullable=False, default=1.0),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "asset_type", "value", name="uq_asset_org_type_value"),
    )
    op.create_index("ix_asset_org_type", "assets", ["org_id", "asset_type"])
    op.create_index("ix_asset_workspace_type", "assets", ["workspace_id", "asset_type"])
    op.create_index("ix_asset_status", "assets", ["status"])

    # ── subdomains ────────────────────────────────────────────
    op.create_table(
        "subdomains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fqdn", sa.String(500), nullable=False),
        sa.Column("root_domain", sa.String(255), nullable=False),
        sa.Column("is_wildcard", sa.Boolean, nullable=False, default=False),
        sa.Column("ip_addresses", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("cname_chain", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("dns_records", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("http_status", sa.Integer),
        sa.Column("https_status", sa.Integer),
        sa.Column("http_title", sa.String(500)),
        sa.Column("http_server", sa.String(255)),
        sa.Column("content_type", sa.String(255)),
        sa.Column("content_length", sa.Integer),
        sa.Column("response_hash", sa.String(64)),
        sa.Column("redirect_chain", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("security_headers", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("http_headers", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("tls_info", postgresql.JSONB),
        sa.Column("tls_expiry", sa.DateTime(timezone=True)),
        sa.Column("tls_issuer", sa.String(500)),
        sa.Column("tls_subject", sa.String(500)),
        sa.Column("tls_sans", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("tls_version", sa.String(20)),
        sa.Column("technologies", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("cdn_provider", sa.String(100)),
        sa.Column("waf_detected", sa.String(100)),
        sa.Column("cms_detected", sa.String(100)),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_probed", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_subdomains_fqdn", "subdomains", ["fqdn"])
    op.create_index("ix_subdomains_org", "subdomains", ["org_id"])

    # ── ip_addresses ──────────────────────────────────────────
    op.create_table(
        "ip_addresses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, default=4),
        sa.Column("is_private", sa.Boolean, nullable=False, default=False),
        sa.Column("asn", sa.String(20)),
        sa.Column("asn_org", sa.String(255)),
        sa.Column("asn_country", sa.String(10)),
        sa.Column("country_code", sa.String(10)),
        sa.Column("country_name", sa.String(100)),
        sa.Column("city", sa.String(100)),
        sa.Column("region", sa.String(100)),
        sa.Column("latitude", sa.Float),
        sa.Column("longitude", sa.Float),
        sa.Column("timezone", sa.String(100)),
        sa.Column("isp", sa.String(255)),
        sa.Column("cloud_provider", sa.String(100)),
        sa.Column("cloud_region", sa.String(100)),
        sa.Column("is_cdn", sa.Boolean, nullable=False, default=False),
        sa.Column("is_hosting", sa.Boolean, nullable=False, default=False),
        sa.Column("is_vpn", sa.Boolean, nullable=False, default=False),
        sa.Column("is_proxy", sa.Boolean, nullable=False, default=False),
        sa.Column("is_tor", sa.Boolean, nullable=False, default=False),
        sa.Column("open_ports_count", sa.Integer, nullable=False, default=0),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ip_addresses_ip", "ip_addresses", ["ip"])
    op.create_index("ix_ip_addresses_org", "ip_addresses", ["org_id"])

    # ── ports ─────────────────────────────────────────────────
    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ip_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port_number", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(10), nullable=False, default="tcp"),
        sa.Column("state", sa.String(20), nullable=False, default="open"),
        sa.Column("service_name", sa.String(100)),
        sa.Column("service_version", sa.String(255)),
        sa.Column("banner", sa.Text),
        sa.Column("product", sa.String(255)),
        sa.Column("extrainfo", sa.String(500)),
        sa.Column("tls_info", postgresql.JSONB),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("ip_id", "port_number", "protocol", name="uq_port_ip_port_proto"),
    )

    # ── technologies ──────────────────────────────────────────
    op.create_table(
        "technologies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100)),
        sa.Column("category", sa.String(100)),
        sa.Column("confidence", sa.Float, nullable=False, default=1.0),
        sa.Column("detection_method", sa.String(100)),
        sa.Column("metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("first_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "name", "version", name="uq_tech_asset_name_version"),
    )

    # ── findings ──────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("subcategory", sa.String(100)),
        sa.Column("status", sa.String(50), nullable=False, default="open"),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("template_id", sa.String(255)),
        sa.Column("template_url", sa.String(500)),
        sa.Column("scanner", sa.String(100)),
        sa.Column("cve_ids", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("cvss_score", sa.Float),
        sa.Column("cvss_vector", sa.String(200)),
        sa.Column("cwe_ids", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("affected_url", sa.String(1000)),
        sa.Column("evidence", sa.Text),
        sa.Column("request_raw", sa.Text),
        sa.Column("response_raw", sa.Text),
        sa.Column("proof", postgresql.JSONB),
        sa.Column("remediation", sa.Text),
        sa.Column("references", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("is_false_positive", sa.Boolean, nullable=False, default=False),
        sa.Column("false_positive_reason", sa.Text),
        sa.Column("is_risk_accepted", sa.Boolean, nullable=False, default=False),
        sa.Column("risk_acceptance_reason", sa.Text),
        sa.Column("risk_accepted_by", postgresql.UUID(as_uuid=True)),
        sa.Column("risk_accepted_until", sa.DateTime(timezone=True)),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_finding_org_severity", "findings", ["org_id", "severity"])
    op.create_index("ix_finding_org_status", "findings", ["org_id", "status"])
    op.create_index("ix_finding_fingerprint", "findings", ["fingerprint", "org_id"])
    op.create_index("ix_finding_workspace", "findings", ["workspace_id"])

    # ── risk_scores ───────────────────────────────────────────
    op.create_table(
        "risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("overall_score", sa.Integer, nullable=False),
        sa.Column("grade", sa.String(2), nullable=False),
        sa.Column("score_version", sa.String(20), nullable=False, default="1.0"),
        sa.Column("network_security_score", sa.Integer, nullable=False, default=100),
        sa.Column("dns_health_score", sa.Integer, nullable=False, default=100),
        sa.Column("web_security_score", sa.Integer, nullable=False, default=100),
        sa.Column("tls_security_score", sa.Integer, nullable=False, default=100),
        sa.Column("exposure_mgmt_score", sa.Integer, nullable=False, default=100),
        sa.Column("patch_hygiene_score", sa.Integer, nullable=False, default=100),
        sa.Column("info_leakage_score", sa.Integer, nullable=False, default=100),
        sa.Column("reputation_score", sa.Integer, nullable=False, default=100),
        sa.Column("misconfiguration_score", sa.Integer, nullable=False, default=100),
        sa.Column("total_assets", sa.Integer, nullable=False, default=0),
        sa.Column("total_findings", sa.Integer, nullable=False, default=0),
        sa.Column("critical_count", sa.Integer, nullable=False, default=0),
        sa.Column("high_count", sa.Integer, nullable=False, default=0),
        sa.Column("medium_count", sa.Integer, nullable=False, default=0),
        sa.Column("low_count", sa.Integer, nullable=False, default=0),
        sa.Column("info_count", sa.Integer, nullable=False, default=0),
        sa.Column("score_breakdown", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("score_factors", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_risk_org_computed", "risk_scores", ["org_id", "computed_at"])

    # ── scans ─────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="pending"),
        sa.Column("modules", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("total_tasks", sa.Integer, nullable=False, default=0),
        sa.Column("completed_tasks", sa.Integer, nullable=False, default=0),
        sa.Column("failed_tasks", sa.Integer, nullable=False, default=0),
        sa.Column("progress_pct", sa.Float, nullable=False, default=0.0),
        sa.Column("assets_found", sa.Integer, nullable=False, default=0),
        sa.Column("findings_found", sa.Integer, nullable=False, default=0),
        sa.Column("new_assets", sa.Integer, nullable=False, default=0),
        sa.Column("new_findings", sa.Integer, nullable=False, default=0),
        sa.Column("removed_assets", sa.Integer, nullable=False, default=0),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_seconds", sa.Integer),
        sa.Column("error_message", sa.Text),
        sa.Column("error_count", sa.Integer, nullable=False, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_org_status", "scans", ["org_id", "status"])
    op.create_index("ix_scan_workspace_created", "scans", ["workspace_id", "created_at"])

    # ── scan_findings ──────────────────────────────────────────
    op.create_table(
        "scan_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("change_type", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── notification_rules ────────────────────────────────────
    op.create_table(
        "notification_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("event_types", postgresql.ARRAY(sa.String), nullable=False),
        sa.Column("channels", postgresql.ARRAY(sa.String), nullable=False),
        sa.Column("min_severity", sa.String(20), nullable=False, default="high"),
        sa.Column("org_filter", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False, server_default="{}"),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── notifications ─────────────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE")),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("is_read", sa.Boolean, nullable=False, default=False),
        sa.Column("is_sent", sa.Boolean, nullable=False, default=False),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("sent_channels", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_notif_workspace_read", "notifications", ["workspace_id", "is_read"])

    # ── screenshots ───────────────────────────────────────────
    op.create_table(
        "screenshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("url", sa.String(1000), nullable=False),
        sa.Column("storage_path", sa.String(500), nullable=False),
        sa.Column("storage_bucket", sa.String(100), nullable=False, default="screenshots"),
        sa.Column("thumbnail_path", sa.String(500)),
        sa.Column("width", sa.Integer),
        sa.Column("height", sa.Integer),
        sa.Column("file_size", sa.Integer),
        sa.Column("format", sa.String(20), nullable=False, default="png"),
        sa.Column("http_status", sa.Integer),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("is_current", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── threat_intel ──────────────────────────────────────────
    op.create_table(
        "threat_intel",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("indicator_type", sa.String(50), nullable=False),
        sa.Column("data", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("risk_score", sa.Integer),
        sa.Column("is_malicious", sa.Boolean, nullable=False, default=False),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("categories", postgresql.ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("enriched_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "source", name="uq_intel_asset_source"),
    )
    op.create_index("ix_intel_org_malicious", "threat_intel", ["org_id", "is_malicious"])

    # ── asset_relationships ───────────────────────────────────
    op.create_table(
        "asset_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(100), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, default=1.0),
        sa.Column("metadata", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("source_asset_id", "target_asset_id", "relationship_type", name="uq_asset_relationship"),
    )


def downgrade() -> None:
    tables = [
        "asset_relationships", "threat_intel", "screenshots", "notifications",
        "notification_rules", "scan_findings", "scans", "risk_scores",
        "findings", "technologies", "ports", "ip_addresses", "subdomains",
        "assets", "organizations", "audit_logs", "api_keys", "users", "workspaces",
    ]
    for table in tables:
        op.drop_table(table)

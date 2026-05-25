"""
ASM Platform — SQLAlchemy Database Models
Complete schema for all platform entities.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index,
    Integer, String, Text, UniqueConstraint, func, text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def gen_uuid():
    return str(uuid.uuid4())


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


# ============================================================
# WORKSPACE & USERS
# ============================================================

class Workspace(TimestampMixin, Base):
    __tablename__ = "workspaces"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    plan = Column(String(50), nullable=False, default="free")
    settings = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    max_organizations = Column(Integer, nullable=False, default=5)
    max_assets = Column(Integer, nullable=False, default=1000)
    max_scans_per_day = Column(Integer, nullable=False, default=10)

    # Relationships
    users = relationship("User", back_populates="workspace", lazy="selectin")
    organizations = relationship("Organization", back_populates="workspace")
    api_keys = relationship("APIKey", back_populates="workspace")
    notification_rules = relationship("NotificationRule", back_populates="workspace")
    audit_logs = relationship("AuditLog", back_populates="workspace")


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="viewer")  # owner, admin, analyst, viewer
    avatar_url = Column(String(500), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    is_verified = Column(Boolean, nullable=False, default=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_backup_codes = Column(ARRAY(String), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    refresh_token_hash = Column(String(255), nullable=True)
    refresh_token_expires = Column(DateTime(timezone=True), nullable=True)
    preferences = Column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("workspace_id", "email", name="uq_user_workspace_email"),
    )

    # Relationships
    workspace = relationship("Workspace", back_populates="users")
    api_keys = relationship("APIKey", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class APIKey(TimestampMixin, Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(20), nullable=False)  # First 8 chars for identification
    scopes = Column(ARRAY(String), nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    usage_count = Column(Integer, nullable=False, default=0)

    # Relationships
    workspace = relationship("Workspace", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=True, index=True)
    changes = Column(JSONB, nullable=True)
    metadata_ = Column("metadata", JSONB, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    severity = Column(String(20), nullable=False, default="info")

    __table_args__ = (
        Index("ix_audit_workspace_created", "workspace_id", "created_at"),
    )

    # Relationships
    workspace = relationship("Workspace", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")


# ============================================================
# ORGANIZATIONS & TARGETS
# ============================================================

class Organization(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Seed data
    domains = Column(ARRAY(String), nullable=False, default=list)
    root_domains = Column(ARRAY(String), nullable=False, default=list)
    ip_ranges = Column(ARRAY(String), nullable=False, default=list)
    asns = Column(ARRAY(String), nullable=False, default=list)
    company_name = Column(String(255), nullable=True)

    # Classification
    industry = Column(String(100), nullable=True)
    tags = Column(ARRAY(String), nullable=False, default=list)
    labels = Column(JSONB, nullable=False, default=dict)
    criticality = Column(Integer, nullable=False, default=3)  # 1-5
    environment = Column(String(50), nullable=False, default="production")

    # Stats (denormalized for performance)
    total_assets = Column(Integer, nullable=False, default=0)
    total_findings = Column(Integer, nullable=False, default=0)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    is_monitoring_active = Column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("workspace_id", "slug", name="uq_org_workspace_slug"),
        Index("ix_org_workspace_active", "workspace_id", "deleted_at"),
    )

    # Relationships
    workspace = relationship("Workspace", back_populates="organizations")
    assets = relationship("Asset", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
    risk_scores = relationship("RiskScore", back_populates="organization")
    notifications = relationship("Notification", back_populates="organization")
    reports = relationship("Report", back_populates="organization")


# ============================================================
# ASSETS
# ============================================================

class Asset(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Asset identity
    asset_type = Column(String(50), nullable=False, index=True)  # subdomain, ip, cidr, url
    value = Column(String(500), nullable=False, index=True)
    status = Column(String(50), nullable=False, default="active", index=True)

    # Classification
    tags = Column(ARRAY(String), nullable=False, default=list)
    labels = Column(JSONB, nullable=False, default=dict)
    criticality = Column(Integer, nullable=False, default=3)
    environment = Column(String(50), nullable=True)
    is_in_scope = Column(Boolean, nullable=False, default=True)

    # Discovery
    discovery_method = Column(String(100), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)

    # Tracking
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Metadata
    metadata_ = Column("metadata", JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("org_id", "asset_type", "value", name="uq_asset_org_type_value"),
        Index("ix_asset_org_type", "org_id", "asset_type"),
        Index("ix_asset_workspace_type", "workspace_id", "asset_type"),
    )

    # Relationships
    organization = relationship("Organization", back_populates="assets")
    subdomain = relationship("Subdomain", back_populates="asset", uselist=False)
    ip_address = relationship("IPAddress", back_populates="asset", uselist=False)
    technologies = relationship("Technology", back_populates="asset")
    findings = relationship("Finding", back_populates="asset")
    screenshots = relationship("Screenshot", back_populates="asset")
    threat_intel = relationship("ThreatIntel", back_populates="asset")


class Subdomain(TimestampMixin, Base):
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # Domain info
    fqdn = Column(String(500), nullable=False, index=True)
    root_domain = Column(String(255), nullable=False, index=True)
    is_wildcard = Column(Boolean, nullable=False, default=False)

    # DNS records
    ip_addresses = Column(ARRAY(String), nullable=False, default=list)
    cname_chain = Column(ARRAY(String), nullable=False, default=list)
    dns_records = Column(JSONB, nullable=False, default=dict)  # A, AAAA, MX, TXT, NS, etc.

    # HTTP fingerprint
    http_status = Column(Integer, nullable=True)
    https_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    http_server = Column(String(255), nullable=True)
    content_type = Column(String(255), nullable=True)
    content_length = Column(Integer, nullable=True)
    response_hash = Column(String(64), nullable=True)
    redirect_chain = Column(JSONB, nullable=False, default=list)
    security_headers = Column(JSONB, nullable=False, default=dict)
    http_headers = Column(JSONB, nullable=False, default=dict)

    # TLS info
    tls_info = Column(JSONB, nullable=True)
    tls_expiry = Column(DateTime(timezone=True), nullable=True)
    tls_issuer = Column(String(500), nullable=True)
    tls_subject = Column(String(500), nullable=True)
    tls_sans = Column(ARRAY(String), nullable=False, default=list)
    tls_version = Column(String(20), nullable=True)

    # Technologies
    technologies = Column(ARRAY(String), nullable=False, default=list)
    cdn_provider = Column(String(100), nullable=True)
    waf_detected = Column(String(100), nullable=True)
    cms_detected = Column(String(100), nullable=True)

    # Tracking
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_probed = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="subdomain")


class IPAddress(TimestampMixin, Base):
    __tablename__ = "ip_addresses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    # IP info
    ip = Column(String(45), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=4)  # 4 or 6
    is_private = Column(Boolean, nullable=False, default=False)

    # Network intelligence
    asn = Column(String(20), nullable=True, index=True)
    asn_org = Column(String(255), nullable=True)
    asn_country = Column(String(10), nullable=True)

    # Geolocation
    country_code = Column(String(10), nullable=True)
    country_name = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    timezone = Column(String(100), nullable=True)

    # Hosting
    isp = Column(String(255), nullable=True)
    cloud_provider = Column(String(100), nullable=True)  # aws, gcp, azure, etc.
    cloud_region = Column(String(100), nullable=True)
    is_cdn = Column(Boolean, nullable=False, default=False)
    is_hosting = Column(Boolean, nullable=False, default=False)
    is_vpn = Column(Boolean, nullable=False, default=False)
    is_proxy = Column(Boolean, nullable=False, default=False)
    is_tor = Column(Boolean, nullable=False, default=False)

    # Stats
    open_ports_count = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="ip_address")
    ports = relationship("Port", back_populates="ip_address")


class Port(TimestampMixin, Base):
    __tablename__ = "ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_id = Column(UUID(as_uuid=True), ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False, index=True)

    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, default="tcp")
    state = Column(String(20), nullable=False, default="open")
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    product = Column(String(255), nullable=True)
    extrainfo = Column(String(500), nullable=True)
    tls_info = Column(JSONB, nullable=True)

    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("ip_id", "port_number", "protocol", name="uq_port_ip_port_proto"),
        Index("ix_port_number", "port_number"),
    )

    # Relationships
    ip_address = relationship("IPAddress", back_populates="ports")


class Technology(TimestampMixin, Base):
    __tablename__ = "technologies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False, index=True)
    version = Column(String(100), nullable=True)
    category = Column(String(100), nullable=True, index=True)  # cdn, waf, cms, framework, etc.
    confidence = Column(Float, nullable=False, default=1.0)
    detection_method = Column(String(100), nullable=True)
    metadata_ = Column("metadata", JSONB, nullable=False, default=dict)

    first_detected = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_detected = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("asset_id", "name", "version", name="uq_tech_asset_name_version"),
    )

    # Relationships
    asset = relationship("Asset", back_populates="technologies")


# ============================================================
# FINDINGS & VULNERABILITIES
# ============================================================

class Finding(TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Identity
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # SHA256 for dedup

    # Classification
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    category = Column(String(100), nullable=False, index=True)
    subcategory = Column(String(100), nullable=True)
    status = Column(String(50), nullable=False, default="open", index=True)  # open, accepted, false_positive, resolved

    # Source
    source = Column(String(100), nullable=False)  # nuclei, custom, manual, etc.
    template_id = Column(String(255), nullable=True, index=True)
    template_url = Column(String(500), nullable=True)
    scanner = Column(String(100), nullable=True)

    # CVE / CVSS
    cve_ids = Column(ARRAY(String), nullable=False, default=list)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    cwe_ids = Column(ARRAY(String), nullable=False, default=list)

    # Evidence
    affected_url = Column(String(1000), nullable=True)
    evidence = Column(Text, nullable=True)
    request_raw = Column(Text, nullable=True)
    response_raw = Column(Text, nullable=True)
    proof = Column(JSONB, nullable=True)

    # Remediation
    remediation = Column(Text, nullable=True)
    references = Column(ARRAY(String), nullable=False, default=list)

    # Tracking
    is_false_positive = Column(Boolean, nullable=False, default=False)
    false_positive_reason = Column(Text, nullable=True)
    is_risk_accepted = Column(Boolean, nullable=False, default=False)
    risk_acceptance_reason = Column(Text, nullable=True)
    risk_accepted_by = Column(UUID(as_uuid=True), nullable=True)
    risk_accepted_until = Column(DateTime(timezone=True), nullable=True)

    # Time
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_finding_org_severity", "org_id", "severity"),
        Index("ix_finding_org_status", "org_id", "status"),
        UniqueConstraint("fingerprint", "org_id", name="uq_finding_fingerprint_org"),
    )

    # Relationships
    organization = relationship("Organization")
    asset = relationship("Asset", back_populates="findings")
    scan_findings = relationship("ScanFinding", back_populates="finding")


# ============================================================
# RISK SCORING
# ============================================================

class RiskScore(TimestampMixin, Base):
    __tablename__ = "risk_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Overall
    overall_score = Column(Integer, nullable=False)
    grade = Column(String(2), nullable=False)  # A, B, C, D, F
    score_version = Column(String(20), nullable=False, default="1.0")

    # Category scores (each 0-100)
    network_security_score = Column(Integer, nullable=False, default=100)
    dns_health_score = Column(Integer, nullable=False, default=100)
    web_security_score = Column(Integer, nullable=False, default=100)
    tls_security_score = Column(Integer, nullable=False, default=100)
    exposure_mgmt_score = Column(Integer, nullable=False, default=100)
    patch_hygiene_score = Column(Integer, nullable=False, default=100)
    info_leakage_score = Column(Integer, nullable=False, default=100)
    reputation_score = Column(Integer, nullable=False, default=100)
    misconfiguration_score = Column(Integer, nullable=False, default=100)

    # Stats
    total_assets = Column(Integer, nullable=False, default=0)
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)

    # Breakdown
    score_breakdown = Column(JSONB, nullable=False, default=dict)
    score_factors = Column(JSONB, nullable=False, default=list)
    computed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("ix_risk_org_computed", "org_id", "computed_at"),
    )

    # Relationships
    organization = relationship("Organization", back_populates="risk_scores")


# ============================================================
# SCANS
# ============================================================

class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Scan config
    scan_type = Column(String(50), nullable=False)  # full, discovery, vuln, quick
    status = Column(String(50), nullable=False, default="pending", index=True)  # pending, queued, running, completed, failed, cancelled
    modules = Column(ARRAY(String), nullable=False, default=list)
    config = Column(JSONB, nullable=False, default=dict)

    # Progress
    total_tasks = Column(Integer, nullable=False, default=0)
    completed_tasks = Column(Integer, nullable=False, default=0)
    failed_tasks = Column(Integer, nullable=False, default=0)
    progress_pct = Column(Float, nullable=False, default=0.0)

    # Results summary
    assets_found = Column(Integer, nullable=False, default=0)
    findings_found = Column(Integer, nullable=False, default=0)
    new_assets = Column(Integer, nullable=False, default=0)
    new_findings = Column(Integer, nullable=False, default=0)
    removed_assets = Column(Integer, nullable=False, default=0)

    # Timing
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Error handling
    error_message = Column(Text, nullable=True)
    error_count = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_scan_org_status", "org_id", "status"),
        Index("ix_scan_workspace_created", "workspace_id", "created_at"),
    )

    # Relationships
    organization = relationship("Organization", back_populates="scans")
    scan_findings = relationship("ScanFinding", back_populates="scan")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    change_type = Column(String(50), nullable=False)  # new, recurring, resolved
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="scan_findings")
    finding = relationship("Finding", back_populates="scan_findings")


# ============================================================
# OUTBOX EVENTS
# ============================================================

class OutboxEvent(TimestampMixin, Base):
    __tablename__ = "outbox_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False, index=True)
    status = Column(String(50), nullable=False, default="pending", index=True)  # pending, publishing, published, failed
    payload = Column(JSONB, nullable=False, default=dict)
    headers = Column(JSONB, nullable=False, default=dict)
    routing_key = Column(String(255), nullable=True, index=True)
    priority = Column(Integer, nullable=False, default=5)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=10)
    next_attempt_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    published_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    aggregate_type = Column(String(100), nullable=True, index=True)
    aggregate_id = Column(String(255), nullable=True, index=True)

    __table_args__ = (
        Index("ix_outbox_pending", "status", "next_attempt_at"),
    )


# ============================================================
# NOTIFICATIONS
# ============================================================

class NotificationRule(TimestampMixin, Base):
    __tablename__ = "notification_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    event_types = Column(ARRAY(String), nullable=False)
    channels = Column(ARRAY(String), nullable=False)  # email, slack, discord, telegram, webhook
    min_severity = Column(String(20), nullable=False, default="high")
    org_filter = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)  # empty = all
    config = Column(JSONB, nullable=False, default=dict)  # webhook URL, emails, etc.
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    workspace = relationship("Workspace", back_populates="notification_rules")


class Notification(TimestampMixin, Base):
    __tablename__ = "notifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)

    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    payload = Column(JSONB, nullable=False, default=dict)

    is_read = Column(Boolean, nullable=False, default=False, index=True)
    is_sent = Column(Boolean, nullable=False, default=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    sent_channels = Column(ARRAY(String), nullable=False, default=list)

    __table_args__ = (
        Index("ix_notif_workspace_read", "workspace_id", "is_read"),
    )

    # Relationships
    organization = relationship("Organization", back_populates="notifications")


# ============================================================
# SCREENSHOTS & EVIDENCE
# ============================================================

class Screenshot(TimestampMixin, Base):
    __tablename__ = "screenshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    url = Column(String(1000), nullable=False)
    storage_path = Column(String(500), nullable=False)
    storage_bucket = Column(String(100), nullable=False, default="screenshots")
    thumbnail_path = Column(String(500), nullable=True)

    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    file_size = Column(Integer, nullable=True)
    format = Column(String(20), nullable=False, default="png")

    http_status = Column(Integer, nullable=True)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_current = Column(Boolean, nullable=False, default=True, index=True)

    # Relationships
    asset = relationship("Asset", back_populates="screenshots")


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

class ThreatIntel(TimestampMixin, Base):
    __tablename__ = "threat_intel"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    source = Column(String(100), nullable=False, index=True)  # shodan, censys, virustotal, etc.
    indicator_type = Column(String(50), nullable=False)  # ip, domain, url, hash
    data = Column(JSONB, nullable=False, default=dict)
    risk_score = Column(Integer, nullable=True)
    is_malicious = Column(Boolean, nullable=False, default=False)
    tags = Column(ARRAY(String), nullable=False, default=list)
    categories = Column(ARRAY(String), nullable=False, default=list)

    enriched_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("asset_id", "source", name="uq_intel_asset_source"),
        Index("ix_intel_org_malicious", "org_id", "is_malicious"),
    )

    # Relationships
    asset = relationship("Asset", back_populates="threat_intel")


# ============================================================
# ASSET RELATIONSHIPS
# ============================================================

class AssetRelationship(TimestampMixin, Base):
    __tablename__ = "asset_relationships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(100), nullable=False)  # resolves_to, hosted_on, related_to, etc.
    confidence = Column(Float, nullable=False, default=1.0)
    metadata_ = Column("metadata", JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("source_asset_id", "target_asset_id", "relationship_type",
                         name="uq_asset_relationship"),
    )


# ============================================================
# SCAN TEMPLATES
# ============================================================

# ============================================================
# REPORTS
# ============================================================

class Report(TimestampMixin, Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    report_type = Column(String(50), nullable=False)  # executive, detailed, csv_export
    format = Column(String(20), nullable=False, default="json")  # json, csv, pdf
    status = Column(String(20), nullable=False, default="pending")  # pending, generating, completed, failed

    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    data = Column(JSONB, nullable=True)  # Full report data snapshot
    file_path = Column(String(500), nullable=True)  # Path to generated file (for PDF)

    stats = Column(JSONB, nullable=False, default=dict)  # total_assets, total_findings, critical_count, etc.
    date_range_start = Column(DateTime(timezone=True), nullable=True)
    date_range_end = Column(DateTime(timezone=True), nullable=True)
    generated_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_report_org_generated", "org_id", "generated_at"),
    )

    # Relationships
    organization = relationship("Organization", back_populates="reports")


class ScanTemplate(TimestampMixin, Base):
    __tablename__ = "scan_templates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scan_type = Column(String(50), nullable=False, default="full")
    modules = Column(ARRAY(String), nullable=False, default=list)
    config = Column(JSONB, nullable=False, default=dict)
    severities = Column(ARRAY(String), nullable=False, default=["critical", "high", "medium", "low"])
    tags = Column(ARRAY(String), nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    is_default = Column(Boolean, nullable=False, default=False)

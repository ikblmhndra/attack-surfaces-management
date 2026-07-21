"""
ASM Platform — Bug Bounty active-testing pipeline models.

Deliberately independent of the ASM Organization/Asset schema: BountyTarget/
BountyAsset never reference Asset, so nothing passively-discovered elsewhere
can bleed into what's actively testable, and nothing found here bleeds into
the ASM inventory. This is a separate pipeline for authorized bug bounty
engagements (HackerOne/Bugcrowd-sourced targets), not a mode of the ASM
pipeline -- see CHANGELOG.md for the full design rationale.
"""
import uuid

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import relationship, validates

from app.db.models.models import Base, TimestampMixin


def _strip_null_bytes(value):
    """Postgres text/JSONB columns reject \\u0000 outright (asyncpg raises
    UntranslatableCharacterError, not a warning) -- and evidence bodies here
    are frequently raw HTTP response bytes decoded with errors="ignore",
    which passes NUL straight through since it's a valid (if unstorable)
    Unicode code point. Recursing here, once, at the ORM boundary catches
    every producer (nuclei, sensitive-file/XXE/upload checks, future ones)
    without each detection module needing to remember to sanitize its own
    excerpt."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _strip_null_bytes(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_null_bytes(v) for v in value]
    return value


class BountyProgram(TimestampMixin, Base):
    __tablename__ = "bounty_programs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False, default="independent")  # hackerone, bugcrowd, independent
    status = Column(String(20), nullable=False, default="paused", index=True)  # active, paused, closed

    # [{"pattern": "*.example.com", "type": "domain"|"ip"|"url", "in_scope": true}, ...]
    # Explicit out-of-scope entries always beat an in-scope match -- see
    # bounty_scope.py::is_target_in_scope, the safety-critical function that
    # reads this field. Nothing executes unless a target passes this check,
    # re-validated inside the worker itself at execution time.
    scope_rules = Column(JSONB, nullable=False, default=list)

    # sqlmap_level/sqlmap_risk, fuzz_intensity (xss/ssrf/lfi), allowed_extra_tags
    # (nuclei's dos/destructive, off by default), rate_limit_rps,
    # testing_window_start/end -- read by workers/bounty/* at execution time,
    # never hardcoded. Defaults to a conservative policy; escalation requires
    # explicitly setting a field here, never a blanket global.
    rules_of_engagement = Column(JSONB, nullable=False, default=dict)

    # Per-stage run status for UI progress, keyed by stage name (recon/probe/
    # vulnscan/exploit/report): {"recon": {"status": "running"|"queued"|
    # "completed"|"skipped"|"failed", "started_at", "finished_at", "summary",
    # "error", "reason"}, ...}. Set to "queued" by the API on run, then
    # transitioned by the worker (workers/bounty/bounty_stage.py) via a
    # targeted jsonb_set so concurrent stages don't clobber each other.
    stage_status = Column(JSONB, nullable=True)

    created_by = Column(UUID(as_uuid=True), nullable=True)

    targets = relationship("BountyTarget", back_populates="program", cascade="all, delete-orphan")
    assets = relationship("BountyAsset", back_populates="program", cascade="all, delete-orphan")


class BountyTarget(TimestampMixin, Base):
    """A human explicitly added this exact value as in-scope for this
    program. The only thing workers/bounty/exploit_worker.py is ever allowed
    to test -- and even this table isn't trusted alone; every execution
    re-validates against BountyProgram.scope_rules, the enforced source of
    truth. This table is the explicit, human-approved record of intent."""
    __tablename__ = "bounty_targets"
    __table_args__ = (
        UniqueConstraint("program_id", "value", name="uq_bounty_target_program_value"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True)
    value = Column(String(500), nullable=False)
    target_type = Column(String(20), nullable=False, default="domain")  # domain, ip, url
    added_by = Column(UUID(as_uuid=True), nullable=True)

    # Populated by bounty.probe (module 5) -- liveness is intrinsic, volatile
    # state of the target itself, same as Asset.liveness_status in the ASM
    # schema, not a separate history table.
    last_probed_at = Column(DateTime(timezone=True), nullable=True)
    is_alive = Column(Boolean, nullable=True)
    probe_metadata = Column(JSONB, nullable=True)

    program = relationship("BountyProgram", back_populates="targets")


class BountyAsset(TimestampMixin, Base):
    """Recon output (modules 1-4: subdomain enum / URL collection / JS
    analysis / path discovery) -- a suggestion list a human reviews and
    explicitly promotes into BountyTarget. Never auto-promoted: discovery
    silently expanding what's in scope is exactly the failure mode this
    schema separation exists to prevent."""
    __tablename__ = "bounty_assets"
    __table_args__ = (
        UniqueConstraint("program_id", "value", "asset_type", name="uq_bounty_asset_program_value_type"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True)
    value = Column(String(1000), nullable=False)
    asset_type = Column(String(20), nullable=False)  # subdomain, url, js_endpoint, secret
    source = Column(String(50), nullable=False)  # subfinder, amass, waybackurls, gau, katana, subjs, js_analysis, ...
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    promoted = Column(Boolean, nullable=False, default=False)  # true once a human promoted it to BountyTarget

    # Extra context a bare value can't carry -- e.g. which JS file a
    # js_endpoint/secret-pattern hit came from, the secret label matched
    # (never the matched secret text itself), confidence.
    metadata_ = Column("metadata", JSONB, nullable=True)

    program = relationship("BountyProgram", back_populates="assets")


class ExploitAttempt(TimestampMixin, Base):
    __tablename__ = "bounty_exploit_attempts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(UUID(as_uuid=True), ForeignKey("bounty_targets.id", ondelete="CASCADE"), nullable=False, index=True)

    module = Column(String(20), nullable=False)  # nuclei, xss, sqli, ssrf, lfi, idor, csrf
    technique = Column(String(100), nullable=True)  # nuclei template_id, or a tool-specific label otherwise
    severity = Column(String(20), nullable=False, default="info")
    status = Column(String(20), nullable=False, default="inconclusive")  # confirmed, not_vulnerable, inconclusive, blocked

    # Sensitive -- request/response, OOB callback proof, payload used. Same
    # handling care as Finding.evidence/request_raw in the ASM schema. For
    # idor, deliberately minimal (which id/field was reachable, not the full
    # data behind it) -- the module stops at first confirmation rather than
    # continuing to enumerate.
    evidence = Column(JSONB, nullable=True)

    executed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    executed_by = Column(UUID(as_uuid=True), nullable=True)

    @validates("evidence")
    def _validate_evidence(self, key, value):
        return _strip_null_bytes(value)


class BountyReport(TimestampMixin, Base):
    __tablename__ = "bounty_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("bounty_programs.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_ids = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)

    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    steps_to_reproduce = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    status = Column(String(20), nullable=False, default="draft")  # draft, submitted, triaged, resolved, paid
    format = Column(String(20), nullable=False, default="markdown")  # html, markdown

    created_by = Column(UUID(as_uuid=True), nullable=True)

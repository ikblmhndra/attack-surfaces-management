-- ASM Platform — PostgreSQL Initialization
-- Runs once on first container start

-- ── Extensions ────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- Trigram search
CREATE EXTENSION IF NOT EXISTS "btree_gin";     -- GIN indexes for JSONB
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- Query analytics
CREATE EXTENSION IF NOT EXISTS "pgcrypto";      -- Cryptographic functions
CREATE EXTENSION IF NOT EXISTS "inet_ops";      -- CIDR/IP indexing (if available)

-- ── Schema setup ──────────────────────────────────────────────
ALTER DATABASE asmdb SET timezone TO 'UTC';
ALTER DATABASE asmdb SET log_min_duration_statement TO 1000; -- Log slow queries >1s

-- ── Row level security preparation ───────────────────────────
-- Note: RLS enforced at application layer via workspace_id filtering
-- These policies are additional defense-in-depth

-- ── Full text search configuration ───────────────────────────
-- Custom text search for security-related terms
CREATE TEXT SEARCH CONFIGURATION asm_search (COPY = english);

-- ── Utility functions ─────────────────────────────────────────

-- Function to soft-delete and cascade
CREATE OR REPLACE FUNCTION soft_delete_cascade()
RETURNS TRIGGER AS $$
BEGIN
    -- Mark all child assets as deleted when org is deleted
    IF TG_TABLE_NAME = 'organizations' THEN
        UPDATE assets SET deleted_at = NOW() WHERE org_id = OLD.id AND deleted_at IS NULL;
        UPDATE findings SET deleted_at = NOW() WHERE org_id = OLD.id AND deleted_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to update org asset/finding counts
CREATE OR REPLACE FUNCTION update_org_stats()
RETURNS TRIGGER AS $$
DECLARE
    v_org_id UUID;
    v_asset_count INT;
    v_finding_count INT;
BEGIN
    IF TG_TABLE_NAME = 'assets' THEN
        v_org_id := COALESCE(NEW.org_id, OLD.org_id);
    ELSIF TG_TABLE_NAME = 'findings' THEN
        v_org_id := COALESCE(NEW.org_id, OLD.org_id);
    END IF;

    SELECT COUNT(*) INTO v_asset_count
    FROM assets
    WHERE org_id = v_org_id AND deleted_at IS NULL AND status = 'active';

    SELECT COUNT(*) INTO v_finding_count
    FROM findings
    WHERE org_id = v_org_id AND deleted_at IS NULL AND status = 'open';

    UPDATE organizations
    SET total_assets = v_asset_count,
        total_findings = v_finding_count,
        updated_at = NOW()
    WHERE id = v_org_id;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Function: compute finding fingerprint (for dedup)
CREATE OR REPLACE FUNCTION finding_fingerprint(
    p_org_id UUID,
    p_template_id TEXT,
    p_target TEXT
) RETURNS TEXT AS $$
BEGIN
    RETURN encode(
        digest(p_org_id::TEXT || ':' || p_template_id || ':' || lower(trim(p_target)), 'sha256'),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- ── Performance indexes (created after table creation by Alembic) ──
-- These are hints for the migration system

-- Partial indexes for active-only queries
-- CREATE INDEX CONCURRENTLY ix_assets_active ON assets(org_id, asset_type, last_seen)
--     WHERE deleted_at IS NULL AND status = 'active';

-- CREATE INDEX CONCURRENTLY ix_findings_open ON findings(org_id, severity, first_seen)
--     WHERE deleted_at IS NULL AND status = 'open' AND is_false_positive = FALSE;

-- GIN index for JSONB metadata search
-- CREATE INDEX CONCURRENTLY ix_assets_metadata ON assets USING GIN(metadata jsonb_path_ops);
-- CREATE INDEX CONCURRENTLY ix_findings_proof ON findings USING GIN(proof jsonb_path_ops);

-- Trigram index for fuzzy search on asset values
-- CREATE INDEX CONCURRENTLY ix_assets_value_trgm ON assets USING GIN(value gin_trgm_ops);
-- CREATE INDEX CONCURRENTLY ix_subdomains_fqdn_trgm ON subdomains USING GIN(fqdn gin_trgm_ops);

-- Array element search
-- CREATE INDEX CONCURRENTLY ix_subdomains_ips ON subdomains USING GIN(ip_addresses);
-- CREATE INDEX CONCURRENTLY ix_subdomains_techs ON subdomains USING GIN(technologies);

-- ── Partition hints (for high-volume tables) ──────────────────
-- findings and audit_logs should be partitioned by created_at monthly
-- risk_scores should be partitioned by computed_at weekly
-- Screenshots are stored in MinIO, not PG

COMMENT ON DATABASE asmdb IS 'ASM Platform — Attack Surface Management Database';

/**
 * ASM Platform — TypeScript Type Definitions
 */

// ── Common ─────────────────────────────────────────────────────
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Grade    = "A" | "B" | "C" | "D" | "F";
export type Status   = "active" | "inactive";

export interface PaginatedResponse<T> {
  items:     T[];
  total:     number;
  page:      number;
  page_size: number;
  pages:     number;
}

// ── Auth ───────────────────────────────────────────────────────
export interface User {
  id:          string;
  email:       string;
  full_name:   string;
  role:        "owner" | "admin" | "analyst" | "viewer";
  workspace_id: string;
  mfa_enabled: boolean;
  last_login?: string;
  created_at:  string;
}

export interface TokenResponse {
  access_token:  string;
  refresh_token: string;
  token_type:    string;
  expires_in:    number;
  user_id:       string;
  workspace_id:  string;
  role:          string;
}

// ── Workspace ──────────────────────────────────────────────────
export interface Workspace {
  id:               string;
  name:             string;
  slug:             string;
  plan:             string;
  is_active:        boolean;
  max_organizations: number;
  max_assets:       number;
  created_at:       string;
}

// ── Organization ───────────────────────────────────────────────
export interface Organization {
  id:                  string;
  name:                string;
  slug:                string;
  description?:        string;
  domains:             string[];
  root_domains:        string[];
  ip_ranges:           string[];
  asns:                string[];
  company_name?:       string;
  industry?:           string;
  tags:                string[];
  criticality:         number;
  environment:         string;
  total_assets:        number;
  total_findings:      number;
  is_monitoring_active: boolean;
  auto_scan_enabled:   boolean;
  scan_policy?:        Record<string, any>;
  scope_allow_patterns?: string[];
  scope_deny_patterns?:  string[];
  last_scan_at?:       string;
  current_score?:      OrgScoreSummary;
  risk_score?:         OrgRiskScore;
  created_at:          string;
  updated_at:          string;
}

export interface OrgScoreSummary {
  overall:     number;
  grade:       Grade;
  critical:    number;
  high:        number;
  medium:      number;
  computed_at: string;
}

export interface OrgRiskScore {
  overall:        number;
  grade:          Grade;
  category_scores: CategoryScores;
  critical:       number;
  high:           number;
  medium:         number;
  low:            number;
  info:           number;
  computed_at:    string;
  score_factors:  ScoreFactor[];
}

export interface CategoryScores {
  network_security:  CategoryScore;
  dns_health:        CategoryScore;
  web_security:      CategoryScore;
  tls_security:      CategoryScore;
  exposure_mgmt:     CategoryScore;
  patch_hygiene:     CategoryScore;
  info_leakage:      CategoryScore;
  reputation:        CategoryScore;
  misconfiguration:  CategoryScore;
}

export interface CategoryScore {
  score:         number;
  grade:         Grade;
  weight:        number;
  finding_count: number;
  factors:       string[];
}

export interface ScoreFactor {
  category:      string;
  score:         number;
  grade:         Grade;
  impact:        number;
  finding_count: number;
  description:   string;
  factors:       string[];
}

// ── Asset ──────────────────────────────────────────────────────
export type AssetType = "subdomain" | "ip" | "cidr" | "url";

export interface Asset {
  id:               string;
  org_id:           string;
  asset_type:       AssetType;
  value:            string;
  status:           "active" | "inactive";
  scope_status?:    "in_scope" | "probable" | "needs_review" | "out_of_scope";
  ownership_confidence?: number;
  ownership_reason?: string;
  exposure_status?: "exposed" | "limited" | "not_exposed" | "unknown" | "unknown_http";
  liveness_status?: "alive" | "dns_only" | "unresolved" | "unknown";
  validation_sources?: Record<string, any>;
  last_verified_at?: string;
  review_status?:    "none" | "pending" | "approved" | "rejected";
  reviewed_by?:      string;
  reviewed_at?:      string;
  review_note?:      string;
  tags:             string[];
  criticality:      number;
  environment?:     string;
  discovery_method?: string;
  discovery_evidence?: Record<string, any>;
  open_findings:    number;
  first_seen:       string;
  last_seen:        string;
  subdomain?:       SubdomainDetail;
  ip?:              IPDetail;
}

export interface SubdomainDetail {
  fqdn:           string;
  root_domain:    string;
  ip_addresses:   string[];
  http_status?:   number;
  http_status_class?: "ok" | "redirect" | "auth_required" | "not_found" | "rate_limited" | "server_error" | "probe_failed" | "other";
  https_status?:  number;
  title?:         string;
  server?:        string;
  technologies:   string[];
  cdn_provider?:  string;
  waf_detected?:  string;
  tls_expiry?:    string;
  tls_issuer?:    string;
  tls_version?:   string;
  tls_info?:      Record<string, any>;
  dns_records?:   Record<string, any>;
  security_headers?: Record<string, string>;
  redirect_chain?: string[];
  last_probed?:   string;
}

export interface IPDetail {
  ip:             string;
  version:        4 | 6;
  asn?:           string;
  asn_org?:       string;
  asn_country?:   string;
  country_code?:  string;
  country_name?:  string;
  city?:          string;
  isp?:           string;
  cloud_provider?: string;
  cloud_region?:  string;
  is_cdn:         boolean;
  is_hosting:     boolean;
  is_vpn:         boolean;
  is_tor:         boolean;
  latitude?:      number;
  longitude?:     number;
  open_ports_count: number;
}

export interface WebEndpoint {
  id: string;
  asset_id: string;
  org_id: string;
  workspace_id: string;
  url: string;
  host: string;
  path: string;
  source: string;
  http_status?: number;
  status_class: string;
  content_type?: string;
  content_length?: number;
  title?: string;
  has_params: boolean;
  is_api: boolean;
  is_auth: boolean;
  is_interesting: boolean;
  score: number;
  score_reasons: string[];
  endpoint_type: "root" | "api" | "auth" | "admin" | "upload" | "static" | "parameterized" | "graphql" | "swagger" | "health" | "debug" | "unknown";
  selected_for_scan: boolean;
  selected_reason?: string;
  scan_status: "not_scanned" | "queued" | "running" | "completed" | "failed";
  last_scanned_at?: string;
  sources: string[];
  source_count: number;
  metadata?: Record<string, any>;
  last_seen?: string;
}

export interface Port {
  port:      number;
  protocol:  string;
  state:     string;
  service?:  string;
  version?:  string;
  banner?:   string;
  first_seen: string;
  last_seen:  string;
}

export interface Technology {
  id:             string;
  name:           string;
  version?:       string;
  category?:      string;
  confidence:     number;
  first_detected: string;
}

// ── Finding ────────────────────────────────────────────────────
export type FindingStatus = "open" | "resolved" | "false_positive" | "accepted";

export interface Finding {
  id:                   string;
  org_id:               string;
  asset_id?:            string;
  title:                string;
  description?:         string;
  severity:             Severity;
  category:             string;
  subcategory?:         string;
  status:               FindingStatus;
  source:               string;
  template_id?:         string;
  template_url?:        string;
  scanner?:             string;
  cve_ids:              string[];
  cvss_score?:          number;
  cvss_vector?:         string;
  cwe_ids:              string[];
  affected_url?:        string;
  evidence?:            string;
  request_raw?:         string;
  response_raw?:        string;
  proof?:               Record<string, any>;
  remediation?:         string;
  references:           string[];
  is_false_positive:    boolean;
  false_positive_reason?: string;
  is_risk_accepted:     boolean;
  risk_acceptance_reason?: string;
  risk_accepted_until?: string;
  first_seen:           string;
  last_seen:            string;
  resolved_at?:         string;
  // Populated relations
  asset?:               Pick<Asset, "id" | "asset_type" | "value" | "criticality">;
  scan_history?:        ScanHistory[];
}

export interface ScanHistory {
  scan_id:     string;
  change_type: "new" | "recurring" | "resolved";
  detected_at: string;
}

// ── Scan ───────────────────────────────────────────────────────
export type ScanType   = "full" | "quick" | "discovery" | "vuln";
export type ScanStatus = "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";
export type ScanProfile = "safe" | "default" | "deep_authorized" | "endpoint" | "limited";

export interface ScanPhaseStatus {
  status?: string;
  completed?: number;
  expected?: number;
  error?: string;
  profile?: ScanProfile;
  web_standard?: number;
  web_limited?: number;
  crawl?: number;
  network?: number;
  screenshot?: number;
  direct?: number;
  skipped_by_status?: Record<string, number>;
}

export interface Scan {
  id:              string;
  org_id:          string;
  scan_type:       ScanType;
  status:          ScanStatus;
  modules:         string[];
  progress_pct:    number;
  phase_status?:   Record<string, ScanPhaseStatus>;
  total_tasks:     number;
  completed_tasks: number;
  assets_found:    number;
  findings_found:  number;
  new_assets:      number;
  new_findings:    number;
  started_at?:     string;
  completed_at?:   string;
  duration_seconds?: number;
  error_message?:  string;
  created_at:      string;
}

// ── Risk Score ─────────────────────────────────────────────────
export interface RiskScore {
  id:             string;
  org_id:         string;
  overall_score:  number;
  grade:          Grade;
  critical:       number;
  high:           number;
  medium:         number;
  low:            number;
  total_assets:   number;
  total_findings: number;
  computed_at:    string;
}

export interface ScoreHistoryPoint {
  date:    string;
  score:   number;
  grade:   Grade;
  org_id:  string;
}

// ── Notification ───────────────────────────────────────────────
export interface Notification {
  id:           string;
  event_type:   string;
  severity:     Severity;
  title:        string;
  message:      string;
  is_read:      boolean;
  org_id?:      string;
  created_at:   string;
}

export interface NotificationRule {
  id:           string;
  name:         string;
  event_types:  string[];
  channels:     string[];
  min_severity: Severity;
  config:       Record<string, any>;
  is_active:    boolean;
}

// ── Threat Intel ───────────────────────────────────────────────
export interface ThreatIntel {
  id:           string;
  source:       string;
  risk_score?:  number;
  is_malicious: boolean;
  tags:         string[];
  categories:   string[];
  enriched_at:  string;
  expires_at?:  string;
  data:         Record<string, any>;
}

// ── API Key ────────────────────────────────────────────────────
export interface APIKey {
  id:           string;
  name:         string;
  key_prefix:   string;
  scopes:       string[];
  usage_count:  number;
  last_used_at?: string;
  expires_at?:  string;
  created_at:   string;
}

// ── Graph ──────────────────────────────────────────────────────
export interface GraphNode {
  id:        string;
  label:     string;
  type:      "org" | "domain" | "ip" | "port" | "tech" | "finding";
  severity?: Severity;
  data?:     Record<string, any>;
}

export interface GraphEdge {
  id:      string;
  source:  string;
  target:  string;
  label?:  string;
  type?:   string;
}

// ── Search ─────────────────────────────────────────────────────
export interface SearchResult {
  assets:          Asset[];
  findings:        Finding[];
  total:           number;
  assets_total:    number;
  findings_total:  number;
  query:           string;
}

// ── WebSocket events ───────────────────────────────────────────
export type WSEventType =
  | "connected"
  | "ping" | "pong"
  | "scan.started" | "scan.progress" | "scan.completed" | "scan.failed"
  | "finding.new"
  | "score.updated"
  | "asset.new"
  | "alert.created"
  | "system.message";

export interface WSEvent<T = any> {
  type:      WSEventType;
  data:      T;
}

export interface ScanProgressEvent {
  scan_id:      string;
  org_id:       string;
  progress_pct: number;
  status:       ScanStatus;
  message?:     string;
  timestamp:    string;
}

export interface ScoreUpdatedEvent {
  org_id:    string;
  score:     number;
  grade:     Grade;
  delta:     number;
  timestamp: string;
}

// ── Audit Log ──────────────────────────────────────────────────
export interface AuditLog {
  id:            string;
  action:        string;
  resource_type: string;
  resource_id?:  string;
  ip_address?:   string;
  created_at:    string;
}

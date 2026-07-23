# Graph Report - attack-surfaces-management  (2026-07-18)

## Corpus Check
- 220 files · ~201,490 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 3117 nodes · 6375 edges · 264 communities (212 shown, 52 thin omitted)
- Extraction: 83% EXTRACTED · 17% INFERRED · 0% AMBIGUOUS · INFERRED: 1071 edges (avg confidence: 0.68)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `83bd1ecf`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- bounty.py
- api.ts
- get_redis
- get_exploit_intel
- get_eol_status
- index.ts
- User
- BaseWorker
- auth.py
- is_target_in_scope
- NucleiWorker
- Changelog
- cn
- DiscoveryWorker
- web_crawl_worker.py
- TestRiskScoringEngine
- assets.py
- findings.py
- devDependencies
- recon_worker.py
- test_scan_pipeline_state.py
- organizations.py
- AssetValidationWorker
- ScannerCoverageWorker
- exploit_worker.py
- 🛡️ ASM Platform
- Asset
- SeverityBadge.tsx
- ASM Platform — Architecture Documentation
- utils.ts
- discovery_worker.py
- update_scan_phase
- FindingInput
- compilerOptions
- get_session
- risk_engine.py
- TaskCoordinator
- ScreenshotWorker
- security.py
- test_scan_policy.py
- ._discover_subdomains_with_sources
- page.tsx
- page.tsx
- .create_nuclei_asset_scan
- APIKey
- get_matching_cves
- NiktoWorker
- ScanScheduler
- scans.py
- verify_token
- report_service.py
- NotificationWorker
- test_secrets_scan.py
- TestComputeImpactLevel
- TestSeverityPenalty
- _FakeHttpResponse
- notifications.py
- scan_profiles.py
- QueueClient
- generate_api_key
- create_queue_event
- TestParseCvssVector
- QueueClient
- _group_heading
- build_executive_narrative
- PortWorker
- FastAPI
- ScanTemplate
- TestScoreToGrade
- FakeResult
- generate_bucket_candidates
- EnrichmentWorker
- Repository Audit
- auth.py
- Report
- get_password_hash
- 2026-05-25 — Scanning Pipeline Lifecycle & UI Reliability Fixes
- dependencies
- env.py
- test_report_service.py
- TestCombineCriticality
- TestDecayFactor
- version_cve_intel.py
- 2026-05-19 — Pipeline Completion & Screenshot Fixes
- 2026-05-21 — Scanning Pipeline Overhaul: 4 Bug Fixes + Katana/FFUF + Scan Modal
- 2026-07-09 — Milestone 4: Scanning Tool Gaps Closed
- normalize_host
- ._create_scheduled_scan
- database.py
- admin.py
- compute_finding_fingerprint
- EnrichmentEngine
- get_cis_mapping
- TestComputeLikelihoodLevel
- compute_ssvc_boost
- _extract_ssvc
- version_in_range
- 2026-07-10 — Milestone 11: Dashboard Data Audit (9 clarity/data-wiring bugs)
- 2026-07-10 — Milestone 7: Finding Validity & Coverage Gaps
- WSClient
- is_unconfirmed_generated_guess
- Settings
- 2026-05-19 — Auto-Scan Toggle & Progress Bar Fix
- 2026-06-02 — API Timeline Query & Queue Runtime Fixes
- report_templates.py
- search
- workspaces.py
- init_db
- 2026-05-19 — Worker Pipeline Fixes
- 2026-05-21 — Redis Coordinator Fix, Manual Nuclei, Pipeline Finalization
- 2026-06-03 — Scan Pipeline Progress and Result UI
- AssetRelationshipGraph.tsx
- scores.py
- _severity_from_cvss
- 2026-07-09 — Milestone 5: Frontend Hardening
- 2026-07-10 — Milestone 10: Tool Parameter Tuning (+ a pre-existing "quick" scan bug found while tracing it)
- 2026-07-10 — Milestone 6: Scan Pipeline Maturity (Recon → Enumeration → Enrichment → Vuln Scanning)
- opensearch.py
- list_screenshots
- _compare_versions
- _parse_version_tuple
- TestCategoryCoverage
- 2026-06-01 — Organization Automation Controls & Tech-Aware Scanning
- 2026-07-10 — Milestone 12: End-to-End Scan Validation (2 real bugs found via a live scan)
- 2026-07-10 — Milestone 8: Exploit Intelligence (EPSS + CISA KEV)
- 2026-07-12 — Milestone 17: Mining already-collected IP/TLS data for uncovered attack surface
- 2026-07-12 — Milestone 21: Version-to-CVE correlation (highest-risk item of the 4-part plan)
- 2026-07-12 — Risk Engine Redesign, Stage 2: CVSS vector data flow + parser (no formula change)
- 2026-07-12 — Risk Engine Redesign, Stage 3: SSVC (Exploitation/Automatable) escalation
- 2026-07-12 — Risk Engine Redesign, Stage 4 (final): Likelihood × Impact matrix
- 2026-07-13 — Attack-surface graph: fixed relationship data, wired the graph to it
- list_intel
- _build_chart_data
- resolve_vendor_product
- 2026-05-17 — Frontend Build Fixes
- 2026-07-09 — Reporting: Fixed Download + PDF Export
- 2026-07-10 — Milestone 9: Finding Content Freezes on Rescan (and a live nuclei cve_ids bug found via UI QA)
- 2026-07-11 — Milestone 15: End-of-Life Software Enrichment (new scanner-family check)
- 2026-07-12 — Risk Engine Redesign, Stage 1: Asset/Org criticality wired into scoring
- 2026-07-13 — Grouped/deduplicated findings view
- 2026-07-13 — Stop persisting unresolved dns_bruteforce/dns_permutation guesses as Assets
- 2026-07-15 — Bug Bounty pipeline Stage 5: report worker (module 13) + frontend — feature COMPLETE
- changelog.sh
- logging.py
- 2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse
- 2026-06-02 — Core Scan Profile & Target Candidate Engine
- 2026-07-09 — CLAUDE.md Onboarding Doc + Architecture Audit
- 2026-07-09 — Milestone 2: Nuclei/Scanner Phase Status Stuck After Completion
- 2026-07-11 — Milestone 13: Second Live-Scan Validation (kpi.go.id) + risk category-map audit
- 2026-07-12 — Milestone 16: Fixed nuclei's own `*-eol` template categorization (M15 follow-up)
- 2026-07-12 — Milestone 18: "quick"/"vuln" scans have been silently running as deep_authorized
- 2026-07-12 — Milestone 19: API surface coverage — OpenAPI/Swagger spec mining + GraphQL introspection
- 2026-07-13 — CIS Controls v8 compliance report mapping
- 2026-07-13 — Scan change/diff detection ("What Changed Since Last Scan")
- 2026-07-15 — Attack Surface Map: dedupe tech nodes, size by importance, quieter default view
- 2026-07-15 — Bug Bounty pipeline Stage 2: recon + probe workers (modules 1-5)
- 2026-07-15 — Bug Bounty pipeline Stage 3: vulnscan worker (module 6, nuclei)
- 2026-07-15 — Bug Bounty pipeline Stage 4: exploit worker (modules 7-12)
- 2026-07-15 — Frontend consistency pass: DNS Intel, Network Intel, sidebar nav
- 2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API)
- 2026-07-15 — PDF report visual redesign
- .get_by_email
- 2026-05-18 — API Trailing Slash Fix
- 2026-06-02 — Scanner Tool Command Hardening
- 2026-07-15 — Fixed overlapping category labels in report bar charts
- 2026-07-15 — Report executive narrative
- .eslintrc.json
- _endpoint_flags
- .__init__
- class-variance-authority
- cmdk
- d3
- date-fns
- framer-motion
- next.config.js
- next-env.d.ts
- geist
- @hookform/resolvers
- lucide-react
- mapbox-gl
- next
- @radix-ui/react-alert-dialog
- @radix-ui/react-avatar
- @radix-ui/react-collapsible
- @radix-ui/react-dialog
- @radix-ui/react-hover-card
- @radix-ui/react-popover
- @radix-ui/react-progress
- @radix-ui/react-scroll-area
- @radix-ui/react-select
- @radix-ui/react-separator
- @radix-ui/react-slider
- @radix-ui/react-switch
- @radix-ui/react-tabs
- @radix-ui/react-tooltip
- react
- react-cytoscapejs
- react-dom
- react-hook-form
- react-hot-toast
- react-map-gl
- react-resizable-panels
- react-virtuoso
- recharts
- 2026-07-15 — Report executive narrative
- tailwind-merge
- @tanstack/react-query
- @tanstack/react-table
- vaul
- zod
- zustand
- tailwind.config.ts
- __init__.py
- __init__.py
- __init__.py
- 2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API)

## God Nodes (most connected - your core abstractions)
1. `cn()` - 86 edges
2. `get_session()` - 85 edges
3. `Changelog` - 74 edges
4. `DiscoveryWorker` - 59 edges
5. `User` - 51 edges
6. `useWorkspaceStore` - 51 edges
7. `Asset` - 46 edges
8. `TaskCoordinator` - 45 edges
9. `TestRiskScoringEngine` - 43 edges
10. `BaseWorker` - 43 edges

## Surprising Connections (you probably didn't know these)
- `test_tls_san_mining_discards_unrelated_third_party_sans()` --indirect_call--> `DiscoveryWorker`  [INFERRED]
  backend/tests/unit/test_scan_pipeline_state.py → workers/scanner/discovery_worker.py
- `test_reverse_dns_merges_known_ips_with_manual_ranges()` --indirect_call--> `DiscoveryWorker`  [INFERRED]
  backend/tests/unit/test_scan_pipeline_state.py → workers/scanner/discovery_worker.py
- `BountyStageWorker` --uses--> `QueueClient`  [INFERRED]
  workers/bounty/bounty_stage.py → backend/app/core/queue_client.py
- `CorrelationWorker` --uses--> `QueueClient`  [INFERRED]
  workers/correlation/correlation_worker.py → backend/app/core/queue_client.py
- `WebCrawlWorker` --uses--> `QueueClient`  [INFERRED]
  workers/crawler/web_crawl_worker.py → backend/app/core/queue_client.py

## Import Cycles
- None detected.

## Communities (264 total, 52 thin omitted)

### Community 0 - "bounty.py"
Cohesion: 0.10
Nodes (54): _asset_to_dict(), _attempt_to_dict(), create_program(), create_target(), delete_program(), delete_report(), delete_target(), get_program() (+46 more)

### Community 1 - "api.ts"
Cohesion: 0.06
Nodes (48): LoginForm, LoginPage(), loginSchema, RegisterForm, RegisterPage(), registerSchema, DnsPage(), IntelPage() (+40 more)

### Community 2 - "get_redis"
Cohesion: 0.05
Nodes (38): ConnectionManager, emit_new_finding(), emit_scan_progress(), emit_score_updated(), publish_event(), ASM Platform — WebSocket Endpoint Real-time event streaming for scan progress, a, WebSocket connection for real-time platform events.      Authentication via `tok, Manages active WebSocket connections.     Organizes connections by workspace_id (+30 more)

### Community 3 - "get_exploit_intel"
Cohesion: 0.16
Nodes (14): generate_bruteforce_hosts(), generate_permutation_hosts(), is_unconfirmed_generated_guess(), normalize_host(), Bounded DNS candidate generation for discovery scans., Generate a bounded wordlist of direct subdomain candidates., Generate conservative env-style permutations from known host labels., True when a discovered host should not be promoted to a persistent Asset row. (+6 more)

### Community 4 - "get_eol_status"
Cohesion: 0.06
Nodes (30): _cache_product_cycles(), _default_cycle(), _fetch_product_cycles(), get_eol_status(), _is_past(), normalize_cycle(), _openssl_cycle(), _parse_eol_date() (+22 more)

### Community 5 - "index.ts"
Cohesion: 0.04
Nodes (53): AttackSurfacePage(), ClusterRow(), NetworkClusters(), SEVERITY_ORDER, CollapsibleContent(), SeverityBadge(), APIKey, Asset (+45 more)

### Community 6 - "User"
Cohesion: 0.11
Nodes (55): Dependency factory for role-based access control.      Usage:         require_ad, RequireRole, AssetReviewRequest, AssetUpdateRequest, BaseModel, BulkActionRequest, FalsePositiveRequest, FindingUpdateRequest (+47 more)

### Community 7 - "BaseWorker"
Cohesion: 0.05
Nodes (29): ABC, BaseWorker, ASM Platform — Base Worker Abstract base class for all queue-consuming workers., Main entry point. Sets up connections and starts consuming., Touch a heartbeat file while the RabbitMQ connection is alive, so         the Do, Establish RabbitMQ connection with retry., Declare exchanges, queues, and bindings., Gracefully close connection. (+21 more)

### Community 8 - "auth.py"
Cohesion: 0.08
Nodes (54): RateLimiter, Redis-backed rate limiter using sliding window algorithm., change_password(), ChangePasswordRequest, Config, forgot_password(), ForgotPasswordRequest, _get_client_ip() (+46 more)

### Community 9 - "is_target_in_scope"
Cohesion: 0.07
Nodes (17): _extract_host(), is_target_in_scope(), _matches_domain_pattern(), _matches_ip_pattern(), _matches_url_pattern(), Any, Bug Bounty pipeline -- scope enforcement.  is_target_in_scope is the single most, Best-effort hostname/IP extraction from a domain, IP, or URL value. (+9 more)

### Community 10 - "NucleiWorker"
Cohesion: 0.09
Nodes (21): test_map_category_does_not_let_http_prefix_shadow_keyword_match(), test_map_category_resolves_eol_templates(), test_map_category_still_resolves_known_cve_via_tag(), test_nuclei_parse_finding_defaults_cvss_vector_to_none(), test_nuclei_parse_finding_extracts_cvss_vector(), test_nuclei_tech_tags_are_curated(), NucleiWorker, Any (+13 more)

### Community 11 - "Changelog"
Cohesion: 0.04
Nodes (53): 2026-05-22 — Port Worker Race Condition Fix, 2026-06-02 — Repository Audit & Runtime Hardening, 2026-06-02 — Scanner Tool Command Hardening, 2026-06-04 — Discovery Engine V2 Milestone 3 Start, 2026-06-04 — Endpoint Intelligence V2 Milestone 4, 2026-06-05 — Crawl Root Endpoint Coverage, 2026-06-06 — Asset Endpoint Pagination, 2026-06-06 — Nuclei Runtime Tuning (+45 more)

### Community 12 - "cn"
Cohesion: 0.09
Nodes (28): AssetDetailPage(), classifyHttpStatus(), HTTP_STATUS_CONFIG, HttpStatusBadge(), ValidationMetric(), ASSET_TYPE_CONFIG, AssetRow(), AssetsPage() (+20 more)

### Community 13 - "DiscoveryWorker"
Cohesion: 0.11
Nodes (15): DiscoveryWorker, json_safe(), Any, AsyncSession, datetime, Query crt.sh certificate transparency logs with retries., Convert scanner evidence into values PostgreSQL JSONB can serialize., Upsert discovered assets into the database. (+7 more)

### Community 14 - "web_crawl_worker.py"
Cohesion: 0.17
Nodes (12): _endpoint_score(), _endpoint_type(), _normalize_url(), Any, Path, GraphQL introspection query test against already-crawled         graphql-shaped, Fetch already-crawled Swagger/OpenAPI-shaped URLs and, if the         response i, Fetch same-root .js files discovered by the crawl and extract hidden         end (+4 more)

### Community 15 - "TestRiskScoringEngine"
Cohesion: 0.08
Nodes (15): Integration-level tests for the full scoring pipeline., Stage 4: a single "critical" finding's Likelihood x Impact matrix         rating, Milestone 7: confidence must actually move a *category* score through         th, Milestone 8: a KEV-boosted CVE finding must hurt its category score         more, Even 100 critical findings can't push a category below 0., Regression test for the false-negative grade found on a real scan: zero critical, The new HIGH aggregate cap shouldn't fire when there are no HIGH findings at all, Stage 1: identical findings differing only in criticality (1 vs 5)         must (+7 more)

### Community 16 - "assets.py"
Cohesion: 0.13
Nodes (39): _asset_to_dict(), assets_by_type(), assets_new_over_time(), _classify_http_status(), _endpoint_to_dict(), export_assets(), _finding_summary(), get_asset() (+31 more)

### Community 17 - "findings.py"
Cohesion: 0.05
Nodes (57): accept_risk(), bulk_action(), _compute_severity_counts(), export_findings(), _finding_exploit_summary(), _finding_to_dict(), findings_by_category(), findings_trend() (+49 more)

### Community 18 - "devDependencies"
Cohesion: 0.05
Nodes (37): autoprefixer, eslint, eslint-config-next, devDependencies, autoprefixer, eslint, eslint-config-next, postcss (+29 more)

### Community 19 - "recon_worker.py"
Cohesion: 0.05
Nodes (74): check_403_bypass(), check_cors(), check_sensitive_files(), discover_api_specs(), graphql_introspection(), _is_catch_all_200(), Any, ClientSession (+66 more)

### Community 20 - "test_scan_pipeline_state.py"
Cohesion: 0.09
Nodes (30): _FakeSessionDB, _patch_get_session(), Unit tests for scan lifecycle and port persistence safety.  NOTE: this file impo, test_fetch_known_ip_assets_returns_asset_values(), test_fetch_known_tls_sans_flattens_and_dedupes(), test_infer_asset_criticality_high_value_escalates_above_low_org_baseline(), test_infer_asset_criticality_high_value_keyword_escalates(), test_infer_asset_criticality_low_value_beats_high_value_keyword() (+22 more)

### Community 21 - "organizations.py"
Cohesion: 0.14
Nodes (35): create_organization(), delete_organization(), get_attack_surface_graph(), get_attack_surface_timeline(), get_network_clusters(), _get_org_or_404(), get_organization(), get_score_history() (+27 more)

### Community 22 - "AssetValidationWorker"
Cohesion: 0.18
Nodes (18): apply_scope_controls(), _first_pattern_match(), merge_rdap_evidence(), normalize_hostname(), _pattern_matches(), Any, Asset validation and scan-gating helpers., Apply organization explicit allow/deny patterns to validation evidence. (+10 more)

### Community 23 - "ScannerCoverageWorker"
Cohesion: 0.15
Nodes (12): Any, ClientSession, Batch-run tlsx over all hosts for TLS-version/cipher enumeration that         Py, Batch-run subzy against CNAME-narrowed candidates instead of a hardcoded, Brand-based S3 bucket-name enumeration.          cloud/enum/aws-s3-bucket-enum.y, Confirm .git exposure directly (not the keyword-matched nuclei/nikto         gue, Cross-reference already-detected Technology rows (name+version) —         collec, Cross-reference already-detected Technology rows against         cve.circl.lu's (+4 more)

### Community 24 - "exploit_worker.py"
Cohesion: 0.09
Nodes (39): check_oauth_jwt(), _decode_jwt_alg(), idor_bac_probe(), _inject(), _params(), Any, ASM Platform — Bug Bounty pipeline: Phase 3 aggressive-exploit modules.  SSTI, N, POST prototype-pollution and mass-assignment JSON bodies to an endpoint;     fla (+31 more)

### Community 25 - "🛡️ ASM Platform"
Cohesion: 0.06
Nodes (33): 1. Clone & Configure, 2. Generate SSL Certificate, 3. Start the Platform, 4. Access the Platform, Adding Enrichment Sources, Adding Scanner Integrations, API Reference, Architecture (+25 more)

### Community 26 - "Asset"
Cohesion: 0.08
Nodes (24): AsyncOpenSearch, BaseModel, User, UUID, ASM Platform — Search API Endpoint Full-text search across assets and findings u, Full-text search across assets and findings., search(), SearchRequest (+16 more)

### Community 27 - "SeverityBadge.tsx"
Cohesion: 0.10
Nodes (25): columnHelper, FindingsPage(), SEVERITY_ORDER, STATUS_LABELS, ViewMode, FindingDetailModal(), FindingDetailModalProps, GroupedFindingRow() (+17 more)

### Community 28 - "ASM Platform — Architecture Documentation"
Cohesion: 0.07
Nodes (28): 10. API Architecture, 11. Security Model, 12. Deployment Guide, 13. Scaling Guide, 1. System Overview, 2. Architecture Principles, 3. High-Level Architecture, 4. Service Architecture (+20 more)

### Community 29 - "utils.ts"
Cohesion: 0.11
Nodes (7): OrganizationsPage(), CATEGORY_LABELS, RisksPage(), GRADE_COLORS, scoreToColor(), scoreToGrade(), SEVERITY_COLORS

### Community 30 - "discovery_worker.py"
Cohesion: 0.08
Nodes (40): ASM Platform — Web Crawl Worker Combines active crawling (katana), passive URL d, ASM Platform — Worker DB Models Lightweight mirror of backend models for use in, Path, Shared content/directory-fuzzing wordlist for ffuf.  Used by web_crawl_worker.py, Prefer a real installed wordlist (dirb/seclists) if present; otherwise write, resolve_fuzz_wordlist(), _merge_target_selection(), Any (+32 more)

### Community 31 - "update_scan_phase"
Cohesion: 0.16
Nodes (7): Any, QueueClient, ASM Platform — Queue Client (Backend API version) Publishes messages to RabbitMQ, Publish a message to the appropriate exchange., Close the connection., Async RabbitMQ publisher with connection management., Establish connection to RabbitMQ.

### Community 32 - "FindingInput"
Cohesion: 0.11
Nodes (14): compute_org_score(), FindingInput, OrgRiskScore, Any, Input finding for score computation., Complete organization risk score., Core risk scoring engine for ASM Platform.      Algorithm:     1. Group findings, Generate prioritized list of score improvement factors. (+6 more)

### Community 33 - "compilerOptions"
Cohesion: 0.07
Nodes (26): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+18 more)

### Community 34 - "get_session"
Cohesion: 0.14
Nodes (23): get_session(), AsyncSession, Context manager providing an async DB session to workers., dedupe_preserve_order(), Publish port scan and nuclei tasks for discovered assets., Update progress from 75 toward 99 based on nuclei_done / nuclei_expected., persist_findings(), main() (+15 more)

### Community 35 - "risk_engine.py"
Cohesion: 0.19
Nodes (18): compute_criticality_multiplier(), compute_matrix_rating(), ImpactLevel, LikelihoodLevel, MatrixRating, datetime, ASM Platform — Risk Scoring Engine Computes organization security scores across, Asset/org criticality -> penalty multiplier. Falls back to the neutral     3 (-> (+10 more)

### Community 36 - "TaskCoordinator"
Cohesion: 0.14
Nodes (5): ASM Platform — Task Coordinator (Redis-based) Coordinates scan task completion a, Atomically check AND claim the terminal slot. Returns True if caller should send, Non-atomic check — kept for backward compatibility. Prefer mark_terminal_if_all_, Uses Redis counters to track per-scan task progress.      Keys:       scan:{scan, TaskCoordinator

### Community 37 - "ScreenshotWorker"
Cohesion: 0.15
Nodes (8): Any, Clean up browser resources., Capture a screenshot for a single URL., Convert PNG screenshot to WebP for ~30% size reduction., Generate a small thumbnail for preview display., Upload screenshot and thumbnail to MinIO., Captures screenshots of alive HTTP/HTTPS services.      Features:     - Headless, ScreenshotWorker

### Community 38 - "security.py"
Cohesion: 0.11
Nodes (14): compute_asset_fingerprint(), is_valid_asn(), is_valid_cidr(), is_valid_domain(), ASM Platform — Security Utilities JWT creation/validation, password hashing, API, Stable fingerprint for asset deduplication., Normalize a domain name: lowercase, strip whitespace and trailing dots., Normalize an IP address string. (+6 more)

### Community 39 - "test_scan_policy.py"
Cohesion: 0.06
Nodes (49): apply_scan_profile(), build_target_candidates(), child_profile_config(), classify_http_status(), dedupe_preserve_order(), normalize_scan_profile(), profile_config(), Any (+41 more)

### Community 40 - "._discover_subdomains_with_sources"
Cohesion: 0.12
Nodes (21): BountyStageWorker, _now(), _publish_next_stage(), Any, ASM Platform — Bug Bounty pipeline: per-stage run-status tracking.  Writes each, Do the stage's work; return a small summary dict (or         {"skipped": "<reaso, In an auto run, hand off to the next stage. Marks the next stage     'queued' im, Merge `payload` into BountyProgram.stage_status[stage] atomically.      `stage` (+13 more)

### Community 41 - "page.tsx"
Cohesion: 0.09
Nodes (19): BountyProgramDetail(), elapsedLabel(), FindingsTab(), ScopeTab(), SEV_CLS, Stage, StagePill(), STAGES (+11 more)

### Community 42 - "page.tsx"
Cohesion: 0.15
Nodes (18): CATEGORY_LABELS, DashboardPage(), fadeUp, getPhaseLabel(), getScanProgressLabel(), ScanActivityRow(), getActivePhaseKey(), getPhaseDetail() (+10 more)

### Community 43 - ".create_nuclei_asset_scan"
Cohesion: 0.15
Nodes (8): classify_http_status(), ensure_subfinder_provider_config(), Path, Run katana to crawl alive URLs and discover hidden endpoints, JS paths, API rout, Fuzz discovered URLs with ffuf to find hidden endpoints, backups, admin panels., Run httpx to probe alive HTTP/HTTPS services., Run passive/generated discovery and keep per-host source evidence., Populate subfinder's provider-config from whichever premium-source API keys

### Community 44 - "APIKey"
Cohesion: 0.12
Nodes (17): get_current_user(), get_token_payload(), get_workspace_id(), AsyncSession, Request, UUID, ASM Platform — Auth Dependencies FastAPI dependencies for JWT/API key auth and R, Resolve the authenticated user from the token payload. (+9 more)

### Community 45 - "get_matching_cves"
Cohesion: 0.16
Nodes (6): _FakeCacheRow, _FakeDB, _FakeScalarResult, ASM Platform — Unit Tests: Version-to-CVE Correlation (cve.circl.lu) Pure-functi, Only ever needs to answer the initial cache-row SELECT — every test     below ei, TestGetMatchingCves

### Community 46 - "NiktoWorker"
Cohesion: 0.16
Nodes (10): NiktoWorker, Any, Path, Map a nikto finding to platform finding format., Map nikto finding to platform severity., Map nikto finding to platform category., Upsert findings, return list of persisted finding IDs., Find the asset matching a URL. (+2 more)

### Community 47 - "ScanScheduler"
Cohesion: 0.11
Nodes (11): main(), Mark assets as inactive if not seen in 7+ days.         This handles disappeared, Recompute risk scores for orgs whose score is >4 hours old., Central scheduler for all periodic platform tasks:      - Full scans:          E, Re-enrich IPs and domains whose intel is expired., Queue periodic validation for active organizations., Fetch EPSS + CISA KEV (keyless, public) and upsert into         exploit_intel. B, Initialize queue connection and start scheduler. (+3 more)

### Community 48 - "scans.py"
Cohesion: 0.20
Nodes (16): PaginatedResponse, ProgramCreateRequest, ProgramUpdateRequest, BaseModel, ReportUpdateRequest, ScopeRule, TargetCreateRequest, BountyAsset (+8 more)

### Community 49 - "verify_token"
Cohesion: 0.20
Nodes (8): create_access_token(), decode_token_unsafe(), Any, Decode JWT without verifying expiry — for debugging only.     Never use in auth, Create a signed JWT access token.      Claims:         sub: user_id         wid:, Decode and validate a JWT token.     Returns payload dict or None on failure., verify_token(), TestJWTTokens

### Community 50 - "report_service.py"
Cohesion: 0.15
Nodes (22): _build_chart_data(), _build_compliance_section(), _build_report_data(), build_report_summary_text(), _fetch_latest_risk_score(), _finding_to_dict(), generate_report(), _humanize_label() (+14 more)

### Community 51 - "NotificationWorker"
Cohesion: 0.16
Nodes (6): NotificationWorker, Any, AsyncSession, Filter changes that match the notification rule criteria., Route to the appropriate channel sender., Evaluates workspace notification rules against scan change events     and dispat

### Community 52 - "test_secrets_scan.py"
Cohesion: 0.22
Nodes (16): find_endpoints(), find_secrets(), find_subdomains(), mask_secret(), Shared secrets/endpoint/subdomain extraction for content fetched during scans (e, test_dedupes_identical_secrets_by_hash(), test_excludes_documented_example_key(), test_excludes_placeholder_values() (+8 more)

### Community 53 - "TestComputeImpactLevel"
Cohesion: 0.21
Nodes (4): compute_impact_level(), CVSS-driven (NVD's own published Qualitative Severity Rating Scale     boundarie, Stage 4: CVSS-driven (NVD's own Qualitative Severity Rating Scale     boundaries, TestComputeImpactLevel

### Community 54 - "TestSeverityPenalty"
Cohesion: 0.18
Nodes (7): compute_severity_penalty(), Compute penalty points for a single finding.     Uses CVSS score if available fo, Milestone 8: EPSS/KEV exploit intelligence escalates a penalty —         opposit, A boost below 1.0 must not be honored — absence of exploit-intel         data is, Stage 1 of the NIST/OWASP risk-engine redesign: a finding on a         criticali, Unlike exploit_boost, criticality_multiplier is NOT floor-clamped at         1.0, TestSeverityPenalty

### Community 55 - "_FakeHttpResponse"
Cohesion: 0.16
Nodes (7): _FakeHttpResponse, _FakeHttpSession, _patch_aiohttp_session(), test_analyze_api_specs_extracts_routes_from_genuine_spec(), test_analyze_api_specs_rejects_real_world_false_positive(), test_analyze_graphql_endpoints_flags_introspection_enabled(), test_analyze_graphql_endpoints_no_finding_when_disabled()

### Community 56 - "notifications.py"
Cohesion: 0.38
Nodes (15): create_rule(), delete_rule(), list_notifications(), list_rules(), mark_all_read(), mark_notification_read(), NotificationRuleCreate, NotificationRuleUpdate (+7 more)

### Community 57 - "scan_profiles.py"
Cohesion: 0.31
Nodes (3): AssetValidationWorker, Any, UUID

### Community 58 - "QueueClient"
Cohesion: 0.21
Nodes (10): getScanProgressLabel(), OrganizationDetailPage(), SCAN_PROFILES, SCAN_TYPES, ScanModal(), ScanModalProps, ScanProfile, ScanType (+2 more)

### Community 59 - "generate_api_key"
Cohesion: 0.21
Nodes (7): generate_api_key(), hash_token(), Generate a new API key.      Returns:         (raw_key, key_hash, key_prefix), Constant-time comparison of API key hash., SHA-256 hash of a token string (for storage)., verify_api_key(), TestAPIKeyUtils

### Community 60 - "create_queue_event"
Cohesion: 0.19
Nodes (6): _group_heading(), Any, ASM Platform — Finding Grouping (display-only aggregation)  Collapses repeated i, Raw `title` is unsafe as a group-level label for CVE-bearing groups —     it emb, ASM Platform — Unit Tests: Finding Grouping Pure-function tests for the group he, TestGroupHeading

### Community 61 - "TestParseCvssVector"
Cohesion: 0.23
Nodes (6): CvssImpactMetrics, parse_cvss_vector(), Parsed Confidentiality/Integrity/Availability impact + Scope from a     CVSS 3.x, CVSS 3.0/3.1 only — covers ~95% of real nuclei template vectors. CVSS     2.0 (d, Stage 2: CVSS 3.x vector -> C/I/A/Scope, observability only (no     scoring-form, TestParseCvssVector

### Community 62 - "QueueClient"
Cohesion: 0.22
Nodes (6): IncomingMessage, Any, Start consuming messages from the queue., Wrapper: decode, process, ack/nack with retry logic., Process one message and release the worker concurrency slot., Process a single message. Must be implemented by subclasses.

### Community 63 - "_group_heading"
Cohesion: 0.26
Nodes (5): Any, Load all non-excluded findings for scoring., Computes organization risk scores after each scan cycle.      Workflow:     1. L, Publish score update to Redis for WebSocket broadcast., RiskWorker

### Community 64 - "build_executive_narrative"
Cohesion: 0.20
Nodes (5): build_executive_narrative(), Any, ASM Platform — Report executive narrative.  Deterministic, templated prose synth, ASM Platform — Unit Tests: Report Executive Narrative, TestBuildExecutiveNarrative

### Community 65 - "PortWorker"
Cohesion: 0.31
Nodes (4): PortWorker, Any, Path, _tool_path()

### Community 66 - "FastAPI"
Cohesion: 0.17
Nodes (12): ASM Platform — API v1 Router Aggregates all endpoint routers., close_rabbitmq(), get_rabbitmq_channel(), init_rabbitmq(), ASM Platform — RabbitMQ Connection for API, create_application(), lifespan(), ASM Platform — FastAPI Application Entry Point (+4 more)

### Community 67 - "ScanTemplate"
Cohesion: 0.44
Nodes (12): create_template(), delete_template(), get_template(), list_templates(), AsyncSession, BaseModel, User, UUID (+4 more)

### Community 68 - "TestScoreToGrade"
Cohesion: 0.24
Nodes (5): CategoryScore, Score for a single category., Convert numeric score to letter grade., score_to_grade(), TestScoreToGrade

### Community 69 - "FakeResult"
Cohesion: 0.21
Nodes (6): FakeDB, FakeResult, test_mark_scan_completed_does_not_publish_when_scan_not_active(), test_mark_scan_failed_records_error_and_event(), test_mark_scan_running_updates_active_scan(), test_port_worker_uses_ip_address_id_for_ports()

### Community 70 - "generate_bucket_candidates"
Cohesion: 0.28
Nodes (11): generate_bucket_candidates(), normalize_seed(), Bounded cloud-storage-bucket name candidate generation.  Mirrors dns_candidates., Generate a bounded list of {seed}, {seed}-{word}, {word}-{seed} bucket names., test_bounded_by_max_names(), test_empty_seeds_yields_no_candidates(), test_generates_bare_seed_first(), test_generates_seed_word_combinations() (+3 more)

### Community 71 - "EnrichmentWorker"
Cohesion: 0.36
Nodes (3): EnrichmentWorker, Any, datetime

### Community 72 - "Repository Audit"
Cohesion: 0.17
Nodes (11): Checks Run, Fixed During Audit, Next Recommended Work, P1-1: Full Backend Unit Test Collection Is Broken, P1-2: Dependency Security Debt Is High, P1-3: Quality Targets Depend on Tools Missing From Runtime Containers, P1-4: `report.daily` Queue Has No Consumer, Pipeline Observations (+3 more)

### Community 73 - "auth.py"
Cohesion: 0.38
Nodes (5): get_minio(), init_minio(), ASM Platform — MinIO Client Initialization, Minio, Initialize Playwright browser and MinIO client.

### Community 74 - "Report"
Cohesion: 0.39
Nodes (11): download_report(), generate_report(), get_report(), list_reports(), AsyncSession, BackgroundTasks, BaseModel, User (+3 more)

### Community 75 - "get_password_hash"
Cohesion: 0.30
Nodes (6): get_password_hash(), Hash a plaintext password with bcrypt., Verify a plaintext password against its bcrypt hash., verify_password(), bcrypt uses random salt → different hash each time., TestPasswordHashing

### Community 76 - "2026-05-25 — Scanning Pipeline Lifecycle & UI Reliability Fixes"
Cohesion: 0.17
Nodes (12): 2026-05-25 — Scanning Pipeline Lifecycle & UI Reliability Fixes, Added: Focused scan pipeline regression tests, Added: Frontend realtime scan cache updates, Added: Transactional outbox for reliable scan queue publishing, Changed: API and scheduler scan creation now enqueue via outbox, Changed: Scan status and API/UI contract normalized, Fixed: Nuclei scans could run far too long, Fixed: Pipeline terminal coordination ignored port scan completion (+4 more)

### Community 77 - "dependencies"
Cohesion: 0.18
Nodes (11): axios, cytoscape, dependencies, axios, cytoscape, @radix-ui/react-dropdown-menu, @radix-ui/react-toast, sonner (+3 more)

### Community 78 - "env.py"
Cohesion: 0.24
Nodes (10): do_run_migrations(), get_url(), Alembic migration environment for ASM Platform. Supports async SQLAlchemy with P, Run migrations without a live DB connection., Run migrations using async engine., Run migrations with live connection., run_async_migrations(), run_migrations_offline() (+2 more)

### Community 79 - "test_report_service.py"
Cohesion: 0.27
Nodes (10): _date_cutoff(), datetime, _fake_finding(), test_build_chart_data_handles_no_findings_without_division_error(), test_date_cutoff_clamps_negative_days_to_zero(), test_date_cutoff_subtracts_days_from_now(), test_finding_to_dict_handles_missing_evidence(), test_finding_to_dict_includes_evidence_when_requested() (+2 more)

### Community 80 - "TestCombineCriticality"
Cohesion: 0.27
Nodes (5): combine_criticality(), Asset.criticality defaults to 3 until manually set or auto-inferred, so     max(, max(asset, org) — an unclassified asset (default 3) falls back to the     org's, max(), not average — a not-yet-classified low asset shouldn't mute         an or, TestCombineCriticality

### Community 81 - "TestDecayFactor"
Cohesion: 0.27
Nodes (4): compute_decay_factor(), Compute time-based decay factor for a finding.     Newer findings have full weig, ASM Platform — Unit Tests: Risk Scoring Engine Tests for category scoring, decay, TestDecayFactor

### Community 82 - "version_cve_intel.py"
Cohesion: 0.27
Nodes (10): _cache_product(), _extract_cvss(), _extract_record(), _fetch_product_cves(), get_matching_cves(), Any, ASM Platform — Version-to-CVE Correlation (cve.circl.lu)  Keyless, publicly-publ, CVSS commonly lives in containers.adp[].metrics[], not containers.cna     — veri (+2 more)

### Community 83 - "2026-05-19 — Pipeline Completion & Screenshot Fixes"
Cohesion: 0.18
Nodes (11): 2026-05-19 — Pipeline Completion & Screenshot Fixes, Added: Global screenshots gallery endpoint, Added: Vuln depth selection, Fixed: crt.sh 502 errors with retry logic, Fixed: Frontend screenshot field name mismatches, Fixed: NGINX screenshot proxy returning 404/301, Fixed: RabbitMQ `ChannelInvalidStateError` on long scans, Fixed: Redis counter race on scan completion (+3 more)

### Community 84 - "2026-05-21 — Scanning Pipeline Overhaul: 4 Bug Fixes + Katana/FFUF + Scan Modal"
Cohesion: 0.18
Nodes (11): 2026-05-21 — Scanning Pipeline Overhaul: 4 Bug Fixes + Katana/FFUF + Scan Modal, Added: FFUF directory/endpoint fuzzing, Added: Frontend Scan Modal with type + toggles, Added: Katana endpoint crawling, Added: Proper URL scheme routing, Added: Tech-aware nuclei routing, Fixed: Findings never persisted (constraint name mismatch), Fixed: Port worker column/constraint names mismatch (+3 more)

### Community 85 - "2026-07-09 — Milestone 4: Scanning Tool Gaps Closed"
Cohesion: 0.18
Nodes (11): 2026-07-09 — Milestone 4: Scanning Tool Gaps Closed, Added: Real subzy integration for subdomain takeover, Added: Real tlsx integration for weak_cipher / old_tls_version, Fixed: nuclei-templates volume pointed at the wrong path, Fixed: Subfinder never used its own premium-source support, Fixed: Worker healthcheck was a no-op, Fixed: Zero version pinning on every Go-based scanning tool, Found (during rebuild): scheduler's healthcheck went unhealthy after the fix above (+3 more)

### Community 86 - "normalize_host"
Cohesion: 0.62
Nodes (6): create_key(), delete_key(), list_keys(), AsyncSession, User, UUID

### Community 87 - "._create_scheduled_scan"
Cohesion: 0.40
Nodes (5): 2026-07-09 — Milestone 1: Risk Scoring False-Negative Fixed, Added: Aggregate HIGH-severity score cap, Fixed: Exposed DB/remote-admin ports under-rated as medium, Fixed: Nuclei findings falling into the wrong risk category, Verified against real scan data (not just unit tests)

### Community 88 - "database.py"
Cohesion: 0.20
Nodes (9): AsyncEngine, close_db(), get_db_engine(), get_session(), AsyncSession, ASM Platform — Database Connection Management Async SQLAlchemy engine with conne, Dispose database engine and close all connections., Dependency-injectable async database session.     Used as FastAPI dependency via (+1 more)

### Community 89 - "admin.py"
Cohesion: 0.44
Nodes (8): list_audit_logs(), list_users(), AsyncSession, BaseModel, User, UUID, update_user(), UserUpdate

### Community 90 - "compute_finding_fingerprint"
Cohesion: 0.29
Nodes (4): compute_finding_fingerprint(), Stable fingerprint for deduplicating findings.     Same org + template + target, ASM Platform — Unit Tests: Security Utilities Tests for JWT creation/validation,, TestFingerprints

### Community 91 - "EnrichmentEngine"
Cohesion: 0.24
Nodes (5): EnrichmentEngine, EnrichmentResult, Any, ASM Platform - Threat intelligence enrichment compatibility layer.  The active e, No-op API plugin engine kept for backwards-compatible imports.

### Community 92 - "get_cis_mapping"
Cohesion: 0.29
Nodes (4): get_cis_mapping(), ASM Platform — CIS Controls v8 compliance mapping (display-only, no scoring effe, Return (control_id, safeguard_id, safeguard_title) for a Finding.category, or No, TestGetCisMapping

### Community 93 - "TestComputeLikelihoodLevel"
Cohesion: 0.31
Nodes (4): compute_likelihood_level(), Driven by exploit_boost, which can only take one of 6 discrete values     today:, Stage 4: driven by exploit_boost's 6 real possible values     ({1.0, 1.2, 1.25,, TestComputeLikelihoodLevel

### Community 94 - "compute_ssvc_boost"
Cohesion: 0.29
Nodes (4): compute_ssvc_boost(), Escalation-only, floor 1.0, meant to be combined via max() with     exploit_inte, Regression guard: CISA KEV already represents "confirmed active         exploita, TestComputeSsvcBoost

### Community 95 - "_extract_ssvc"
Cohesion: 0.31
Nodes (4): _extract_ssvc(), CISA ADP Vulnrichment's SSVC assessment lives in the same     containers.adp[].m, Stage 3: CISA ADP Vulnrichment's SSVC assessment lives in the same     container, TestExtractSsvc

### Community 96 - "version_in_range"
Cohesion: 0.31
Nodes (4): Check a detected version against one CIRCL "versions[]" entry, e.g.     {"versio, version_in_range(), Real shape verified against cve.circl.lu/api/search/apache/http_server     befor, TestVersionInRange

### Community 97 - "2026-07-10 — Milestone 11: Dashboard Data Audit (9 clarity/data-wiring bugs)"
Cohesion: 0.20
Nodes (10): 2026-07-10 — Milestone 11: Dashboard Data Audit (9 clarity/data-wiring bugs), Fixed: Attack Surface graph always showing "IPs: 0", Fixed: Category Breakdown rendering array indices ("0","1","2"...) instead of category names, Fixed (clarity, not a bug): Assets list Technologies/HTTP/TLS Expiry blank for ~96% of rows, Fixed: DNS Intel page never received the detailed fields it was designed to show, Fixed: Network Intelligence table showed only Source + permanently-empty Risk Score/Tags/Categories, Fixed: Overview/Risk Scores KPIs reading from the wrong or missing fields, Fixed: Reports page overstated Compliance/Custom report capability (+2 more)

### Community 98 - "2026-07-10 — Milestone 7: Finding Validity & Coverage Gaps"
Cohesion: 0.20
Nodes (10): 2026-07-10 — Milestone 7: Finding Validity & Coverage Gaps, Added: JavaScript analysis in the crawl pipeline (B2), Added: real `.git` exposure confirmation + secrets scanning (B1), Added: `workers/` test infrastructure (didn't exist at all before this), Explicitly deferred: active exploitation confirmation (A3), Fixed: CVE finding confidence field existed and was already scored, but hardcoded to 1.0 everywhere (A2), Fixed: ffuf content/directory fuzzing was fully implemented but disabled everywhere (B3), Fixed: Finding triage status silently reset to "open" on every rescan (A1) (+2 more)

### Community 100 - "is_unconfirmed_generated_guess"
Cohesion: 0.40
Nodes (5): 2026-07-16 — Bug Bounty pipeline: per-stage run status (progress visibility), Added, Fixed (found during verification), Note on automation (raised by the user, not built), Verified

### Community 101 - "Settings"
Cohesion: 0.25
Nodes (4): get_settings(), ASM Platform — Application Configuration All settings loaded from environment va, Settings, BaseSettings

### Community 102 - "2026-05-19 — Auto-Scan Toggle & Progress Bar Fix"
Cohesion: 0.22
Nodes (9): 2026-05-19 — Auto-Scan Toggle & Progress Bar Fix, Added: Auto-scan enable/disable, Added: New Scan modal on dashboard, Added: Scan phase label in progress bar, Fixed: Empty error messages in discovery logs, Fixed: Nuclei worker `ModuleNotFoundError: No module named 'app'`, Fixed: OpenSearch excessive RAM usage, Fixed: Progress bar stuck at 0% (+1 more)

### Community 103 - "2026-06-02 — API Timeline Query & Queue Runtime Fixes"
Cohesion: 0.22
Nodes (9): 2026-06-02 — API Timeline Query & Queue Runtime Fixes, Added: Production scan policy, phase status, and enrichment worker, Fixed: Asset detail client-side crash, Fixed: Crawl endpoint persistence on oversized archive URLs, Fixed: Enrichment worker dependency imports, Fixed: Nginx stale upstream DNS after service rebuilds, Fixed: Nuclei timeout reported as zero findings, Fixed: PostgreSQL timeline aggregation errors (+1 more)

### Community 104 - "report_templates.py"
Cohesion: 0.38
Nodes (6): create_queue_event(), Any, Unit tests for transactional outbox helpers., test_create_queue_event_defaults(), test_create_queue_event_preserves_headers_and_priority(), test_prepare_event_is_idempotent_for_coordinator()

### Community 105 - "search"
Cohesion: 0.33
Nodes (3): User, Dependency factory for minimum role level enforcement.     Owner > Admin > Analy, RequireMinRole

### Community 106 - "workspaces.py"
Cohesion: 0.57
Nodes (7): get_workspace(), invite_member(), list_members(), AsyncSession, User, UUID, update_workspace()

### Community 107 - "init_db"
Cohesion: 0.25
Nodes (5): init_db(), Initialize async database engine and session factory., main(), main(), main()

### Community 108 - "2026-05-19 — Worker Pipeline Fixes"
Cohesion: 0.25
Nodes (8): 2026-05-19 — Worker Pipeline Fixes, Changed: All worker services replicas set to 1, Fixed: Go tools shadowed by Python CLI entrypoints, Fixed: httpx using Python CLI instead of Go binary, Fixed: RabbitMQ exchange bindings missing, Fixed: SQLAlchemy 2.0 `pg_insert` ORM incompatibility, Fixed: Stale Python bytecache causing old constraint name error, Fixed: `worker-port` not running

### Community 109 - "2026-05-21 — Redis Coordinator Fix, Manual Nuclei, Pipeline Finalization"
Cohesion: 0.25
Nodes (8): 2026-05-21 — Redis Coordinator Fix, Manual Nuclei, Pipeline Finalization, Added: Manual nuclei scan endpoint, Added: Manual scan tab in frontend ScanModal, Fixed: Discovery worker never finalizes when zero downstream work queued, Fixed: Edit organization button does nothing, Fixed: Missing `UUID` import in scans endpoint, Fixed: Nuclei worker doesn't update scan status to "running", Fixed: `register_script` is NOT async in redis-py 5.x (blocks ALL pipeline completion)

### Community 110 - "2026-06-03 — Scan Pipeline Progress and Result UI"
Cohesion: 0.25
Nodes (8): 2026-06-03 — Scan Pipeline Progress and Result UI, Added: Asset validation and scope confidence milestone, Added: Asset validation worker and analyst review workflow, Added: Durable scan observability milestone, Changed: Richer asset result presentation, Changed: Scan progress and result visibility, Fixed: Accurate nuclei and crawl task accounting, Fixed: Pipeline observability coverage

### Community 111 - "AssetRelationshipGraph.tsx"
Cohesion: 0.29
Nodes (7): ALWAYS_LABELED_TYPES, AssetGraphProps, AssetRelationshipGraph(), GraphEdge, GraphNode, NODE_STYLES, SEVERITY_COLORS

### Community 112 - "scores.py"
Cohesion: 0.62
Nodes (6): list_scores(), AsyncSession, User, UUID, score_breakdown(), score_history()

### Community 114 - "2026-07-09 — Milestone 5: Frontend Hardening"
Cohesion: 0.29
Nodes (7): 2026-07-09 — Milestone 5: Frontend Hardening, Changed: Relabeled the "Threat Intelligence" page, Fixed: Frontend called two backend endpoints that didn't exist, Fixed: Frontend dependencies could not be installed from a clean clone, Fixed: Next.js and axios pinned at versions with disclosed CVEs, Fixed: `tsc --noEmit` and `npm run lint` didn't actually work, Verification

### Community 115 - "2026-07-10 — Milestone 10: Tool Parameter Tuning (+ a pre-existing "quick" scan bug found while tracing it)"
Cohesion: 0.29
Nodes (7): 2026-07-10 — Milestone 10: Tool Parameter Tuning (+ a pre-existing "quick" scan bug found while tracing it), Fixed: katana crawl depth was too shallow to ever trigger known-files discovery, Fixed: nmap `--version-light` was hardcoded on even for the authorized/deep profile, Fixed: nuclei concurrency/bulk-size were well below nuclei's own defaults for the "deep" profile, Fixed: subfinder's own default cuts off passive-source enumeration early for a thorough scan, Found and fixed while tracing the above: `DEFAULT_SCAN_POLICY` was silently overriding "quick" scans' own tuning, Verification

### Community 116 - "2026-07-10 — Milestone 6: Scan Pipeline Maturity (Recon → Enumeration → Enrichment → Vuln Scanning)"
Cohesion: 0.29
Nodes (7): 2026-07-10 — Milestone 6: Scan Pipeline Maturity (Recon → Enumeration → Enrichment → Vuln Scanning), Fixed: Correlation worker redundantly recomputed the full org graph on every nuclei batch, Fixed: DNS bruteforce wordlist was too thin, Fixed: Nuclei never ran `info`-severity templates, Fixed: Nuclei ran one target per subprocess instead of batching — enforced redundantly across, Fixed: On-demand ("full"/"vuln") scans only covered top-100 ports, Verification

### Community 119 - "list_screenshots"
Cohesion: 0.40
Nodes (5): list_screenshots(), AsyncSession, User, UUID, ASM Platform — Screenshots API Global screenshot gallery with pagination, org fi

### Community 120 - "_compare_versions"
Cohesion: 0.47
Nodes (3): _compare_versions(), -1 if a<b, 0 if equal, 1 if a>b — pads the shorter tuple with zeros so     (2, 4, TestCompareVersions

### Community 121 - "_parse_version_tuple"
Cohesion: 0.47
Nodes (3): _parse_version_tuple(), Best-effort numeric version parse for comparison — "2.4.49" -> (2,4,49).     Ret, TestParseVersionTuple

### Community 123 - "2026-06-01 — Organization Automation Controls & Tech-Aware Scanning"
Cohesion: 0.33
Nodes (6): 2026-06-01 — Organization Automation Controls & Tech-Aware Scanning, Added: Dedicated endpoint crawling phase, Added: Per-organization automatic scan control, Added: Technology-aware nuclei pre-scan, Changed: HTTP status-aware scan routing and asset triage, Fixed: Scan lifecycle edge cases and scheduler restart behavior

### Community 124 - "2026-07-10 — Milestone 12: End-to-End Scan Validation (2 real bugs found via a live scan)"
Cohesion: 0.33
Nodes (6): 2026-07-10 — Milestone 12: End-to-End Scan Validation (2 real bugs found via a live scan), Backfilled: recategorized the 53 pre-existing miscategorized findings, Fixed: nuclei `http-*` templates miscategorized as `exposed_admin_panel`, platform-wide, Fixed: subdomain takeover check crashes the instant it has real candidates to check, Follow-up: chased down every remaining loose end flagged above, Verification

### Community 125 - "2026-07-10 — Milestone 8: Exploit Intelligence (EPSS + CISA KEV)"
Cohesion: 0.33
Nodes (6): 2026-07-10 — Milestone 8: Exploit Intelligence (EPSS + CISA KEV), Added: EPSS/KEV surfaced on findings (live join, not frozen at scan time), Added: `exploit_intel` table + daily refresh (EPSS + CISA KEV), Added: exploit-likelihood boost in risk scoring — escalation-only, a different axis from confidence, Added: frontend surfacing for M7 confidence + M8 EPSS/KEV (previously API-only), Verification

### Community 126 - "2026-07-12 — Milestone 17: Mining already-collected IP/TLS data for uncovered attack surface"
Cohesion: 0.33
Nodes (6): 2026-07-12 — Milestone 17: Mining already-collected IP/TLS data for uncovered attack surface, Added: reverse-DNS lookups against this org's own already-confirmed IP assets, Added: TLS certificate SAN mining as a new subdomain-discovery source, Caveat surfaced during this work: `DiscoveredAsset` candidates have no review UI at all, Confirmed as correct, deliberately not touched: ASN→CIDR expansion never auto-scans, Verification

### Community 127 - "2026-07-12 — Milestone 21: Version-to-CVE correlation (highest-risk item of the 4-part plan)"
Cohesion: 0.33
Nodes (6): 2026-07-12 — Milestone 21: Version-to-CVE correlation (highest-risk item of the 4-part plan), Added: keyless CVE-by-version correlation via cve.circl.lu, Fixed (prerequisite, found while building this): `cve_ids` silently dropped for every non-nuclei finding, Not yet decided — flagged for the user, not assumed, Verification, Verified against real production data, not just synthetic tests

### Community 128 - "2026-07-12 — Risk Engine Redesign, Stage 2: CVSS vector data flow + parser (no formula change)"
Cohesion: 0.33
Nodes (6): 2026-07-12 — Risk Engine Redesign, Stage 2: CVSS vector data flow + parser (no formula change), Added, Decision (via AskUserQuestion, before implementation), Explicitly not in scope for this stage, The gap found before writing this stage's plan, Verified against real production data

### Community 129 - "2026-07-12 — Risk Engine Redesign, Stage 3: SSVC (Exploitation/Automatable) escalation"
Cohesion: 0.33
Nodes (6): 2026-07-12 — Risk Engine Redesign, Stage 3: SSVC (Exploitation/Automatable) escalation, Added, Decision (via AskUserQuestion, before implementation), Explicitly not in scope for this stage, The gap found before writing this stage's plan, Verified against real production data

### Community 130 - "2026-07-12 — Risk Engine Redesign, Stage 4 (final): Likelihood × Impact matrix"
Cohesion: 0.33
Nodes (6): 2026-07-12 — Risk Engine Redesign, Stage 4 (final): Likelihood × Impact matrix, Added, Decision: scope kept to a "narrow" replacement, not a full restructure, Explicitly not in scope for this stage, Investigation before implementation (2 Explore agents + a Plan agent, all grounded in live code/DB), Verified against real production data

### Community 131 - "2026-07-13 — Attack-surface graph: fixed relationship data, wired the graph to it"
Cohesion: 0.33
Nodes (6): 2026-07-13 — Attack-surface graph: fixed relationship data, wired the graph to it, Added, Explicitly not done, Fixed, Real-browser verification (follow-up, same day), Verified against real production data

### Community 132 - "list_intel"
Cohesion: 0.50
Nodes (4): list_intel(), AsyncSession, User, UUID

### Community 133 - "_build_chart_data"
Cohesion: 0.40
Nodes (3): dns_fingerprint(), Stable fingerprint for wildcard DNS comparison., Run dnsx to resolve all record types for discovered hosts.

### Community 135 - "2026-05-17 — Frontend Build Fixes"
Cohesion: 0.40
Nodes (5): 2026-05-17 — Frontend Build Fixes, Fixed: Broken imports in dashboard, Fixed: Missing config files, Fixed: Missing/nonexistent dependencies, Fixed: TypeScript errors

### Community 136 - "2026-07-09 — Reporting: Fixed Download + PDF Export"
Cohesion: 0.67
Nodes (3): test_endpoint_score_keeps_low_signal_static_pages_low(), test_endpoint_score_prioritizes_high_signal_sources(), _endpoint_flags()

### Community 137 - "2026-07-10 — Milestone 9: Finding Content Freezes on Rescan (and a live nuclei cve_ids bug found via UI QA)"
Cohesion: 0.40
Nodes (5): 2026-07-10 — Milestone 9: Finding Content Freezes on Rescan (and a live nuclei cve_ids bug found via UI QA), Added: frontend surfacing for Milestone 7 confidence + Milestone 8 EPSS/KEV, with real screenshot verification, Fixed: Finding content (severity, proof, cve_ids, evidence, ...) never refreshed on rescan, Found via frontend visual QA (Milestone 8's Playwright setup) and fixed: nuclei sometimes never populates `cve_ids` at all, Verification

### Community 138 - "2026-07-11 — Milestone 15: End-of-Life Software Enrichment (new scanner-family check)"
Cohesion: 0.40
Nodes (5): 2026-07-11 — Milestone 15: End-of-Life Software Enrichment (new scanner-family check), A real bug caught by testing before deploying: `is_eol` computed wrong, Added: keyless EOL lookup + cache, new `eol` scanner-family check, Found but not fixed (out of scope for this pass, noted for later), Verification

### Community 139 - "2026-07-12 — Risk Engine Redesign, Stage 1: Asset/Org criticality wired into scoring"
Cohesion: 0.40
Nodes (5): 2026-07-12 — Risk Engine Redesign, Stage 1: Asset/Org criticality wired into scoring, Added, Explicitly not in scope for this stage, The gap found before writing this stage's plan, Verified against real production data

### Community 140 - "2026-07-13 — Grouped/deduplicated findings view"
Cohesion: 0.40
Nodes (5): 2026-07-13 — Grouped/deduplicated findings view, Added, Explicitly not in scope, Fixed (prerequisite, found while verifying this in a browser), Verified against real production data

### Community 141 - "2026-07-13 — Stop persisting unresolved dns_bruteforce/dns_permutation guesses as Assets"
Cohesion: 0.40
Nodes (5): 2026-07-13 — Stop persisting unresolved dns_bruteforce/dns_permutation guesses as Assets, Added, Changed, Data cleanup (existing rows, confirmed with the user before running), Explicitly not changed

### Community 142 - "2026-07-15 — Bug Bounty pipeline Stage 5: report worker (module 13) + frontend — feature COMPLETE"
Cohesion: 0.40
Nodes (5): 2026-07-15 — Bug Bounty pipeline Stage 5: report worker (module 13) + frontend — feature COMPLETE, Added — frontend (`frontend/src/app/dashboard/bounty/`), Added — report worker + API (module 13), Bug bounty pipeline — final state, Verified

### Community 143 - "changelog.sh"
Cohesion: 0.80
Nodes (4): append_entry(), interactive(), changelog.sh script, usage()

### Community 144 - "logging.py"
Cohesion: 0.67
Nodes (3): ASM Platform — Structured Logging Configuration JSON logging with structlog for, Configure structlog + stdlib logging., setup_logging()

### Community 145 - "2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse"
Cohesion: 0.29
Nodes (17): cancel_scan(), _discovered_asset_summary(), get_scan(), list_scans(), manual_scan(), AsyncSession, Scan, User (+9 more)

### Community 146 - "2026-06-02 — Core Scan Profile & Target Candidate Engine"
Cohesion: 0.50
Nodes (4): 2026-06-02 — Core Scan Profile & Target Candidate Engine, Added: Central scan profiles for vulnerability scanning, Added: Target candidate builder for downstream scanner selection, Changed: Scan profile controls in frontend

### Community 147 - "2026-07-09 — CLAUDE.md Onboarding Doc + Architecture Audit"
Cohesion: 0.50
Nodes (4): 2026-07-09 — CLAUDE.md Onboarding Doc + Architecture Audit, Added: CLAUDE.md for Claude Code, Found: Queue routing tables can drift (not yet fixed), Found: `report.daily` queue has no consumer (not yet fixed)

### Community 148 - "2026-07-09 — Milestone 2: Nuclei/Scanner Phase Status Stuck After Completion"
Cohesion: 0.50
Nodes (4): 2026-07-09 — Milestone 2: Nuclei/Scanner Phase Status Stuck After Completion, Fixed: Racy phase-status write let "completed" get overwritten back to "running", Fixed: `scanner` umbrella phase had no completion logic at all, Verified against a real fresh scan (not simulated)

### Community 149 - "2026-07-11 — Milestone 13: Second Live-Scan Validation (kpi.go.id) + risk category-map audit"
Cohesion: 0.50
Nodes (4): 2026-07-15 — Bug Bounty pipeline Stage 3: vulnscan worker (module 6, nuclei), Added, Not yet built (later stages, per the approved plan), Verified

### Community 150 - "2026-07-12 — Milestone 16: Fixed nuclei's own `*-eol` template categorization (M15 follow-up)"
Cohesion: 0.50
Nodes (4): 2026-07-12 — Milestone 16: Fixed nuclei's own `*-eol` template categorization (M15 follow-up), Backfilled: 27 pre-existing miscategorized findings, Fixed: `*-eol` nuclei templates fell through to the wrong default category, Verification

### Community 151 - "2026-07-12 — Milestone 18: "quick"/"vuln" scans have been silently running as deep_authorized"
Cohesion: 0.50
Nodes (4): 2026-07-12 — Milestone 18: "quick"/"vuln" scans have been silently running as deep_authorized, Found and fixed: `crawl_nuclei_max_targets` was backwards for the most-thorough profile, Found and fixed (far more severe): `DEFAULT_SCAN_POLICY` hardcoded `scan_profile: "deep_authorized"`, Verification

### Community 152 - "2026-07-12 — Milestone 19: API surface coverage — OpenAPI/Swagger spec mining + GraphQL introspection"
Cohesion: 0.50
Nodes (4): 2026-07-12 — Milestone 19: API surface coverage — OpenAPI/Swagger spec mining + GraphQL introspection, Added: GraphQL introspection query check, Added: OpenAPI/Swagger spec parsing → new crawl candidates, Verification

### Community 153 - "2026-07-13 — CIS Controls v8 compliance report mapping"
Cohesion: 0.17
Nodes (12): OutboxEvent, _dispatch_event(), dispatch_pending_outbox_once(), _prepare_event(), AsyncSession, Transactional outbox dispatcher for reliable queue publishing., _run_dispatcher(), start_outbox_dispatcher() (+4 more)

### Community 154 - "2026-07-13 — Scan change/diff detection ("What Changed Since Last Scan")"
Cohesion: 0.50
Nodes (4): 2026-07-13 — Scan change/diff detection ("What Changed Since Last Scan"), Added, Real-browser verification (follow-up, same day), Verified against real production data, two ways

### Community 155 - "2026-07-15 — Attack Surface Map: dedupe tech nodes, size by importance, quieter default view"
Cohesion: 0.50
Nodes (4): 2026-07-15 — Attack Surface Map: dedupe tech nodes, size by importance, quieter default view, Changed, Fixed, Verified against real production data + real browser

### Community 156 - "2026-07-15 — Bug Bounty pipeline Stage 2: recon + probe workers (modules 1-5)"
Cohesion: 0.50
Nodes (4): 2026-07-15 — Bug Bounty pipeline Stage 2: recon + probe workers (modules 1-5), Added, Not yet built (later stages, per the approved plan), Verified

### Community 157 - "2026-07-15 — Bug Bounty pipeline Stage 3: vulnscan worker (module 6, nuclei)"
Cohesion: 0.50
Nodes (4): 2026-07-15 — Bug Bounty pipeline Stage 4: exploit worker (modules 7-12), Added, Not yet built, Verified

### Community 158 - "2026-07-15 — Bug Bounty pipeline Stage 4: exploit worker (modules 7-12)"
Cohesion: 0.40
Nodes (5): 2026-07-18 — Bug Bounty framework parity, Phase 2: WAF, API/GraphQL discovery, sensitive files, CORS, 403-bypass, Added, Fixed (surfaced during verification against the vuln-test fixture), Still to come, Verified

### Community 159 - "2026-07-15 — Frontend consistency pass: DNS Intel, Network Intel, sidebar nav"
Cohesion: 0.50
Nodes (4): 2026-07-15 — Frontend consistency pass: DNS Intel, Network Intel, sidebar nav, Explicitly not done, Fixed, Verified in a real browser

### Community 160 - "2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API)"
Cohesion: 0.50
Nodes (4): 2026-07-11 — Milestone 13: Second Live-Scan Validation (kpi.go.id) + risk category-map audit, Fixed: 3 finding categories missing from risk_engine's scoring map entirely, Fixed (incidental): stale test masked by the same api-container collection gap, Verification

### Community 161 - "2026-07-15 — PDF report visual redesign"
Cohesion: 0.50
Nodes (4): 2026-07-15 — PDF report visual redesign, Also investigated (no change needed), Changed, Verified against real production data

### Community 181 - ".get_by_email"
Cohesion: 0.50
Nodes (4): 2026-07-13 — CIS Controls v8 compliance report mapping, Added, Real-browser verification (follow-up, same day), Verified against real production data

### Community 182 - "2026-05-18 — API Trailing Slash Fix"
Cohesion: 0.67
Nodes (3): 2026-05-18 — API Trailing Slash Fix, Added: Changelog scripts + make targets, Fixed: Trailing slash mismatch on 10 root endpoints

### Community 183 - "2026-06-02 — Scanner Tool Command Hardening"
Cohesion: 0.67
Nodes (3): 2026-07-11 — Milestone 14: EPSS/KEV exploit-intel lookup silently broken by CVE-ID casing, Fixed: EPSS/KEV lookup was case-sensitive; almost every real CVE finding missed it, Verification

### Community 184 - "2026-07-15 — Fixed overlapping category labels in report bar charts"
Cohesion: 0.67
Nodes (3): 2026-07-12 — Milestone 20: ffuf content-discovery depth (recursion + extension fuzzing), Added: bounded recursion + sensitive-file extension fuzzing, `deep_authorized` only, Verification

### Community 187 - "_endpoint_flags"
Cohesion: 0.67
Nodes (3): 2026-07-15 — Fixed overlapping category labels in report bar charts, Fixed, Verified against real production data

### Community 188 - ".__init__"
Cohesion: 0.50
Nodes (4): 2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse, Fixed: Findings upsert fails — `ON CONFLICT` requires unique index, not btree, Fixed: Nuclei JSON output lines may be arrays, not objects, Fixed: `UnboundLocalError: cannot access local variable 'findings'`

### Community 224 - "2026-07-15 — Report executive narrative"
Cohesion: 0.67
Nodes (3): 2026-07-15 — Report executive narrative, Added, Verified against real production data

### Community 263 - "2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API)"
Cohesion: 0.50
Nodes (4): 2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API), Added, Not yet built (later stages, per the approved plan), Verified

## Knowledge Gaps
- **553 isolated node(s):** `extends`, `next/core-web-vitals`, `nextConfig`, `name`, `version` (+548 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **52 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `get_session()` connect `get_session` to `User`, `BaseWorker`, `NucleiWorker`, `DiscoveryWorker`, `web_crawl_worker.py`, `recon_worker.py`, `test_scan_pipeline_state.py`, `ScannerCoverageWorker`, `exploit_worker.py`, `2026-07-13 — CIS Controls v8 compliance report mapping`, `Asset`, `discovery_worker.py`, `ScreenshotWorker`, `._discover_subdomains_with_sources`, `NiktoWorker`, `ScanScheduler`, `scans.py`, `NotificationWorker`, `scan_profiles.py`, `QueueClient`, `_group_heading`, `PortWorker`, `EnrichmentWorker`?**
  _High betweenness centrality (0.117) - this node is a cross-community bridge._
- **Why does `Scan` connect `User` to `PortWorker`, `get_session`, `ScreenshotWorker`, `EnrichmentWorker`, `NucleiWorker`, `DiscoveryWorker`, `web_crawl_worker.py`, `NiktoWorker`, `2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse`, `report_service.py`, `organizations.py`, `2026-07-13 — CIS Controls v8 compliance report mapping`, `Asset`, `discovery_worker.py`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `compute_org_score()` connect `FindingInput` to `risk_engine.py`, `_group_heading`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Are the 13 inferred relationships involving `DiscoveryWorker` (e.g. with `FakeDB` and `_FakeHttpResponse`) actually correct?**
  _`DiscoveryWorker` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 48 inferred relationships involving `User` (e.g. with `get_current_user()` and `get_token_payload()`) actually correct?**
  _`User` has 48 INFERRED edges - model-reasoned connections that need verification._
- **What connects `extends`, `next/core-web-vitals`, `nextConfig` to the rest of the system?**
  _553 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `bounty.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1038961038961039 - nodes in this community are weakly interconnected._
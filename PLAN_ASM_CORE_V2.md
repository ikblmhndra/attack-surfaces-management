# ASM Core V2 Improvement Plan

## Objective

Upgrade the platform from a working scanner pipeline into a production-grade Attack Surface Management core. The target is not just "more tools", but a pipeline that can discover broader assets, validate ownership and exposure, explain what was scanned, prioritize risk with context, and present analyst-ready results in the UI.

## Implementation Status

Last updated: 2026-06-03.

### Completed

- [x] **Milestone 1: Durable Scan Observability**
  - [x] Added `scan_phase_runs` durable phase timeline table.
  - [x] Added `scan_target_selections` durable target selection table.
  - [x] Added SQLAlchemy models for both observability tables.
  - [x] Added Alembic migration `008_scan_observability`.
  - [x] Updated shared worker phase helper so `update_scan_phase()` upserts durable phase records.
  - [x] Added worker helper `workers/scan_observability.py` for target selection persistence.
  - [x] Discovery now records target selection rows for targeting output: network, web standard, web limited, crawl, and screenshot candidates.
  - [x] Crawl now records endpoint targets selected for nuclei with score and reasons.
  - [x] Nuclei now records batch targets and profile metadata.
  - [x] Port now records IP batch targets.
  - [x] Screenshot now records attempted screenshot targets and success/failed counts.
  - [x] Enrichment now records asset targets and completed/failed counts.
  - [x] Correlation now records intermediate and terminal phase summaries.
  - [x] Scan detail API now returns `phase_runs`, `target_summary`, `target_selections`, and `why_no_findings`.
  - [x] Added `/dashboard/scans/[id]` scan detail UI.
  - [x] Scan list links each scan to its detail page.
  - [x] Added initial "Why No Findings" explanations using phase state and target coverage.
  - [x] Runtime migration was applied successfully with `make migrate`.
  - [x] Docker rebuild/recreate was completed for API, frontend, discovery, crawl, and nuclei workers.
- [x] **Milestone 2: Asset Validation and Scope Confidence - initial implementation**
  - [x] Added asset validation fields for scope, ownership confidence, liveness, exposure, validation evidence, and last verified timestamp.
  - [x] Added Alembic migration `009_asset_validation` with historical backfill for existing subdomain/IP assets.
  - [x] Added deterministic `asset_validation` service for DNS, HTTP, TLS, redirect, and root-domain evidence.
  - [x] Discovery now validates alive hosts before persistence and downstream target selection.
  - [x] Downstream target candidate selection gates active web/crawl/screenshot scans on validation by default.
  - [x] Port-discovered IP assets receive baseline validation state.
  - [x] Scan target selections record validation-gated skipped targets.
  - [x] Scan detail "Why No Findings" can explain validation-gated targets.
  - [x] Asset API and UI now expose validation state and evidence.

### Partially Complete

- [x] Durable phase writes are implemented through the shared phase helper.
  - [x] `port` writes durable phase state with `targets_total` and `open_ports`.
  - [x] `enrich` writes durable phase state with `targets_total`, `completed`, and `failed`.
  - [x] `screenshot` writes durable phase state with `targets_total`, `success`, and `failed`.
  - [x] `correlation` writes durable phase state for intermediate and terminal correlation, including relationship/change/risk queue summary.
  - [ ] Future scanner workers must use the same helper when added.
- [x] Target selections are persisted for current Milestone 1 workers.
  - [x] Discovery records target selections for network, web standard, web limited, crawl, and screenshot candidates during `targeting`.
  - [x] Crawl records endpoint targets selected for nuclei with score and score reasons.
  - [x] Nuclei records batch targets and profile metadata.
  - [x] Port records IP batch targets under phase `port`.
  - [x] Screenshot records attempted hosts/URLs under phase `screenshot`.
  - [x] Enrichment records asset targets under phase `enrich`.
  - [ ] Future scanner workers must record target selections when added.
- [x] "Why No Findings" covers the first core cases and expanded Milestone 1 cases.
  - [x] No web targets.
  - [x] No endpoint targets.
  - [x] Incomplete nuclei.
  - [x] Missing durable target records.
  - [x] Scan failure.
  - [x] Nuclei completed with no findings.
  - [x] Safety-policy template exclusions.
  - [x] Endpoint budget cap reached.
  - [x] Scan errors present.
  - [x] Validation-gated targets.
  - [ ] Future reasons should be added after scanner expansion, especially no eligible scanner profile.
- [ ] Milestone 2 follow-ups that are intentionally not in the initial implementation.
  - [ ] Add a dedicated `asset.validate` queue and worker for periodic revalidation.
  - [ ] Add RDAP/ASN ownership evidence and confidence scoring.
  - [ ] Add organization-level allow/deny pattern controls beyond root domains.
  - [ ] Add explicit analyst review workflow for `needs_review` assets.

### Not Started

- [ ] Milestone 3: Discovery Engine V2.
- [ ] Milestone 4: Endpoint Intelligence V2.
- [ ] Milestone 5: Scanner Coverage Expansion.
- [ ] Milestone 6: Risk and Finding Lifecycle V2.

## Current Gaps

- Discovery is still mostly domain/subdomain and web-first. It needs stronger passive sources, DNS brute force, permutations, ASN/IP expansion, and cloud exposure discovery.
- Asset validation is not yet a first-class decision engine. Assets need ownership confidence, exposure status, liveness state, and reason codes.
- Vulnerability scanning is too nuclei-centric. Nuclei is useful, but ASM also needs TLS, DNS, takeover, secrets, cloud bucket, service, and exposure-specific checks.
- Endpoint crawling exists, but endpoint intelligence is not yet a complete phase with lifecycle, scoring, selected-for-scan tracking, and UI explanations.
- Risk scoring still needs more business and exposure context, not just scanner severity.
- UI shows results, but it does not yet behave like an analyst workflow: scan timeline, "why no findings", target coverage, endpoint reasoning, evidence, and remediation flow are still incomplete.

## Design Principles

- Keep all default scanning safe for authorized ASM. Destructive, DoS, brute force, and intrusive checks stay disabled unless explicitly enabled server-side.
- Prefer repeatable phase outputs over raw logs. Every phase should persist counts, selected targets, skipped targets, errors, and timing.
- Treat discovery, validation, scanning, enrichment, correlation, and risk as separate concerns with clear data contracts.
- Do not add tools without normalized storage and UI value. Every new tool needs parser, persistence, failure handling, and result display.
- Make partial success explicit. Timeouts, skipped assets, rate limits, and failed probes should be visible in API/UI instead of silently disappearing.

## Target Pipeline

### Phase 1: Scope Intake and Policy Resolution

Inputs:
- Organization domains, IP ranges, ASNs, company name, cloud identifiers, tags, environment, and criticality.
- Organization `scan_policy`.
- Scan template override.
- Manual request config.

Resolution order:
`system defaults < organization scan_policy < scan template < manual request config`

Required output:
- Immutable scan config snapshot.
- Resolved modules.
- Budgets and safety caps.
- Scope manifest:
  - root domains
  - IP ranges
  - ASNs
  - explicit URLs
  - allowed/excluded host patterns
  - out-of-scope patterns

Implementation targets:
- `backend/app/services/scan_service.py`
- `backend/app/services/scan_profiles.py`
- `backend/app/db/models/models.py`
- Alembic migration if new scan manifest columns are needed.

Acceptance criteria:
- API returns resolved scan policy in scan detail.
- UI can show "what scope this scan used".
- Manual config cannot exceed hard safety caps unless server-side setting allows it.

### Phase 2: Discovery Engine V2

#### Passive Domain and Subdomain Discovery

Existing tools:
- `subfinder`
- `assetfinder`
- `chaos` where configured

Add or improve sources:
- crt.sh certificate transparency puller.
- Common Crawl URL/domain extraction.
- Wayback host extraction.
- SecurityTrails integration, optional API key.
- Censys host/cert integration, optional API key.
- Shodan domain/host integration, optional API key.

Required output:
- `discovered_assets` or equivalent normalized records with:
  - value
  - asset_type
  - source
  - confidence
  - first_seen
  - last_seen
  - evidence
  - scan_id

#### Active DNS Discovery

Add:
- DNS brute force with tiered wordlists.
- DNS permutation/mutation.
- Wildcard DNS detection.
- Resolver health checks.
- NXDOMAIN and wildcard suppression.

Suggested tools:
- `dnsx`
- `puredns` or `shuffledns` if Docker image support is acceptable.
- `gotator` or custom permutation generator.

Required output:
- Resolved hosts.
- CNAME chains.
- wildcard detection result.
- DNS source reason.

#### ASN and IP Expansion

Add:
- ASN-to-prefix expansion from org ASNs.
- Reverse DNS on discovered IPs within budget.
- RDAP/org matching.
- Optional BGP source enrichment.

Suggested sources:
- Team Cymru whois.
- RDAP.
- BGPView optional.
- Shodan/Censys optional.

Required output:
- Candidate IP ranges.
- Ownership confidence.
- Hosting/cloud/CDN classification.
- Reason why IP is considered in scope.

#### Cloud Exposure Discovery

Add safe checks for:
- S3 bucket candidates.
- GCS bucket candidates.
- Azure Blob candidates.
- Common public object storage naming patterns.

Required output:
- Bucket-like asset records.
- Public/private/unknown exposure status.
- Evidence URL and HTTP status.

Implementation targets:
- `workers/scanner/discovery_worker.py`
- New `workers/discovery/` helper modules:
  - `passive_sources.py`
  - `dns_bruteforce.py`
  - `permutations.py`
  - `asn_expansion.py`
  - `cloud_storage.py`

Acceptance criteria:
- Discovery phase can explain counts by source.
- Wildcard DNS does not inflate asset inventory.
- Out-of-scope patterns are excluded before downstream scanning.
- Discovery UI shows source distribution and skipped reasons.

### Phase 3: Asset Validation Engine

Purpose:
Turn raw discoveries into trusted ASM assets.

Add fields or tables for:
- `ownership_confidence`: 0.0 to 1.0.
- `ownership_reason`: DNS, cert, RDAP, ASN match, explicit scope, manual.
- `exposure_status`: live, parked, redirect_only, auth_wall, cdn_only, rate_limited, dead, unknown.
- `liveness_status`: alive, intermittent, dead.
- `validation_sources`: JSONB source evidence.
- `last_verified_at`.
- `scope_status`: in_scope, out_of_scope, needs_review.

Validation checks:
- DNS resolution.
- HTTP/HTTPS probing.
- Redirect target ownership.
- TLS certificate subject/SAN match.
- RDAP/ASN ownership match.
- CDN/WAF detection.
- Parked domain detection.
- Cloud provider classification.

Implementation targets:
- New worker: `workers/validation/asset_validation_worker.py`
- New queue: `asset.validate`
- API serializers in `backend/app/api/v1/endpoints/assets.py`
- UI asset detail and asset table.

Acceptance criteria:
- Every new asset has validation state before heavy scanning.
- Out-of-scope or low-confidence assets are not sent to active scanners by default.
- UI can show why asset is trusted or needs review.

### Phase 4: Target Selection Engine V2

Purpose:
Centralize target selection instead of each worker making isolated choices.

Target groups:
- `network_targets`: IPs and ports for port/service scanning.
- `web_targets_standard`: live web assets suitable for normal nuclei.
- `web_targets_limited`: auth, redirect, rate-limited, or error targets for conservative templates.
- `crawl_targets`: web roots for endpoint discovery.
- `screenshot_targets`: representative live web targets.
- `takeover_targets`: CNAME or dangling service candidates.
- `cloud_targets`: public bucket/storage candidates.

Add target selection reasons:
- live HTTP 200/3xx.
- auth wall.
- admin path.
- API path.
- interesting port.
- new asset.
- critical asset.
- high-risk technology.
- takeover candidate.
- exposed storage candidate.

Implementation targets:
- `backend/app/services/scan_profiles.py`
- New module: `backend/app/services/target_selection.py`
- Worker integration:
  - `workers/scanner/discovery_worker.py`
  - `workers/crawler/web_crawl_worker.py`
  - `workers/scanner/port_worker.py`

Acceptance criteria:
- Scan detail API can show selected vs skipped target counts.
- UI can answer "what was scanned and why".
- Target caps are applied after risk-aware sorting, not random ordering.

### Phase 5: Port and Service Intelligence V2

Existing:
- `naabu`
- web-port `httpx` fingerprinting.

Improve:
- Keep `naabu` fast port discovery.
- Add conservative service fingerprinting for selected non-web ports.
- Add TLS check on TLS-capable ports.
- Add protocol-specific exposure classification.

Suggested tools:
- `nmap -sV --version-light` for bounded non-web service version detection.
- `tlsx` for TLS metadata.
- `httpx` for web services.

Persist:
- product
- version
- extrainfo
- banner
- TLS issuer, expiry, SANs, protocol, cipher
- service confidence
- dangerous service flag
- public admin service flag

High-risk services:
- RDP, SSH, Telnet, FTP, SMB, MSSQL, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch/OpenSearch, Kubernetes API, Docker API, Jenkins, Grafana, Prometheus, RabbitMQ, MinIO.

Implementation targets:
- `workers/scanner/port_worker.py`
- `backend/app/api/v1/endpoints/assets.py`
- UI asset detail ports section.

Acceptance criteria:
- Open ports are categorized by service risk.
- UI shows service/version/TLS/banner where available.
- Scanner respects per-scan service fingerprinting budget.

### Phase 6: Endpoint Intelligence Engine V2

Existing:
- Katana.
- GAU.
- FFUF.
- Endpoint scoring.

Improve lifecycle:
1. Collect URLs from active crawling and passive archives.
2. Normalize and dedupe.
3. Probe with httpx.
4. Classify endpoint.
5. Score endpoint.
6. Persist score and reasons.
7. Select targets for endpoint nuclei.
8. Track whether endpoint was scanned and when.

Endpoint fields to add:
- `score`
- `score_reasons`
- `selected_for_scan`
- `selected_reason`
- `last_scanned_at`
- `scan_status`
- `endpoint_type`: api, auth, admin, upload, static, parameterized, graphql, swagger, health, debug, unknown.
- `source_count`
- `sources`

Tooling:
- `katana` for active crawling.
- `gau` for passive URLs.
- Optional `waybackurls`.
- `ffuf` for bounded path discovery.
- Optional `hakrawler` only if it adds measurable value.

Decision:
- Keep `katana + gau + ffuf` as baseline.
- Add `waybackurls` only if Common Crawl/Wayback parsing is not enough.
- Do not add more crawlers until endpoint normalization and UI are strong.

Implementation targets:
- `workers/crawler/web_crawl_worker.py`
- `backend/app/db/models/models.py`
- Alembic migration for endpoint fields.
- `backend/app/api/v1/endpoints/assets.py`
- `frontend/src/app/dashboard/assets/[id]/page.tsx`

Acceptance criteria:
- Endpoint tab shows score, reasons, source list, classification, and scan status.
- Endpoint nuclei selection is deterministic and explainable.
- Scan detail shows endpoint coverage summary.

### Phase 7: Vulnerability and Exposure Scanning V2

#### Nuclei

Keep:
- Safe template exclusions by default.
- Same-host redirects.
- Redaction and response caps.
- Automatic scan where appropriate.

Improve:
- Separate nuclei profiles:
  - `web_baseline`
  - `endpoint_high_signal`
  - `network_safe`
  - `tls_dns`
  - `takeover`
  - `cloud_exposure`
- Track batch profile in message and phase status.
- Store timeout/partial result status per batch.
- Add optional template allowlist for specific scan templates.

#### Non-Nuclei Checks

Add dedicated checks:
- TLS expiry, weak protocol/cipher, cert mismatch.
- DNS SPF/DMARC/DKIM/MX issues.
- Subdomain takeover candidate validation.
- Public bucket exposure.
- Exposed admin/service detection.
- Secret exposure checks for `.env`, `.git`, config files, backup files.

Suggested tools:
- `tlsx`
- `dnsx`
- Nuclei takeover templates plus custom CNAME validation.
- Custom lightweight HTTP exposure checks.

Implementation targets:
- `workers/scanner/nuclei_worker.py`
- New workers or modules:
  - `workers/scanner/tls_worker.py`
  - `workers/scanner/dns_security_worker.py`
  - `workers/scanner/takeover_worker.py`
  - `workers/scanner/cloud_exposure_worker.py`

Acceptance criteria:
- Finding source clearly identifies scanner and profile.
- Timeout batches are marked partial or failed with reason.
- Zero findings scan can explain coverage and skipped checks.

### Phase 8: Finding Validation and Deduplication V2

Improve:
- Stable fingerprint includes org, asset, template/check id, affected URL, matcher context.
- Validate finding evidence completeness.
- Reprobe affected URL for high/critical where safe.
- Mark stale findings resolved after configurable grace period.
- Track finding lifecycle across scans.

Add fields:
- `validation_status`: confirmed, weak_evidence, stale, unreachable, needs_review.
- `validation_reason`.
- `last_validated_at`.
- `confidence`.
- `evidence_summary`.

Implementation targets:
- `workers/correlation/correlation_worker.py`
- `backend/app/api/v1/endpoints/findings.py`
- `frontend/src/components/modals/FindingDetailModal.tsx`

Acceptance criteria:
- Duplicate findings do not explode across scans.
- Resolved/stale findings are handled automatically.
- UI shows confidence and validation state.

### Phase 9: Risk Engine V2

Risk score inputs:
- Scanner severity.
- Finding confidence.
- Asset criticality.
- Internet exposure.
- Auth/no-auth exposure.
- Known exploit/CVE/CVSS/EPSS where available.
- Sensitive service exposed.
- High-risk technology.
- Threat intel hit.
- New asset/new finding recency.
- Business environment: production/staging/dev.
- Ownership confidence.

Risk outputs:
- Asset risk score.
- Organization risk score.
- Finding priority score.
- Top risk drivers.
- Risk trend.

Implementation targets:
- `workers/risk/risk_worker.py`
- `backend/app/api/v1/endpoints/scores.py`
- UI dashboard risk widgets.

Acceptance criteria:
- UI can explain why an asset/finding is high priority.
- Risk score changes are traceable to drivers.
- Low-confidence/out-of-scope assets do not inflate org score.

### Phase 10: Analyst UI V2

#### Scan Detail Page

Add `/dashboard/scans/[id]`.

Sections:
- Scope manifest.
- Phase timeline with duration, status, targets, batches, errors.
- Discovery source breakdown.
- Target selection summary.
- Queue/runtime status.
- Coverage summary:
  - assets discovered
  - assets validated
  - endpoints found
  - endpoints scanned
  - ports scanned
  - nuclei batches completed
  - checks skipped
- "Why no findings?" panel:
  - no live web targets
  - no selected endpoint targets
  - nuclei timed out
  - templates skipped by safety policy
  - target budget cap reached
  - findings filtered/deduped

#### Asset Detail Page

Improve:
- Ownership confidence panel.
- Exposure status.
- Source/evidence timeline.
- Rich ports with risk labels.
- Technologies normalized by source.
- Endpoint intelligence tab.
- Relationships graph.
- Findings grouped by service/endpoint.

#### Findings Workflow

Improve:
- Reason modal for false positive and accepted risk.
- Bulk actions.
- Evidence summary.
- Validation state.
- Re-test finding action.
- Export with current filters.

Implementation targets:
- `frontend/src/app/dashboard/scans/[id]/page.tsx`
- `frontend/src/app/dashboard/scans/page.tsx`
- `frontend/src/app/dashboard/assets/[id]/page.tsx`
- `frontend/src/app/dashboard/findings/page.tsx`
- Shared components:
  - `ScanPhaseTimeline`
  - `CoverageSummary`
  - `TargetSelectionPanel`
  - `RiskDriversPanel`
  - `EvidencePanel`

Acceptance criteria:
- Analyst can determine scan state without reading logs.
- Analyst can see why an asset or endpoint was scanned.
- Analyst can see why no findings were produced.

## Data Model Plan

### New or Extended Tables

#### `scan_phase_runs`

Purpose:
Durable phase-level state instead of only JSONB `phase_status`.

Fields:
- `id`
- `scan_id`
- `phase`
- `status`
- `started_at`
- `completed_at`
- `duration_seconds`
- `expected_tasks`
- `completed_tasks`
- `failed_tasks`
- `targets_total`
- `targets_selected`
- `targets_skipped`
- `errors`
- `warnings`
- `summary` JSONB

#### `scan_target_selections`

Purpose:
Persist what was selected or skipped and why.

Fields:
- `id`
- `scan_id`
- `asset_id`
- `target`
- `target_type`
- `phase`
- `profile`
- `selected`
- `score`
- `reasons` ARRAY/JSONB
- `skip_reason`
- `created_at`

#### `discovery_evidence`

Purpose:
Store source evidence for discovered assets.

Fields:
- `id`
- `asset_id`
- `scan_id`
- `source`
- `source_type`
- `confidence`
- `evidence` JSONB
- `first_seen`
- `last_seen`

#### Extend `assets`

Add:
- `ownership_confidence`
- `ownership_reason`
- `scope_status`
- `exposure_status`
- `liveness_status`
- `last_verified_at`

#### Extend `web_endpoints`

Add:
- `score`
- `score_reasons`
- `endpoint_type`
- `selected_for_scan`
- `selected_reason`
- `scan_status`
- `last_scanned_at`
- `sources`
- `source_count`

#### Extend `findings`

Add:
- `confidence`
- `validation_status`
- `validation_reason`
- `last_validated_at`
- `evidence_summary`
- `priority_score`
- `risk_drivers`

## Queue and Worker Plan

Current queues remain:
- `scan.discovery`
- `scan.port`
- `scan.crawl`
- `scan.nuclei`
- `scan.screenshot`
- `enrich.assets`
- `correlation.process`
- `risk.compute`

Add queues:
- `asset.validate`
- `scan.tls`
- `scan.dns_security`
- `scan.takeover`
- `scan.cloud_exposure`
- `finding.validate`

Required worker behavior:
- Every worker updates durable phase/task state.
- Every worker publishes structured phase summary.
- Every worker handles partial success.
- Every worker has bounded concurrency and per-scan budgets.
- Every worker emits metrics: started, completed, failed, timeout, targets processed.

## Tooling Plan

### Keep and Improve

- `subfinder`: passive subdomain discovery.
- `assetfinder`: supplemental passive discovery.
- `dnsx`: DNS resolution and brute force validation.
- `httpx`: HTTP probing and tech detection.
- `naabu`: fast port discovery.
- `nuclei`: safe vulnerability/misconfig scanning.
- `katana`: active crawling.
- `gau`: passive URL discovery.
- `ffuf`: bounded content/path discovery.

### Add Carefully

- `tlsx`: TLS metadata and weak TLS checks.
- `puredns` or `shuffledns`: high-quality DNS brute forcing with wildcard handling.
- `gotator`: DNS permutation generation.
- `nmap`: bounded `-sV --version-light` only for selected ports.
- `waybackurls`: optional if archive URL coverage from GAU/Common Crawl is insufficient.

### Avoid for Now

- Heavy exploit frameworks.
- Aggressive fuzzers by default.
- Credential brute force.
- Intrusive template packs.
- Any scanner that cannot output structured JSON or be safely bounded.

## Implementation Roadmap

### Milestone 1: Durable Scan Observability

Status: **completed for initial implementation on 2026-06-03**.

Scope:
- [x] Add `scan_phase_runs`.
- [x] Add `scan_target_selections`.
- [x] Add scan detail API.
- [x] Add scan detail UI.
- [x] Update discovery, crawl, nuclei, port, screenshot, and enrichment to write target selection records.
- [x] Update shared phase helper so workers using `update_scan_phase()` write durable phase summaries.
- [x] Enrich current port, enrichment, screenshot, and correlation phase summaries with phase-specific fields.
- [ ] Follow-up: future scanner workers must add phase summaries and target selection rows when introduced.

Why first:
Without durable observability, adding more tools will create more confusion.

Acceptance:
- [x] A scan can be debugged from UI/API through phase timeline, target coverage, target selections, and no-finding explanations.
- [x] Queue progress and phase progress are visible through runtime counters and durable phase state.
- [x] "Why no findings?" has enough data to explain common initial causes.
- [x] "Why no findings?" includes expanded Milestone 1 reasons such as safety exclusions, budget caps, completed nuclei with no findings, and scan errors.
- [ ] Follow-up: add validation-gated and scanner-profile reasons after asset validation and scanner expansion.

### Milestone 2: Asset Validation and Scope Confidence

Scope:
- [x] Add ownership confidence and exposure/liveness fields.
- [x] Validate DNS, HTTP, TLS, redirect ownership, and organization root-domain evidence during discovery.
- [x] Block low-confidence/out-of-scope assets from active scanning by default.
- [x] Persist validation evidence and show it in asset API/UI.
- [x] Backfill existing assets from historical subdomain/IP state.
- [ ] Add asset validation worker for periodic revalidation.
- [ ] Add RDAP/ASN ownership evidence.
- [ ] Add analyst review workflow for `needs_review` assets.

Acceptance:
- [x] Assets show in-scope/out-of-scope/needs-review.
- [x] Downstream scan target selection uses validation state.
- [x] Scan detail records validation-gated skipped targets.

### Milestone 3: Discovery Engine V2

Scope:
- Add CT logs, Common Crawl/Wayback host extraction, optional SecurityTrails/Censys/Shodan providers.
- Add DNS brute force and permutations.
- Add ASN/IP expansion.
- Add cloud bucket candidates.
- Persist discovery evidence.

Acceptance:
- Discovery source breakdown appears in scan detail.
- Wildcard DNS and duplicate sources are handled.
- New asset source evidence is visible in asset detail.

### Milestone 4: Endpoint Intelligence V2

Scope:
- Extend `web_endpoints`.
- Improve normalization, source merging, classification, scoring.
- Track selected/scanned endpoint state.
- Improve endpoint UI.

Acceptance:
- Endpoint tab explains source, type, score, reasons, and scan status.
- Nuclei endpoint targets are deterministic and bounded.

### Milestone 5: Scanner Coverage Expansion

Scope:
- Add TLS worker.
- Add DNS security worker.
- Add takeover worker.
- Add cloud exposure worker.
- Add non-web service fingerprinting.
- Expand nuclei profiles.

Acceptance:
- Findings are categorized by scanner/check family.
- Scanner coverage summary shows what checks ran and what was skipped.
- Defaults remain safe.

### Milestone 6: Risk and Finding Lifecycle V2

Scope:
- Add finding confidence and validation state.
- Add contextual risk scoring and risk drivers.
- Add stale/resolved finding lifecycle.
- Improve findings UI workflow.

Acceptance:
- Asset/finding priority is explainable.
- Old stale findings do not remain open forever without validation.

## Testing Strategy

### Unit Tests

- Scan policy merge and safety caps.
- Target selection scoring and skip reasons.
- Discovery source parsers.
- DNS wildcard suppression.
- Endpoint normalization and classification.
- Nuclei profile selection.
- Risk score driver calculation.
- Finding fingerprint stability.

### Integration Tests

- Full scan creates expected phase runs.
- Discovery evidence persists across passive and active sources.
- Asset validation gates downstream scans.
- Crawl produces endpoints, selects targets, and queues endpoint nuclei batches.
- Nuclei partial timeout stores partial result state.
- Correlation completes exactly once after all expected work is done.
- Risk worker recomputes affected assets and org score.

### Runtime Smoke Tests

Profiles:
- `safe`
- `default`
- `deep_authorized`

Targets:
- local mock HTTP service with known pages and headers.
- local mock DNS fixtures where possible.
- authorized external domain only when explicitly approved.

Smoke checks:
- Queues drain.
- DLQs remain empty.
- Phase timeline complete.
- Asset validation state present.
- Endpoint scores and selected reasons present.
- Findings appear for controlled test fixtures.
- UI pages render without client-side exceptions.

## Operational Controls

- Per-org concurrent scan limit.
- Per-scan timeout and phase timeout.
- Queue backpressure display.
- Worker scale recommendations by profile.
- Kill/retry stuck scan operation.
- DLQ replay operation with audit log.
- Template update status and template version tracking.
- Provider API quota tracking.

## Security and Compliance Controls

- Default deny for intrusive templates.
- Scan authorization statement per organization.
- Audit log for scan start, config changes, and risky profile usage.
- Sensitive evidence redaction.
- No raw secrets in logs.
- Scope exclusion enforcement before active scanning.
- Rate limits per domain/IP.
- User-visible warning for deep authorized profile.

## UI Deliverables

- `/dashboard/scans/[id]`: scan detail and phase timeline.
- Asset detail:
  - validation state
  - source evidence
  - richer ports
  - endpoint intelligence
  - risk drivers
- Findings:
  - confidence
  - validation status
  - reason modals
  - bulk actions
  - retest action
- Dashboard:
  - attack surface growth
  - newly exposed services
  - high-risk assets
  - stale assets
  - scan health and queue backlog

## Success Metrics

- Discovery coverage increases without large false-positive growth.
- Every active scan target has a persisted reason.
- Every skipped target has a persisted reason.
- UI can explain scan progress and zero-finding scans.
- DLQ rate remains near zero.
- Long-running scans show batch-level progress.
- Analyst can prioritize findings from risk drivers, not severity alone.

## Next Implementation Recommendation

Start **Milestone 2: Asset Validation and Scope Confidence**.

Reason:
Milestone 1 is now implemented, so the next bottleneck is trust. Before expanding discovery sources or scanners, the platform should decide whether each discovered asset is in scope, alive, exposed, and owned with enough confidence to justify active scanning.

Suggested next PR scope:
- Add asset validation fields or a dedicated validation table.
- Add `asset.validate` queue and worker.
- Validate DNS, HTTP, TLS certificate, redirect ownership, and RDAP/ASN evidence.
- Add `scope_status`, `ownership_confidence`, `ownership_reason`, `exposure_status`, `liveness_status`, and `last_verified_at`.
- Gate downstream active scans on validation state.
- Show validation state and evidence in asset detail UI.

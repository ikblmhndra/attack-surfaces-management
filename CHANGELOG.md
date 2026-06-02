# Changelog

All notable changes to this project are documented below, sorted newest-first.

---

## 2026-06-02 — API Timeline Query & Queue Runtime Fixes

### Fixed: Asset detail client-side crash
- **File**: `frontend/src/app/dashboard/assets/[id]/page.tsx`
- Asset detail now normalizes `open_findings` from either a count or API summary array before rendering badges and sidebar metrics.
- **Impact**: Assets with open finding objects in the detail response no longer trigger a React client-side exception.

### Fixed: Crawl endpoint persistence on oversized archive URLs
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/Dockerfile`
- Crawl persistence now skips URLs and hosts that exceed database column limits and clamps bounded display fields before upsert.
- GAU passive URL collection now runs with bounded per-host concurrency instead of sequentially processing every host.
- Optional FFUF fuzzing now runs inside the crawl phase after live web discovery, so fuzzed paths are validated, persisted as `web_endpoints`, and can feed endpoint-level nuclei scans.
- Crawl progress updates are now monotonic, so late crawl completion cannot move a scan backward from a higher progress percentage.
- Nuclei batches generated from crawled endpoints now use a dedicated HTTP-only endpoint template profile with a bounded endpoint scan timeout.
- **Impact**: Passive GAU/Katana results with extremely long historical URLs no longer fail the entire crawl task or leave scans stuck near completion.

### Fixed: Nuclei timeout reported as zero findings
- **Files**: `workers/scanner/nuclei_worker.py`, `workers/scanner/discovery_worker.py`, `workers/crawler/web_crawl_worker.py`, `backend/app/services/scan_service.py`, `frontend/src/components/modals/ScanModal.tsx`
- Nuclei worker now parses partial result files after timeout and treats empty timed-out batches as worker errors instead of silently completing with zero findings.
- Technology detections are still logged, but no longer become a global `-tags` filter by default. This restores coverage for generic exposure, misconfiguration, takeover, default-login, CVE, and vulnerability templates that manual nuclei runs would include.
- Full scan defaults now use smaller nuclei batches and longer scan timeout, reducing repeated batch timeouts on large crawled endpoint sets.

### Fixed: PostgreSQL timeline aggregation errors
- **Files**: `backend/app/api/v1/endpoints/organizations.py`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/api/v1/endpoints/findings.py`
- Timeline and trend endpoints now use a stable literal date bucket for `date_trunc`, preventing PostgreSQL `GroupingError` failures when frontend refreshes organization metrics after scan execution.

### Fixed: RabbitMQ local disk alarm blocking scan queue publishes
- **File**: `infrastructure/rabbitmq/rabbitmq.conf`
- RabbitMQ disk watermark now uses a fixed `2GB` threshold instead of `1.5x` available memory, preventing local/dev environments with usable disk space from blocking AMQP publishers.

---

## 2026-06-01 — Organization Automation Controls & Tech-Aware Scanning

### Added: Dedicated endpoint crawling phase
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/scanner/discovery_worker.py`, `workers/task_coordinator.py`, `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/006_web_endpoints.py`, `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `docker-compose.yml`
- Added a separate `scan.crawl` worker phase that runs after live web discovery and before expanded nuclei endpoint scans.
- Crawl combines Katana for active crawling and GAU for passive URL collection, validates candidates with httpx, normalizes/deduplicates URLs, and stores scoped results in the new `web_endpoints` table.
- Discovery now queues crawl batches for `ok` and `redirect` web assets instead of doing inline crawling, keeping discovery faster and making crawl progress trackable through coordinator counters.
- Interesting endpoint selection now feeds bounded nuclei batches for API/auth/admin/upload/config-style paths without scanning every discovered URL.
- Asset detail now includes an Endpoints tab with URL, source, HTTP status, content type, title, and API/auth/parameter/interesting indicators.
- Added the `worker-crawl` Docker service and `CRAWL_CONCURRENCY` setting; worker images now include `gau`.
- Added a default GAU config at `workers/config/gau.toml`, copied it to `/root/.gau.toml` in worker images, and made the crawl worker invoke GAU with an explicit config path.

### Fixed: Scan lifecycle edge cases and scheduler restart behavior
- **Files**: `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scheduler/scheduler.py`, `docker-compose.yml`, `.env.example`
- Discovery now marks screenshot work as complete when no screenshot task is queued, including scans with the screenshot module enabled but zero discovered subdomains.
- Port worker now marks port batches complete even when an empty IP batch is received, preventing malformed/manual queue messages from leaving a scan waiting forever.
- Discovery updates `total_tasks` from the actual downstream batch count so UI progress reflects queued port, nuclei, and screenshot work more accurately.
- Scheduler no longer queues a full scan two minutes after every restart by default. Set `RUN_FULL_SCAN_ON_START=true` to keep that behavior.
- Scheduled scans now skip organizations that already have an active scan or a recent completed scan within the configured interval, reducing duplicate automated scans after deploys or scheduler catch-up.
- Workers now cap RabbitMQ prefetch to their configured concurrency, so heavy scan workers do not reserve more unacked messages than they can process.
- Scan cancellation now records `completed_at`, keeping terminal scan rows consistent for reporting and UI sorting.

### Changed: HTTP status-aware scan routing and asset triage
- **Files**: `workers/scanner/discovery_worker.py`, `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/page.tsx`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/types/index.ts`
- Discovery now classifies probed web services as `ok`, `redirect`, `auth_required`, `not_found`, `rate_limited`, `server_error`, `probe_failed`, or `other`.
- Katana and ffuf only crawl/fuzz `ok` and `redirect` targets, avoiding noisy 404/auth/error surfaces.
- Nuclei now skips default scans for 404 targets and routes auth/server/rate-limited targets through a bounded limited profile.
- Asset APIs expose `http_status_class` and support filtering assets by HTTP status class.
- Asset list and detail views now show HTTP status badges and include an HTTP class filter.

### Added: Technology-aware nuclei pre-scan
- **Files**: `workers/scanner/discovery_worker.py`, `workers/scanner/nuclei_worker.py`, `frontend/src/components/modals/ScanModal.tsx`
- HTTP probing now normalizes `httpx -tech-detect` output, persists detected technologies in the `technologies` table, and passes a technology map to nuclei batches.
- Nuclei now converts only curated technologies (for example Next.js, React, WordPress, Apache, Nginx, Jenkins, Grafana) into template tags while keeping automatic scan enabled, avoiding the broad tag explosion that previously made scans run too long.

### Added: Per-organization automatic scan control
- **Files**: `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/005_org_auto_scan.py`, `backend/app/api/v1/endpoints/organizations.py`, `workers/scheduler/scheduler.py`, `frontend/src/app/dashboard/organizations/new/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Organizations now have an `auto_scan_enabled` setting. It can be set during organization creation and changed from the organization edit dialog.
- The scheduler now requires both workspace-level `auto_scan_enabled` and organization-level `auto_scan_enabled` before queueing default quick/full automated scans.

---

## 2026-05-25 — Scanning Pipeline Lifecycle & UI Reliability Fixes

### Added: Transactional outbox for reliable scan queue publishing
- **Files**: `backend/app/services/outbox_service.py`, `backend/app/db/migrations/versions/003_outbox_events.py`, `backend/app/db/models/models.py`
- Scan creation now persists queue publish events in `outbox_events` within the same database transaction as the `Scan` row. A background dispatcher publishes pending events to RabbitMQ with retry/backoff and marks scans failed after repeated publish failures.
- Coordinator Redis preparation is idempotent per outbox event, preventing retry attempts from double-counting expected worker batches.
- Queue publishers now declare durable queues and bindings before publishing, so outbox-dispatched scan messages are retained even if a worker is temporarily stopped.
- **Impact**: Prevents silent-stuck scans when the API commits a scan but crashes or loses RabbitMQ connectivity before publishing the queue message.

### Changed: API and scheduler scan creation now enqueue via outbox
- **Files**: `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/scans.py`, `workers/scheduler/scheduler.py`
- Organization-triggered scans, manual nuclei scans, and scheduled scans now create outbox events instead of publishing directly from the request/scheduler path. Manual scan Redis coordinator setup is performed by the outbox dispatcher before publishing the nuclei message.

### Fixed: Port scan persistence used the wrong foreign key
- **File**: `workers/scanner/port_worker.py`
- Port results were inserted with `ports.ip_id = assets.id`, but the schema requires `ports.ip_id` to reference `ip_addresses.id`.
- **Impact**: Port scan results could fail persistence with FK errors and push worker messages into retry/DLQ.
- **Fix**: Upsert `IPAddress` records for IP assets first, then persist `Port` rows using the returned `ip_addresses.id`. Port worker now persists discovered IP assets even when no open ports are found and uses the Go tool path in Docker so `naabu` is available at runtime.

### Fixed: Scan lifecycle could hang or overwrite cancelled scans
- **Files**: `workers/scan_state.py`, `workers/base_worker.py`, scanner workers, `workers/correlation/correlation_worker.py`
- Workers did not consistently skip terminal scans, max-retry failures did not mark scans failed, and terminal correlation could overwrite `cancelled`/`failed` status as `completed`.
- **Fix**: Added shared lifecycle helpers for running/failed/completed transitions, terminal status guards, max-retry failure propagation, and completion that only applies to active scans.

### Fixed: Pipeline terminal coordination ignored port scan completion
- **Files**: `workers/task_coordinator.py`, `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`
- Redis terminal checks only waited for nuclei and screenshot completion, so a full scan could complete before port batches finished.
- **Fix**: Added `port_expected`/`port_done` counters and included them in the atomic terminal Lua check. Expected counters are now registered before queue publish to avoid fast-worker races.

### Changed: Scan status and API/UI contract normalized
- **Files**: `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/scans.py`, `backend/app/api/v1/endpoints/organizations.py`, `frontend/src/app/dashboard/scans/page.tsx`
- Scan creation now transitions to `queued` after successful publish, active scan limits include `queued`, manual scans validate workspace ownership, `/scans` supports `search`, and failed scan errors are visible in the scans table.

### Added: Frontend realtime scan cache updates
- **Files**: `frontend/src/lib/useRealtimeEvents.ts`, `frontend/src/app/dashboard/page.tsx`, `frontend/src/app/dashboard/scans/page.tsx`
- Added a WebSocket hook that listens for scan, score, and finding events and invalidates relevant React Query caches while keeping polling as fallback.

### Added: Focused scan pipeline regression tests
- **Files**: `backend/tests/unit/test_scan_pipeline_state.py`, `backend/tests/unit/test_outbox_service.py`
- Added unit coverage for scan lifecycle transitions, terminal-scan completion guards, failure event emission, and port persistence using `ip_addresses.id` for `ports.ip_id`.

### Fixed: Runtime API/WebSocket URL defaults
- **Files**: `docker-compose.yml`, `infrastructure/nginx/nginx.conf`
- Frontend default API URL pointed at `/api` while FastAPI routes are mounted at `/api/v1`, and `/ws` proxied to the wrong backend path.
- **Fix**: Default `NEXT_PUBLIC_API_URL` is now `/api/v1`; Nginx `/ws` and `/ws/` proxy cleanly to `/api/v1/ws/`.

### Fixed: Nuclei scans could run far too long
- **Files**: `workers/scanner/nuclei_worker.py`, `workers/scanner/discovery_worker.py`, `workers/base_worker.py`, `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/004_unique_finding_fingerprint_org.py`, `frontend/src/components/modals/ScanModal.tsx`, `docker-compose.yml`
- Nuclei template path pointed to an empty `/opt/nuclei-templates` directory, so workers did not constrain scans to the intended template directories. Full scans also added broad technology tags and allowed one-hour batch runtime.
- **Fix**: Pointed workers at `/root/nuclei-templates`, restricted default template directories, disabled tech-tag broadening unless explicitly enabled, reduced default nuclei concurrency/bulk size, added bounded scan/template timeouts, and lowered full-scan nuclei batch size.
- Worker concurrency now holds the semaphore for the full message processing lifetime, preventing nuclei batches from exceeding the configured worker concurrency under queue bursts.
- Default web UI scans now use nuclei automatic tech-aware scanning plus ASM-safe exposure/misconfiguration templates. Full scans still include CVE/vulnerability directories, but no longer run the entire template repository without a path filter.
- Finding persistence now has the required unique constraint on `(fingerprint, org_id)`, so nuclei/nikto upserts do not fail and requeue forever when a vulnerability is found.

### Fixed: Unit-test regressions in CIDR validation and critical risk scoring
- **Files**: `backend/app/core/security.py`, `backend/app/services/risk_engine.py`
- CIDR validation no longer accepts a bare IP as a network. Risk scoring now caps the overall score when effective critical-finding penalty is high, so critical exposure meaningfully affects the posture score even when category weights are narrow.

---

## 2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse

### Fixed: Findings upsert fails — `ON CONFLICT` requires unique index, not btree
- **File**: Database schema / `workers/scanner/nuclei_worker.py`
- `pg_insert(Finding.__table__).on_conflict_do_update(index_elements=["fingerprint", "org_id"])` requires a **unique** constraint or unique index on those columns in PostgreSQL. The existing `ix_finding_fingerprint` was a regular (non-unique) btree index, so every insert threw `InvalidColumnReferenceError: there is no unique or exclusion constraint matching the ON CONFLICT specification`.
- **Impact**: **Root cause of findings not appearing in the UI**. The finding was parsed correctly from nuclei JSON output, but the database upsert failed. The `message_processing_error` exception was caught by the BaseWorker and the message was requeued (infinite retry loop).
- **Fix**: Replaced index `ix_finding_fingerprint` with unique index `uq_finding_fingerprint_org` via `CREATE UNIQUE INDEX`.

### Fixed: `UnboundLocalError: cannot access local variable 'findings'`
- **File**: `workers/scanner/nuclei_worker.py:146`
- When `findings_raw` was empty (nuclei found zero vulnerabilities), the `findings` variable was never assigned before `log.info("nuclei_scan_completed", findings=len(findings))` referenced it.
- **Impact**: When nuclei found nothing (e.g., zero findings), the log line threw `UnboundLocalError`, the message was requeued with retry, and the correlation terminal message was never sent. Scan stayed "running" forever despite having zero findings.
- **Fix**: Initialize `findings = []` before the `if findings_raw:` branch.

### Fixed: Nuclei JSON output lines may be arrays, not objects
- **File**: `workers/scanner/nuclei_worker.py:273-281`
- `nuclei -json-export` can output JSON arrays on a single line. `json.loads(line)` returned a list, which was passed to `_parse_finding()` as `raw` — calling `raw.get("template-id")` on a list raised `AttributeError`.
- **Fix**: Check `isinstance(parsed, list)` → `results.extend(parsed)`. Also guard `_parse_finding()` with `isinstance(raw, dict)`.

---

## 2026-05-22 — Port Worker Race Condition Fix

### Fixed: Race condition causes scan to complete before port worker's nuclei tasks finish
- **File**: `workers/scanner/port_worker.py`
- Port worker queued additional `scan.nuclei` messages for discovered IPs (via `_queue_nuclei()`) and incremented `nuclei_expected` AFTER the discovery worker already finished its nuclei batches. If the discovery-based nuclei + screenshot completed first, the terminal condition `nuclei_done >= nuclei_expected && screenshot_done == 1` would trigger prematurely — scan marked "completed" while port worker hadn't even started queuing its nuclei tasks yet.
- **Impact**: Scan status showed "done" but nuclei worker was still running. Results from port-discovered IPs were orphaned.
- **Fix**: Removed `_queue_nuclei()` entirely from port worker. Discovery worker already queues nuclei for all discovered subdomains (which cover standard HTTP/HTTPS via httpx probing). Port scanning now focuses solely on port discovery and persistence. Non-standard port coverage (e.g. 8080, 8443) was never actually done by `_queue_nuclei` (it only queued `http://IP` and `https://IP`), so no coverage is lost.

### Fixed: Manual scan Redis coordinator silently fails on error
- **File**: `backend/app/api/v1/endpoints/scans.py`
- Coordinator setup (Redis keys for `nuclei_expected`, `screenshot_done`) was wrapped in `try/except Exception: pass` — if Redis was unavailable, the keys were never created and the manual scan would hang at "running" forever with zero error feedback.
- **Fix**: Removed inner `try/except` so Redis errors propagate to the outer error handler, which marks the scan as `failed` with a descriptive message and returns HTTP 500.

---

## 2026-05-21 — Redis Coordinator Fix, Manual Nuclei, Pipeline Finalization

### Fixed: `register_script` is NOT async in redis-py 5.x (blocks ALL pipeline completion)
- **File**: `workers/task_coordinator.py`
- `await r.register_script()` raised `TypeError: object AsyncScript can't be used in 'await' expression`. `register_script()` is synchronous in redis-py 5.x — it returns an `AsyncScript` whose `__call__` is awaitable, but `register_script` itself is not.
- **Impact**: **Root cause of every scan stuck at "running"**. Neither nuclei nor screenshot workers could call `mark_terminal_if_all_done` — the terminal correlation message was never sent. Messages were requeued infinitely (77+ backlog in `scan.nuclei`).
- **Fix**: Remove `await` from `r.register_script()`.

### Fixed: Discovery worker never finalizes when zero downstream work queued
- **File**: `workers/scanner/discovery_worker.py`
- When discovery finds 0 assets, no nuclei/screenshot batches are published, `add_nuclei_expected` is never called, and no downstream worker exists to call `mark_terminal_if_all_done`. The scan stays "running" forever even though nothing will ever process it.
- **Fix**: Added `_finalize_if_no_work()` — sets `screenshot_done=1` and atomically calls `mark_terminal_if_all_done`, publishing the terminal correlation message if it wins the race. `_queue_downstream` now returns `nuclei_queued` boolean.

### Fixed: Nuclei worker doesn't update scan status to "running"
- **File**: `workers/scanner/nuclei_worker.py`
- Manual nuclei scans stayed stuck in "pending" because the nuclei worker never called `_update_scan_status`. Added status→running + `started_at` update at the start of `process()`.

### Fixed: Missing `UUID` import in scans endpoint
- **File**: `backend/app/api/v1/endpoints/scans.py`
- `UUID` was used in type hints but only `import uuid` was present — no `from uuid import UUID`. Caused `NameError` on container restart.

### Added: Manual nuclei scan endpoint
- **File**: `backend/app/api/v1/endpoints/scans.py`
- `POST /scans/manual` — accepts `org_id`, `targets` (list of URLs/domains), `vuln_depth`. Creates scan record, publishes directly to `scan.nuclei` queue, sets up Redis coordinator keys. Returns `201` with `scan_id`.

### Added: Manual scan tab in frontend ScanModal
- **File**: `frontend/src/components/modals/ScanModal.tsx`
- New "Manual Nuclei" tab alongside existing "Automated" tab. User enters targets (one per line in textarea), clicks "Run Nuclei" which calls `POST /scans/manual`.

### Fixed: Edit organization button does nothing
- **File**: `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Edit button only toggled `editing` boolean but no UI was rendered. Added full edit modal with fields: name, description, domains, IP ranges, ASNs, company, industry, criticality, environment. Calls `PUT /organizations/{id}`.

---

## 2026-05-21 — Scanning Pipeline Overhaul: 4 Bug Fixes + Katana/FFUF + Scan Modal

### Fixed: Findings never persisted (constraint name mismatch)
- **File**: `workers/scanner/nuclei_worker.py`
- `on_conflict_do_update(constraint="uq_finding_fingerprint_org")` referenced a non-existent constraint. The `findings` table only has a regular index on `(fingerprint, org_id)`, not a named unique constraint. Every finding insert threw `UndefinedObjectError` and was dead-lettered.
- **Fix**: Changed to `index_elements=["fingerprint", "org_id"]` — uses the existing index.
- **Impact**: **Primary root cause** of zero findings in the UI.

### Fixed: Scheduler-triggered scans produced zero downstream work
- **File**: `workers/scheduler/scheduler.py`
- Config published by `_schedule_full_scans()` was missing the `modules` key → `config.get("modules", [])` returned `[]` → all stage checks failed → nothing queued.
- **Fix**: Added `"modules": ["discovery", "port", "nuclei", "screenshot"]` to full scan config.

### Fixed: Port worker column/constraint names mismatch
- **File**: `workers/scanner/port_worker.py`
- `asset_id`→`ip_id`, `port`→`port_number`, `service`→`service_name`, removed non-existent `org_id`. Constraint `uq_port_asset_port_protocol` → `index_elements`.

### Fixed: Quick scan module names incompatible with worker checks
- **File**: `workers/scheduler/scheduler.py`
- `modules: ["dns", "http", "tls"]` → `["discovery", "nuclei"]`.

### Fixed: Stale `DEFAULT_MODULES` in scan service
- **File**: `backend/app/services/scan_service.py`
- Removed dead `nikto`, `probe`, `dns`, `enrich` module names. Updated all scan types to match actual worker checks.

### Added: Tech-aware nuclei routing
- **Files**: `discovery_worker.py`, `nuclei_worker.py`
- Discovery passes `tech_map: {url: [nginx, php, ...]}` with nuclei tasks. Worker adds tech names as `-include-tags` filters. Always includes `cve` + `vulnerabilities` tags.

### Added: Katana endpoint crawling
- **File**: `discovery_worker.py` — new `_crawl_endpoints()`
- Runs `katana` against httpx-alive URLs to discover JS files, API routes, hidden paths. Results added to nuclei targets. Toggle via `config.crawl` (default: `true`).

### Added: FFUF directory/endpoint fuzzing
- **File**: `discovery_worker.py` — new `_fuzz_endpoints()`
- Optional `ffuf` fuzzing to discover `/admin/`, `/.git`, `/.env`, `/backup/`, API paths. Auto-calibrates to filter 404/redirects. Uses wordlist at `/usr/share/wordlists/dirb/common.txt`, SecList, or built-in 50-entry fallback. Toggle via `config.fuzz` (default: `false`).

### Added: Frontend Scan Modal with type + toggles
- **File**: `frontend/src/components/modals/ScanModal.tsx` (new)
- Replaced one-click "Run Scan" button with a modal: scan type selector (full/quick/discovery/vuln), pipeline preview, endpoint crawling toggle (katana), directory fuzzing toggle (ffuf), advanced options. Integrated into org detail page.

### Added: Proper URL scheme routing
- **File**: `port_worker.py`
- Port worker now sends both `https://ip` and `http://ip` (not only `http://`). Discovery uses URLs with scheme from httpx results.

---

## 2026-05-19 — Pipeline Completion & Screenshot Fixes

### Fixed: Scan marked "completed" while nuclei still running
- **Files**: `correlation_worker.py`, `screenshot_worker.py`
- Added `is_terminal` flag. Only screenshot sends `is_terminal=True`. Correlation completes scan only on terminal messages.

### Fixed: NGINX screenshot proxy returning 404/301
- **File**: `infrastructure/nginx/nginx.conf`
- Changed `location /storage/` → `location ^~ /storage/` to force prefix matching over regex.

### Fixed: Frontend screenshot field name mismatches
- **File**: `frontend/src/app/dashboard/assets/[id]/page.tsx`
- `s.created_at`/`s.taken_at` → `s.captured_at`. `s.screenshot_url` → `s.url`.

### Added: Global screenshots gallery endpoint
- **File**: `backend/app/api/v1/endpoints/screenshots.py` (new)
- `GET /screenshots` with pagination, org filtering, domain search, workspace scoping.

### Fixed: Screenshots gallery page crash
- **File**: `frontend/src/app/dashboard/screenshots/page.tsx`
- `new Date(undefined)` from mismatched field names crashed the page with `RangeError`.

### Fixed: crt.sh 502 errors with retry logic
- **File**: `discovery_worker.py`
- Added 3 attempts with exponential backoff and rotating User-Agent.

### Fixed: Redis counter race on scan completion
- **File**: `workers/task_coordinator.py`
- Atomic Lua script `mark_terminal_if_all_done` ensures only one worker (the last nuclei batch or screenshot) sends the terminal message.

### Fixed: RabbitMQ `ChannelInvalidStateError` on long scans
- **File**: `base_worker.py`
- Increased heartbeat to 300s. Added `ChannelInvalidStateError` handler + try/except around all ack/reject calls.

### Added: Vuln depth selection
- **Files**: `nuclei_worker.py`, `frontend/src/app/dashboard/page.tsx`
- Critical/default/full nuclei template depth configurable per scan.

### Fixed: Workers ignore `modules` list
- **File**: `discovery_worker.py`
- Vuln scans no longer run discovery. Module list gates all downstream stages.

---

## 2026-05-19 — Auto-Scan Toggle & Progress Bar Fix

### Added: Auto-scan enable/disable
- **Files**: `frontend/src/app/dashboard/settings/page.tsx`, `workspaces.py`, `scheduler.py`
- New `auto_scan_enabled` checkbox in Settings. Scheduler filters based on workspace settings.

### Fixed: Progress bar stuck at 0%
- **Files**: All workers
- Each worker now sets `progress_pct` at its stage. Changed to `func.greatest()` to prevent progress from going backwards.

### Fixed: RabbitMQ exchange bindings lost on restart
- **File**: `base_worker.py`
- Added `EXCHANGE_MAP` and auto-bind queue to exchange on every startup.

### Fixed: OpenSearch excessive RAM usage
- **File**: `docker-compose.yml`, `correlation_worker.py`
- JVM heap 1GB→512MB. Index replicas set to 0 (single node).

### Added: Scan phase label in progress bar
- **File**: `frontend/src/app/dashboard/scans/page.tsx`, `frontend/src/app/dashboard/page.tsx`
- Phase label: Queued → Starting → Discovery → Port → Vuln scan → Screenshots → Finalizing.

### Fixed: Empty error messages in discovery logs
- **File**: `discovery_worker.py`
- Added type+message to error logging for crtsh/assetfinder/timeout errors.

### Fixed: Nuclei worker `ModuleNotFoundError: No module named 'app'`
- **File**: `docker-compose.yml`
- Added missing `./backend/app:/app/app:ro` volume to nuclei worker.

### Added: New Scan modal on dashboard
- **File**: `frontend/src/app/dashboard/page.tsx`
- Dashboard "New Scan" button now opens modal with org selector + scan type.

---

## 2026-05-19 — Worker Pipeline Fixes

### Fixed: `worker-port` not running
- **File**: `docker-compose.yml`
- Port worker service was defined but never started. Pipeline stalled after discovery.

### Fixed: RabbitMQ exchange bindings missing
- **File**: `infrastructure/rabbitmq/definitions.json`
- Manually declared bindings for all exchanges. Root cause unknown (definitions.json loading issue).

### Fixed: httpx using Python CLI instead of Go binary
- **File**: `workers/Dockerfile`
- Python `httpx` pip package installed a broken CLI at `/usr/local/bin/httpx` that shadowed the ProjectDiscovery Go binary. `http_probed alive=0` despite valid subdomains.
- **Fix**: `rm -f /usr/local/bin/httpx` after pip install. Prepend `/go/bin` to PATH.

### Fixed: SQLAlchemy 2.0 `pg_insert` ORM incompatibility
- **Files**: 9 worker files
- `pg_insert(Model)` → `pg_insert(Model.__table__)` to bypass ORM bulk persistence path.

### Fixed: Go tools shadowed by Python CLI entrypoints
- **File**: `workers/Dockerfile`
- `PATH=/go/bin:...:$PATH` (prepend instead of append) to avoid future collisions.

### Fixed: Stale Python bytecache causing old constraint name error
- **File**: `workers/scanner/discovery_worker.py`
- `__pycache__` retained old constraint name. Cleared cache for clean reload.

### Changed: All worker services replicas set to 1
- **File**: `docker-compose.yml`
- Development resource optimization. Removed `deploy.replicas` blocks.

---

## 2026-05-18 — API Trailing Slash Fix

### Fixed: Trailing slash mismatch on 10 root endpoints
- **Files**: 10 backend endpoint files
- `@router.get("/")` → `@router.get("")`. Frontend axios calls without trailing slash got 405.

### Added: Changelog scripts + make targets
- **Files**: `scripts/changelog.sh`, `Makefile`
- CLI helper and make targets for changelog management.

---

## 2026-05-17 — Frontend Build Fixes

### Fixed: Missing/nonexistent dependencies
- Removed `@radix-ui/react-badge` (never existed in npm). Downgraded `@tanstack/react-table` to 8.16.0 (CJS-compatible). Added `geist@1.3.1`.

### Fixed: Missing config files
- Created `tsconfig.json`, `postcss.config.js`, `next-env.d.ts`.

### Fixed: Broken imports in dashboard
- Removed dead component imports. Fixed `GradeRing` import path.

### Fixed: TypeScript errors
- Extracted inline const maps into typed `Record<string, ...>` variables.

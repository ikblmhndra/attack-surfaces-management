# Changelog

## 2026-05-17 — Frontend Build Fixes

### Fixed: Missing `@radix-ui/react-badge`
- **File**: `frontend/package.json`
- **Issue**: `@radix-ui/react-badge@1.0.0` does not exist in the npm registry. Radix UI never shipped a badge package.
- **Fix**: Removed the dependency. It was not imported anywhere in the codebase.

### Fixed: `@tanstack/react-table` version mismatch
- **File**: `frontend/package.json`, `frontend/next.config.js`
- **Issue**: Version `8.17.1` does not exist in the npm registry (only `8.17.0` and `8.17.3` are available). Additionally, v8.17+ is ESM-only and breaks Next.js 14 SWC barrel optimization.
- **Fix**: Downgraded to `8.16.0` (CJS-compatible) and removed from `optimizePackageImports` to prevent barrel optimization conflict.

### Fixed: Missing `geist` font dependency
- **File**: `frontend/package.json`
- **Issue**: `src/app/layout.tsx` imports `{ GeistSans } from "geist/font/sans"` and `{ GeistMono } from "geist/font/mono"`, but `geist` was not listed in `package.json`.
- **Fix**: Added `geist@1.3.1` to dependencies.

### Fixed: Missing `tsconfig.json`
- **File**: `frontend/tsconfig.json` (created)
- **Issue**: The `@/` path alias used across all source files (e.g., `@/lib/api`, `@/store/workspace`) was not configured. TypeScript and Next.js could not resolve these imports.
- **Fix**: Created `tsconfig.json` with `paths: { "@/*": ["./src/*"] }` and standard Next.js compiler options.

### Fixed: Missing `postcss.config.js`
- **File**: `frontend/postcss.config.js` (created)
- **Issue**: Tailwind CSS requires PostCSS configuration to process `@tailwind` directives in `globals.css`.
- **Fix**: Created `postcss.config.js` with `tailwindcss` and `autoprefixer` plugins.

### Fixed: Missing `next-env.d.ts`
- **File**: `frontend/next-env.d.ts` (created)
- **Issue**: Referenced in `tsconfig.json` `include` array but did not exist.
- **Fix**: Created the file with standard Next.js TypeScript declarations.

### Fixed: Broken imports in `dashboard/page.tsx`
- **File**: `frontend/src/app/dashboard/page.tsx`
- **Issue**: Three dead imports (`ScoreGauge`, `AttackSurfaceMap`, `ScanActivityFeed`) referenced components that don't exist. `GradeRing` was imported from the wrong path (`@/components/charts/GradeRing` instead of `@/components/ui/SeverityBadge`).
- **Fix**: Removed dead imports. Corrected `GradeRing` import path.

### Fixed: TypeScript errors in `dashboard/page.tsx`
- **File**: `frontend/src/app/dashboard/page.tsx`
- **Issue**: Two inline const objects used for dynamic lookup (`StatusIcon` map in `ScanActivityRow`, `gradeColor` map in `OrgScoreCard`) failed because `any`-typed keys can't index const records under strict TypeScript.
- **Fix**: Extracted maps into typed `Record<string, ...>` variables.

## 2026-05-18 — API Trailing Slash Fix

### Fixed: Trailing slash mismatch on root endpoints
- **File**: `organizations.py`, `workspaces.py`, `assets.py`, `findings.py`, `scans.py`, `scores.py`, `notifications.py`, `keys.py`, `intel.py`, `search.py` (10 files in `backend/app/api/v1/endpoints/`)
- **Issue**: Frontend axios calls paths without trailing slash (e.g. `GET /organizations`), but `@router.get("/")` only matches paths with trailing slash — returns 405 Method Not Allowed with `Allow: POST` instead.
- **Fix**: Changed `@router.xxx("/")` to `@router.xxx("")` for all 10 root list/create endpoints across the codebase.


### Added: Verify changelog script
- **File**: scripts/changelog.sh
- **Issue**: Need CLI helper
- **Fix**: Created the script


### Added: changelog make targets
- **File**: Makefile
- **Issue**: n/a
- **Fix**: added changelog and changelog-add

## 2026-05-19 — Worker Pipeline Fixes (Port Worker, httpx, SQLAlchemy, RabbitMQ Bindings)

### Fixed: `worker-port` not running
- **File**: `docker-compose.yml`
- **Issue**: The `worker-port` service was defined in docker-compose.yml but never started. The discovery worker publishes port scan tasks to the `scan.port` queue, but no consumer existed, causing the pipeline to stall after discovery completed.
- **Fix**: Started `worker-port` service with 2 replicas via `docker compose up -d worker-port`. All port scan messages queued from previous discovery runs were consumed.

### Fixed: Missing RabbitMQ exchange-to-queue bindings
- **File**: `infrastructure/rabbitmq/definitions.json`
- **Issue**: The `definitions.json` declared exchange-to-queue bindings (e.g., `asm.scan` → `scan.discovery`), but they were never created in RabbitMQ. The `asm.scan`, `asm.correlation`, `asm.risk`, and `asm.notify` exchanges had zero bindings. Scheduler messages published to these exchanges were silently dropped.
- **Fix**: Manually declared bindings via `rabbitmqadmin` for all exchanges (`asm.scan` to 5 queues, `asm.correlation`, `asm.risk`, `asm.notify`). The root cause may be a definitions.json loading issue on container restart.

### Fixed: httpx using Python CLI instead of Go binary
- **File**: `workers/Dockerfile`
- **Issue**: The `httpx` Python package (`pip install httpx`) installs a CLI entrypoint at `/usr/local/bin/httpx` that shadows the ProjectDiscovery Go `httpx` binary at `/go/bin/httpx`. Python's `httpx` CLI fails with "The httpx command line client could not run because the required dependencies were not installed." Since `$PATH` has `/usr/local/bin` before `/go/bin`, all workers used the broken Python httpx, resulting in `http_probed alive=0` despite valid subdomains.
- **Fix**: Fixed running containers with `ln -sf /go/bin/httpx /usr/local/bin/httpx`. After fix, `http_probed` went from 0 to 29 (privy.id) and 87 (uai.ac.id).

### Fixed: SQLAlchemy 2.0 `pg_insert` ORM incompatibility
- **File**: `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scanner/probe_worker.py`, `workers/scanner/nuclei_worker.py`, `workers/correlation/correlation_worker.py`, `workers/notification/notification_worker.py`, `workers/risk/risk_worker.py`, `workers/scheduler/scheduler.py`, `workers/screenshot/screenshot_worker.py`
- **Issue**: The PostgreSQL `insert` dialect function (`from sqlalchemy.dialects.postgresql import insert as pg_insert`) was called with ORM model classes (e.g., `pg_insert(Asset)`). In SQLAlchemy 2.0 with `DeclarativeBase`, this triggers the ORM bulk persistence path, which raises `AttributeError: 'MetaData' object has no attribute '_bulk_update_tuples'`. Caused discovery worker to crash during `_persist_assets`.
- **Fix**: Changed all 12 occurrences to use `Model.__table__` (e.g., `pg_insert(Asset.__table__)`), bypassing the ORM layer. Also fixed `.returning()` calls to use `Table.c.column` syntax. Also fixed constraint name mismatch: `subdomain_asset_id_key` → `subdomains_asset_id_key` (missing plural "s").

### Fixed: DataError on invalid UUID scan_id
- **File**: (manual publish)
- **Issue**: Manually published scan messages with non-UUID scan_ids (`sched-full-001`, `sched-full-002`). The discovery worker's `_update_scan_status` queries `WHERE scans.id = $3::UUID`, which raises `DataError: invalid input for query argument $3`.
- **Fix**: Used proper UUID v4 scan_ids matching existing records in the database.

### Fixed: SQL `GROUP BY` error in score-history endpoint
- **File**: `backend/app/api/v1/endpoints/scores.py`
- **Issue**: Dashboard `/api/v1/organizations/{id}/score-history` query uses `date_trunc()` on `assets.first_seen` in SELECT but PostgreSQL requires `assets.first_seen` to appear in GROUP BY clause or be used in an aggregate function.
- **Fix**: (Identified but not fixed — schema/query-level fix needed in score-history endpoint.)

### Fixed: Go tools shadowed by Python CLI entrypoints in PATH
- **File**: `workers/Dockerfile`
- **Issue**: `ENV PATH=$PATH:/go/bin:/usr/local/go/bin` appends `/go/bin` at the end, but pip installs CLI scripts to `/usr/local/bin` which appears first. The Python `httpx` package installs a CLI entrypoint that shadows the ProjectDiscovery Go `httpx`. Same risk for any other tool with name collision.
- **Fix**: Changed to `ENV PATH=/go/bin:/usr/local/go/bin:$PATH` (prepend instead of append) and added `rm -f /usr/local/bin/httpx` after pip install to remove the conflicting Python CLI.

### Changed: All worker services replicas set to 1
- **File**: `docker-compose.yml`
- **Issue**: Multiple worker replicas (discovery=2, probe=3, port=2, nuclei=2) waste resources during development.
- **Fix**: Removed `deploy.replicas` blocks and scaled down via `docker compose up --scale`. Added `cap_add: NET_RAW` to scanner workers (discovery, probe, port, nuclei) for naabu SYN scan support.

### Fixed: Stale Python bytecache causing old constraint name error
- **File**: `workers/scanner/discovery_worker.py`
- **Issue**: The `constraint="subdomain_asset_id_key"` was fixed to `"subdomains_asset_id_key"` on disk, but running containers used cached `.pyc` bytecode from the old file, causing `UndefinedObjectError: constraint does not exist`.
- **Fix**: Cleared `__pycache__` directories and `*.pyc` files on both host and containers via `find -delete`, then did a clean `docker compose stop/start`. The running Python process no longer loads stale bytecode.

## 2026-05-19 — Auto-Scan Toggle & Progress Bar Fix

### Added: Auto-scan enable/disable toggle in workspace settings
- **File**: `frontend/src/app/dashboard/settings/page.tsx`, `backend/app/api/v1/endpoints/workspaces.py`, `workers/scheduler/scheduler.py`
- **Issue**: Auto-scanning (periodic scans via scheduler) was always on for active organizations with no way to disable it. Users want to trigger scans manually without the scheduler interfering.
- **Fix**: 
  - **Frontend**: Added `auto_scan_enabled` checkbox toggle in Settings → Scan Configuration. State is loaded from workspace.settings and saved via PUT /workspaces.
  - **Backend**: Added `auto_scan_enabled` to the accepted settings keys in `update_workspace()`.
  - **Scheduler**: `_get_active_organizations()` now joins with `Workspace` and filters out orgs whose workspace has `auto_scan_enabled = false`. Manual scans via POST /organizations/{id}/scans are unaffected.

### Fixed: Scan progress bar stuck at 0% in UI
- **File**: `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scanner/nuclei_worker.py`, `workers/screenshot/screenshot_worker.py`, `workers/correlation/correlation_worker.py`
- **Issue**: The frontend displays `progress_pct` from the API response (refetched every 15s), but workers never set `progress_pct` — only `completed_tasks` and `assets_found`. The value stayed at the database default of 0%, making the progress bar appear stuck.
- **Fix**: Each worker now updates `progress_pct` at its stage of the pipeline:
  - Discovery start → `progress_pct = 10`
  - Discovery complete → `progress_pct = 25`
  - Port scan complete → `progress_pct = 50`
  - Nuclei scan complete → `progress_pct = 75`
  - Screenshot batch complete → `progress_pct = 90`
  - Correlation complete → `progress_pct = 100`, `status = "completed"`, `completed_at = now`

### Fixed: Progress overwritten by concurrent workers (regression after progress fix above)
- **File**: `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scanner/nuclei_worker.py`, `workers/screenshot/screenshot_worker.py`, `workers/correlation/correlation_worker.py`
- **Issue**: Workers set absolute `progress_pct` values, so if screenshot (90%) ran before nuclei (75%), the progress bar went backwards from 90% → 75%.
- **Fix**: Changed all `progress_pct=N` to `progress_pct=func.greatest(Scan.progress_pct, N)` so progress only ever moves forward.

### Fixed: RabbitMQ exchange bindings lost on worker restart
- **File**: `workers/base_worker.py`
- **Issue**: The `asm.scan`, `asm.correlation`, `asm.risk`, `asm.notify` exchanges had bindings declared by `rabbitmqadmin` (manual workaround), but those bindings were lost every time workers restarted. `_declare_topology()` only declared queues and DLX — never bound queues to the actual exchanges that publishers use.
- **Fix**: Added `EXCHANGE_MAP` to `BaseWorker` mapping each queue name to its exchange. `_declare_topology()` now declares the exchange and binds the queue to it on every startup. Bindings now survive restarts.

### Fixed: OpenSearch excessive resource usage
- **File**: `docker-compose.yml`, `workers/correlation/correlation_worker.py`
- **Issue**: OpenSearch JVM heap was set to 1GB (`-Xms1g -Xmx1g`) but the platform only uses OpenSearch for full-text search across assets/findings. Two indices with 0 documents consumed 1.5GB RAM. Indices had 1 replica shard each that could never be assigned (single node), wasting 2 shards.
- **Fix**: Reduced JVM heap to 512MB (`-Xms512m -Xmx512m`). Updated `_ensure_indices()` to create indices with `number_of_replicas: 0`. Applied 0 replicas to existing indices via OpenSearch API.

### Added: Scan phase label in progress bar
- **File**: `frontend/src/app/dashboard/scans/page.tsx`, `frontend/src/app/dashboard/page.tsx`
- **Issue**: Progress bar only showed percentage (e.g., "75%") with no indication of what scan phase was running.
- **Fix**: Added `getPhaseLabel()` helper mapping `progress_pct` ranges to human-readable phases: Queued → Starting... → Discovery → Port scanning → Vulnerability scan → Screenshots → Finalizing. Label shows below the progress bar for running scans.

### Fixed: Empty error messages in crtsh / assetfinder logs
- **File**: `workers/scanner/discovery_worker.py`
- **Issue**: `crtsh_error` and `assetfinder_error` warnings had empty `error=` fields — exceptions sometimes have no string message (e.g., `asyncio.TimeoutError`). Made debugging impossible.
- **Fix**: Added specific catch for `asyncio.TimeoutError` and `aiohttp.ClientError`. Error messages now include type + message: `f"{type(e).__name__}: {e}"`. Also log HTTP status on non-200 responses and subprocess exit codes.

### Fixed: Nuclei worker `ModuleNotFoundError: No module named 'app'`
- **File**: `docker-compose.yml`
- **Issue**: `worker-nuclei` overrides the `volumes:` list from `worker-base` anchor, which completely replaces it (YAML anchor behavior). The override had `./workers:/app/workers`, `worker-tmp`, and `nuclei-templates` but was **missing** `./backend/app:/app/app:ro`. When nuclei found findings and tried `from workers.db_models import ...` → `from app.db.models.models import ...`, the `app` module wasn't available.
- **Fix**: Added `./backend/app:/app/app:ro` to the nuclei worker's volumes. Only nuclei was affected because it's the only worker that overrides volumes.

### Added: New Scan modal with scan type selection
- **File**: `frontend/src/app/dashboard/page.tsx`
- **Issue**: The "New Scan" button on the dashboard was a stub (`onClick={() => {/* trigger scan modal */}}`) — did nothing. Also, all scan triggers (header quick scan, org page run scan) were one-click with no option to choose scan type.
- **Fix**: Added a full scan modal with:
  - Organization selector (dropdown of all orgs, defaults to active org)
  - Scan type selector with 4 options (Full Scan, Quick Scan, Discovery, Vulnerability) — each with description
  - "Start Scan" button with loading state
  - Uses existing `POST /organizations/{id}/scans` endpoint
  - Modal dismisses on background click or Cancel

## 2026-05-19 — Pipeline Completion & Screenshot Fixes

### Fixed: Scan marked "completed" while nuclei still running
- **Files**: `workers/correlation/correlation_worker.py`, `workers/screenshot/screenshot_worker.py`
- **Root Cause**: Each nuclei batch published `correlation.process` on completion. The correlation worker unconditionally called `_complete_scan()` and downstream tasks (change detection, risk engine, notifications). The first nuclei batch to finish would win the race and mark the scan done while remaining nuclei batches were still running.
- **Fix**:
  - Added `is_terminal` flag to correlation messages. Only the screenshot worker sends `is_terminal=True` (it is always the last worker in the pipeline). Nuclei sends `is_terminal=False`.
  - Correlation worker only runs `_complete_scan()`, change detection, risk computation, and notifications when `is_terminal=True`. Intermediate messages (from nuclei) still do incremental work (dedup, relationships, indexing).
  - Screenshot worker now publishes to `correlation.process` after it finishes (even with 0 targets), providing the terminal trigger.

### Fixed: NGINX screenshot proxy returning 404/301 instead of image
- **File**: `infrastructure/nginx/nginx.conf`
- **Root Cause**: The `location /storage/` prefix block was being shadowed by the regex location `~* \.(webp)$` (static assets route to Next.js). NGINX processes regex locations before bare prefix locations.
- **Fix**: Changed to `location ^~ /storage/` to force prefix matching over regex, routing screenshot requests to MinIO instead of the Next.js frontend.

### Fixed: Frontend screenshot field name mismatches
- **File**: `frontend/src/app/dashboard/assets/[id]/page.tsx`
- **Root Cause**: The frontend referenced `s.created_at` and `s.taken_at`, but the API returns `captured_at`. Also used `s.screenshot_url` as fallback for `s.url`, but the API only returns `url`.
- **Fix**: Changed to use `s.captured_at` and `s.url` (no fallbacks).

### Added: Global screenshots gallery endpoint
- **File**: `backend/app/api/v1/endpoints/screenshots.py` (new), `backend/app/api/v1/router.py`
- **Issue**: The `/dashboard/screenshots` page was calling `GET /api/v1/screenshots?` which returned 404 — the endpoint didn't exist.
- **Fix**: Added `GET /screenshots` with:
  - Pagination (`page`, `page_size`, `pages`, `total`)
  - Org filtering via `org_id` query param
  - Search by domain via `search` query param
  - Workspace scoped via the `Asset` join (since `Screenshot` lacks `workspace_id`)
  - Returns `asset_value` (domain name) alongside existing screenshot fields
  - Registered at `/api/v1/screenshots`

### Fixed: Screenshots gallery page crash (client-side exception)
- **File**: `frontend/src/app/dashboard/screenshots/page.tsx`
- **Root Cause**: The page referenced `s.created_at || s.taken_at`, but the new API returns `captured_at`. Both fallback values were `undefined`, so `new Date(undefined)` created an Invalid Date, and `date-fns/formatDistanceToNow` threw a `RangeError: Invalid time value` — crashing the entire page.
- **Fix**: Changed all field references to match the API: `s.captured_at`, `s.url`, `s.asset_value`. Removed dead fallback fields (`screenshot_url`, `s.domain`, `s.created_at`, `s.taken_at`).

### Fixed: crt.sh 502 errors with retry logic
- **File**: `workers/scanner/discovery_worker.py`
- **Root Cause**: `crt.sh` (free CT log service) frequently returns 502/503 under load. The worker made a single attempt with a custom `User-Agent: ASM-Platform/1.0` that could get rate-limited.
- **Fix**: Added 3 attempts with exponential backoff (1s, 2s), rotating User-Agent across common browser strings. Non-200/502/503 status codes still fail immediately.

### Fixed: Scan race condition — Redis counter guarantees all work is done before completion
- **Files**: `workers/task_coordinator.py` (new), `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scanner/nuclei_worker.py`, `workers/screenshot/screenshot_worker.py`
- **Root Cause**: The `is_terminal` flag approach was still racy — if screenshot worker finished before all nuclei batches, it would send `is_terminal=True` prematurely.
- **Fix**: Added Redis-based `TaskCoordinator` with three counters per scan:
  - `nuclei_expected` — incremented by discovery and port workers for each nuclei batch published
  - `nuclei_done` — incremented by each nuclei worker on completion
  - `screenshot_done` — set to 1 by screenshot worker
  - The terminal `correlation.process` message is only sent when `nuclei_done >= nuclei_expected && screenshot_done == 1`. Whichever worker (last nuclei batch or screenshot) detects this condition sends the terminal message.
- **Files changed**:
  - `workers/task_coordinator.py`: New Redis-based counter helper class
  - `workers/scanner/discovery_worker.py`: Added `coord.add_nuclei_expected(scan_id)` per nuclei batch published
  - `workers/scanner/port_worker.py`: Added `coord.add_nuclei_expected(scan_id)` per IP-based nuclei batch published
  - `workers/scanner/nuclei_worker.py`: Calls `coord.incr_nuclei_done()` then `coord.is_all_done()` — sends terminal message if all clear
  - `workers/screenshot/screenshot_worker.py`: Calls `coord.set_screenshot_done()` then `coord.is_all_done()` — sends terminal message if all clear
  - Redis keys are cleaned up after terminal message is sent

### Fixed: RabbitMQ `ChannelInvalidStateError` on long-running workers
- **File**: `workers/base_worker.py`
- **Root Cause**: The RabbitMQ connection heartbeat (default 60s) would fire during long-running nuclei scans (often 2-5 minutes), closing the channel. When the nuclei process finally finished, `message.ack()` would throw `ChannelInvalidStateError`, and the error handler's retry/dead-letter reject logic would fail with the same error — causing cascading tracebacks.
- **Fixes**:
  - Increased default heartbeat to 300s (configurable via `RABBITMQ_HEARTBEAT` env var) so long scans don't trigger timeout.
  - Added `ChannelInvalidStateError` handler in `_handle_message()` that logs a warning and exits gracefully instead of crashing.
  - All `ack()`/`reject()` calls in error paths are wrapped in try/except to prevent cascading failures.

# Technical Requirements Document (TRD)

> A product-planning document, not user- or developer-facing system documentation — it sits outside the
> [Diátaxis](https://diataxis.fr) Tutorial/How-to/Reference/Explanation structure the rest of `docs/`
> follows (see [README.md](./README.md)), deliberately, rather than being forced into one of those
> modes.

Companion to [PRD.md](./PRD.md) — that document says *what* the product must do and for whom; this one
says what the *system* must satisfy to deliver it. Implementation detail (exact schemas, exact
endpoints, exact diagrams) lives in [ARCHITECTURE.md](./ARCHITECTURE.md), [DATA_MODEL.md](./DATA_MODEL.md),
[PIPELINES.md](./PIPELINES.md), and [API_REFERENCE.md](./API_REFERENCE.md) — this file states the
requirements those documents fulfill, not a second copy of them.

## 1. Technology stack requirements

| Requirement | Choice | Why |
|---|---|---|
| Backend framework | FastAPI (Python 3.12), async throughout | Native async DB/HTTP I/O for a workload dominated by waiting on external tools/network, not CPU |
| ORM | SQLAlchemy 2.0 (async) | `pg_insert` upsert support, mature migration story via Alembic |
| Worker framework | Hand-rolled `BaseWorker` over `aio_pika` | No heavier task-queue framework (Celery/etc.) needed — retry/DLQ/backoff/graceful-shutdown/metrics fit in one shared base class, see [DEVELOPMENT.md](./DEVELOPMENT.md) |
| Frontend | Next.js 14 App Router + TypeScript | SSR shell + client-side interactivity for a dashboard-heavy product; App Router's route-based code splitting matches the two-product split naturally |
| Primary datastore | PostgreSQL 16 | JSONB for the many semi-structured fields (evidence, scope_rules, proof) without a second document store |
| Task broker | RabbitMQ (topic/direct/fanout exchanges, per-queue DLQ) | Chained pipeline stages, fan-out (nuclei/scanner per-target batches) and fan-in (correlation firing once) both needed — see [PIPELINES.md](./PIPELINES.md) |
| Object storage | MinIO (S3-compatible) | Self-hostable, no cloud dependency for screenshots/PDF reports |
| Full-text/analytics | OpenSearch | Search endpoint backing |
| Cache/pub-sub | Redis | Rate limiting, `task_coordinator`'s fan-in counters + atomic Lua finalize, live-event pub/sub for the WebSocket relay |

## 2. System architecture requirements

- **No central pipeline orchestrator.** Each worker is responsible for publishing its own next-stage
  message; adding a stage means adding a worker + a queue entry, not touching an orchestrator. Trade-off
  accepted: the queue-routing-table triplication gotcha (see [ARCHITECTURE.md](./ARCHITECTURE.md#known-drift-and-dead-code-factually))
  is the direct cost of this choice and must be watched, not solved by adding an orchestrator later
  without a deliberate decision to do so.
- **Every pipeline-triggering write goes through a transactional outbox**, never a direct publish on the
  request path — a crash between "committed" and "published" must never lose a message. See
  [ARCHITECTURE.md](./ARCHITECTURE.md#request-flow-creating-an-asm-scan-outbox-pattern).
- **Fan-out stages must fan back in exactly once.** `task_coordinator.py`'s Redis + atomic Lua script
  exists specifically so a scan with N nuclei batches doesn't fire correlation N times.
- **Workers must be horizontally scalable independently of each other** — `docker compose up -d --scale
  worker-X=N --no-recreate`, no stage assumes a fixed peer count.
- **Two data schemas, zero foreign keys between them** (ASM vs. Bug Bounty) — a passive-discovery bug
  must never be able to expand what active testing can touch, structurally, not just by convention.

## 3. Non-functional requirements

### 3.1 Security

- **Scope-gate is the highest-priority security requirement in the whole system.** Every URL the Bug
  Bounty exploit stage touches passes two independent, execution-time-re-validated checks (scope rules +
  approved-target ownership) — see [PIPELINES.md](./PIPELINES.md#the-scope-gate) for the diagram and
  [EXPLANATION.md](./EXPLANATION.md#the-scope-gate-the-load-bearing-safety-property-of-the-whole-bug-bounty-pipeline)
  for why it's built this way.
  This must be re-verified, not assumed still-true, after any change to `bounty_scope.py`,
  `exploit_worker.py`, or any new exploit module.
- **Product entitlement is enforced server-side**, not just hidden in the UI — `RequireProduct` at the
  router level, independent of what the frontend chooses to render. See
  [API_REFERENCE.md](./API_REFERENCE.md#product-entitlement).
- **RBAC**: 4-level role hierarchy, checked per-endpoint via `RequireRole`/`RequireMinRole`.
- **Credentials**: API keys stored hashed, never plaintext; only a key's prefix is retained unhashed for
  lookup. Passwords hashed (see `backend/app/core/security.py`). MFA (TOTP) available.
- **JWT**: short-lived access tokens (default 60 min), rotating refresh tokens with server-side
  revocation (stored hash comparison, not just signature validity).
- **Network isolation**: only NGINX sits on the public Docker network; every other service — including
  Postgres, RabbitMQ, Redis, all 17 workers — is internal-only. See
  [ARCHITECTURE.md](./ARCHITECTURE.md#container-topology--networks).
- **Rate limiting**: per-route NGINX zones, tightest on auth endpoints (10r/m) and scan-trigger endpoints
  (20r/m) — see [ARCHITECTURE.md](./ARCHITECTURE.md#nginx-routing).
- **Evidence sanitization**: any evidence field persisted from raw external response bytes must be
  sanitized against invalid-for-Postgres content (e.g. NUL bytes) at the ORM boundary, not per-caller —
  see the `ExploitAttempt.evidence` `@validates` hook in [DATA_MODEL.md](./DATA_MODEL.md).
- **CI-enforced**: `bandit -r backend/app/ -ll` runs on every push (`.github/workflows/ci.yml`).

### 3.2 Reliability

- **At-least-once message delivery with bounded retry**: `MAX_RETRIES=3` (default) per queue, exponential
  backoff, then dead-letter to `{queue}.dlq` and mark the owning scan/program `failed` — never silently
  drop a failed unit of work.
- **Idempotent-safe upserts** where a worker might reprocess a message (`pg_insert(Model.__table__)`
  pattern, not `pg_insert(Model)` — see [DEVELOPMENT.md](./DEVELOPMENT.md#known-quirks)).
- **Graceful shutdown**: `BaseWorker` drains in-flight tasks on SIGTERM/SIGINT rather than dropping them
  mid-processing.
- **Health checks** on every long-running service (`docker-compose.yml` `healthcheck:` blocks) plus a
  worker-side heartbeat file (`workers/base_worker.py::_heartbeat_loop`) so a hung event loop or dropped
  RabbitMQ connection is detectable even though the process itself is still alive.

### 3.3 Performance & scalability

Indicative scan durations (single-worker-instance baseline, varies with target size and worker count):

| Scan type | Duration | Modules |
|---|---|---|
| `full` | 2–8 hours | Discovery + Probe + Port + Nuclei + Screenshot |
| `quick` | 15–30 min | DNS + HTTP + Headers + TLS |
| `discovery` | 30–90 min | Subdomain + DNS + HTTP only |
| `vuln` | 1–4 hours | Nuclei on already-known assets |

Every worker's concurrency is independently tunable via its own env var (`docker-compose.yml`), default
2–3 for most, 1 for the two heaviest Bug Bounty stages (`vulnscan`, `exploit` — nuclei runs and real
browser automation are the expensive operations):

```
DISCOVERY_CONCURRENCY=3   PORT_CONCURRENCY=3        CRAWL_CONCURRENCY=2
ENRICHMENT_CONCURRENCY=2  VALIDATION_CONCURRENCY=2  SCANNER_CONCURRENCY=2
BOUNTY_RECON_CONCURRENCY=2  BOUNTY_PROBE_CONCURRENCY=2
BOUNTY_VULNSCAN_CONCURRENCY=1  BOUNTY_EXPLOIT_CONCURRENCY=1  BOUNTY_REPORT_CONCURRENCY=2
```

Recommended production sizing (unverified against real large-scale deployment — carried forward as
planning guidance, treat as a starting point not a benchmark):

| Component | Small (<100 orgs) | Medium (100–500) | Large (500+) |
|---|---|---|---|
| API replicas | 2 | 4 | 8 |
| Discovery workers | 2 | 4 | 8 |
| Nuclei workers | 2 | 6 | 12 |
| PostgreSQL RAM | 8GB | 16GB | 32GB+ |
| OpenSearch RAM | 4GB | 8GB | 16GB+ |

Every Bug Bounty worker run is bounded regardless of how wide a program's scope is (`MAX_URLS=200`,
`MAX_URLS_PER_MODULE=15`, per-module caps down to single digits for the most expensive checks like
DOM-XSS) — an unbounded run is treated as a correctness bug, not an acceptable slow path. See
[PIPELINES.md](./PIPELINES.md#exploit-module-reference).

### 3.4 Observability

- Every worker exposes its own Prometheus `/metrics` endpoint (`start_http_server` in `BaseWorker.run`).
- Structured logging (`structlog`) throughout backend and workers.
- Prometheus scrapes `api` + every worker; Grafana dashboards on top.
- Per-scan, per-phase status is queryable independent of logs (`Scan.phase_status`, `ScanPhaseRun`,
  `ScanTargetSelection` — the "why was this target selected or skipped" audit trail), and live-pushed to
  the frontend over WebSocket, not just polled.

## 4. Data requirements

Full schema in [DATA_MODEL.md](./DATA_MODEL.md). Requirements this schema must satisfy:

- Every tenant-scoped table carries `workspace_id` (directly or via its parent) for row-level isolation.
- Soft-delete (`deleted_at`) on entities where a hard delete would break historical reporting
  (`Organization`, `Asset`, `Finding`).
- Findings must be de-duplicatable across repeated scans via a stable fingerprint, not by exact-row
  equality.
- Bug Bounty evidence (`ExploitAttempt.evidence`) must never fail to persist due to binary/invalid
  content from a real target response — sanitized at the model boundary.
- Reference/global data (EPSS, KEV, EOL, CVE cache) must not require a workspace/org FK — it's shared
  across every tenant and refreshed independently of any specific scan.

## 5. API requirements

Full endpoint-by-endpoint reference in [API_REFERENCE.md](./API_REFERENCE.md). Requirements:

- REST, JSON, versioned under `/api/v1`.
- Every endpoint requires authentication (JWT bearer or API key) except registration/login/password-reset.
- Collection routes use `@router.get("")`, never a trailing slash (avoids a 307 redirect breaking some
  clients).
- Product-gated routers 403 cleanly with an actionable message when a workspace lacks the required
  product, rather than 404ing or silently returning empty data.
- Bulk operations (e.g. asset promotion) must exist wherever a plausible real workflow would otherwise
  require many rapid sequential single-item calls, to avoid the caller needing to fight rate limits.
- A WebSocket channel per workspace delivers live pipeline/notification events without polling.

## 6. Infrastructure requirements

- **Fully containerized**, Docker Compose as the reference orchestration (no Kubernetes manifests in
  this repo today — a production deployment on k8s would need its own translation layer, not covered
  here).
- **Self-hosted, no mandatory external SaaS dependency** — every core capability (discovery, scanning,
  storage, search, notifications-via-webhook) works with zero third-party API keys. Optional integrations
  (SMTP, Slack/Discord/Telegram webhooks) degrade gracefully when unconfigured.
- Minimum host sizing: 8GB RAM (16GB recommended), 100GB disk.
- TLS termination at NGINX; a self-signed cert is generated by `make generate-ssl` for local/dev use,
  production deployments must supply real certificates.
- Worker containers mount `backend/app` read-only (`./backend/app:/app/app:ro`) — a deliberate
  requirement so backend model/service changes propagate to workers without a worker image rebuild,
  while still preventing a worker process from writing back into backend source.

## 7. Testing requirements

- Backend: `pytest`, unit tests runnable without the full stack (`tests/unit/`), integration tests
  requiring live services (`tests/integration/`). No `conftest.py`/`pytest.ini` — tests import `app.*`
  directly and must run with `backend/` as the working directory.
- CI (`.github/workflows/ci.yml`) on every push: `ruff check`, `ruff format --check`, `isort --check-only`,
  `mypy` (backend), `bandit` security scan, frontend `lint` + `type-check`, then the backend unit test
  suite with coverage upload.
- ⚠️ **Known CI/lint gap**: `ruff check` in CI and `make lint` both scope to `backend/app/` only —
  `workers/` is not mounted into the api container and has been a silent lint no-op for the whole
  `workers/` tree. Not yet fixed; treat any `workers/` lint findings as currently unenforced.
- Frontend: `npm run type-check` (`tsc --noEmit`) and `npm run lint` are the practical gate in absence of
  meaningful `jest` coverage (`npm test` currently runs `--passWithNoTests`).
- Any UI change should be exercised in a real browser (this repo's own working practice has been
  headless-Chromium/Playwright screenshot verification against real, not synthetic, data wherever
  feasible) before being considered done — type-checking verifies code correctness, not feature
  correctness.

## 8. Deployment requirements

```bash
make setup && make up-build   # env file + self-signed cert + build every image + start
make migrate                  # alembic upgrade head
make health                   # verify container health
```

- Migrations must be reviewed, not blindly shipped from `alembic revision --autogenerate` — this repo's
  autogenerate currently surfaces a large amount of unrelated pre-existing schema drift alongside any
  real change; see [DEVELOPMENT.md](./DEVELOPMENT.md#migrations).
- A schema change affecting a column read by both `backend/app` and `workers/` must be verified against
  both `models.py` and `workers/db_models.py` (worker-side ORM models are kept independently defined,
  though mapped to the same tables).
- Frontend container is `target: production`, no hot reload — a UI change requires an explicit rebuild
  (`docker compose build frontend && docker compose up -d --no-deps frontend`) before it's visible, even
  in an otherwise-live environment.

## 9. Technical constraints & known limitations

Carried forward from [ARCHITECTURE.md's drift notes](./ARCHITECTURE.md#known-drift-and-dead-code-factually)
and [DEVELOPMENT.md's known quirks](./DEVELOPMENT.md#known-quirks), consolidated here as standing
technical debt:

1. Three independent copies of the queue routing table can silently drift from each other.
2. `backend/app/integrations/{scanners,enrichment}/` and `backend/app/workers/` are empty/near-empty
   stub packages, not real extension points — a contributor reading only package names could reasonably
   but incorrectly assume otherwise. There's also a *third*, separate empty directory,
   `backend/workers/` (top-level, no `app/`) — genuinely empty, no `__init__.py` even. It's what the
   `api` container's `/app/workers` resolves to (the `api` service only mounts `backend/`, not the
   real repo-root `workers/` package that worker containers mount). Found (2026-07-28) because
   `backend/tests/unit/test_scan_pipeline_state.py` does `from workers import scan_state` — that import
   can only ever succeed in a worker container's environment, never the `api` container's, so this one
   test fails collection whenever `make test`/`docker compose exec api pytest tests/` runs. Pre-existing,
   unrelated to any dependency version — not fixed here, flagged for whoever owns test infra next.
3. Editing a running worker's `.py` file on disk does not take effect until that worker container is
   restarted — a process-level fact, not a bug, but a frequent source of false-negative manual testing
   if forgotten.
4. `workers/` is excluded from CI/`make lint`'s ruff scope entirely.
5. `custom` report format is still a plain alias of `technical` with no section-picker built.
   `compliance` (unlike an older version of this note claimed) does have real framework mapping — every
   finding maps to a CIS Controls v8 Control + Safeguard, display-only.
6. `ecdsa` (a transitive dependency of `python-jose[cryptography]`) has one open CVE
   (PYSEC-2026-1325, a Minerva timing side-channel on ECDSA P-256 signing) with **no fix released or
   planned** — upstream considers timing side-channels out of scope. Accepted as a documented risk, not
   remediated: verified (`grep -rn "algorithm=\|algorithms=" backend/ workers/`) that this platform's
   JWT usage is exclusively `HS256` (symmetric, `settings.ALGORITHM`) everywhere, never an EC-based
   algorithm (ES256/384/512), so `ecdsa`'s vulnerable `sign_digest()` path is never actually exercised by
   this application's own code.

Scheduled/recurring report generation is deliberately **not** on this list — it's a confirmed non-goal
(see [PRD.md §10](./PRD.md)), not standing debt to resolve.

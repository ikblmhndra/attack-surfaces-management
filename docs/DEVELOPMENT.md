# Development reference

Command reference, the risk-scoring formula's exact numbers, config wiring, and known quirks worth
keeping in your head while working in this repo. For step-by-step task guides (adding a migration,
adding a worker queue, reverse-proxying a new service), see [HOWTO.md](./HOWTO.md). For a guided first
run of the whole stack, see [TUTORIAL.md](./TUTORIAL.md).

## Makefile command reference

| Command | Does |
|---|---|
| `make setup` | Generate `.env`, self-signed SSL cert |
| `make up-build` | Build every image, start the stack |
| `make migrate` | `alembic upgrade head` |
| `make health` | Check every container is healthy |
| `make logs-api`, `make logs-workers`, `make logs-nginx` | Tail logs |
| `make test`, `make test-unit`, `make test-integration`, `make test-coverage` | See [HOWTO.md](./HOWTO.md#how-to-run-the-test-suite-or-a-single-test) |
| `make lint` | `ruff check app/ workers/` + `npm run lint` (frontend) |
| `make format` | `ruff format` + `isort` (backend) + `npm run format` (frontend) |
| `make type-check` | `mypy app/` + `tsc --noEmit` |
| `make migrate-create MSG="..."`, `make migrate-rollback` | See [HOWTO.md](./HOWTO.md#how-to-add-a-new-database-migration) |
| `make db-shell` | `psql` shell |
| `make shell-api`, `make shell-worker` | Shell into a container |
| `make workers-scale NUCLEI=6 ...` | See [HOWTO.md](./HOWTO.md#how-to-scale-workers) |

Everything runs through `docker compose` under the hood; most targets `exec` into already-running
containers, so `up`/`up-build` has to come first. There is no `conftest.py`/`pytest.ini` — tests `import
app.*` directly and only run correctly with `backend/` as the working directory.

Frontend isn't containerized for local dev: `cd frontend && npm install && npm run dev`
(`localhost:3000`). `npm run type-check` / `npm run lint` / `npm test` (currently
`--passWithNoTests`, little/no coverage yet) run the same way, outside Docker.

## Risk scoring formula

`backend/app/services/risk_engine.py`, tested in `backend/tests/unit/test_risk_engine.py`.

1. Findings currently `false_positive`, `resolved`, or `is_risk_accepted` are excluded entirely.
2. Every remaining finding maps to one of 9 categories (`FINDING_CATEGORY_MAP`; unmapped categories
   default to `misconfiguration`) and gets a severity-based raw penalty:

   | Severity | Penalty |
   |---|---|
   | critical | 25.0 |
   | high | 15.0 |
   | medium | 8.0 |
   | low | 3.0 |
   | info | 1.0 |

3. Each penalty is scaled by exponential time decay: `exp(-λ × days_old)`, `λ = RISK_DECAY_LAMBDA`
   (default `0.05`) → half-life ≈ 14 days (`ln(2)/0.05 ≈ 13.9`).
4. Each penalty is also scaled by an asset/org criticality multiplier (`Asset.criticality` /
   `Organization.criticality`, 1–5): `{1: 0.70, 2: 0.85, 3: 1.00, 4: 1.15, 5: 1.30}` — criticality 3 (the
   schema default for both) is the neutral point.
5. Per category: `category_score = max(0, 100 - min(Σ decayed·weighted penalties, 100))`.
6. `overall_score = Σ(category_score × category_weight)`, weights (sum to 1.0):

   | Category | Weight |
   |---|---|
   | Exposure Management | 18% |
   | Network Security | 15% |
   | Web Security | 15% |
   | TLS Security | 12% |
   | Patch Hygiene | 10% |
   | DNS Health | 10% |
   | Info Leakage | 8% |
   | Reputation | 7% |
   | Misconfiguration | 5% |

7. Letter grade: `≥90 A`, `≥75 B`, `≥60 C`, `≥40 D`, else `F`.

## Config

All settings are env-driven via `backend/app/core/config.py` (`pydantic-settings`, `Settings` class),
loaded once via `get_settings()`/`settings`. `.env.example` documents the full current set. See
[HOWTO.md](./HOWTO.md#how-to-add-a-new-environment-variable) for how to add one (workers don't share
this object — they read `os.getenv(...)` directly).

## Known quirks

Short, factual — see `CHANGELOG.md` for the full incident write-ups behind each one.

- **`pg_insert(Model)` vs `pg_insert(Model.__table__)`** — SQLAlchemy 2.0 requires the latter for
  upserts in worker code; passing the ORM class directly breaks the bulk-persistence path.
- **Go tool binaries vs pip packages of the same name** — the pip `httpx` package installs a CLI at
  `/usr/local/bin/httpx` that can shadow the ProjectDiscovery Go `httpx` binary if `PATH` isn't ordered
  correctly. `workers/Dockerfile` prepends `/go/bin` to `PATH` for exactly this reason.
- **Trailing slashes** — endpoint collection routes are `@router.get("")`, never `@router.get("/")`; a
  trailing slash 307-redirects, which breaks some clients/axios calls without `trailingSlash` config.
- **Worker containers mount `backend/app` read-only** — editing a backend module used by workers takes
  effect on worker restart, no image rebuild; a new worker *file* or new dependency does need one.
- **Workers are long-running processes** — editing a `.py` file on disk does not update an
  already-running worker's in-memory module. `docker compose restart worker-X` is required before a
  code change takes effect.
- **NGINX rate limiting on rapid sequential calls** — the `api` zone (200r/m, burst 50) trips on
  patterns like promoting hundreds of items one HTTP call at a time. The fix is a real bulk endpoint in
  one transaction (`POST /bounty/programs/{id}/assets/promote-bulk`), not client-side pacing.
- **Frontend container has no hot reload** — `target: production` in `docker-compose.yml`; a `.tsx`
  change needs `docker compose build frontend && docker compose up -d --no-deps frontend`.
- **RabbitMQ's Prometheus plugin has no per-queue labels by default** — `rabbitmq_queue_messages` (and
  similar) only exposes one cluster-wide aggregate unless `prometheus.return_per_object_metrics = true`
  is set in `rabbitmq.conf` (~24 queues here, so the added series count is small). Without it, any
  dashboard panel expecting a `queue`/`vhost` label silently renders nothing, indistinguishable from a
  broken query.
- **Three queue-routing tables can drift** — see
  [ARCHITECTURE.md#known-drift-and-dead-code-factually](./ARCHITECTURE.md).

For registration → workspace → product entitlement (relevant if extending auth), see
[EXPLANATION.md#why-product-entitlement-is-chosen-once-at-registration](./EXPLANATION.md) and
[API_REFERENCE.md#product-entitlement](./API_REFERENCE.md).

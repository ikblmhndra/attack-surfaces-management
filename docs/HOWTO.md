# How-to guides

Goal-oriented steps for a specific task, assuming you already have the stack running (see
[TUTORIAL.md](./TUTORIAL.md) if not) and some baseline familiarity with the codebase (see
[ARCHITECTURE.md](./ARCHITECTURE.md) if not). Each guide below gets you to one concrete outcome — for
background on *why* things work this way, see [EXPLANATION.md](./EXPLANATION.md); for the exhaustive
fact tables, see [ARCHITECTURE.md](./ARCHITECTURE.md), [PIPELINES.md](./PIPELINES.md),
[DEVELOPMENT.md](./DEVELOPMENT.md).

## How to run the test suite, or a single test

Run everything:

```bash
make test              # pytest tests/ -v            (inside the api container)
make test-unit         # tests/unit/ only
make test-integration  # tests/integration/ — needs the full stack running
make test-coverage
```

Run one file or one test function directly — useful while iterating on a single fix:

```bash
docker compose exec api pytest tests/unit/test_risk_engine.py -v
docker compose exec api pytest tests/unit/test_risk_engine.py::test_grade_boundaries -v
```

There is no `conftest.py`/`pytest.ini` in this repo — tests `import app.*` directly, so they only work
run from `backend/` as the working directory. `docker compose exec api ...` already gives you that; if
you're running pytest outside the container, `cd backend` first.

## How to add a new database migration

1. Change the SQLAlchemy model(s) in `backend/app/db/models/`.
2. Generate a draft: `make migrate-create MSG="add xyz table"` (`alembic revision --autogenerate`).
3. **Read the generated file before shipping it.** This repo's autogenerate currently picks up a large
   amount of pre-existing, unrelated schema drift across many tables (server-default/nullable mismatches
   accumulated over time, nothing to do with your actual change). Strip the diff down to only the
   `op.*` calls relevant to what you're actually changing; hand-write the rest if the tool's output is
   too noisy to trust as-is.
4. For a genuinely simple, single-column addition, it's often faster to skip autogenerate and hand-write
   the migration directly — see
   `backend/app/db/migrations/versions/4ec377801f60_add_workspace_enabled_products.py` for the pattern
   (one column, explicit `server_default` so existing rows backfill correctly, `alter_column` to drop
   the default afterward if the model itself shouldn't have one long-term).
5. Apply it: `make migrate` (`alembic upgrade head`).
6. To undo: `make migrate-rollback`.

## How to add a new environment variable

1. Add the field to the `Settings` class in `backend/app/core/config.py`, with a sensible default for
   non-production (`pydantic-settings` reads it from the environment automatically once declared).
2. If a **worker** (not just the API) needs this value: workers read `os.getenv(...)` directly, they
   don't share the backend's `Settings` object. Add the same variable to that worker's own
   `environment:` block in `docker-compose.yml` explicitly — being under the shared `x-common-env` YAML
   anchor is *not* enough if the anchor itself doesn't already list it (this exact gap is why
   `worker-notification` never got `SMTP_*` vars — see [EXPLANATION.md](./EXPLANATION.md#platform-self-security-what-was-found-what-wasnt)).
3. Add the variable to `.env.example` with a placeholder/comment so the full set stays documented and
   discoverable.
4. Restart the affected service(s) — a plain `docker compose restart <service>` picks up a
   `docker-compose.yml` environment change only if the container is recreated; if you only edited a
   `:ro`-mounted config file (not `docker-compose.yml` itself), see
   [How to reverse-proxy a new internal service](#how-to-reverse-proxy-a-new-internal-service-through-nginx)
   below for a related gotcha about restart vs. reload.

## How to add a new worker queue

1. Pick a queue name (`<domain>.<verb>`, matching the existing convention — `scan.discovery`,
   `bounty.recon`, etc.) and decide its exchange type (`topic` for most stage-to-stage handoffs,
   `fanout` if multiple consumers must all see every message like `correlation.process`, `direct` for a
   single dedicated consumer).
2. Add it to **all three** independent routing tables — they don't share a single source of truth and
   will silently disagree if you miss one:
   - `workers/base_worker.py::EXCHANGE_MAP`
   - `workers/queue_client.py::ROUTING_CONFIG`
   - `backend/app/core/queue_client.py::ROUTING_CONFIG` (as of this writing, this one is already missing
     `scan.scanner` — check it isn't missing anything else while you're in there)
3. Write the worker: subclass `BaseWorker`, set `QUEUE`/`CONCURRENCY`, implement `process(message)`. You
   get connection/reconnect, retry-with-backoff, DLQ dead-lettering, and Prometheus metrics for free —
   don't reimplement any of that.
4. Add the service to `docker-compose.yml` (its own `command:`, `environment:` block if it needs
   env vars per the guide above, and — if you want it in the "ASM Overview" Grafana dashboard — add its
   `worker-yourname:8001` target to `infrastructure/prometheus/prometheus.yml`'s `asm-workers` job).
5. If this worker publishes to the *next* stage's queue itself (chaining, like the ASM scan pipeline
   does), test that the chain actually advances end-to-end, not just that your one stage runs in
   isolation — a past bug let a scan type skip a stage because one worker didn't check the scan's
   `modules` list before acting (see [PIPELINES.md](./PIPELINES.md#asm-scan-pipeline)).
6. Restart: `docker compose up -d --build <your-new-service>` (a brand-new service needs the image
   built at least once, unlike editing an existing worker's `.py` file, which only needs a restart).

## How to reverse-proxy a new internal service through NGINX

Based directly on standing up Grafana and Prometheus behind NGINX — both mistakes below were made once
already and are easy to repeat with a new service.

1. Add a `location` block in `infrastructure/nginx/nginx.conf`. **Use the `^~` modifier**
   (`location ^~ /yourservice/ { ... }`), not a plain `location /yourservice/ { ... }` — without it, an
   existing regex location for static assets (`location ~* \.(js|css|...)$`) will win over your prefix
   location for any `.js`/`.css` request under your path (NGINX's own matching rules: a regex location
   always beats a plain prefix location unless the prefix has `^~`), silently routing those requests to
   the frontend upstream instead, where they 404. This is exactly what happened to Grafana and
   Prometheus's own bundles the first time.
2. If the upstream app has its own idea of "subpath" (Grafana's `GF_SERVER_SERVE_FROM_SUB_PATH`,
   Prometheus's `--web.external-url`/`--web.route-prefix`): check whether it expects the prefix
   preserved or stripped before deciding on a trailing slash in `proxy_pass`. Grafana expects it
   preserved — `proxy_pass http://grafana:3000;` (no trailing slash) — a trailing-slash `proxy_pass`
   strips the prefix and causes an infinite redirect loop as the app keeps trying to "correct" the
   client back to a prefixed URL nginx just stripped.
3. Decide on auth: does the upstream have its own login (Grafana does — nothing extra needed) or not
   (Prometheus doesn't — add nginx `auth_basic` + a `.htpasswd` file). **Never commit the `.htpasswd`
   file** — it's a credential file; keep it out of version control same as `.env`.
4. Restart, don't just reload: `curl -X POST http://localhost:9090/-/reload`-style lifecycle endpoints
   (and NGINX's own `nginx -s reload`) have been observed *not* to actually pick up a bind-mounted config
   file change reliably in this environment — a full `docker compose restart <service>` is the
   dependable path. Verify with `docker compose exec <service> cat <config-path>` that the running
   container actually sees your edit before assuming a change didn't work.
5. Test end to end with `curl`, not just "it loads in a browser": check the bare path 200s, check a
   `.js`/`.css` asset under it also 200s (not just the HTML shell), and check auth actually gates it if
   you added `auth_basic`.

## How to scale workers

```bash
make workers-scale NUCLEI=6 DISCOVERY=4 PORT=3
# equivalent to: docker compose up -d --scale worker-nuclei=6 --no-recreate
```

Scale whichever worker type is the current bottleneck for a given workload — nuclei scans are usually
the slowest stage on a large scan, so that's the one most often scaled up first.

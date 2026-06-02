# Repository Audit

Date: 2026-06-02

## Scope

This audit focused on runtime health, scan pipeline reliability, frontend build health, Docker/Compose hygiene, queue state, dependency security, and obvious API/UI regressions.

## Checks Run

| Check | Result |
| --- | --- |
| `docker compose ps` | Core services and workers were healthy. |
| `docker compose config --quiet` | Passed. |
| `docker compose exec -T api alembic current` | Database is at `007_scan_policy_phase_status (head)`. |
| `docker compose build frontend` | Passed. Next config warning fixed. |
| `docker compose exec -T api pytest tests/unit/test_scan_policy.py tests/unit/test_crawl_endpoint_scoring.py -q --tb=short` | Passed: `2 passed, 1 skipped`. |
| `docker compose exec -T api pytest tests/unit/ -q --tb=short` | Failed during collection; see finding P1-1. |
| `pip-audit -r backend/requirements.txt` | Failed with 47 known vulnerabilities across 10 packages. |
| Temporary `npm audit --omit=dev` from `frontend/package.json` | Found production vulnerabilities: critical Next.js, high Axios, moderate PostCSS. |
| RabbitMQ queue inspection | No DLQ backlog; `report.daily` has messages but no consumer. |

## Fixed During Audit

- Updated worker Makefile targets to reference current services: discovery, port, crawl, nuclei, screenshot, correlation, risk, enrichment, notification, and scheduler.
- Corrected `.env.example` frontend API URL to `/api/v1`.
- Moved Next.js `serverExternalPackages` config to the Next 14-supported experimental key.
- Added UUID path converters for asset and finding detail routes so static routes like `/assets/export` and `/findings/export` are not shadowed.
- Added `.dockerignore` files for backend, frontend, and workers to keep env files, caches, and generated artifacts out of Docker build contexts.

## Priority Findings

### P1-1: Full Backend Unit Test Collection Is Broken

`tests/unit/test_scan_pipeline_state.py` imports the root `workers` package, but the API container only mounts `backend/` at `/app`. Inside that container, `/app/workers` resolves to the backend package placeholder, not the repository root `workers/` package.

Impact: `make test-unit` cannot run the full unit suite in the documented container path, so CI-equivalent local verification is unreliable.

Recommended fix: run worker tests in the worker image or mount the root worker package into the API test environment and update `PYTHONPATH` deterministically.

### P1-2: Dependency Security Debt Is High

Backend audit found vulnerable packages including `python-multipart`, `python-jose`, `cryptography`, `pillow`, `aiohttp`, `jinja2`, `weasyprint`, `pytest`, and `starlette`.

Frontend production audit found critical Next.js advisories, high Axios advisories, and moderate PostCSS advisories. The frontend also lacks `package-lock.json`, so dependency resolution is not reproducible.

Recommended fix: add a lockfile, upgrade Next.js within the 14.x patched line if possible, upgrade Axios/PostCSS, then upgrade backend packages in controlled batches with regression tests.

### P1-3: Quality Targets Depend on Tools Missing From Runtime Containers

The Makefile runs `ruff`, `isort`, `mypy`, `bandit`, and `safety` inside the API container, but those tools are not installed in the runtime API image.

Impact: documented commands like `make lint`, `make format`, `make type-check`, and `make security-scan` are not reliable locally.

Recommended fix: create a dedicated dev/test image stage or run quality checks in ephemeral tool containers that install CI dependencies.

### P1-4: `report.daily` Queue Has No Consumer

The scheduler publishes `report.daily`, and RabbitMQ showed `report.daily` with one ready message and zero consumers.

Impact: scheduled report jobs can accumulate silently.

Recommended fix: add a report worker service or disable/report-gate the scheduler job until report consumption is implemented.

## Pipeline Observations

- Scan phases now have stronger coordination through `phase_status` and enrichment wait logic.
- Nuclei backlog was active during audit (`scan.nuclei` had ready/unacknowledged messages), but DLQs were clear.
- The current crawl strategy is directionally right: Katana plus GAU plus bounded FFUF in crawl, then high-signal endpoint selection into nuclei.
- Remaining hardening should focus on deterministic test execution, dependency upgrades, queue consumer coverage, and production scan SLO metrics.

## Next Recommended Work

1. Fix containerized test packaging so `make test-unit` passes end to end.
2. Add `frontend/package-lock.json` and upgrade vulnerable frontend packages.
3. Upgrade backend vulnerable dependencies in small batches and run API/worker regression tests after each batch.
4. Add or disable the daily report queue consumer path.
5. Add scan pipeline metrics for phase duration, queued age, timeout count, and findings per phase.

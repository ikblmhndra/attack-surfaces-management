# 🛡️ ASM Platform

**Production-grade Attack Surface Management & External Security Posture Management**

Self-hosted · API-First · Multi-Tenant · Containerized · Enterprise-Ready

---

## Overview

ASM Platform ships **two products from one codebase**, gated per-workspace at registration
(`Workspace.enabled_products`, chosen once, at signup — see [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md#registration--workspace--product-entitlement)):

1. **Attack Surface Management (ASM)** — continuous, passive discovery and monitoring of an
   organization's internet-facing footprint, nuclei-based vulnerability scanning, correlation, weighted
   risk scoring, and change notifications.
2. **Bug Bounty** — authorized, scope-gated *active* testing (recon → probe → vulnerability scan →
   exploit confirmation → report drafting) for real bug bounty engagements, with an explicit two-gate
   scope check on every single request the exploit stage ever makes.

```
ASM:         Discovery → Enumeration → Fingerprinting → Vulnerability Scanning → Correlation → Risk Scoring → Alerts
Bug Bounty:  Recon → Probe → Vulnerability Scan → Exploit Confirmation → Report Draft
```

**For the full picture — diagrams included — start at [`docs/README.md`](./docs/README.md).** This
file stays a quick-start; the `docs/` set is the actual reference: [PRD](./docs/PRD.md) (product
requirements, personas, roadmap) and [TRD](./docs/TRD.md) (technical/non-functional requirements) for
the *why*, plus architecture, full data model/ERD, pipeline internals, complete API reference, frontend
structure, and dev workflow + gotchas for the *how*.

### Core Capabilities

| Capability | Tools / Method |
|---|---|
| **Subdomain Discovery** | subfinder, amass, assetfinder, crt.sh |
| **DNS Enumeration** | dnsx (A, AAAA, MX, TXT, SPF, DMARC, NS, CNAME) |
| **HTTP Probing** | httpx (status, title, headers, TLS, tech detection) |
| **Port Scanning** | naabu, nmap (service banners, versions) |
| **Vulnerability Scanning** | nuclei (CVEs, misconfigs, exposures), + Bug Bounty's own active exploit modules (XSS/SQLi/SSRF/LFI/IDOR/CSRF/SSTI/NoSQL/mass-assignment/OAuth/BAC/upload/XXE) |
| **Screenshots** | Playwright/Chromium |
| **Enrichment** | Keyless ASN/RDAP/network-baseline data — **not** third-party threat-intel APIs; see [Threat intel note](#a-note-on-threat-intelligence) below |
| **Risk Scoring** | Custom engine: 9 weighted categories, exponential time decay, criticality multiplier |
| **Continuous Monitoring** | APScheduler, diff-based change detection |
| **Bug Bounty active testing** | Real headless-browser (Playwright) recon of SPA-only routes, real two-identity IDOR confirmation, real token-execution proof of DOM/stored XSS — see [docs/PIPELINES.md](./docs/PIPELINES.md#bug-bounty-pipeline) |
| **Notifications** | Email, Slack, Discord, Telegram, Webhooks — shared by both products |

#### A note on "threat intelligence"

Despite what older drafts of this README claimed, **there is no Shodan/VirusTotal/AbuseIPDB/OTX/Censys
integration in this codebase.** `backend/app/integrations/enrichment/engine.py` is explicitly a no-op
plugin engine kept only for import compatibility. The real enrichment path
(`workers/enrichment/enrichment_worker.py`) is keyless ASN/RDAP/network-baseline data, by design — no
dependency on paid/entitled third-party APIs. There are no intel API keys in `.env.example`. If you're
looking to add one, that's a real, deliberate product decision to revisit with the project owner first,
not a bug to silently "fix."

---

## Architecture

```
Internet → NGINX → FastAPI (REST/WS) → PostgreSQL
                              ↓              ↑
                         RabbitMQ     OpenSearch
                              ↓
        ┌──────────────────────┼──────────────────────┐
        ↓                      ↓                       ↓
  ASM pipeline            Bug Bounty pipeline     (shared) Notification
  discovery → port/crawl  bounty-recon → probe →   Worker
  → nuclei/scanner →      vulnscan → exploit →
  correlation → risk       report
```

There is **no central orchestrator** — every worker publishes the next pipeline stage's message itself
after finishing its own. Full diagrams (queue topology, fan-in/fan-out, the Bug Bounty scope-gate model)
are in [`docs/PIPELINES.md`](./docs/PIPELINES.md) and [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md).

**Stack:**
- **Backend:** Python 3.12 + FastAPI + SQLAlchemy (async)
- **Frontend:** Next.js 14 + TypeScript + Tailwind CSS
- **Database:** PostgreSQL 16 (primary store)
- **Cache:** Redis 7 (caching, pub/sub, rate limiting)
- **Queue:** RabbitMQ 3.13 (task broker, dead-letter queues)
- **Storage:** MinIO (screenshots, evidence, reports)
- **Search:** OpenSearch 2.x (full-text, analytics)
- **Proxy:** NGINX (TLS, rate limiting, routing)
- **Observability:** Prometheus + Grafana

---

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose v2+
- 8GB RAM minimum (16GB recommended)
- 100GB disk space

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/asm-platform
cd asm-platform

# Copy and edit environment variables
cp .env.example .env
nano .env  # Set passwords, API keys, etc.
```

### 2. Generate SSL Certificate

```bash
make generate-ssl
```

For production, replace `infrastructure/nginx/ssl/cert.pem` and `key.pem` with real certificates.

### 3. Start the Platform

```bash
# Build and start all services
make up-build

# Run database migrations
make migrate

# Check all services are healthy
make health
```

### 4. Access the Platform

| Service | URL | Credentials |
|---|---|---|
| **Web Dashboard** | https://localhost | Register at /auth/register |
| **API Docs** | https://localhost/api/docs | (dev mode only) |
| **Grafana** | http://localhost:3001 | admin / (GRAFANA_PASSWORD) |
| **RabbitMQ UI** | http://localhost:15672 | asm / (RABBITMQ_PASSWORD) |
| **Prometheus** | http://localhost:9090 | — |

---

## Configuration

All configuration is via environment variables in `.env`:

### Required

```env
SECRET_KEY=<64-char random hex>          # JWT signing key
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
RABBITMQ_PASSWORD=<strong-password>
MINIO_ACCESS_KEY=<access-key>
MINIO_SECRET_KEY=<secret-key>
```

### Optional — Notifications

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASSWORD=

SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

---

## Usage

### Creating Your First Organization

```bash
# Via API
curl -X POST https://localhost/api/v1/organizations \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ACME Corp",
    "domains": ["acme.com"],
    "root_domains": ["acme.com"],
    "industry": "technology",
    "criticality": 4
  }'
```

### Triggering a Scan

```bash
curl -X POST https://localhost/api/v1/organizations/<org-id>/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "full",
    "modules": ["discovery", "probe", "nuclei", "screenshot"]
  }'
```

### Scan Types

| Type | Duration | Modules |
|---|---|---|
| `full` | 2-8 hours | Discovery + Probe + Port + Nuclei + Screenshot |
| `quick` | 15-30 min | DNS + HTTP + Headers + TLS |
| `discovery` | 30-90 min | Subdomain + DNS + HTTP only |
| `vuln` | 1-4 hours | Nuclei on known assets |

---

## Bug Bounty Usage

Only reachable if the workspace picked (or was updated to include) `bounty` in `enabled_products`.

```bash
# Create a program — scope_rules is the enforced source of truth for every stage below
curl -X POST https://localhost/api/v1/bounty/programs \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{
    "name": "ACME Bug Bounty", "platform": "hackerone",
    "scope_rules": [{"pattern": "*.acme.com", "type": "domain", "in_scope": true}]
  }'

# Recon seeds itself from scope_rules — no manual target entry needed to start
curl -X POST https://localhost/api/v1/bounty/programs/<program-id>/run/pipeline \
  -H "Authorization: Bearer <token>"
# → runs recon → probe → vulnscan → exploit → report automatically; a human still has to
#   explicitly Promote a recon suggestion into an approved Target before exploit ever touches it
```

See [`docs/PIPELINES.md`](./docs/PIPELINES.md#bug-bounty-pipeline) for the full stage-by-stage
breakdown and the two-gate scope-safety model.

---

## API Reference

Full OpenAPI documentation: `https://localhost/api/docs` (dev mode). Complete, verified endpoint tables
(every router, every method/path, product-gating) live in [`docs/API_REFERENCE.md`](./docs/API_REFERENCE.md) —
the summary below is deliberately partial.

### Authentication

```bash
# Login
POST /api/v1/auth/login
{"email": "user@example.com", "password": "password"}

# Use returned access_token as Bearer
Authorization: Bearer <access_token>

# API Key (alternative)
X-API-Key: asm_<your-api-key>
```

### Key Endpoints

```
GET  /api/v1/organizations                    List organizations
POST /api/v1/organizations                    Create organization
GET  /api/v1/organizations/{id}               Get org details + risk score
POST /api/v1/organizations/{id}/scans         Trigger scan

GET  /api/v1/assets?org_id=&type=&status=    List assets
GET  /api/v1/findings?org_id=&severity=      List findings
GET  /api/v1/scores?org_id=                  Get risk scores
GET  /api/v1/scores/history                  Score trend data

POST /api/v1/search                           Full-text search
POST /api/v1/reports/generate                 Generate PDF report

GET  /api/v1/notifications                    List alerts
POST /api/v1/notifications/rules              Create alert rule

GET  /api/v1/bounty/programs                  List Bug Bounty programs
POST /api/v1/bounty/programs/{id}/run/pipeline  Run recon→probe→vulnscan→exploit→report
GET  /api/v1/bounty/programs/{id}/summary     Findings rollup + severity distribution
```

---

## Risk Scoring

Scores are computed across 9 security categories, each weighted:

| Category | Weight | What It Measures |
|---|---|---|
| Exposure Management | 18% | Admin panels, default creds, exposed services |
| Network Security | 15% | Open ports, exposed protocols |
| Web Security | 15% | Security headers, HTTPS enforcement |
| TLS Security | 12% | Certificate validity, cipher suites |
| Patch Hygiene | 10% | Known CVEs in detected technologies |
| DNS Health | 10% | SPF, DMARC, zone transfer, takeovers |
| Information Leakage | 8% | Git repos, env files, debug endpoints |
| Reputation Signals | 7% | Threat intel, blacklists, malware |
| Misconfiguration | 5% | CORS, clickjacking, open redirects |

**Grades:** A (90-100) · B (75-89) · C (60-74) · D (40-59) · F (0-39)

Findings decay over time using: `penalty × e^(-0.05 × days_old)`

---

## Scaling

### Worker Scaling

```bash
# Scale specific workers
make workers-scale NUCLEI=6 DISCOVERY=4 PROBE=8

# Or via docker compose directly
docker compose up -d --scale worker-nuclei=6 --no-recreate
```

### Recommended Production Sizing

| Component | Small (<100 orgs) | Medium (100-500) | Large (500+) |
|---|---|---|---|
| API replicas | 2 | 4 | 8 |
| Discovery workers | 2 | 4 | 8 |
| Nuclei workers | 2 | 6 | 12 |
| PostgreSQL RAM | 8GB | 16GB | 32GB+ |
| OpenSearch RAM | 4GB | 8GB | 16GB+ |

---

## Development

### Running Locally

```bash
# Start infrastructure only
make up-infra

# Run API in development mode
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Run frontend in development mode
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
make test           # All tests
make test-unit      # Unit tests only
make test-coverage  # With coverage report
```

Full command reference, migration gotchas, and the risk-scoring formula are in
[`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md).

### Adding a scanner or enrichment source

`backend/app/integrations/scanners/` and the `BaseScannerPlugin`/`BaseEnrichmentPlugin` interfaces
described in older docs **do not exist in code** — both integration packages are empty stubs kept only
so old imports don't break. The real extension points:

- **New scan tool/stage**: add a file to `workers/scanner/` or `workers/crawler/`, one file per
  tool/stage, wired directly into the queue chain (`workers/base_worker.py::EXCHANGE_MAP` +
  `workers/queue_client.py::ROUTING_CONFIG` + `backend/app/core/queue_client.py::ROUTING_CONFIG` — all
  three, see [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md#gotchas-from-real-incidents--see-changelogmd-for-the-full-stories)).
- **New Bug Bounty exploit module**: add a check function to `workers/bounty/exploit_tools.py` /
  `exploit_ext.py` / a new file, dispatch it from `workers/bounty/exploit_worker.py`, follow the
  existing confirmed-vs-inconclusive status discipline (see
  [`docs/PIPELINES.md`](./docs/PIPELINES.md#exploit-module-reference)).

---

## Security Notes

- All scanning is performed only on authorized targets
- Workspace isolation enforced at API and database layers
- JWT tokens with 1-hour expiry + rotating refresh tokens
- API keys hashed with SHA-256, never stored in plaintext
- All service-to-service communication on internal Docker network
- NGINX rate limiting: 100 req/min global, 10 req/min auth endpoints
- Security headers: HSTS, CSP, X-Frame-Options on all responses

---

## Project Structure

```
asm-platform/
├── backend/                    # FastAPI Python backend — request/response layer + business services.
│   │                           # Does NOT run scans itself; enqueues work via the transactional outbox.
│   ├── app/
│   │   ├── api/v1/             # REST API endpoints, one file per router (see docs/API_REFERENCE.md)
│   │   │   ├── endpoints/      #   organizations.py, assets.py, scans.py, ..., bounty.py
│   │   │   └── dependencies/   #   auth.py — RequireRole, RequireProduct, get_current_user
│   │   ├── core/                # Config (pydantic-settings), security (JWT), DB connection
│   │   ├── db/
│   │   │   ├── models/          # models.py (ASM, 31 tables) + bounty_models.py (Bug Bounty, 5 tables)
│   │   │   └── migrations/      # Alembic
│   │   ├── integrations/        # scanners/ and enrichment/ are empty stub packages — dead, not the
│   │   │                        # real extension point, see docs/ARCHITECTURE.md "Docs vs. reality"
│   │   ├── services/            # Business logic: risk_engine.py, scan_service.py, bounty_scope.py,
│   │   │                        # bounty_report.py, outbox_service.py, ...
│   │   └── workers/              # Empty stub package (0-byte __init__.py) — NOT where workers live
│   └── tests/                   # Unit + integration tests
├── frontend/                    # Next.js 14 TypeScript UI — two dashboard shells, see docs/FRONTEND.md
│   └── src/
│       ├── app/
│       │   ├── auth/            # login, register (product picker), forgot-password
│       │   └── dashboard/       # ASM tabs + bounty/ (program list + [id]/page.tsx, 6 tabs)
│       ├── components/          # Sidebar/DashboardHeader take variant="asm"|"bounty"
│       ├── lib/                 # api.ts — axios client, token storage, refresh interceptor
│       └── store/                # workspace.ts — Zustand: auth, enabledProducts, RBAC helpers
├── workers/                     # The REAL standalone queue workers (17 types + scheduler)
│   ├── scanner/                 # discovery, port, nuclei, coverage (subzy/wafw00f/...)
│   ├── crawler/                 # httpx + katana web crawling
│   ├── correlation/             # asset dedup + relationship engine
│   ├── risk/                    # risk score computation trigger
│   ├── enrichment/               # keyless ASN/RDAP/network-baseline — see the threat-intel note above
│   ├── validation/               # asset ownership/scope validation
│   ├── screenshot/               # Playwright screenshot capture
│   ├── notification/             # alert dispatch (email/slack/discord/telegram/webhook)
│   ├── scheduler/                 # APScheduler cron jobs (EPSS/KEV refresh, daily summaries)
│   ├── bounty/                    # recon/probe/vulnscan/exploit/report — the whole Bug Bounty pipeline
│   ├── base_worker.py             # shared retry/DLQ/metrics/graceful-shutdown base class
│   ├── task_coordinator.py        # Redis + Lua fan-in/fan-out completion tracking
│   └── scan_state.py / scan_phase.py / scan_observability.py   # progress + audit-trail helpers
├── infrastructure/               # Docker configs
│   ├── nginx/                    # Reverse proxy config, rate-limit zones
│   ├── postgres/                 # DB init + tuning
│   ├── rabbitmq/                 # Queue topology definitions
│   ├── prometheus/               # Metrics scraping
│   └── grafana/                  # Dashboards
├── docs/                         # ARCHITECTURE.md, DATA_MODEL.md, PIPELINES.md, API_REFERENCE.md,
│                                  # FRONTEND.md, DEVELOPMENT.md — start at docs/README.md
├── .github/workflows/            # CI/CD pipelines
├── docker-compose.yml            # Main orchestration
├── Makefile                      # Operational commands
├── CHANGELOG.md                  # Dated, per-change log — the actual project history
└── .env.example                  # Environment template
```

---

## License

Proprietary — For authorized security assessment use only.
This platform is intended exclusively for testing systems you own or have explicit permission to test.

---

*Built for production security operations · v1.0.0*

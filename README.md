# 🛡️ ASM Platform

**Production-grade Attack Surface Management & External Security Posture Management**

Self-hosted · API-First · Multi-Tenant · Containerized · Enterprise-Ready

---

## Overview

ASM Platform is a comprehensive security platform for continuous external attack surface discovery, exposure tracking, risk scoring, and security posture visibility. Built for security teams, MSSPs, red teams, and enterprise SOC operations.

```
Discovery → Enumeration → Fingerprinting → Vulnerability Scanning → Correlation → Risk Scoring → Alerts
```

### Core Capabilities

| Capability | Tools / Method |
|---|---|
| **Subdomain Discovery** | subfinder, amass, assetfinder, crt.sh, chaos |
| **DNS Enumeration** | dnsx (A, AAAA, MX, TXT, SPF, DMARC, NS, CNAME) |
| **HTTP Probing** | httpx (status, title, headers, TLS, tech detection) |
| **Port Scanning** | naabu, nmap (service banners, versions) |
| **Vulnerability Scanning** | nuclei (10,000+ templates: CVEs, misconfigs, exposures) |
| **Screenshots** | Playwright/Chromium (WebP, thumbnails) |
| **Threat Intelligence** | Shodan, VirusTotal, AbuseIPDB, AlienVault OTX |
| **Risk Scoring** | Custom engine: 9 categories, weighted, decay model |
| **Continuous Monitoring** | APScheduler, diff-based change detection |
| **Notifications** | Email, Slack, Discord, Telegram, Webhooks |

---

## Architecture

```
Internet → NGINX → FastAPI (REST/WS) → PostgreSQL
                              ↓              ↑
                         RabbitMQ     OpenSearch
                              ↓
              ┌───────────────┼───────────────┐
              ↓               ↓               ↓
        Discovery         Nuclei         Correlation
         Worker           Worker          Worker
              ↓               ↓               ↓
        Screenshot         Risk           Notify
         Worker           Worker          Worker
```

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

### Optional — Threat Intelligence

```env
SHODAN_API_KEY=                          # Shodan host intelligence
VIRUSTOTAL_API_KEY=                      # Malware/reputation checks
ABUSEIPDB_API_KEY=                       # IP abuse database
OTX_API_KEY=                             # AlienVault OTX threat feeds
CENSYS_API_ID=                           # Censys internet scan data
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

## API Reference

Full OpenAPI documentation: `https://localhost/api/docs` (dev mode)

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

### Adding Scanner Integrations

1. Create a plugin in `backend/app/integrations/scanners/`
2. Implement the `BaseScannerPlugin` interface
3. Register in `backend/app/integrations/scanners/__init__.py`
4. Add worker message handler in `workers/scanner/`

### Adding Enrichment Sources

1. Create a plugin in `backend/app/integrations/enrichment/`
2. Extend `BaseEnrichmentPlugin` (see `engine.py`)
3. Register in `EnrichmentEngine.__init__`

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
├── backend/                    # FastAPI Python backend
│   ├── app/
│   │   ├── api/v1/            # REST API endpoints
│   │   ├── core/              # Config, security, DB connections
│   │   ├── db/                # SQLAlchemy models + migrations
│   │   ├── integrations/      # Scanner + enrichment plugins
│   │   ├── services/          # Business logic
│   │   └── workers/           # Inline async workers
│   └── tests/                 # Unit + integration tests
├── frontend/                   # Next.js 14 TypeScript UI
│   └── src/
│       ├── app/               # App router pages
│       ├── components/        # UI components
│       ├── lib/               # API client, utilities
│       └── store/             # Zustand state management
├── workers/                   # Standalone queue workers
│   ├── scanner/               # Discovery, probe, nuclei, port
│   ├── correlation/           # Asset dedup + relationship engine
│   ├── notification/          # Alert dispatch (email/slack/etc)
│   ├── screenshot/            # Playwright screenshot capture
│   └── scheduler/             # APScheduler cron jobs
├── infrastructure/            # Docker configs
│   ├── nginx/                 # Reverse proxy config
│   ├── postgres/              # DB init + tuning
│   ├── rabbitmq/              # Queue topology
│   ├── prometheus/            # Metrics scraping
│   └── grafana/               # Dashboards
├── docs/                      # Architecture documentation
├── .github/workflows/         # CI/CD pipelines
├── docker-compose.yml         # Main orchestration
├── Makefile                   # Operational commands
└── .env.example               # Environment template
```

---

## License

Proprietary — For authorized security assessment use only.
This platform is intended exclusively for testing systems you own or have explicit permission to test.

---

*Built for production security operations · v1.0.0*

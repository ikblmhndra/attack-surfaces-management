# ASM Platform — Architecture Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Principles](#architecture-principles)
3. [High-Level Architecture](#high-level-architecture)
4. [Service Architecture](#service-architecture)
5. [Data Flow Diagrams](#data-flow-diagrams)
6. [Database Design (ERD)](#database-design)
7. [Scan Pipeline](#scan-pipeline)
8. [Risk Scoring Engine](#risk-scoring-engine)
9. [Worker Orchestration](#worker-orchestration)
10. [API Architecture](#api-architecture)
11. [Security Model](#security-model)
12. [Deployment Guide](#deployment-guide)
13. [Scaling Guide](#scaling-guide)

---

## 1. System Overview

**ASM Platform** is a production-grade, self-hosted Attack Surface Management and External Security Posture Management platform. It provides continuous external asset discovery, exposure tracking, risk scoring, and security posture visibility for security teams, MSSPs, red teams, and enterprise SOC operations.

### Core Capabilities
| Capability | Description |
|---|---|
| Asset Discovery | Automated subdomain, IP, port, service discovery |
| Exposure Management | Continuous vulnerability and misconfiguration detection |
| Risk Scoring | Per-category weighted scoring (0–100) with grade system |
| Threat Intel | Enrichment via Shodan, Censys, VirusTotal, AbuseIPDB |
| Continuous Monitoring | Scheduled scans with diff-based change detection |
| Multi-Tenancy | Workspace isolation, RBAC, API keys |
| Executive Reporting | PDF exports, dashboards, trend analytics |

---

## 2. Architecture Principles

- **API-First**: Every capability exposed via versioned REST API
- **Event-Driven**: Scanner → Queue → Correlation → Risk → Notify
- **Immutable History**: All scan snapshots preserved; diffs computed on read
- **Modular Plugins**: Scanner and enrichment integrations as hot-swappable plugins
- **Zero-Trust Internal**: Service-to-service auth via shared secrets + network isolation
- **Observability-First**: Metrics, structured logging, distributed tracing built in

---

## 3. High-Level Architecture

```mermaid
graph TB
    subgraph CLIENT["Client Layer"]
        WEB["Next.js Web App"]
        CLI["ASM CLI"]
        API_CLIENT["API Clients / Integrations"]
    end

    subgraph GATEWAY["Gateway Layer"]
        NGINX["NGINX Reverse Proxy\n(TLS Termination, Rate Limiting)"]
    end

    subgraph API["API Layer"]
        FASTAPI["FastAPI Backend\n(REST API v1)"]
        WS["WebSocket Server\n(Real-time events)"]
    end

    subgraph QUEUE["Message Queue"]
        RABBITMQ["RabbitMQ\n(Task Broker)"]
    end

    subgraph WORKERS["Worker Layer"]
        SCAN_W["Scan Workers\n(subfinder, naabu, nuclei, httpx)"]
        CORR_W["Correlation Workers\n(dedup, relationship mapping)"]
        RISK_W["Risk Engine Workers\n(score computation)"]
        NOTIFY_W["Notification Workers\n(email, slack, webhook)"]
        SHOT_W["Screenshot Workers\n(Playwright)"]
        SCHED["Scheduler\n(APScheduler)"]
    end

    subgraph STORAGE["Storage Layer"]
        PG["PostgreSQL\n(Primary data store)"]
        REDIS["Redis\n(Cache + pub/sub)"]
        MINIO["MinIO\n(Screenshots, evidence, reports)"]
        OS["OpenSearch\n(Full-text search + analytics)"]
    end

    subgraph ENRICH["Enrichment Layer"]
        SHODAN["Shodan API"]
        CENSYS["Censys API"]
        VT["VirusTotal API"]
        ABUSEIPDB["AbuseIPDB"]
        OTX["AlienVault OTX"]
    end

    subgraph OBS["Observability"]
        PROM["Prometheus"]
        GRAF["Grafana"]
        LOGS["Structured Logs"]
    end

    CLIENT --> NGINX
    NGINX --> FASTAPI
    NGINX --> WS
    FASTAPI --> PG
    FASTAPI --> REDIS
    FASTAPI --> RABBITMQ
    FASTAPI --> OS
    SCHED --> RABBITMQ
    RABBITMQ --> SCAN_W
    RABBITMQ --> CORR_W
    RABBITMQ --> RISK_W
    RABBITMQ --> NOTIFY_W
    RABBITMQ --> SHOT_W
    SCAN_W --> PG
    SCAN_W --> MINIO
    SCAN_W --> ENRICH
    CORR_W --> PG
    CORR_W --> OS
    RISK_W --> PG
    NOTIFY_W --> REDIS
    FASTAPI --> PROM
    WORKERS --> PROM
```

---

## 4. Service Architecture

```mermaid
graph LR
    subgraph BACKEND["Backend Services (FastAPI)"]
        AUTH["auth\n/api/v1/auth"]
        ORGS["organizations\n/api/v1/orgs"]
        ASSETS["assets\n/api/v1/assets"]
        SCANS["scans\n/api/v1/scans"]
        FINDS["findings\n/api/v1/findings"]
        SCORES["scores\n/api/v1/scores"]
        INTEL["intel\n/api/v1/intel"]
        NOTIF["notifications\n/api/v1/notifications"]
        REPORTS["reports\n/api/v1/reports"]
        SEARCH["search\n/api/v1/search"]
        ADMIN["admin\n/api/v1/admin"]
        WS_EP["websocket\n/ws"]
    end

    subgraph CORE["Core Services"]
        RBAC_SVC["RBAC Service"]
        AUDIT_SVC["Audit Service"]
        SCORE_SVC["Scoring Service"]
        CORR_SVC["Correlation Service"]
        RISK_SVC["Risk Engine"]
        SCHED_SVC["Scheduler Service"]
    end

    AUTH --> RBAC_SVC
    ORGS --> RBAC_SVC
    ASSETS --> CORR_SVC
    FINDS --> SCORE_SVC
    SCORES --> RISK_SVC
    SCANS --> SCHED_SVC
    ALL --> AUDIT_SVC
```

---

## 5. Data Flow Diagrams

### 5.1 Asset Discovery Flow

```mermaid
sequenceDiagram
    participant U as User
    participant API as FastAPI
    participant Q as RabbitMQ
    participant SW as Scan Worker
    participant DB as PostgreSQL
    participant ES as OpenSearch
    participant CW as Correlation Worker
    participant RW as Risk Worker
    participant NW as Notify Worker

    U->>API: POST /api/v1/scans {org_id, scan_type}
    API->>DB: Create scan record (status=pending)
    API->>Q: Publish scan.discovery task
    API-->>U: {scan_id, status: "queued"}

    Q->>SW: Consume scan.discovery task
    SW->>SW: Run subfinder, amass, dnsx
    SW->>DB: Upsert discovered subdomains
    SW->>Q: Publish scan.probe task per batch
    SW->>Q: Publish scan.port task per IP batch

    Q->>SW: Consume scan.probe task
    SW->>SW: Run httpx on subdomains
    SW->>DB: Update asset HTTP fingerprints
    SW->>Q: Publish scan.nuclei task

    Q->>SW: Consume scan.nuclei task
    SW->>SW: Run nuclei templates
    SW->>DB: Upsert findings
    SW->>Q: Publish correlation.process task

    Q->>CW: Consume correlation.process
    CW->>DB: Merge duplicates, build relationships
    CW->>ES: Index assets and findings
    CW->>Q: Publish risk.compute task

    Q->>RW: Consume risk.compute
    RW->>DB: Read all org findings
    RW->>RW: Compute category scores
    RW->>DB: Write risk_scores snapshot
    RW->>Q: Publish notify.check task

    Q->>NW: Consume notify.check
    NW->>DB: Read notification rules
    NW->>NW: Evaluate triggers
    NW->>NW: Send email/slack/webhook
    NW->>DB: Mark notifications sent
```

### 5.2 Continuous Monitoring Flow

```mermaid
flowchart TD
    SCHED["APScheduler\n(Cron-based)"] -->|Every N hours| Q["RabbitMQ"]
    Q --> SW["Scan Worker"]
    SW --> DISC["Run Discovery\nSubdomain + DNS + Ports"]
    DISC --> SNAP["Take Snapshot\n(current state)"]
    SNAP --> DIFF["Diff Engine\nCompare to last snapshot"]
    DIFF --> CHANGES{{"Changes\nDetected?"}}
    CHANGES -->|Yes| ALERT["Create Change Events\n(new_asset, removed_asset, new_finding, etc.)"]
    ALERT --> NOTIFY["Notification Worker\n(Push alerts)"]
    CHANGES -->|No| LOG["Log: No changes"]
    DIFF --> CORR["Correlation Worker\n(Update relationships)"]
    CORR --> RISK["Risk Engine\n(Recompute scores)"]
    RISK --> DB["PostgreSQL\n(Write new score snapshot)"]
    DB --> WS["WebSocket\n(Push real-time update to UI)"]
```

---

## 6. Database Design (ERD)

```mermaid
erDiagram
    WORKSPACES {
        uuid id PK
        string name
        string slug
        string plan
        timestamp created_at
        timestamp updated_at
        bool is_active
    }

    USERS {
        uuid id PK
        uuid workspace_id FK
        string email
        string password_hash
        string full_name
        string role
        bool mfa_enabled
        string mfa_secret
        bool is_active
        timestamp last_login
        timestamp created_at
    }

    ORGANIZATIONS {
        uuid id PK
        uuid workspace_id FK
        string name
        string slug
        string[] domains
        string[] ip_ranges
        string[] asns
        string industry
        string[] tags
        string[] labels
        int criticality
        timestamp created_at
        timestamp updated_at
    }

    ASSETS {
        uuid id PK
        uuid org_id FK
        string asset_type
        string value
        string status
        string[] tags
        int criticality
        bool is_active
        jsonb metadata
        timestamp first_seen
        timestamp last_seen
        timestamp updated_at
    }

    SUBDOMAINS {
        uuid id PK
        uuid asset_id FK
        uuid org_id FK
        string fqdn
        string[] ip_addresses
        string status
        bool is_wildcard
        jsonb dns_records
        jsonb http_info
        jsonb tls_info
        string[] technologies
        int http_status
        string title
        int response_size
        timestamp first_seen
        timestamp last_seen
    }

    IP_ADDRESSES {
        uuid id PK
        uuid org_id FK
        string ip
        string version
        string asn
        string asn_org
        string country
        string city
        string isp
        string cloud_provider
        bool is_cdn
        jsonb metadata
        timestamp first_seen
        timestamp last_seen
    }

    PORTS {
        uuid id PK
        uuid ip_id FK
        int port_number
        string protocol
        string service_name
        string banner
        string version
        string state
        jsonb tls_info
        timestamp first_seen
        timestamp last_seen
    }

    TECHNOLOGIES {
        uuid id PK
        uuid asset_id FK
        string name
        string version
        string category
        string confidence
        jsonb metadata
        timestamp detected_at
    }

    FINDINGS {
        uuid id PK
        uuid org_id FK
        uuid asset_id FK
        string title
        string description
        string severity
        string category
        string status
        string template_id
        string cve_id
        int cvss_score
        string evidence
        string remediation
        jsonb metadata
        bool is_false_positive
        timestamp first_seen
        timestamp last_seen
        timestamp resolved_at
    }

    RISK_SCORES {
        uuid id PK
        uuid org_id FK
        int overall_score
        string grade
        jsonb category_scores
        int total_assets
        int total_findings
        int critical_count
        int high_count
        int medium_count
        int low_count
        jsonb score_breakdown
        timestamp computed_at
    }

    SCANS {
        uuid id PK
        uuid org_id FK
        uuid created_by FK
        string scan_type
        string status
        string[] modules
        jsonb config
        int total_tasks
        int completed_tasks
        int failed_tasks
        string error_message
        timestamp started_at
        timestamp completed_at
        timestamp created_at
    }

    SCAN_FINDINGS {
        uuid id PK
        uuid scan_id FK
        uuid finding_id FK
        string change_type
        timestamp created_at
    }

    NOTIFICATIONS {
        uuid id PK
        uuid workspace_id FK
        uuid org_id FK
        string event_type
        string severity
        string title
        string message
        jsonb payload
        bool is_read
        bool is_sent
        timestamp created_at
    }

    NOTIFICATION_RULES {
        uuid id PK
        uuid workspace_id FK
        string event_type
        string[] channels
        string min_severity
        jsonb config
        bool is_active
        timestamp created_at
    }

    API_KEYS {
        uuid id PK
        uuid workspace_id FK
        uuid user_id FK
        string name
        string key_hash
        string key_prefix
        string[] scopes
        timestamp expires_at
        timestamp last_used_at
        timestamp created_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid workspace_id FK
        uuid user_id FK
        string action
        string resource_type
        string resource_id
        jsonb changes
        string ip_address
        string user_agent
        timestamp created_at
    }

    SCREENSHOTS {
        uuid id PK
        uuid asset_id FK
        string storage_path
        string url
        int width
        int height
        int file_size
        timestamp captured_at
    }

    THREAT_INTEL {
        uuid id PK
        uuid asset_id FK
        string source
        string indicator_type
        jsonb data
        int risk_score
        bool is_malicious
        timestamp enriched_at
        timestamp expires_at
    }

    WORKSPACES ||--o{ USERS : "has"
    WORKSPACES ||--o{ ORGANIZATIONS : "contains"
    ORGANIZATIONS ||--o{ ASSETS : "has"
    ASSETS ||--o{ SUBDOMAINS : "includes"
    ASSETS ||--o{ TECHNOLOGIES : "detected"
    ASSETS ||--o{ FINDINGS : "has"
    ASSETS ||--o{ SCREENSHOTS : "has"
    ASSETS ||--o{ THREAT_INTEL : "enriched"
    IP_ADDRESSES ||--o{ PORTS : "exposes"
    ORGANIZATIONS ||--o{ RISK_SCORES : "scored"
    ORGANIZATIONS ||--o{ SCANS : "scanned"
    SCANS ||--o{ SCAN_FINDINGS : "found"
    FINDINGS ||--o{ SCAN_FINDINGS : "in"
    WORKSPACES ||--o{ NOTIFICATION_RULES : "has"
    WORKSPACES ||--o{ NOTIFICATIONS : "receives"
    WORKSPACES ||--o{ API_KEYS : "has"
    WORKSPACES ||--o{ AUDIT_LOGS : "logs"
```

---

## 7. Scan Pipeline

```mermaid
flowchart LR
    subgraph DISC["Discovery Phase"]
        SUB["Subfinder\n+ Amass\n+ Assetfinder"]
        CRT["crt.sh\n+ Chaos\n+ DNSX"]
        SUB --> DEDUP["Deduplication"]
        CRT --> DEDUP
    end

    subgraph ENUM["Enumeration Phase"]
        DNS["DNS Enumeration\nA, AAAA, MX, TXT\nSPF, DMARC, NS, CNAME"]
        HTTP["HTTP Probing\n(httpx)\nStatus, Headers\nTitle, TLS, Redirects"]
        PORT["Port Scanning\n(naabu + nmap)\nService banners, TLS"]
        DEDUP --> DNS
        DEDUP --> HTTP
        DNS --> PORT
    end

    subgraph FINGER["Fingerprinting Phase"]
        TECH["Tech Detection\n(Wappalyzer rules)\nCDN, WAF, CMS\nFrameworks"]
        SCREEN["Screenshots\n(Playwright)"]
        HTTP --> TECH
        HTTP --> SCREEN
    end

    subgraph VULN["Vulnerability Phase"]
        NUC["Nuclei\n(10,000+ templates)\nMisconfigs, CVEs\nExposures"]
        HEADERS["Security Headers\nAnalysis"]
        TLS_CHK["TLS/SSL\nChecks"]
        TECH --> NUC
        PORT --> NUC
        HTTP --> HEADERS
        HTTP --> TLS_CHK
    end

    subgraph ENRICH["Enrichment Phase"]
        SHODAN["Shodan\nLookup"]
        VT["VirusTotal\nReputation"]
        ABUSE["AbuseIPDB\nReputation"]
        NUC --> SHODAN
        NUC --> VT
        NUC --> ABUSE
    end

    subgraph OUTPUT["Output Phase"]
        CORR["Correlation\nEngine"]
        RISK["Risk Scoring\nEngine"]
        INDEX["OpenSearch\nIndexing"]
        NOTIFY["Notifications"]
        SHODAN --> CORR
        VT --> CORR
        ABUSE --> CORR
        CORR --> RISK
        RISK --> INDEX
        RISK --> NOTIFY
    end
```

---

## 8. Risk Scoring Engine

### Category Weights

| Category | Weight | Description |
|---|---|---|
| Network Security | 15% | Open ports, exposed services, firewall presence |
| DNS Health | 10% | SPF, DMARC, DNSSEC, zone transfer |
| Web Security | 15% | Security headers, HTTPS enforcement, CSP |
| TLS Security | 12% | Cert validity, cipher suites, protocol versions |
| Exposure Management | 18% | Exposed admin panels, default creds, sensitive paths |
| Patch Hygiene | 10% | Known CVEs in detected technologies |
| Information Leakage | 8% | Git exposure, debug endpoints, stack traces |
| Reputation Signals | 7% | Threat intel feeds, malicious indicators |
| Misconfiguration Risk | 5% | CORS, clickjacking, open redirects |

### Scoring Formula

```
category_score = 100 - Σ(finding_penalty × severity_weight × confidence × decay_factor)

severity_weights:
  CRITICAL = 25
  HIGH     = 15
  MEDIUM   = 8
  LOW      = 3
  INFO     = 1

decay_factor = e^(-λ × days_since_detection)  # λ = 0.05 (30-day half-life)

overall_score = Σ(category_score × category_weight)

grade_thresholds:
  A = 90–100
  B = 75–89
  C = 60–74
  D = 40–59
  F = 0–39
```

---

## 9. Worker Orchestration

```mermaid
graph TB
    subgraph SCHED["Scheduler (APScheduler)"]
        CRON["Cron Jobs\nEvery N hours per org"]
        TRIGGER["Manual Triggers\nvia API"]
    end

    subgraph QUEUES["RabbitMQ Exchanges + Queues"]
        EX_SCAN["Exchange: scan\n(topic)"]
        EX_CORR["Exchange: correlation\n(fanout)"]
        EX_RISK["Exchange: risk\n(direct)"]
        EX_NOTIFY["Exchange: notify\n(topic)"]

        Q_DISC["Queue: scan.discovery"]
        Q_PROBE["Queue: scan.probe"]
        Q_PORT["Queue: scan.port"]
        Q_NUCLEI["Queue: scan.nuclei"]
        Q_SCREEN["Queue: scan.screenshot"]
        Q_CORR["Queue: correlation.process"]
        Q_RISK["Queue: risk.compute"]
        Q_NOTIFY["Queue: notify.send"]
        Q_DLQ["Queue: dead.letter"]

        EX_SCAN --> Q_DISC
        EX_SCAN --> Q_PROBE
        EX_SCAN --> Q_PORT
        EX_SCAN --> Q_NUCLEI
        EX_SCAN --> Q_SCREEN
        EX_CORR --> Q_CORR
        EX_RISK --> Q_RISK
        EX_NOTIFY --> Q_NOTIFY
    end

    subgraph WORKERS["Worker Pools"]
        W_DISC["Discovery Workers\n(x3 replicas)"]
        W_PROBE["Probe Workers\n(x5 replicas)"]
        W_PORT["Port Workers\n(x2 replicas)"]
        W_NUCLEI["Nuclei Workers\n(x3 replicas)"]
        W_SCREEN["Screenshot Workers\n(x2 replicas)"]
        W_CORR["Correlation Workers\n(x2 replicas)"]
        W_RISK["Risk Workers\n(x2 replicas)"]
        W_NOTIFY["Notify Workers\n(x1 replica)"]
    end

    SCHED --> EX_SCAN
    Q_DISC --> W_DISC
    Q_PROBE --> W_PROBE
    Q_PORT --> W_PORT
    Q_NUCLEI --> W_NUCLEI
    Q_SCREEN --> W_SCREEN
    Q_CORR --> W_CORR
    Q_RISK --> W_RISK
    Q_NOTIFY --> W_NOTIFY

    W_DISC -->|on failure| Q_DLQ
    W_NUCLEI -->|on failure| Q_DLQ
```

---

## 10. API Architecture

### Endpoint Structure

```
/api/v1/
├── auth/
│   ├── POST   /register
│   ├── POST   /login
│   ├── POST   /refresh
│   ├── POST   /logout
│   ├── POST   /mfa/enable
│   └── POST   /mfa/verify
├── workspaces/
│   ├── GET    /
│   ├── POST   /
│   ├── GET    /{id}
│   ├── PUT    /{id}
│   ├── DELETE /{id}
│   └── POST   /{id}/invite
├── organizations/
│   ├── GET    /
│   ├── POST   /
│   ├── GET    /{id}
│   ├── PUT    /{id}
│   ├── DELETE /{id}
│   ├── GET    /{id}/assets
│   ├── GET    /{id}/findings
│   ├── GET    /{id}/scores
│   ├── GET    /{id}/scans
│   └── GET    /{id}/timeline
├── assets/
│   ├── GET    /
│   ├── GET    /{id}
│   ├── PUT    /{id}
│   ├── DELETE /{id}
│   ├── GET    /{id}/findings
│   ├── GET    /{id}/technologies
│   ├── GET    /{id}/screenshots
│   └── GET    /{id}/intel
├── scans/
│   ├── GET    /
│   ├── POST   /
│   ├── GET    /{id}
│   ├── POST   /{id}/cancel
│   └── GET    /{id}/results
├── findings/
│   ├── GET    /
│   ├── GET    /{id}
│   ├── PUT    /{id}
│   ├── POST   /{id}/false-positive
│   └── POST   /{id}/accept-risk
├── scores/
│   ├── GET    /
│   ├── GET    /history
│   └── GET    /breakdown
├── search/
│   └── POST   /
├── reports/
│   ├── POST   /generate
│   └── GET    /{id}/download
├── notifications/
│   ├── GET    /
│   ├── POST   /rules
│   ├── PUT    /rules/{id}
│   └── DELETE /rules/{id}
├── admin/
│   ├── GET    /users
│   ├── PUT    /users/{id}
│   └── GET    /audit-logs
└── keys/
    ├── GET    /
    ├── POST   /
    └── DELETE /{id}
```

---

## 11. Security Model

```mermaid
graph TD
    REQ["Incoming Request"] --> NGINX_RL["NGINX Rate Limiting\n(per IP, per endpoint)"]
    NGINX_RL --> TLS_TERM["TLS Termination\n(TLSv1.2+ only)"]
    TLS_TERM --> AUTH_MW["Auth Middleware"]

    AUTH_MW --> JWT_CHK{{"JWT\nPresent?"}}
    JWT_CHK -->|No| APIKEY_CHK{{"API Key\nPresent?"}}
    JWT_CHK -->|Yes| JWT_VALID["Validate JWT\n(signature + expiry)"]
    APIKEY_CHK -->|Yes| KEY_VALID["Validate API Key\n(hash comparison)"]
    APIKEY_CHK -->|No| REJECT_401["401 Unauthorized"]

    JWT_VALID --> RBAC["RBAC Check\n(role + resource + action)"]
    KEY_VALID --> RBAC
    RBAC -->|Denied| REJECT_403["403 Forbidden"]
    RBAC -->|Allowed| WORKSPACE_ISO["Workspace Isolation\n(row-level security)"]
    WORKSPACE_ISO --> HANDLER["Route Handler"]
    HANDLER --> AUDIT["Audit Log\n(async write)"]
    HANDLER --> RESP["Response\n(sanitized)"]
```

### RBAC Matrix

| Role | Read Assets | Write Assets | Run Scans | Manage Users | Admin |
|---|---|---|---|---|---|
| Owner | ✅ | ✅ | ✅ | ✅ | ✅ |
| Admin | ✅ | ✅ | ✅ | ✅ | ❌ |
| Analyst | ✅ | ✅ | ✅ | ❌ | ❌ |
| Viewer | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## 12. Deployment Guide

### Prerequisites
- Docker 24+ and Docker Compose v2+
- 8 CPU cores, 32GB RAM minimum (production)
- 500GB SSD storage

### Quick Start
```bash
git clone https://github.com/your-org/asm-platform
cd asm-platform
cp .env.example .env
# Edit .env with your secrets and API keys
make setup
make up
# Platform available at https://localhost
```

### Production Deployment
```bash
# Pull latest
git pull origin main

# Build images
make build

# Run database migrations
make migrate

# Start all services
make up-prod

# Check health
make health
```

---

## 13. Scaling Guide

### Horizontal Scaling

| Component | Min | Recommended | Max Notes |
|---|---|---|---|
| API (FastAPI) | 2 | 4 | Stateless, scale freely |
| Scan Workers | 3 | 10 | CPU-bound, scale with scan volume |
| Nuclei Workers | 2 | 8 | IO-bound, aggressive scaling OK |
| Screenshot Workers | 1 | 4 | High memory (2GB/worker) |
| Correlation Workers | 2 | 4 | CPU-bound |
| Risk Workers | 1 | 3 | Mostly DB-bound |
| Notify Workers | 1 | 2 | IO-bound |

### Database Scaling
- Read replicas for analytics queries
- Partition `findings` and `audit_logs` by `created_at` (monthly)
- Partition `risk_scores` by `computed_at` (weekly)
- Connection pooling via PgBouncer

### Queue Scaling
- RabbitMQ clustering (3-node minimum for HA)
- Queue priority for critical scans
- Dead-letter queues with 3 retry attempts

---

*Generated by ASM Platform Architecture System*

# Tutorial: your first scan

A guided, hands-on walk-through: by the end, you'll have the whole stack running locally, a registered
account, an organization with a domain, a completed scan, and a computed risk score you can look at. Not
a reference — if you already know the stack and just need a command reminder, see
[DEVELOPMENT.md](./DEVELOPMENT.md); if you want to understand *why* any of this works the way it does,
see [EXPLANATION.md](./EXPLANATION.md).

You'll need Docker and Docker Compose installed, and a terminal. Everything below runs from the repo
root.

## 1. Bring the stack up

```bash
make setup
```

This generates a `.env` file (random secrets filled in for you) and a self-signed TLS certificate — you
haven't started anything yet, this just prepares the config every other service needs.

```bash
make up-build
```

This builds every Docker image (backend, frontend, each worker) and starts the full stack: Postgres,
Redis, RabbitMQ, MinIO, OpenSearch, the API, the frontend, NGINX, and 17 worker processes. First run
takes a few minutes — subsequent runs are much faster since images are cached. You'll see a wall of
container startup logs; that's expected.

```bash
make migrate
```

Applies every database migration (`alembic upgrade head`) — the schema doesn't exist until this runs.

**Checkpoint** — confirm everything actually came up healthy before moving on:

```bash
make health
```

You should see every service reporting healthy. If something isn't, `make logs-api` or
`make logs-workers` is the first place to look.

## 2. Register an account

Open `https://localhost` in a browser (the self-signed cert means your browser will warn you — that's
expected for local dev, accept it). You'll land on the registration page.

Fill in your email, a password (12+ characters — the API rejects anything shorter), your name, and a
workspace name. You'll also be asked to pick a product: **ASM**, **Bug Bounty**, or both. This choice is
permanent for this workspace (see [EXPLANATION.md](./EXPLANATION.md#why-product-entitlement-is-chosen-once-at-registration)
for why) — pick **ASM** for this tutorial, since that's the pipeline we're about to walk through.

**Checkpoint** — after submitting, you should land directly on the ASM dashboard overview, already
logged in. If you'd rather do this step by API instead of the browser:

```bash
curl -sk -X POST https://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "password": "a-real-password-12-chars-plus",
    "full_name": "Your Name",
    "workspace_name": "My Workspace",
    "enabled_products": ["asm"]
  }'
```

This returns an `access_token` and `refresh_token` — save the `access_token`, you'll pass it as
`Authorization: Bearer <token>` on every API call below if you're following along this way instead of
the browser.

## 3. Create an organization

An `Organization` is the thing ASM actually scans — a company/target with one or more domains. In the
dashboard: **Organizations → New Organization**, give it a name and at least one domain you're
authorized to scan (a domain you own, or a deliberately-vulnerable test target).

Or by API:

```bash
curl -sk -X POST https://localhost/api/v1/organizations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example Corp",
    "domains": ["example.com"]
  }'
```

**Checkpoint** — the response includes an `id`. Save it; you'll need it for the next step. The
organization should also now appear in the dashboard's Organizations list.

## 4. Trigger a scan

In the dashboard: open the organization, click **Run Scan**, leave the defaults (`scan_type: full`),
confirm. Or by API:

```bash
curl -sk -X POST https://localhost/api/v1/organizations/$ORG_ID/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "full"}'
```

This returns a `scan_id` **immediately** — the API doesn't wait for the scan to run. It committed a
`Scan` row and a message to an outbox table in the same database transaction, then returns; a background
dispatcher publishes that message to RabbitMQ a moment later, and `worker-discovery` picks it up from
there (see [ARCHITECTURE.md](./ARCHITECTURE.md#request-flow-creating-an-asm-scan-outbox-pattern) if
you want the exact mechanics — you don't need them to keep following along here).

**Checkpoint** — if you're in the browser, watch the scan detail page: you should see live progress
updates (discovery → port scan → crawl → nuclei → correlation → risk scoring) arriving over WebSocket
without you refreshing the page. This can take anywhere from under a minute to several minutes depending
on how much the target domain actually exposes — a small test domain finishes fast.

## 5. See the results

Once the scan reaches `completed`: **Findings** shows whatever nuclei and the other scanners confirmed,
**Assets** shows every subdomain/IP/port discovered, and the organization's card on the dashboard
overview now shows a computed risk grade (A–F) instead of a placeholder. Click into the risk score for
the full category breakdown (`GET /organizations/{id}` includes the latest `RiskScore`, or
`GET /scores/breakdown?org_id=...` for the full 9-category detail) — see
[DEVELOPMENT.md#risk-scoring-formula](./DEVELOPMENT.md) if you want to understand exactly how that
number was computed.

That's the whole loop: register → organization → scan → findings → score. Everything else in this
platform (Bug Bounty's separate pipeline, notification rules, reports, the API reference at
`/api/docs`) builds on the same account and workspace you just created.

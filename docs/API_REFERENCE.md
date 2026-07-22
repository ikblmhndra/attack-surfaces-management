# API Reference

Base path: `/api/v1` (behind NGINX, see [ARCHITECTURE.md](./ARCHITECTURE.md#nginx-routing)). Every
endpoint list below was extracted directly from the router decorators in
`backend/app/api/v1/endpoints/*.py` on 2026-07-21 — this is exhaustive, not a curated subset.

## Authentication

Two auth methods, both resolved by `get_token_payload` (`backend/app/api/v1/dependencies/auth.py`):

1. **JWT bearer token** — `Authorization: Bearer <token>`. Claims: `sub` (user id), `wid` (workspace
   id), `role`, `type` (`access`/`refresh`), `products` (the workspace's `enabled_products`, embedded at
   register/login/refresh time via `create_access_token`'s `extra_claims` — avoids an extra DB query on
   the hot path for product-gating).
2. **API key** — `X-API-Key: <key>`. Looked up by its stored prefix, hash-verified, scope-checked.
   Doesn't carry a `products` claim (it's long-lived, so trusting one embedded at issue time would go
   stale if entitlement changes later) — `RequireProduct` falls back to a fresh `Workspace` lookup for
   this path specifically.

### RBAC — `RequireRole` / `RequireMinRole`

Role hierarchy: `owner(4) > admin(3) > analyst(2) > viewer(1)`. Pre-built dependencies:
`require_viewer`, `require_analyst`, `require_admin` (all `RequireMinRole`, i.e. "at least this level"),
`require_owner` (`RequireRole(["owner"])`, exact match). Applied per-endpoint.

### Product entitlement — `RequireProduct`

Wired at the **router** level in `backend/app/api/v1/router.py`, not per-endpoint — one line gates an
entire router's surface:

```python
api_router.include_router(bounty.router, prefix="/bounty", dependencies=[Depends(require_bounty_product)])
```

| Router | Gate | Reasoning |
|---|---|---|
| `organizations`, `assets`, `scans`, `findings`, `scores`, `intel`, `reports`, `screenshots`, `templates` | `require_asm_product` | ASM-only concepts |
| `bounty` | `require_bounty_product` | Bug Bounty-only concepts |
| `auth`, `workspaces`, `notifications`, `admin`, `keys`, `websocket`, `search` | *ungated* | Cross-cutting — auth has to work before any product is even known; notifications/keys/admin/search/websocket serve either product equally (e.g. a bounty-only workspace still configures notification channels through the exact same `NotificationRule` table an ASM workspace would) |

A request to a gated router from a workspace lacking that product gets `403` with
`"This workspace isn't enabled for 'X'. Enabled: Y"`. The frontend mirrors this (route redirects,
`Sidebar` variant, hidden nav) purely for UX — the API is the actual enforcement boundary; see
[FRONTEND.md](./FRONTEND.md).

## `auth` — Authentication (ungated)

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | Creates a **brand-new** `Workspace` + owner `User` — self-serve signup never joins an existing workspace. Body includes `enabled_products` (validated non-empty subset of `{asm, bounty}`, defaults to `["asm"]`). |
| POST | `/auth/login` | MFA-aware (`428` + `X-MFA-Required` header if TOTP required and not supplied). |
| POST | `/auth/refresh` | Rotates both tokens; refresh token hash is stored server-side and checked, so refresh tokens are revocable. |
| POST | `/auth/logout` | Invalidates the stored refresh token hash. |
| POST | `/auth/mfa/setup`, `/auth/mfa/enable`, `/auth/mfa/disable` | TOTP (pyotp) enrollment. |
| GET/PUT | `/auth/me` | Profile read/update; read includes `enabled_products` (joined from `Workspace`). |
| POST | `/auth/change-password`, `/auth/forgot-password`, `/auth/reset-password` | |

## `workspaces` (ungated)

| Method | Path | Notes |
|---|---|---|
| GET | `/workspaces` | Current workspace details. |
| GET | `/workspaces/members` | User list. |
| POST | `/workspaces/invite` | `invite_token` exists in the register schema but the field is currently unused/dead in `register()` — every registration creates a new workspace regardless. |
| PUT | `/workspaces` | Update settings. |

## `organizations` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/organizations` | List / create. |
| GET/PUT/DELETE | `/organizations/{org_id}` | Soft-delete on DELETE. |
| POST | `/organizations/{org_id}/scans` | **Triggers the ASM pipeline** — creates a `Scan` row, publishes `scan.discovery` via outbox. Extra-rate-limited at NGINX (`scan` zone). |
| POST | `/organizations/{org_id}/scans/nuclei-assets` | Ad-hoc nuclei run against a specific asset subset. |
| POST | `/organizations/{org_id}/assets/validate` | Triggers `asset.validate`. |
| GET | `/organizations/{org_id}/scans` | Scan history. |
| GET | `/organizations/{org_id}/score-history` | Risk score trend. |
| GET | `/organizations/{org_id}/timeline` | Change-event timeline. |
| GET | `/organizations/{org_id}/attack-surface-graph` | Node/edge graph for the Attack Surface visualization. |
| GET | `/organizations/{org_id}/network-clusters` | Shared-IP/ASN clustering — see `CHANGELOG.md` for the group-size cap on this. |

## `assets` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/assets` | Paginated, filterable list. |
| GET | `/assets/{asset_id}` | |
| PATCH | `/assets/{asset_id}` | |
| POST | `/assets/{asset_id}/review` | Human review workflow (`review_status`). |
| GET | `/assets/{asset_id}/endpoints`, `/findings`, `/screenshots`, `/technologies`, `/intel`, `/relationships` | Sub-resource views. |
| GET | `/assets/stats/by-type`, `/stats/new-over-time` | Dashboard aggregates. |
| GET | `/assets/export` | CSV/JSON export. |

## `scans` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/scans` | List. |
| GET | `/scans/{scan_id}` | Detail, including `phase_status`. |
| POST | `/scans/manual` | One-off scan outside an organization's normal cadence. |
| POST | `/scans/{scan_id}/cancel` | |

## `findings` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/findings`, `/findings/grouped` | List / dedup-grouped view. |
| GET/PUT | `/findings/{finding_id}` | |
| POST | `/findings/{finding_id}/false-positive`, `/accept-risk`, `/reopen` | Triage actions. |
| POST | `/findings/bulk-action` | |
| GET | `/findings/stats/by-category`, `/stats/trend` | |
| GET | `/findings/export` | |

## `scores` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/scores`, `/scores/history`, `/scores/breakdown` | Risk score read paths — see [DEVELOPMENT.md](./DEVELOPMENT.md#risk-scoring-formula) for the formula. |

## `intel` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/intel` | Reads `ThreatIntel` rows — keyless ASN/RDAP data, not third-party threat feeds; see [ARCHITECTURE.md](./ARCHITECTURE.md#docs-vs-reality). |

## `reports` — ASM only

| Method | Path | Notes |
|---|---|---|
| POST | `/reports/generate` | Synchronous, `BackgroundTasks`-driven (not queue-based) — `executive` format is summary-only, `technical`/`compliance`/`custom` get the full finding list (the latter two are currently aliases, no real framework-mapping built yet). `format="pdf"` renders via WeasyPrint and uploads to the MinIO `reports` bucket. |
| GET | `/reports`, `/reports/{report_id}`, `/reports/{report_id}/download` | |

## `screenshots` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET | `/screenshots` | |

## `templates` — ASM only

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/templates` | `ScanTemplate` CRUD — named, reusable scan configs. |
| GET/PATCH/DELETE | `/templates/{template_id}` | |

## `notifications` (ungated)

| Method | Path | Notes |
|---|---|---|
| GET | `/notifications` | |
| POST | `/notifications/mark-all-read` | |
| PATCH | `/notifications/{notification_id}/read` | |
| GET/POST | `/notifications/rules` | `NotificationRule` CRUD — channels: email/slack/discord/telegram/webhook. |
| PUT/DELETE | `/notifications/rules/{rule_id}` | |

## `admin` (ungated, `require_admin`/`require_owner` per-endpoint)

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/users` | |
| PUT | `/admin/users/{user_id}` | |
| GET | `/admin/audit-logs` | |

## `keys` (ungated)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/keys` | API key management. |
| DELETE | `/keys/{key_id}` | |

## `search` (ungated)

| Method | Path | Notes |
|---|---|---|
| POST | `/search` | Global search — OpenSearch-backed. |

## `websocket` (ungated)

`/ws` — live event stream, subscribed per-workspace (`asm:events:{workspace_id}` Redis pub/sub channel
relayed over the socket). Carries scan progress, finding events, and Bug Bounty stage status updates.

## `bounty` — Bug Bounty only

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/bounty/programs` | List / create a `BountyProgram`. |
| GET/PUT/DELETE | `/bounty/programs/{program_id}` | |
| POST | `/bounty/programs/{program_id}/run/pipeline` | Triggers the full auto-chained pipeline (`auto_chain: true`). |
| POST | `/bounty/programs/{program_id}/run/{stage}` | Triggers exactly one stage (`recon/probe/vulnscan/exploit/report`), no auto-chain. Refuses non-`active` programs. |
| GET | `/bounty/programs/{program_id}/targets` | Approved, testable list. |
| POST | `/bounty/programs/{program_id}/targets` | Add a target manually — still scope-checked. |
| DELETE | `/bounty/programs/{program_id}/targets/{target_id}` | |
| GET | `/bounty/programs/{program_id}/assets` | Recon suggestions (`asset_type`, `promoted` query filters). |
| POST | `/bounty/programs/{program_id}/assets/{asset_id}/promote` | Single-asset promote → creates a `BountyTarget`. |
| POST | `/bounty/programs/{program_id}/assets/promote-bulk` | Up to 500 assets, one transaction — built specifically to avoid the NGINX `api` rate zone (200r/m) when promoting hundreds of assets one at a time; per-asset outcome reported (`promoted`/`skipped` with a reason each). |
| GET | `/bounty/programs/{program_id}/findings` | `ExploitAttempt` list. |
| GET | `/bounty/programs/{program_id}/summary` | Smart-classifier rollup: totals, severity distribution, priority-bucket samples — powers the Summary tab. |
| GET | `/bounty/programs/{program_id}/report.html` | Self-contained shareable HTML report with per-finding step-by-step PoC sections. |
| GET/POST | `/bounty/programs/{program_id}/reports` | `BountyReport` draft list / (stage-generated, not user-POSTed in practice). |
| GET/PUT/DELETE | `/bounty/programs/{program_id}/reports/{report_id}` | |

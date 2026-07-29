# Changelog

All notable changes to this project are documented below, sorted newest-first.

---

## 2026-07-28 — Fixed modals rendering off-center (framer-motion clobbered Tailwind centering)

Follow-up to the same-day overlay-blur fix: user reported the modal itself "still isn't centered."
Separate bug — the overlay fix only ever touched `Dialog.Overlay`, never `Dialog.Content`. Investigated
fresh (Explore agent, retried once after a transient API disconnect) before touching code.

Root cause: all three modals (`FindingDetailModal.tsx`, `ScanModal.tsx`, the inline "New Scan" modal in
`dashboard/page.tsx`) put both framer-motion's animated `scale`/`y` props and Tailwind's
`-translate-x-1/2 -translate-y-1/2` centering classes on the *same* `motion.div`. framer-motion (11.2)
composes its tracked values into a single `transform` written as an inline style every frame; since
inline `style` always outranks a class selector, that completely overwrote Tailwind's centering
transform rather than merging with it — `left-1/2`/`top-1/2` (plain `left`/`top`, unaffected) still
pinned the box's top-left corner to viewport center, but the `-50%/-50%` corrective shift was gone,
leaving every modal shifted down-and-right by roughly half its own size.

Ruled out first, with evidence, before landing on the real cause: the new shared `DialogOverlay`
component (only touches the backdrop), `Dialog.Portal` container scoping (all three are bare, so they
already render to `document.body`, unaffected by the sidebar's padding offset), and an ancestor-transform
escape issue (already fixed once, 2026-07-23, and confirmed still intact).

### Fixed
- **`FindingDetailModal.tsx`, `ScanModal.tsx`, `dashboard/page.tsx`**: split the single `motion.div` into
  an outer plain `div` (owns only `fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2`, no
  framer-motion props, so nothing ever overwrites its transform) wrapping an inner `motion.div` (keeps
  the entrance animation and all existing visual styling, no positioning classes of its own). Also
  switched each modal's `w-[calc(100%-2rem)]`-style width to `w-[calc(100vw-2rem)]` — with the width now
  resolving against the new wrapper (an auto-sized `fixed` box) instead of directly against the viewport,
  a percentage-based `calc()` would no longer reliably resolve; `vw` sidesteps that entirely.

### Verified
- `tsc --noEmit` and `next lint` clean.
- Rebuilt and redeployed the frontend; API needed a manual restart after (an unrelated, transient
  RabbitMQ-connection-refused race on boot, not caused by this change — same recovery as the last
  redeploy).
- Real-browser check via Playwright, reusing/creating disposable test accounts: measured each modal's
  actual DOM bounding box against the viewport's true center programmatically (not just eyeballing a
  screenshot) for both the "New Scan" modal and `ScanModal` (via a real organization's Run Scan dialog)
  — both landed at exactly `(0.0, 0.0)` offset from true center.

---

## 2026-07-28 — Fixed illegible background behind every modal (dim + blur regression)

User sent a screenshot of the Findings page with a finding-detail modal open, asking why the background
content was now nearly illegible. Investigated (Explore agent) before proposing a fix: three modal
components (`FindingDetailModal.tsx`, `ScanModal.tsx`, the inline "New Scan" modal in `dashboard/page.tsx`)
each independently hand-rolled the identical Radix `Dialog.Overlay` block —
`bg-black/60 backdrop-blur-sm` — a hardcoded, theme-unaware literal carried over byte-for-byte from
before the light theme was added (commit `08c0688`, 2026-07-23) and never revisited. `backdrop-blur` (a
gaussian blur smearing whatever's behind it) was the more likely dominant cause of "illegible"
specifically, not the 60% opacity alone — cross-checked against shadcn/ui (80% opacity, no blur), Radix's
own docs example, and MUI's `Backdrop` (all plain opacity, no `backdrop-filter`).

### Fixed
- **`frontend/src/app/globals.css`**: added a themed `--overlay` token — `222 47% 11%` (= light theme's
  own `--foreground`) in `:root`, `222 47% 4%` (= dark theme's own `--background`, a near no-op tint
  preserving the existing dark-theme look) in `.dark`. No new numbers invented, both reuse existing
  per-theme values.
- **`frontend/tailwind.config.ts`**: added `overlay: "hsl(var(--overlay))"` next to the other semantic
  colors.
- **New `frontend/src/components/ui/Dialog.tsx`**: a single shared `DialogOverlay` component
  (`bg-overlay/60`, blur dropped entirely, not reduced), matching the `components/ui/Collapsible.tsx`
  convention (re-export what needs no styling, wrap only the piece that needs fixed classes). Replaces
  the 3 duplicated 7-line blocks with `<DialogOverlay />` at each call site — the July 23 CHANGELOG entry
  already established the pattern of converting duplicated modal markup/hardcoded color literals onto
  shared components and theme tokens in this codebase; this follows the same pattern rather than
  patching 3 copies in place.

### Verified
- `tsc --noEmit` and `next lint` clean (no new warnings; the `Dialog`/`motion` imports each file still
  uses for `Dialog.Content` stay referenced, so no unused-import issue from removing the inline overlay
  block).
- Rebuilt and redeployed the frontend (`target: production`, no hot reload).
- Real-browser check via Playwright (`worker-screenshot` container's existing install, registered a
  disposable test account through the real API to reach an authenticated dashboard): screenshotted the
  "New Scan" modal in both dark and light theme — background sidebar/stat cards fully legible behind the
  overlay in both, no blur smear, modal still clearly visually separated from the page.

---

## 2026-07-27 — Bug Bounty pipeline: fixed detector false-positives/noise, added JWT + JSON-CSRF coverage

Live-diagnosed against the "OWASP Juice Shop" bug bounty program (real target, authenticated testing):
of 939 accumulated findings, 63% were `inconclusive` and dominated by two detectors (`jsonbody` 387,
`bac` 123 — 54% of the entire table) that fired on nearly every URL regardless of real vulnerability,
burying the ~64 genuinely confirmed findings (SQLi auth-bypass, DOM XSS, IDOR, SSTI, CORS). Also found
2 false *confirmed* findings (`.env`/`.htpasswd` "exposure" hits that were actually the target's
`security.txt` catch-all content) and a crawler bug feeding JS-expression fragments (e.g. `'+L(i[8])+'`)
into the target list as if they were real routes. Verified every root cause live via curl against the
target before touching code, then verified every fix live the same way post-change (see PR/session
notes) — a fresh vulnscan+exploit run post-fix went from the historical noise pattern to 7 curated
exploit findings (down from 24 in the prior run), including a new critical finding (JWT `alg:none`
forgery) that no prior module could have caught.

### Fixed
- **`workers/bounty/detect.py`**: `_is_catch_all_200()` now returns `(is_catch_all, baseline_body)`
  instead of a bare bool (with an optional per-run cache so repeat callers on the same base issue the
  nonce probe once). `check_sensitive_files()` now skips a hit when its body matches that baseline
  body, regardless of content-type — the old guard only special-cased HTML-shaped catch-alls, missing a
  base whose own catch-all is plain text (verified live: `.../.well-known/security.txt/.env` and
  `.../.htpasswd` both 200 with identical `security.txt` prose, which trivially contains a stray `=`
  and `:`, satisfying those signatures).
- **`workers/bounty/exploit_ext.py`**: `run_json_body_mutations()`'s `nosql-body` case no longer treats
  a bare HTTP 500 as a hit — verified live that Express's generic error handler 500s on almost any
  malformed POST body regardless of NoSQL operators, so this fired on nearly every POST-able endpoint.
  Now requires either an explicit driver-error signature, or a baseline (benign-body) POST that did
  *not* itself 500. `idor_bac_probe()` now skips catch-all-200 hosts entirely (every method/response
  looked "accepted" there regardless of real access control) and requires the alternate-method response
  to genuinely differ in shape from the GET baseline (not just "a 2xx different from GET" — a normal
  POST-201-vs-GET-401 pair used to fire on its own). `bac-unauth-privileged` can now graduate from
  `inconclusive` to `confirmed` when the caller supplies the pipeline's own session token as a second,
  optional comparison request (previously unused for this check even though every other module already
  had it available).
- **`workers/bounty/upload_xxe.py`**: `check_unrestricted_upload()` now skips catch-all-200 hosts too
  (same false-positive shape as `bac` above — a server that 2xxs everything "accepts" any upload).
- **`workers/bounty/recon_worker.py`**: `_persist()` now rejects any discovered `url`/`js_endpoint`
  asset whose path (raw or percent-decoded) contains JS-expression punctuation (`+()[]{}` ) — traced to
  `tools.py::ENDPOINT_PATTERN`'s char class (allowed `{}`) and katana's `-jc` JS-string extraction
  lifting template/concatenation fragments out of bundled scripts and persisting them as if they were
  real routes.
- **`workers/bounty/tools.py`**: `ENDPOINT_PATTERN` char class no longer allows `{}`; `run_katana()`'s
  output filter now drops lines matching the same punctuation instead of only stripping `\`/`%5C`/`%22`.
- **`workers/bounty/idor_confirm.py`**: `_looks_like_resource` renamed to `looks_like_resource` (now a
  cross-module utility, reused by the `idor_bac_probe` fix above).

### Added
- **`workers/bounty/exploit_ext.py::check_jwt_weakness`** (new "jwt" exploit module) — using the
  pipeline's own valid session token: tests whether a token-gated endpoint accepts an unsigned
  (`alg:none`) re-encoding of the same claims (confirmed live on this program: `/rest/user/authentication-details`
  and `/api/Users` both accepted it), and for HS256 tokens, whether the signature matches a small
  built-in list of common weak secrets (mathematically conclusive on a byte-exact HMAC match, no live
  replay needed). Self-validates the target URL as a real oracle first (anonymous denied, real token
  accepted) so it never runs against a public or catch-all endpoint.
- **`workers/bounty/exploit_ext.py::check_json_csrf`** (folded into the existing "csrf" module) —
  `run_csrf` only parses classic HTML `<form>` markup, which a JSON-only SPA never emits, so it silently
  reported clean on that entire class of app. This checks the actual browser-enforced primitive instead:
  does login set a session cookie at all (a bearer-token-only scheme is structurally CSRF-resistant and
  correctly reports nothing), and if so, does it carry `SameSite=Strict/Lax`.
- `ALL_MODULES`/`DEFAULT_MODULES` in `exploit_worker.py` gained `"jwt"`; `catch_all_cache` is now shared
  across `bac`/`upload` within one exploit run and across `check_sensitive_files`/`check_403_bypass`
  within one vulnscan run (`vulnscan_worker.py`), so a given origin's catch-all probe fires once per
  run, not once per URL/module.

## 2026-07-27 — Ground-truthed coverage against Juice Shop's own Score Board; one more generic check added

User asked to drive a real headless browser (Playwright) to `/#/score-board` — Juice Shop's own built-in
challenge tracker, which flags each of its 173 named challenges "solved"/"unsolved" as soon as *any*
request (from us or anyone) triggers the underlying bug. Used this as ground truth to sanity-check the
fixes above rather than trusting our own findings table: 13/173 solved, and every one of the 13 maps
cleanly to a finding our pipeline already has (`Login Admin`→sqli-auth-bypass, `DOM XSS`→dom-xss,
`View Basket`→idor-cross-identity, `Exposed Metrics`→nuclei/prometheus-metrics, `Security Policy`→
recon crawl of `security.txt`, `Upload Type`→upload module, `Email Leak`→CORS reflected-origin, etc.).

Also used it to catch a *false positive* the score board proves is stale: the historical `ssti`
"confirmed" finding on `/redirect?to=` doesn't correspond to any solved challenge — `SSTi` is still
listed unsolved. Reproduced `run_ssti()` live against that exact URL: it now correctly returns `[]`.
The "49" the old finding matched on was never template evaluation — it's a substring of Express's own
stack trace line number (`route.js:149:13`), present in both the baseline *and* payload responses. The
baseline-diff this file's docstring already describes (`SSTI_PAYLOADS` baseline check, present before
today's other changes) already guards against exactly this; the stale DB row just predates whichever
earlier change added it. No code change needed here — confirmed working as intended, left as a data-
hygiene note rather than mutated (didn't bulk-touch existing findings).

Categorized the 98 other unsolved (of the ones rendered without further scrolling — score board uses
virtual-scroll and 111/173 loaded is what two different scroll strategies converged on): a large chunk
are Juice Shop's separate "Coding Challenges" (fix a source file, not discoverable by any dynamic
scanner) or single-instance business-logic puzzles (specific coupon codes, a specific GDPR export flow,
a specific cryptocurrency address) that would require hardcoding Juice-Shop-specific knowledge into a
platform whose entire design point is being target-agnostic — deliberately not chased. One class stood
out as genuinely generic and missing: **ownership-impersonation via request body** (`Forged Feedback`,
`Forged Review` — submitting content "as" another user by supplying their ID instead of letting the
server derive it from the session), the same shape of bug as the existing `mass-assignment` case, just
on ownership fields instead of privilege fields.

### Added
- **`workers/bounty/exploit_ext.py::run_json_body_mutations`**: new `ownership-assignment` case —
  POSTs a sentinel owner ID (`999999999`) under the common `UserId`/`userId`/`user_id`/`authorId`/
  `ownerId`/`createdBy` field-name conventions; a hit requires the exact sentinel value to be echoed
  back (not just the field name, unlike the existing `mass-assignment` case — a literal value match is
  a stronger signal and was cheap to do here). `inconclusive`/`high` — same "candidate, not extraction"
  discipline as every other module in this file.

### Investigated, not built (flagged for a separate scoping conversation if wanted)
- **`CSRF`** still unsolved despite the new `check_json_csrf` — correctly finds no session cookie
  (Juice Shop's SPA login is Bearer-only), so whatever mechanism the game's own `CSRF` challenge uses
  isn't the classic cookie-based primitive this check targets. Not yet root-caused.


## 2026-07-27 — Vulnerable/outdated frontend JS component detection (retire.js-style)

Follow-up to the Score Board gap analysis above — built the flagged "vulnerable components" detector.
Scope note going in: Juice Shop's own `Vulnerable Library`/`Legacy Typosquatting`/`Supply Chain Attack`
challenges are about a *backend* npm dependency (or are pure source-review "Coding Challenges"), not a
frontend bundle, so this specific target's own score board wasn't expected to move much from this — and
didn't (0 findings against all 36 of its real JS assets, verified live, no crashes). Built anyway because
the *capability* — detecting known-vulnerable frontend JS libraries by version banner, the same thing
retire.js/Wappalyzer-style tools do — is a real, generically valuable gap for actual bug bounty targets
that do bundle outdated jQuery/Bootstrap/AngularJS(1.x), which is extremely common in the wild.

Deliberately a small, high-confidence starting table (3 libraries, well-documented CVEs only) rather
than a full retire.js-scale database — wrong version-fingerprint data would actively mislead a report,
so precision over coverage here. Caught one accuracy bug in testing before it ever shipped: an early
version flagged a Bootstrap 3.x install as needing "3.4.1" it deserved but tested a *4.x* threshold
first and reported "upgrade to 4.3.1" (a different major branch entirely — a real Bootstrap 3 site
would never make that jump for a patch). Fixed by making ranges major-version-aware where the upstream
project actually maintains parallel branches (Bootstrap); jQuery/AngularJS don't have that problem
(one continuously-maintained line each), so those stay a flat "upgrade to the latest fix" cascade.
Verified against synthetic vulnerable/patched/cross-major-boundary cases before and after the fix.

### Added
- **`workers/bounty/detect.py::check_vulnerable_components`** (new) — fetches a JS asset (bounded to
  its first 60KB; version banners are always at the top of a bundle), matches against
  `LIBRARY_VERSION_SIGNATURES`: jQuery (< 3.5.0 CVE-2020-11022/11023, < 3.4.0 CVE-2019-11358, < 1.9.0
  CVE-2015-9251), Bootstrap (< 4.3.1 CVE-2019-8331, < 3.4.1 CVE-2018-14040/41/42, major-branch-aware),
  AngularJS 1.x (< 1.6.0, pre-sandbox-removal). Skips non-JS content (HTML catch-all shells) explicitly.
- Wired into `workers/bounty/vulnscan_worker.py::_run_detection` as a new `"components"` module —
  JS-suffixed URLs are split out of the same 400-row `BountyAsset` fetch `endpoint_urls` already uses
  (no second query), bounded by new `MAX_DETECT_JS_FILES = 25`.


## 2026-07-26 — Restructured docs/ around the Diátaxis framework, added an executive summary

User asked whether the documentation followed any recognized standard, then asked to restructure it to
match Diátaxis (Tutorial / How-to / Reference / Explanation, kept separate rather than mixed in one
file) as closely as reasonably possible, plus a separate executive summary.

Audited every doc against the framework first: Reference and Explanation content existed but were
tangled together in the same files (a routing *table* sitting next to *why the architecture is shaped
this way* prose, in the same document); there was no Tutorial at all; the closest thing to a How-to
guide (`DEVELOPMENT.md`'s command lists and gotchas) read like a reference lookup, not a goal-oriented
task walkthrough.

### Added
- **`docs/TUTORIAL.md`** (new) — hands-on, narrated first run: bring the stack up, register, create an
  organization, trigger a scan, read the resulting risk score. Written in second person with explicit
  checkpoints, not a bare command list.
- **`docs/HOWTO.md`** (new) — task-oriented guides: run the test suite, add a migration, add an env var,
  add a new worker queue, reverse-proxy a new internal service through NGINX (codifying the three
  Grafana/Prometheus lessons from 2026-07-23 into one coherent checklist instead of three separate
  gotchas), scale workers.
- **`docs/EXPLANATION.md`** (new) — every "why" consolidated in one place: why two pipelines, the scope
  gate's safety property, why recon needs a real browser for SPA apps, why the two dashboard shells are
  separate, why the light theme/Radix/reduced-motion work happened, why Scalar is self-hosted instead of
  CDN-loaded, why product entitlement is chosen once at registration, what the platform self-security
  audit found and didn't find, and the running "docs vs. reality" correction log.
- **`docs/EXECUTIVE_SUMMARY.md`** (new) — half-page, non-technical: what the product does, why
  self-hosted, where it stands, pointers to PRD/full docs for more detail.

### Changed
- **`docs/ARCHITECTURE.md`**, **`docs/PIPELINES.md`**, **`docs/FRONTEND.md`**: stripped of the
  discursive "why" prose that used to sit next to their reference tables/diagrams (moved to
  EXPLANATION.md, with a pointer left behind); what remains is closer to pure Reference — structural
  facts, tables, diagrams as diagrams, not argument.
- **`docs/DEVELOPMENT.md`**: narrowed to Reference (Makefile command table, the risk-scoring formula's
  exact numbers, config wiring, a trimmed factual "known quirks" list) — the actionable "how do I do X"
  content moved to HOWTO.md, the "why" content moved to EXPLANATION.md.
- **`docs/PRD.md`**, **`docs/TRD.md`**: left as-is structurally (both are product-planning documents,
  not user/developer system documentation, so they sit outside Diátaxis's four modes on purpose) but
  each got a short note saying so, plus a link from PRD.md to the new executive summary. Also fixed a
  second instance of the same stale compliance-report claim corrected in API_REFERENCE.md a few days
  ago (PRD.md's product-scope table still said "no real framework-mapping built yet" for `compliance`
  reports — missed in that earlier pass).
- **`docs/README.md`**: rewritten as a Diátaxis-labeled index (which mode each doc is, plus a separate
  "outside the four modes" group for PRD/TRD/Executive Summary) with reading-order guidance per audience.

### Verified
- Re-ran the broken-GFM-table-row check across every doc file plus the root `README.md` — clean.
- Grepped for every anchor link that moved as part of the split (`ARCHITECTURE.md#why-two-pipelines-not-one`,
  `ARCHITECTURE.md#docs-vs-reality`, `DEVELOPMENT.md`'s old gotchas/registration anchors,
  `PIPELINES.md`'s old scope-gate anchor) across the whole repo, not just `docs/` — found and fixed 9
  stale cross-references left dangling by the restructure, including 2 in the root `README.md` that
  predated this session's work entirely.

---

## 2026-07-26 — Documentation catch-up: 6 files drifted since the 2026-07-21 rewrite

User flagged that the full documentation rewrite from 2026-07-21 seemed incomplete. Re-audited every
doc against current code (same discipline as the original rewrite) instead of guessing what was
missing, and found real drift across 6 files — one of them an outright factual error, not just an
omission.

### Fixed
- **`docs/API_REFERENCE.md`**: the `reports` endpoint row claimed "no real framework-mapping built yet"
  for `compliance`/`custom` reports — flatly wrong now; `backend/app/services/compliance_mapping.py`
  has real CIS Controls v8 mapping, added 2026-07-15. Corrected, and added the executive-narrative
  feature (`report_narrative.py`) that was also undocumented.
- **`docs/PRD.md`**: the roadmap still listed a suspected cross-tenant data leak as "flagged as high
  priority but not yet actioned" — it was actually investigated exhaustively on 2026-07-22 (every
  endpoint file, the auth/JWT layer, the correlation worker's cross-org queries) and not found.
  Corrected to reflect that only 2 of the original 3 self-security issues are still real
  (workspace-invite stub, SMTP env-var gap — both confirmed still unfixed while writing this), plus a
  new low-priority hardening nit the audit surfaced (`findings.py::bulk_action`'s UPDATE statements
  don't re-assert `workspace_id`, though not currently exploitable).

### Added
- **`docs/ARCHITECTURE.md`**: `/grafana/` and `/prometheus/` added to the NGINX routing table and the
  container-topology diagram (missing entirely — the reverse-proxy work landed after this doc was
  written); noted `opensearch-dashboards` is stopped by default now.
- **`docs/FRONTEND.md`**: the Attack Surface Map's `attack-surface/` entry was still described as just
  "graph visualization" — added a real section on all 3 views (Clusters/Heatmap/Graph legacy) and which
  data source each uses; added a "Theming and accessibility" section (the Radix UI modal/dropdown
  rewrite, light theme, `MotionConfig reducedMotion`) that had no coverage at all; added the new root
  `page.tsx` to the App Router tree.
- **`docs/DEVELOPMENT.md`**: 4 new gotchas from the infra work that weren't captured anywhere — the
  NGINX regex-static-asset-location-beats-plain-prefix bug (`^~` requirement), Grafana's subpath
  trailing-slash redirect-loop trap, Prometheus's `/-/reload` not actually refreshing its bind-mounted
  config in this environment (full restart does), and RabbitMQ needing
  `prometheus.return_per_object_metrics = true` before any per-queue metric exists at all.
- **`docs/PIPELINES.md`**: a short note that ASM reporting is deliberately not a queue pipeline stage
  (synchronous `BackgroundTasks`, not chained), with a pointer to the compliance-mapping/narrative
  detail now in API_REFERENCE.md.

### Verified
- Grepped every changed doc for the specific gap terms (`/grafana/`, `Heatmap`, `Theming`,
  `return_per_object`, `CIS Controls`, etc.) to confirm each landed exactly once in the intended file,
  not zero and not duplicated.
- Re-ran the same broken-GFM-table-row check used during the original rewrite (a `|`-initial line not
  also `|`-terminal) against all 6 changed files — clean.
- Confirmed the 2 "still open" self-security claims directly against current code before writing them
  down, rather than trusting the earlier investigation's memory: `workspaces.py::invite_member` is
  still a bare `return {"message": "Invitation sent"}`, and `docker-compose.yml`'s `worker-notification`
  environment block still has no `SMTP_*` vars.

---

## 2026-07-26 — Interactive API reference at `/api/docs` (self-hosted Scalar)

User asked for OpenAPI-backed API docs (OpenAPI + Scalar or Swagger UI), explicitly asking to check
which fits before building. Investigation found: `main.py` already had `docs_url`/`redoc_url`/
`openapi_url` wired up, but all three were conditionally disabled whenever `ENVIRONMENT=production`
(the live value in `.env`) -- so none of `/api/docs`, `/api/redoc`, `/api/openapi.json` were reachable
at all. Router tags were already clean (`Authentication`, `Bug Bounty`, etc., set at
`include_router(..., tags=[...])` in `router.py`), a good foundation either way. The deciding factor
between the two options: FastAPI's built-in Swagger UI, and every common Scalar integration, both
default to loading their JS/CSS from `cdn.jsdelivr.net` -- which nginx's existing CSP (`script-src
'self'`) blocks outright, so either choice needed self-hosting regardless, not just picking the
"easier" one. Chose Scalar for the nicer UI/DX given roughly equal self-hosting effort either way.

### Added
- **`backend/app/static/scalar/standalone-1.63.0.js`**: Scalar's standalone browser bundle, vendored
  locally at a pinned version (not `@latest`, not loaded from jsdelivr at request time) — downloaded
  once, verified byte-identical against the pinned CDN URL, then committed as a local asset.
- **`GET /api/docs`** (`backend/app/main.py`): returns an HTML page with a `<script id="api-reference"
  data-url="/api/openapi.json">` tag followed by the vendored bundle inlined directly in a `<script>`
  block — no separate static-file route needed, which also sidesteps the location-precedence bug the
  Grafana/Prometheus nginx work found (an `/api/static/...` route would otherwise get hijacked by
  nginx's regex `.js`/`.css` location, same class of bug fixed there).
- `openapi_url="/api/openapi.json"` is now always on regardless of `ENVIRONMENT` — it's read-only API
  shape, not live data, and the same surface is already fully documented in
  `docs/API_REFERENCE.md`, which is already in the repo. `docs_url`/`redoc_url` stay permanently
  disabled (`None`) since Scalar replaces both.
- Cross-linked from `docs/API_REFERENCE.md` and `docs/README.md`; the API_REFERENCE.md doc now also
  notes the real limitation the schema exposes: most endpoints don't declare a Pydantic
  `response_model`, so generated response schemas are often generic (request bodies are accurately
  typed, since most POST/PUT endpoints do use Pydantic request models).

### Verified
- `curl`-tested through nginx (no nginx.conf changes needed at all — both paths flow through the
  existing `/api/` proxy block): `/api/openapi.json` 200s with 85 real paths across all 16 expected
  tags; `/api/docs` 200s, full 3.7MB bundle present in the response body, gzip applied
  (`content-encoding: gzip`) so actual wire size is much smaller.
- Real-browser check via Playwright (run inside the `worker-screenshot` container, which already has
  it installed, against the live nginx-fronted URL): page title, sidebar tag groups (confirmed both
  "Authentication" and "Bug Bounty" render), and the client-code-sample panel all populated correctly
  from the real schema. 14 console errors, all the same known/accepted CSP font-blocks
  (`fonts.scalar.com` blocked by `font-src 'self'`) — cosmetic only, falls back to system fonts,
  deliberately not loosening the CSP for it.

---

## 2026-07-23 — Grafana dashboard tuning: removed dead panels, fixed RabbitMQ per-queue metrics

User asked for the Grafana dashboard (`infrastructure/grafana/dashboards/asm-overview.json`) to be tuned
for clarity after noticing several panels showing "No data." Queried every panel's PromQL expression
directly against Prometheus to tell genuinely-broken panels apart from panels that were just quiet.

### Removed
- **PostgreSQL Connections** and **Redis Memory Usage** panels -- both depend on `postgres-exporter`/
  `redis-exporter`, which don't exist in `docker-compose.yml` (same gap identified in the earlier
  Prometheus/OpenSearch infra audit below). A permanently-empty panel is worse than no panel; removed
  rather than left blank. Panels 7 and 9 widened to fill the freed space.

### Fixed
- **RabbitMQ Queue Depth**: the panel's own `legendFormat` was `{{queue}}` and its query filtered
  `{vhost="/"}`, but RabbitMQ's Prometheus plugin only exposes a single cluster-wide aggregate by
  default -- `rabbitmq_queue_messages` had *no* `queue`/`vhost` labels at all, so the panel had been
  wired for per-queue data it could never receive. Added `prometheus.return_per_object_metrics = true`
  to `infrastructure/rabbitmq/rabbitmq.conf` (~24 queues, so the added cardinality is small) and changed
  the query to `sum by (queue) (rabbitmq_queue_messages_ready)`.
- **Failed Messages (DLQ)**: a workspace with zero failures ever and a workspace with a broken metric
  looked identical (both rendered as an empty panel). Wrapped the query with `or on() vector(0)` so zero
  failures now renders as an explicit flat 0 line.
- **API P99 Latency**: 35 handler series crammed into one legend was unreadable. Wrapped in
  `topk(8, ...)` to show only the 8 slowest endpoints.
- **Worker Processing Time (p99)**: widened the `rate()` window from 5m to 15m -- during low-traffic
  windows a worker with zero processed messages produced a 0/0 `histogram_quantile`, rendering as a NaN
  gap in the graph.
- Corrected the `reqps` (HTTP-request-flavored) unit on the Worker Messages Processed / Error Rate /
  Failed Messages panels to `ops`, since these count queue messages, not HTTP requests.

### Verified
- Restarted RabbitMQ; all 9 workers reconnected automatically and all Prometheus targets stayed `up`
  (no pipeline disruption). Confirmed `rabbitmq_queue_messages_ready` now returns 32 labeled series (one
  per real queue + DLQ, matching `EXCHANGE_MAP`).
- Queried every changed panel's expression directly against `/api/v1/query` and confirmed real,
  non-empty results (topk(8) latency handlers, per-queue depths, the DLQ `vector(0)` fallback).
- Confirmed via Grafana's own dashboard API (`/api/dashboards/uid/asm-platform-overview`) that the
  file-provisioned dashboard auto-reloaded to the new panel set (version bumped 1 -> 2) with no manual
  restart needed.

---

## 2026-07-23 — nginx: fixed bare-origin 404, reverse-proxied Grafana + Prometheus

User reported `https://<host>/` (no path) 404ing, and asked to have it redirect to the dashboard when
logged in / to the login form otherwise -- and to route Grafana and Prometheus through nginx instead of
their direct host ports, while investigating.

### Fixed
- **`frontend/src/app/page.tsx`** (new): the root route had no `page.tsx` at all -- Next.js App Router
  was correctly 404ing on `/` by its own design, nginx's `error_page 404 = @fallback` block was never the
  problem (it just re-proxied to the same upstream). New root page waits on `useWorkspaceStore`'s
  `isLoading`/`isAuthenticated` (already resolved on app boot by `Providers.tsx`) and forwards to
  `/dashboard` (or `/dashboard/bounty`, mirroring the login page's own product check) or `/auth/login`.
- **Grafana reverse-proxy redirect loop**: initially proxied `/grafana/` with a trailing-slash
  `proxy_pass http://grafana:3000/;`, which strips the `/grafana` prefix before forwarding -- but Grafana
  is running with `GF_SERVER_SERVE_FROM_SUB_PATH=true` and expects that prefix preserved, so it kept
  redirecting back to `/grafana/` forever. Fixed by dropping the trailing slash so the full path forwards
  unchanged (the documented-correct pattern for reverse-proxying Grafana under a subpath).
  - **`GRAFANA_ROOT_URL`** in `.env` was still the literal placeholder `https://your-domain.com/grafana`,
    which would have made Grafana redirect to a domain that doesn't resolve. Updated to the real address
    in use, `https://172.25.1.77/grafana/`.
- **Grafana/Prometheus assets 404ing through nginx ("failed to load application files" / blank page)**:
  root cause was location-matching precedence, not either app -- an existing regex location
  (`~* \.(js|css|...)$`) in `nginx.conf` matches *any* static-asset request and, per nginx's rules, always
  wins over a plain prefix location, so every `/grafana/public/...` and `/prometheus/static/...` request
  was being routed to the frontend Next.js upstream instead, 404ing there. Added the `^~` modifier to
  both new locations (matching the same pattern already used for `location ^~ /storage/`) so they stop
  the regex fallthrough for anything under their prefix.
- **`prometheus.yml`/`docker-compose.yml` reload not taking effect via the `/-/reload` HTTP endpoint**:
  in this environment, Prometheus's bind-mounted config file only picked up host-side edits after a full
  `docker compose restart`, not the `--web.enable-lifecycle` reload API (confirmed via mismatched
  inode/device/mtime between the host file and the file the running container actually read). Worth
  remembering for future infra config edits in this environment.

### Added
- **`location ^~ /grafana/`** in `nginx.conf`, proxying to `grafana:3000` -- protected by Grafana's own
  login (no separate nginx-side auth needed).
- **`location ^~ /prometheus/`**, proxying to `prometheus:9090` -- protected by nginx Basic Auth
  (`auth_basic` + `infrastructure/nginx/conf.d/.htpasswd`), since Prometheus has no login of its own.
  Credentials generated and shared out-of-band with the user (not committed to the repo).
- **`docker-compose.yml`**: `GF_SERVER_SERVE_FROM_SUB_PATH: "true"` on the `grafana` service;
  `--web.external-url=/prometheus/` + `--web.route-prefix=/` added to the `prometheus` command args --
  both required for each app to generate correct links/assets under its nginx subpath.

### Verified
- `curl`-tested every path end to end after each fix: `/` now 200s and serves the spinner+redirect page
  (confirmed via rebuilt frontend image, `docker.compose build frontend` -- required since it's a
  `target: production` Next.js build, no hot-reload); `/grafana/` 302s to `/grafana/login` (200);
  `/prometheus/` 401s with no credentials, 302s to `/prometheus/graph` (200) with them; static assets
  under both prefixes (`.js`/`.css`) return 200 instead of 404.
- Flagged, not fixed (user's call): `GRAFANA_PASSWORD` in `.env` is still the placeholder
  `CHANGE_ME_grafana_password` -- now that Grafana is reachable from the same public-facing domain as
  the app, this should be rotated to a real password before relying on it.

---

## 2026-07-23 — Infra audit: orphaned Docker volumes reclaimed, Prometheus/OpenSearch cruft trimmed

User asked whether `infrastructure/`'s observability stack (Grafana, Prometheus, OpenSearch) was actually
used or just carried along unused, specifically to find safe storage wins. Audited every scrape target,
dashboard panel, and OpenSearch index against real, live data rather than assuming from config alone.

### Findings
- **OpenSearch itself: genuinely used.** `asm-findings` (2,349 docs) and `asm-assets` (3,673 docs) are
  real, live-indexed data (`correlation_worker.py::_index_to_opensearch`, read back by `GET /search`).
- **OpenSearch Dashboards (the Kibana-like UI on :5601): never actually used.** Its `.kibana_1` index has
  0 saved objects since the service was first added (`git log` shows `infrastructure/grafana/` -- and by
  the same token this service -- untouched since the first commit). Stopped the container
  (`docker compose stop opensearch-dashboards`, not removed from `docker-compose.yml` -- data lives in
  the shared `opensearch-data` volume regardless, so nothing is lost and it's a one-command restart if
  ever needed).
- **Prometheus: half its scrape targets were dead config, never real containers.** Live `/api/v1/targets`
  showed 6 of 11 jobs healthy (`asm-api`, `asm-workers` x9, `rabbitmq`, `prometheus` self) and 5
  permanently down: `postgres-exporter`/`redis-exporter`/`nginx-exporter`/`node-exporter` (containers
  that were never added to `docker-compose.yml` -- DNS lookup failures, not a recent regression) and
  `minio` (403, no auth configured) plus a `scheduler` target that can never work since `ScanScheduler`
  doesn't subclass `BaseWorker` and never calls `start_http_server()`.
- **Orphaned volumes from an old/renamed project instance**: `docker volume ls` turned up 10 volumes
  prefixed `asm-platform-by-claude-ilalaelah18_*` with no matching `docker compose ls` project and no
  container (running or stopped) referencing them -- ~362MB, entirely dead.
- **`prometheus-data` itself: 895MB**, the single largest volume in the live project. TSDB stats showed
  `erlang_vm_allocators` (RabbitMQ's Erlang VM internals, exposed by the `rabbitmq_prometheus` plugin)
  alone accounted for 912 of ~3,456 total series -- high-cardinality detail nothing dashboards or alerts
  on, accumulating under the 30-day retention window for no benefit.

### Fixed / Removed
- Deleted the 10 orphaned `asm-platform-by-claude-ilalaelah18_*` volumes (user ran this directly --
  `docker volume rm` is blocked from automated execution by this environment's auto-mode classifier).
- `infrastructure/prometheus/prometheus.yml`: removed the 5 scrape jobs pointing at exporters that don't
  exist (`postgres`, `redis`, `nginx`, `node`, `minio`) and the `scheduler` target from the `asm-workers`
  job; added a `metric_relabel_configs` drop rule for `erlang_vm_allocators.*` on the `rabbitmq` job
  (confirmed the existing Grafana panel only ever queried `rabbitmq_queue_messages`, never this metric,
  so nothing else was affected).
- Stopped `opensearch-dashboards`.

### Verified
- Confirmed all 10 orphaned volumes gone (`docker volume ls` no longer lists them), all `attack-
  surfaces-management_*` volumes untouched.
- Reloaded Prometheus (discovered along the way: its `/-/reload` HTTP endpoint didn't actually refresh
  the bind-mounted config in this environment -- a full `docker compose restart prometheus` did; see the
  nginx entry above for the same discovery recurring). Confirmed via `/api/v1/targets` the dead jobs are
  gone and the live ones (`asm-api`, `asm-workers`, `rabbitmq`, `prometheus`) stayed healthy throughout;
  confirmed `erlang_vm_allocators` dropped to 0 series and `rabbitmq_queue_messages` (the panel's actual
  dependency) unaffected.
- Left `prometheus-data`'s existing 895MB untouched (ages out naturally over the 30d retention window)
  rather than deleting the volume outright, per the user's choice not to reset historical data.

---

## 2026-07-23 — Frontend: risk heatmap view on Attack Surface Map (additive, no old view touched)

Follow-up to the design-recommendation pass below. User was explicit that any new-design work had
to stay additive -- old views stay reachable, nothing gets replaced.

### Added
- **`components/charts/RiskHeatmap.tsx`** (new): a third view on `dashboard/attack-surface/page.tsx`
  (`Clusters` / `Heatmap` / `Graph (legacy)` toggle -- the existing two are byte-for-byte unchanged).
  Reuses the same already-fetched `NetworkClustersResponse` the `Clusters` view uses (no new API
  call) and renders every cluster + standalone host as a grid cell, colored on a continuous cool
  (emerald) → hot (red) gradient by a weighted-severity score (critical=4/high=3/medium=2/low=1),
  normalized against the highest-risk cell in the current dataset. Zero-finding cells render neutral
  rather than "cool-green" (a heatmap where "nothing happening" competes visually with real signal
  is the wrong call -- matches the GitHub-contribution-graph convention of gray-for-none). Clicking a
  cell expands the same severity-count + top-findings detail the cluster list already shows.
  Color uses the app's existing severity hues (emerald ~160°/amber ~48°/red 0°) as translucent tints
  over the existing surface color, not solid fills -- same technique the severity badges already use,
  so it didn't need separate light/dark contrast tuning per cell.
- **`globals.css`**: added `.hud-corners`, an opt-in utility (small corner-bracket accent via
  `::before`/`::after`, `currentColor`-based so it needs no per-theme color) -- applied only to the
  new heatmap's cells, not retrofitted onto `.glass-card`/`.metric-card` globally.
- Wired up `bg-grid-pattern`/`bg-grid` as the heatmap grid's backdrop texture -- both were already
  defined in `tailwind.config.ts` but unused anywhere in the app until now.
- Verified via `tsc --noEmit`, `next lint`, `next build` (all clean; `/dashboard/attack-surface`
  bundle grew 10.3kB → 11.5kB for the new view). Visual appearance not eyeballed in a browser (no
  screenshot tool available this session), same caveat as the entry below.

---

## 2026-07-23 — Frontend: dashboard modal/dropdown accessibility fixes + light theme

Ran a UI/UX audit of the frontend shell (Sidebar, DashboardHeader, modals, shared badge
components) against the ui-ux-pro-max accessibility/style checklist, then fixed what it found and
added a light theme on top of the same token layer.

### Fixed (accessibility)
- **`components/modals/ScanModal.tsx`, `components/modals/FindingDetailModal.tsx`, and the inline
  "New Scan" modal in `app/dashboard/page.tsx`**: all three were hand-rolled `fixed inset-0` overlay
  divs with no `role="dialog"`, no focus trap, no Escape-to-close, and no return-focus-on-close —
  despite `@radix-ui/react-dialog` already being a dependency and unused anywhere in the app.
  Rewired all three onto `Dialog.Root`/`Portal`/`Overlay`/`Content`/`Title`/`Description`/`Close`,
  keeping the existing framer-motion enter animation via `asChild`. Bonus side-effect: since
  `Dialog.Portal` renders into `document.body`, these modals are no longer nested under
  `dashboard/layout.tsx`'s page-transition `motion.div` — a `position: fixed` element nested under
  an ancestor with an active CSS `transform` is positioned relative to that ancestor, not the
  viewport, so modal centering could have been subtly off during a route-change animation before.
- **`components/layout/DashboardHeader.tsx`**: the org selector, notifications, and user-menu
  dropdowns were custom `useState` + manual `mousedown` outside-click-listener divs (no
  `role="menu"`, no arrow-key nav) — again despite `@radix-ui/react-dropdown-menu` being an unused
  dependency. Rewired all three onto `DropdownMenu.Root`/`Trigger`/`Portal`/`Content`/`Item`, which
  also let the manual outside-click `useEffect` be deleted entirely.
- Added `aria-label` to icon-only controls that had none: notification bell, user-menu trigger,
  sidebar collapse toggle, and every sidebar nav `Link` when the sidebar is collapsed (previously
  relying on `title` alone, which isn't reliably picked up as an accessible name by screen readers,
  and in the nav-item case wasn't even on the focusable `<a>` — it was on a non-interactive child
  div).
- **`components/layout/Providers.tsx`**: wrapped the app in framer-motion's
  `<MotionConfig reducedMotion="user">`, so every existing motion animation (page transitions,
  sidebar width, dropdown/modal enter) now respects the OS-level reduced-motion setting for free,
  instead of having none of them do so.

### Added (light theme)
- Found the theme infrastructure already half-scaffolded and disconnected: `store/workspace.ts` had
  an unused `theme: "dark" | "light"` field (persisted, but never read to toggle anything),
  `tailwind.config.ts` had `darkMode: ["class"]` configured but no component ever used a `dark:`
  variant, and `globals.css` already defined unused `--severity-*`/`--grade-*` CSS vars that nothing
  consumed (`SeverityBadge.tsx` had its own third, independent copy of the same color mapping using
  literal `red-500`/`orange-400`-style Tailwind classes instead).
- Restructured `globals.css`'s `:root` to hold light-theme values by default, moved the existing
  (unchanged, pixel-identical) dark palette under a `.dark` class block. Converted the `surface`
  (900-600; 950 stays a fixed dark value on purpose, see below), `critical`/`high`/`medium`/`low`/
  `info`, `grade-a..f`, and `brand.400` Tailwind color entries in `tailwind.config.ts` from static
  hex to `hsl(var(--x))`, so every existing call site (`bg-surface-800`, `text-critical`,
  `text-brand-400`, etc. — hundreds of them across the app) becomes theme-aware without editing the
  call sites themselves. Picked new light-mode shades by actually computing WCAG contrast ratios
  (not eyeballing) — e.g. severity/grade text uses 700-weight-equivalent shades in light mode
  (`red-700`-ish, `emerald-700`-ish, etc.) since the original 400-weight shades measured 1.5–2.8:1 on
  white, well under the 4.5:1 AA minimum for 12px badge text.
- `surface-950` (terminal/code-pane background in `.terminal`, the attack-surface graph canvas, and
  the login/register hero splash) was deliberately left un-themed / always-dark — code panes and a
  dark marketing-style auth splash are common conventions to keep dark regardless of app theme, and
  this was a scope call, not an oversight.
- Rewired `components/ui/SeverityBadge.tsx` (`SeverityBadge`, `StatusBadge`, `GradeRing`,
  `ScorePill`, `KEVBadge`, `EPSSBadge`, `ConfidenceIndicator`) onto the newly theme-aware tokens
  instead of their hardcoded literal classes — this one file is used on nearly every dashboard page,
  so it was the highest-leverage place to make theming actually show up in real content.
- Added a theme toggle (Sun/Moon button) to `DashboardHeader`, wired to a new `setTheme`/
  `toggleTheme` action in `store/workspace.ts`. `app/layout.tsx` gained a small blocking inline
  script that applies the persisted theme class before first paint (reads the same
  `localStorage["asm-workspace"]` key zustand's persist middleware writes) to avoid a flash of the
  wrong theme on reload.

### Explicitly not in scope for this pass
- Per-page one-off accent colors (e.g. a handful of `cyan-400`/`purple-400`/`rose-300` usages
  scattered across individual dashboard pages) were not hunted down and converted — only the shared
  token layer and components used everywhere were made theme-aware. Some rarely-visited pages may
  still have an isolated low-contrast color in light mode.
- The dashboard shell has no mobile/responsive layout at all (fixed-width sidebar, no drawer) —
  noted in the audit as a separate, larger finding, not addressed here.
- Verified via `tsc --noEmit`, `next lint`, and `next build` (all clean, no new warnings/errors) plus
  a dev-server smoke test (`/auth/login`, `/dashboard` both compile and return 200). Not verified:
  actual visual appearance in a browser — no screenshot/browser-automation tool was available in
  this session, so the light theme's look was reasoned about via computed contrast ratios and
  careful token tracing, not eyeballed.

---

## 2026-07-22 — Fixed silent Telegram notification failures on titles with Markdown syntax

User asked to verify the Telegram notification channel actually works end-to-end. Channel wiring itself
was already complete (`_send_telegram()` in `workers/notification/notification_worker.py`, `TELEGRAM_BOT_TOKEN`/
`TELEGRAM_CHAT_ID` already declared in `docker-compose.yml`'s `worker-notification` service, `POST
/notifications/rules` already accepts `channels: ["telegram"]` + per-rule `config` override), but tracing
the actual message-send path surfaced a real bug: `_send_telegram()` interpolates `org_name` and finding
titles/change messages directly into a `parse_mode: "Markdown"` (Telegram's strict legacy mode) payload.
Real finding titles in the DB contain unescaped syntax characters (`Drupal User Enumeration [Redirect]`) —
`[` triggers Telegram's link-parsing and, unbalanced, makes the whole `sendMessage` call fail with `can't
parse entities`. `_dispatch()`'s per-channel try/except swallows that error silently (just a log line), so
a workspace with a Telegram rule configured would have real alerts vanish exactly when a finding title
happened to contain `_ * \` [`, with zero visible indication anything went wrong — the same silent-no-op
shape as the SMTP env-var gap below.

### Fixed
- **`workers/notification/notification_worker.py`**: added `_escape_telegram_md()` (escapes `_ * \` [`
  per Telegram legacy Markdown's special-character set) and applied it to `org_name`, the change type
  label, and the change message before they're interpolated into the Telegram payload text. Hand-written
  formatting markup (the bold/italic wrapping we add ourselves) is untouched — only the dynamic/user-derived
  segments are escaped.

### Verified
- Confirmed the concrete real-data trigger first: `SELECT DISTINCT title FROM findings WHERE title ~
  '[_*\`\[\]]'` returned real unescaped titles (`Drupal User Enumeration [Redirect]`, `Drupal User
  Enumration [Ajax]`, `Apache mod_negotiation - Pseudo Directory Listing`) confirming this isn't
  theoretical.
- Confirmed network egress from the `worker-notification` container to `api.telegram.org` works (200 OK).
- Restarted `worker-notification`; came up clean, no errors.
- Dry-run message construction (real title + `org_name` containing `&`/`[`) confirmed correct escaping
  output (`\[`, `\_`) with formatting markup intact.
- **Not done**: a live send test against a real Telegram bot — `.env`'s `TELEGRAM_BOT_TOKEN`/
  `TELEGRAM_CHAT_ID` are unset and no `NotificationRule` exists yet for the real workspace; user opted to
  defer the live-send test until real bot credentials are available rather than have one fabricated.

---

## 2026-07-21 — Full repo documentation rewrite, with diagrams

The user asked for complete, well-organized, detailed documentation of the whole repo, diagrams
included. `docs/ARCHITECTURE.md` and the root `README.md` both predated this project's Bug Bounty
pipeline entirely and had accumulated real, known drift from the actual code (flagged in `CLAUDE.md`'s
own "Docs vs. reality" section) — rather than write new docs on top of that drift, every claim below was
re-verified against the current code before being written down.

### Added
- **`docs/ARCHITECTURE.md`** (rewritten) — system context diagram, container/network topology diagram
  (both Mermaid `flowchart`), the full NGINX routing/rate-limit table, two `sequenceDiagram`s (JWT
  dashboard-load flow, the transactional-outbox scan-creation flow), and why ASM/Bug Bounty are
  deliberately separate schemas/pipelines rather than one.
- **`docs/DATA_MODEL.md`** (new) — two Mermaid `erDiagram`s (ASM's 31 tables, Bug Bounty's 5) plus a
  complete field-by-field reference table for every single table in both schemas, read directly from
  `models.py`/`bounty_models.py` rather than summarized from memory.
- **`docs/PIPELINES.md`** (new) — the authoritative queue-topology table (from
  `workers/base_worker.py::EXCHANGE_MAP`), a Mermaid flowchart of the ASM scan pipeline
  (discovery→port/crawl→nuclei/scanner→correlation→risk→notify, with the `task_coordinator` fan-in gate
  shown explicitly), a Mermaid flowchart of the Bug Bounty pipeline
  (recon→probe→vulnscan→exploit→report, `NEXT_STAGE`-driven auto-chain), a third flowchart specifically
  for the two-gate exploit scope-safety model, and a table of all 12 exploit modules with their
  confirmed-vs-inconclusive discipline.
- **`docs/API_REFERENCE.md`** (new) — every endpoint on every router, extracted directly from the
  `@router.*` decorators (exhaustive, not curated), the JWT/API-key auth model, and the product-gating
  table (`RequireProduct`, wired at the router level) added earlier this week.
- **`docs/FRONTEND.md`** (new) — App Router tree, the two-dashboard-shell split (`Sidebar`/
  `DashboardHeader` `variant="asm"|"bounty"`) as a Mermaid flowchart, the Zustand store shape, and a
  tab-by-tab breakdown of the Bug Bounty program-detail page including the Recon-tab subdomain-fetch fix
  from earlier today.
- **`docs/DEVELOPMENT.md`** (new) — full Makefile/command reference, the risk-scoring formula worked
  through step by step (severity penalty → exponential decay → criticality multiplier → per-category cap
  → weighted sum → letter grade, with every constant), and the complete incident-derived gotchas list.
- **`docs/README.md`** (new) — index + suggested reading order for the above.
- **Root `README.md`** — added a Bug Bounty overview/usage section (previously absent entirely),
  corrected the threat-intel claims, fixed the "Adding Scanner/Enrichment Integrations" section to point
  at the real extension points, and rewrote "Project Structure" to reflect the actual repo (including
  that `backend/app/workers/` is a 0-byte stub package, not where workers actually live).
- **`docs/PRD.md`** (new, follow-up same day) — product vision, personas, a status table per capability
  (shipped / partial / not-started, e.g. `technical`/`compliance`/`custom` reports are currently aliases
  with no real framework-mapping, `report.daily` is dead code) for both ASM and Bug Bounty, numbered
  functional requirements, explicit non-goals, and the current roadmap/priorities pulled from the
  project's own standing priority notes (core detection maturity first, platform self-security issues and
  dependency CVEs deliberately deferred, Tenable ASM as the reference completeness bar). Extended same-day
  after the user asked for "usecase dll" (use-case diagrams etc.): two use-case diagrams (ASM, Bug Bounty
  — Mermaid has no native UML use-case notation, so actors are boxes and use cases are stadium/pill shapes
  in a system-boundary subgraph, the standard workaround) plus 4 `stateDiagram-v2` entity-lifecycle
  diagrams (Scan status, BountyProgram status, ASM Finding status, Bug Bounty `ExploitAttempt` status) —
  each verified against the actual code driving that status field, not assumed (e.g. `Scan`'s
  `ACTIVE_STATUSES`/`TERMINAL_STATUSES` read directly from `workers/scan_state.py`; confirmed
  `BountyProgram.status` transitions are UI-convention-enforced only, not database-constrained, and said
  so explicitly in the diagram's caption rather than overstating a strict state machine that isn't
  actually there).
- **`docs/TRD.md`** (new) — the non-functional requirements PRD's features must satisfy: security (the
  Bug Bounty scope-gate treated explicitly as the single highest-priority security requirement in the
  system), reliability (retry/DLQ/idempotent-upsert/graceful-shutdown requirements), performance/
  scalability (per-worker concurrency defaults, per-module exploit-run bounds, indicative scan durations),
  observability, infra, testing (including the standing `workers/` CI-lint-scope gap), and a consolidated
  technical-debt list. Deliberately references ARCHITECTURE/DATA_MODEL/PIPELINES/API_REFERENCE for
  implementation detail rather than duplicating them — states requirements, not a second copy of the
  reference docs.

### Fixed
- **Two more docs-vs-reality gaps found while verifying facts, not previously flagged anywhere**:
  `backend/app/workers/` (referenced in the old README's project-structure tree as "inline async
  workers") is an empty stub package — real workers live entirely under top-level `workers/`. And the
  risk-decay half-life: `CLAUDE.md` says "~30-day half-life", but `risk_engine.py`'s own docstring and
  the actual math (`ln(2)/0.05 ≈ 13.9 days`) both say ~14 days — the new docs use the mathematically
  verified value.
- **Five broken Markdown tables** — several table cells were authored wrapped across two physical source
  lines for my own editing readability, but GFM table rows must be a single physical line; a wrapped
  continuation line with no leading `|` silently breaks that row's rendering. Found by scripting a check
  (any `|`-initial line not also `|`-terminal) across every new/edited file rather than trusting a visual
  read-through, which is exactly the kind of thing that's easy to eyeball past. Fixed in `README.md` (3
  rows) and `docs/ARCHITECTURE.md` (2 rows).

### Verified
- Every Mermaid code fence across all 6 new/rewritten docs is balanced (`10` diagrams total: 4 in
  ARCHITECTURE, 2 in DATA_MODEL, 3 in PIPELINES, 1 in FRONTEND) and no diagram leaked a stray arrow/dot
  character outside a quoted label (both checked by script, not by eye — this environment has no Mermaid
  renderer available to actually render-check them).
- Ran the same broken-table-row check (any `|`-initial line not also `|`-terminal) against `PRD.md`/
  `TRD.md` before considering them done — clean, no repeat of the earlier mistake.
- Every fact underlying these docs was re-derived from the current code in this session (not carried
  forward from the previous `ARCHITECTURE.md` or `README.md`): `docker-compose.yml`'s full service/port
  list, `workers/base_worker.py::EXCHANGE_MAP`, every `models.py`/`bounty_models.py` column,
  `workers/bounty/bounty_stage.py::NEXT_STAGE`, every `@router.*` decorator across all 17 endpoint files,
  `infrastructure/nginx/nginx.conf`'s routing/rate-limit rules, and `risk_engine.py`'s exact weights/
  penalties/multipliers/grade boundaries.

---

## 2026-07-21 — Bug Bounty program detail page: readability redesign (+ a real grouping bug it exposed)

The user flagged the Bug Bounty program detail page as "kurang enak dibaca" (uncomfortable to read). Root
cause, confirmed by viewing the real KPI program's own data (66 targets, 450 recon assets) rather than
guessing: Targets/Recon/Findings render as one flat, endlessly-scrolling list where a domain row and a URL
row underneath it look identically weighted, with no search, filter, or grouping to navigate hundreds of
rows. Iterated on interactive HTML mockups (published as an artifact) against two design directions before
touching real code, per the user's own request to see it first.

### Added
- **Targets & Recon tabs**: URLs now nest under their parent domain (matched by exact hostname) as
  collapsible groups, instead of one undifferentiated flat list. A **Grouped / Table** toggle switches
  between that hierarchy and a dense sortable table for fast scanning — kept both instead of forcing a
  single tradeoff, since the two mockup directions shown to the user each won on a different axis
  (hierarchy clarity vs. scan speed). Added search (domain/URL substring) and filter chips (Targets:
  all/alive/no-response; Recon: all/promoted/not-promoted) to both. `groupByDomain()` is a small generic
  helper shared by both tabs, keyed off `target_type === "domain"` / `asset_type === "subdomain"`.
- **Findings tab**: search + status chips (confirmed/candidate) + severity chips (critical through info),
  previously not filterable at all despite being the tab most in need of triage.
- **Visual polish pass**: replaced ad-hoc unicode glyphs used in the mockup stage with real `lucide-react`
  icons throughout (sidebar-equivalent tab icons, priority-bucket icons keyed by bucket-name prefix --
  idor/bac/auth/upload/payment/webhook/debug/graphql -- pipeline stage icons). Smooth expand/collapse via
  CSS grid-template-rows transition (no layout jump), hover-lift on cards (`LIFT` shared class), a pulsing
  "active" status dot, `tabular-nums` on every count so columns of numbers stay aligned, and a
  `SearchX`/`Inbox`-style empty state component instead of a bare italic sentence.
- Icon system and reusable primitives (`SearchInput`, `FilterChip`, `ViewToggle`, `EmptyState`) are new,
  colocated in the same file since they're specific to this page and not yet needed elsewhere.

### Fixed
- **Recon tab's grouping had nothing to group under, on this exact program** -- found live while validating
  against KPI's real data, not caught by the design mockups (synthetic data doesn't reproduce pagination
  edge cases). `GET .../assets` sorts by `discovered_at DESC` and caps `page_size` at 200 server-side; KPI
  has 450 recon assets (122 `subdomain`, 311 `url`, plus js_endpoint/js_finding) and, because URLs are
  discovered *after* subdomains in the recon pipeline, the 200 most-recently-discovered rows were **100%
  url-type -- zero subdomains** made it into the fetched page at all, so the new grouped view silently fell
  back to one giant flat list on exactly the program this feature was built for. Fixed by fetching
  `asset_type=subdomain` in its own parallel query (subdomain counts are an order of magnitude smaller than
  URL counts in practice, comfortably under the 200 cap) and merging with the general fetch, deduped by id.
  Added a visible amber note ("Showing the N most recent of TOTAL") when the merged set is still truncated,
  rather than silently dropping older items with no indication -- the truncation itself is a pre-existing,
  accepted limit (the old flat list had the same 200-item cap with no complaint), only the *silent* part
  was new and worth surfacing honestly now that grouping depends on it.

### Verified
- Two rounds of interactive HTML mockups shown to the user before writing real code (published as a single
  evolving artifact, same URL redeployed each round) -- first a 2-option comparison (grouped-hierarchy vs.
  dense-table), then a full-page version combining both into one Grouped/Table toggle per the user's
  "lebih comprehensive" request, then a visual-polish pass (real icons, animations) per "masih kurang
  sentuhan". Implementation only started after explicit approval of the polished mockup.
- Real implementation validated against the actual `KPI` program (not synthetic data) via a JWT minted
  directly for the real user for headless-browser screenshotting: all 6 tabs render correctly, search
  ("jdih" correctly isolates that one domain's 7 URLs), Grouped/Table toggle both work, filter chip counts
  match real data (Targets: 66 all/66 alive/0 down; Recon: 322 all/199 not-promoted/123 promoted after the
  fix). No console errors attributable to this change (pre-existing/unrelated: a Google Fonts CSP warning
  and a WebSocket 403 from the synthetic auth token used for testing, neither touched by this work).
  `tsc --noEmit` clean, `eslint` clean (0 errors), backend suite unaffected (311 passed, 1 pre-existing
  skip -- this was a frontend-only change).

---

## 2026-07-20 — Split ASM and Bug Bounty into separate, workspace-entitled products

The user wanted ASM and Bug Bounty separated at the user/workspace level rather than mixed into one
sidebar -- registration now asks which product(s) a new workspace wants (ASM, Bug Bounty, or both), and
each renders as its own dashboard shell rather than a shared nav with a "Bug Bounty" item bolted on.

### Added
- **`Workspace.enabled_products`** (`backend/app/db/models/models.py`, migration `4ec377801f60`) --
  `ARRAY(String)`, e.g. `["asm"]` / `["bounty"]` / `["asm","bounty"]`. A self-serve registration always
  creates a brand-new workspace (never joins an existing one -- confirmed by reading `register()` before
  building this), so product selection is a natural one-time choice made right there, not a per-user
  setting layered on top later. Migration backfills every pre-existing workspace to `["asm"]` (server
  default, since they all predate Bug Bounty entirely) -- hand-written rather than using the autogenerated
  migration, which had picked up a large amount of unrelated pre-existing schema drift across ~30 other
  tables that had nothing to do with this change.
- **`RequireProduct`** dependency (`backend/app/api/v1/dependencies/auth.py`) -- FastAPI dependency factory
  wired at the router level (`api_router.include_router(..., dependencies=[Depends(require_asm_product)])`
  in `router.py`), not per-endpoint, so a whole product's endpoint surface is gated in one place. Reads the
  workspace's product list from a new `products` JWT claim (set at register/login/refresh via
  `create_access_token`'s existing `extra_claims` param -- no signature change needed) for the common
  bearer-token path; falls back to a fresh DB lookup for API-key auth, since a long-lived key shouldn't
  trust a claim that could go stale if the workspace's entitlement changes later. `organizations`, `assets`,
  `scans`, `findings`, `scores`, `intel`, `reports`, `screenshots`, `templates` gated on `"asm"`; `bounty`
  gated on `"bounty"`. Cross-cutting routers (`auth`, `workspaces`, `notifications`, `admin`, `keys`,
  `websocket`, `search`) stay ungated -- they serve every workspace regardless of product (e.g. a
  bounty-only workspace still configures notification channels through the same `NotificationRule` rows an
  asm workspace would).
- **`RegisterRequest.enabled_products`** -- validated non-empty subset of `{asm, bounty}`
  (`@field_validator`), defaults to `["asm"]`. `TokenResponse` and `GET /auth/me` now also return
  `enabled_products` so the frontend can route without an extra round trip.
- **Register page product picker** (`frontend/src/app/auth/register/page.tsx`) -- two selectable cards
  (ASM / Bug Bounty), at-least-one validation, ASM pre-selected by default.
- **Two fully separate dashboard shells** -- `Sidebar.tsx` now takes a `variant: "asm" | "bounty"` prop
  selecting an entirely different nav tree and branding (icon/title/accent), instead of one shared list with
  a "Bug Bounty" item mixed in (removed). `dashboard/layout.tsx` picks the variant purely from the route
  (`pathname.startsWith("/dashboard/bounty")`) and redirects to whichever product the workspace *is*
  entitled to if the current route's product isn't enabled -- a UX-side mirror of `RequireProduct`, not a
  replacement for it (the API still enforces this regardless of what the frontend shows). A "Switch to
  ASM"/"Switch to Bug Bounty" control appears only when a workspace is entitled to both.
- **`DashboardHeader.tsx`** also takes the `variant` prop -- the org selector and "Quick Scan" button are
  ASM-only concepts (`/organizations` is now product-gated) and are hidden entirely on the Bug Bounty shell
  rather than firing a request that can only 403; the `organizations` query itself is skipped
  (`enabled: !isBounty`) rather than just hiding its result.
- `workspace.ts` store: `enabledProducts` (persisted) + `hasProduct()` helper, populated from the `/auth/me`
  response `login()`/`refreshUser()` already receive -- no new API call needed.

### Verified
- Backend: registered 3 real workspaces via the actual `/auth/register` endpoint (asm-only, bounty-only,
  both) and hit `/organizations` + `/bounty/programs` with each token -- asm-only got 200/403, bounty-only
  got 403/200, both got 200/200. Confirmed the JWT's embedded `products` claim matches what was requested,
  and that invalid input (`enabled_products: []` or an unknown value) 422s with a clear message.
  `test_security.py::test_extra_claims_included` (pre-existing) already covered the `extra_claims` mechanism
  this reuses. Full backend suite: 311 passed, 1 pre-existing/unrelated skip.
- **Critical real-data check before any of this went live**: the migration's backfill would have defaulted
  the user's own real workspace (`b65ec528-...`, 2 live bounty programs -- KPI, OWASP Juice Shop) to
  `["asm"]` only, locking them out of their own bounty data the moment `RequireProduct` started enforcing.
  Caught and fixed by explicitly setting that workspace to `["asm","bounty"]` before wiring the router gate
  live; confirmed via `bounty_programs` count join that this is in fact the workspace with real program data,
  not a guess.
- Frontend: rebuilt and redeployed the production frontend container, then exercised all 3 registration
  combinations end-to-end through the real UI (Playwright, isolated browser contexts per case so sessions
  couldn't bleed into each other) -- correct landing page per combination, product switcher present only for
  "both", direct navigation to the disallowed product's route correctly redirects back, Bug Bounty shell
  renders its own rose-branded sidebar/header with zero ASM chrome (screenshotted and visually confirmed).
  `tsc --noEmit` clean throughout. All 6 test workspaces created during validation deleted by exact ID
  afterward; confirmed the real `john` workspace and pre-existing `Test Workspace` were unaffected at every
  step.

---

## 2026-07-20 — Bug Bounty pipeline: hash-routed SPA XSS coverage (search route + stored XSS)

The user asked why XSS still wasn't scoring hits on the real `owasp-juice.com` engagement despite manual
testing routinely finding several, and asked to check the target's own challenge scoreboard for what was
still unsolved. Investigation (root-caused with a real headless-browser test against the live target before
writing any code, matching this session's established discipline) found two compounding, general pipeline
gaps, not a Juice-Shop-specific quirk.

### Root cause
- **The vulnerable route was never discovered.** Juice Shop's reflected-XSS search box is a hash-routed SPA
  path (`#/search?q=...`) that renders its query param straight into the DOM client-side -- it never touches
  the network as an HTTP request (a hash fragment is never sent to the server), so `browser_crawl.py`'s
  network-request listener could never see it, and every other recon tool (katana/waybackurls/gau) only
  found the *backing* REST call (`/rest/products/search?q=`), a JSON endpoint with no relation to the actual
  client-side rendering bug. Confirmed live: navigating a real headless browser straight to
  `#/search?q=<iframe src="javascript:alert(\`xss\`)">` executes the payload for real.
- **Even if discovered, it wouldn't have been tested.** `exploit_dom.py::run_dom_xss` (and
  `exploit_tools.py::url_has_params`/`recon_ext.py::classify_url`, used to build the exploit stage's
  param-URL candidate pool) all read query params via `urlparse(url).query` alone -- which is empty for a
  hash-routed URL like this, since the "query string" lives inside `.fragment` instead. A URL shaped this
  way would have been silently invisible to every param-injection module, not just XSS.

### Added
- **`browser_crawl.py`**: `page.url()` is now captured after *every* navigation (initial load, each internal
  link click, and a new search-probe step), not just off the network-request listener -- a hash-routed SPA's
  own client-side navigation (clicking a `routerlink`, submitting a search) changes `page.url()` without ever
  firing an HTTP request the old listener-only approach could see. Added a narrow, deliberate exception to
  this module's "never fills a form" rule: typing into a search-style input and reading back the resulting
  URL, gated to a tight selector (`type=search`/name/placeholder/aria-label containing "search") -- search is
  idempotent by definition, unlike every other form on a real app. Also handles a collapsed search-icon-only
  toggle (confirmed live: Juice Shop's real `<input>` carries zero discriminating attributes at all -- generic
  `id="mat-input-1"`, no name/aria-label/placeholder -- until a `<mat-icon>search</mat-icon>` toggle is
  clicked first): falls back to clicking anything labelled "search" by icon text/aria-label/title, then to
  whatever plain input becomes newly visible, since the revealed field routinely has no attributes to match
  on at all.
- **`exploit_dom.py`**: `_params`/`_inject` now fall back to parsing/rewriting a hash-fragment-embedded query
  string (`#/path?q=x`) when the URL's real `.query` is empty, via a shared `_query_location()` helper --
  same fix class as the discovery-side one above, needed because a real browser renders both forms
  identically even though `urlparse` only ever sees one of them.
- **`exploit_worker.py`**: DOM-XSS's own candidate pool (`dom_xss_urls`) now tops up the existing
  xss-bucketed query-param URLs with any owned URL carrying a hash-fragment-embedded query string --
  deliberately *not* changed upstream in `url_has_params`/`classify_url` themselves, since those also gate
  the HTTP-only modules (dalfox/sqlmap/ssrf/...), which correctly have no use for a fragment the server would
  never see regardless.
- **`exploit_stored.py`** (new): persisted/stored XSS confirmation -- every existing XSS check only proves
  *reflected* behaviour (same request/response cycle). This fills and submits a real, visible form field
  found on the page (deliberately narrow keyword match: comment/feedback/review/bio/about/description/...,
  explicitly excluding search/password/email/login fields) with a uniquely-tokened payload (same inert
  `img`/`svg onerror`/`onload` marker-setting sink as `exploit_dom.py`), then checks for that exact token
  executing -- first on the same page (an SPA re-rendering its own submission immediately), then again after
  a fresh reload (the classic stored-XSS shape). Unlike every other check in this pipeline, this one creates
  real, visible content on the target rather than just probing and discarding a response -- gated behind an
  explicit `rules_of_engagement.stored_xss_test = true` opt-in, the same "real capability increase, not a bug
  fix" precedent set by the two-identity IDOR feature, independent of the `exploit_modules` list.

### Verified
- `browser_crawl` against the real `owasp-juice.com`: correctly discovers and persists
  `http://owasp-juice.com/#/search?q=asmsearchprobe1` as a `BountyAsset` (source `browser_crawl`) via the
  icon-toggle fallback -- confirmed the exact same generic attribute-based selector alone still matches
  nothing on this target's real search input, exactly as diagnosed.
- `exploit_dom.py::run_dom_xss` against that exact discovered URL: `dom-xss`/`confirmed`/`high`, real token
  execution (`window.__asmxss` set by an injected `<img onerror>`/`<svg onload>`).
- `exploit_stored.py::check_stored_xss` against a synthetic test server: confirmed on the vulnerable page
  (unescaped stored render), correctly empty on the safe/escaped one. Against the real target's one
  discovered storable-content page (`/#/contact`), correctly returns empty -- that form requires a CAPTCHA,
  an intentionally out-of-scope obstacle for any generic automated tool (same category as CSP bypass), not a
  bug in the check: confirmed the submit button stays disabled with only the comment field filled, so the
  module's own submit-then-check flow correctly never gets a false positive out of it.
- **Full pipeline, not just isolated function calls**: triggered a real `bounty.recon` run against the live
  `owasp-juice.com` program -- the fixed `browser_crawl` discovered and persisted the hash-route URL with no
  manual URL feeding. Triggered a real `bounty.exploit` run immediately after (with `stored_xss_test: true`
  set) -- `dom-xss`/`confirmed` on that exact URL appeared in `bounty_exploit_attempts` from the ordinary
  pipeline dispatch path, and a critical/high notification fired through the existing `notify.send` pipeline.
  No `stored-xss` row, matching the CAPTCHA-gated negative result above.
- Re-checked the target's own `/api/Challenges` scoreboard: its `reflectedXssChallenge` flag still didn't
  flip even with the exact literal payload the challenge's own hint text suggests (`<iframe
  src="javascript:alert(\`xss\`)">`) -- tested directly to rule out a payload-shape issue on our end. This
  appears to be a target-specific detection quirk in how Juice Shop's own challenge-tracking hooks work
  (likely keyed off the raw server-side `/rest/products/search` request log rather than pure DOM execution),
  not a flaw in the finding itself -- the token-execution proof is structurally the same kind of evidence
  `dom-xss` findings already rely on elsewhere in this pipeline. Backend bounty scope suite green (28 tests).

---

## 2026-07-20 — Bug Bounty pipeline: 5 new detection/response modules (+ a live NUL-byte crash it exposed)

The user asked "what else should be improved" for the bounty pipeline and approved building all five
proposed items directly: subdomain takeover, session-derived IDOR candidates, critical-finding
notifications, file-upload/XXE detection, and deeper GraphQL testing.

### Added
- **Subdomain takeover (subzy)** -- `workers/bounty/tools.py::run_subzy` ports `coverage_worker.py`'s
  existing ASM-pipeline subzy wrapper (same CLI flags, same "trust `status`, not the tool's own
  unreliable `vulnerable` boolean" quirk) into the bounty pipeline. `vulnscan_worker.py::
  _run_takeover_check` runs it against every in-scope target host and records a `high`/`confirmed`
  finding per CNAME-to-unclaimed-resource match.
- **Session-derived IDOR candidates** -- `idor_confirm.py::derive_id_candidates`/
  `derive_session_id_urls` mine the logged-in test identity's own login-response fields (e.g. Juice
  Shop's `bid`) for id/uid/bid/pid/gid/oid/aid/cid-named scalar values, then construct `{path}/{id}`
  variants for bare in-scope resource paths that don't already carry a path- or query-id. Wired into
  `exploit_worker.py` right after the ownership-scope check, capped at `MAX_SESSION_DERIVED_URLS = 20`.
  `exploit_worker.py` now calls `login_and_get_session` (token + flattened scalar fields) instead of
  `login_and_get_token` (token only) to get these fields.
- **Critical/confirmed finding notifications** -- `workers/bounty/notify.py::notify_critical_findings`
  publishes onto the existing `notify.send` queue/`NotificationWorker` (Slack/Discord/Telegram/email/
  webhook, keyed by workspace) rather than building a bounty-specific channel sender; `BountyProgram` has
  no `org_id`, which `Notification.org_id` being nullable already accommodates. Filters strictly to
  `severity in {critical, high} AND status == confirmed` -- an `inconclusive` finding, however severe if
  true, never fires a notification. Called from both `vulnscan_worker.py` and `exploit_worker.py` after
  their respective persist commits.
- **File upload / XXE detection** -- `workers/bounty/upload_xxe.py`: `check_unrestricted_upload` POSTs an
  inert file with a dangerous extension (`.php`/`.svg`/`.html`) across common field names and flags 2xx
  acceptance as `inconclusive`/`high` (whether it's actually web-accessible needs human confirmation);
  `check_xxe` POSTs a classic external-entity payload targeting `/etc/passwd` and reuses `exploit_tools.py`
  's own `LFI_SIGNATURES` set for confirmation, `confirmed`/`critical` on a match. New `"upload"` module
  added to `exploit_worker.py`'s `ALL_MODULES`/`DEFAULT_MODULES`, dispatched against URLs matching the
  existing `upload` priority bucket.
- **Deeper GraphQL testing** -- `detect.py::graphql_schema_scan` runs a `__schema` introspection query and
  flags type/field names matching a sensitive-name pattern (password/secret/token/apiKey/admin/...),
  `inconclusive`/`medium` (introspection proves the field is *named* sensitively and reachable via schema,
  not that it's actually readable). `detect.py::check_graphql_batching` POSTs a 5-element query-array batch
  and flags acceptance as `inconclusive`/`low` (batch-based rate-limit bypass risk). Both dispatched from
  `vulnscan_worker.py::_run_detection` against endpoint URLs matching the existing `graphql` priority
  bucket (`PRIORITY_BUCKETS["graphql"]`, aliased there as `GRAPHQL_URL_RE`).

### Fixed
- **`_detect_attempt()` (`vulnscan_worker.py`) was hardcoding `"status": "confirmed"`** regardless of what
  the underlying finding dict actually said -- found while wiring the new GraphQL checks, which explicitly
  return `status: "inconclusive"`. Every check that predates this session's GraphQL work happened to only
  ever return a result when genuinely confirmed, so the bug was latent/harmless until now. Fixed to
  `finding.get("status", "confirmed")`.
- **NUL bytes in evidence crashed the JSONB insert, silently looping a real scan to failure** -- found live
  against the actual `kpi.go.id` production program (not a test one): a `.DS_Store` sensitive-file finding's
  raw-byte excerpt (decoded with `errors="ignore"`, which passes a NUL byte through unchanged since it's a valid, just
  unstorable, Unicode code point) hit Postgres's `UntranslatableCharacterError` on every insert attempt,
  requeuing at `retry=3` -- one message away from exhausting `MAX_RETRIES` and dead-lettering the whole
  `bounty.vulnscan` stage as failed for a real, live engagement. Fixed with a `@validates("evidence")` hook
  on `ExploitAttempt` (`backend/app/db/models/bounty_models.py`) that recursively strips NUL bytes at the
  ORM boundary -- covers every current and future evidence producer (nuclei, sensitive-file, XXE/upload,
  GraphQL) in one place, rather than patching each detection module's own excerpt-building code.

### Verified
- `check_unrestricted_upload`/`check_xxe` against a synthetic Python test server covering vulnerable and
  safe cases for both checks -- all 4 scenarios correct.
- `graphql_schema_scan`/`check_graphql_batching` against a synthetic GraphQL-shaped test server (sensitive
  vs. clean schema, batch-accepted vs. batch-rejected) -- all 4 scenarios correct.
- The NUL-byte fix: constructed an `ExploitAttempt` directly inside the running `worker-bounty-vulnscan`
  container with embedded `\x00` bytes in nested evidence -- confirmed stripped. Then let the *actual stuck
  message* against the live `kpi.go.id` program run to completion rather than clearing/replaying it
  synthetically: `bounty_vulnscan_completed` (868s elapsed, nuclei=3, detection=1, takeover=0, no crash),
  and the previously-failing `.DS_Store` row now persisted (`bounty_exploit_attempts`, confirmed, excerpt
  reduced from ~1800 raw bytes to a clean 23-char sanitized string).
- No GraphQL finding fired against `kpi.go.id` in that same run -- expected, not a bug: its recon assets
  contain no GraphQL-shaped endpoint URL, so `GRAPHQL_URL_RE` never matched, mirroring the upload/XXE
  module's earlier negative-but-valid result against Juice Shop.
- Backend bounty scope suite green (28 tests, `test_bounty_scope.py`).

---

## 2026-07-20 — Bug Bounty pipeline: bulk-promote recon assets (checkboxes + multi-select)

The user had just manually promoted 202 recon assets one at a time (scripted around nginx's per-client rate
limit, `zone=api rate=200r/m burst=50`, since that many sequential individual API calls trips it) and asked
for a checkbox-based multi-select in the Recon tab instead.

### Added
- **`POST /programs/{id}/assets/promote-bulk`** (`backend/app/api/v1/endpoints/bounty.py`) -- same rule as
  the existing single-asset `promote` endpoint (asset-type check, scope check, dedup against existing
  targets), applied to up to 500 assets in one request/transaction. Per-asset outcome reported as
  `{promoted: [...], skipped: [{asset_id, value, reason}]}` with reasons (`out_of_scope`,
  `not_a_target_shape:*`, `already_promoted`, `target_already_exists`, `not_found`) rather than failing the
  whole batch on the first rejection. This is the actual fix for the rate-limit problem, not just a frontend
  convenience -- one request instead of N sequential ones.
- Recon tab (`frontend/.../bounty/[id]/page.tsx`): a checkbox per promotable (unpromoted, subdomain/url/ip)
  asset row, a header "Select all (N)" checkbox, and a "Promote Selected (N)" button that calls the new bulk
  endpoint, invalidates the assets/targets queries, and toasts a promoted/skipped summary. Non-promotable
  rows (js_endpoint/js_finding/graphql/already-promoted) render no checkbox, consistent with the existing
  single-item "Promote" button's own visibility rule.

### Verified
- Backend: bulk call against 5 known out-of-scope assets (external credit links from the earlier browser-
  crawl entry) -> all correctly skipped with `reason: out_of_scope`, 0 promoted. Bulk call against a
  synthetic in-scope subdomain asset -> promoted successfully, target created. Both cleaned up by specific
  tracked ID afterward (never a bulk/filtered delete) -- the real `KPI` program was confirmed untouched
  throughout.
- Frontend: rebuilt and redeployed the (production-mode, no hot-reload) frontend container, then exercised
  the actual UI end-to-end via headless Chrome against 3 synthetic unpromoted assets -- "Select all"
  selected them (+ the real remaining out-of-scope ones), "Promote Selected" fired one bulk request, and the
  toast/list updated to reflect the promoted/skipped split. `tsc --noEmit` clean. Backend bounty scope suite
  green (28 tests).

---

## 2026-07-20 — Bug Bounty pipeline: step-by-step PoC in the HTML report (+ a real "stale finding" bug it exposed)

The user asked for step-by-step proof-of-concept instructions in the shareable HTML report. That logic
already existed (`workers/bounty/report_templates.py::build_report`, used for the per-finding Markdown
`BountyReport` drafts in the Reports tab) but the polished HTML report (`app/services/bounty_report.py::
render_html`, the Summary tab's "Open HTML Report") never used it -- and wiring it in surfaced a real,
separate bug worth fixing before shipping the feature at all.

### Added
- Moved the report-templating logic to `backend/app/services/bounty_report_templates.py` (was `workers/
  bounty/report_templates.py`) -- both the worker-side Markdown drafts and the backend-side HTML report
  need it, and workers already import backend directly (the reverse direction doesn't exist in this
  codebase), so shared logic belongs in `app.services`. `report_worker.py` updated to the new import; old
  file removed (only the one importer, no back-compat shim needed).
- Significantly richer `_build_steps()`: previously handled only `poc_url` / `payload+param` / `matched_at`
  shapes generically. Added dedicated, accurate step-by-step branches for every technique introduced this
  session that has its own distinct evidence shape: `sqli-auth-bypass` (baseline-vs-payload login request
  pair), `idor-cross-identity-confirmed` (identity A vs identity B request pair), `bac-unauth-privileged`
  (unauthenticated request), `method-switch-*` (GET baseline vs the alternate method). Added a generic
  fallback that surfaces *every* evidence field the pipeline actually recorded when no specific branch
  matches, so a finding's steps are never thinner than the real evidence available. Added `MODULE_META`/
  `TECHNIQUE_META` entries for `ssti`/`nosql`/`jsonbody`/`oauth`/`bac` and their sub-techniques (prototype-
  pollution, mass-assignment, nosql-body) -- these previously fell through to a generic "nuclei" label with
  the wrong impact/remediation text entirely.
- `render_html` now renders a "Proof of Concept" section: one expandable `<details>` per top finding (title,
  steps-to-reproduce with real request/response snippets, impact, remediation) below the existing summary
  table, native-HTML-only (no JS) so it works in the self-contained report with no dependencies.
- `exploit_dom.py`'s DOM-XSS finding now records the actual `payload`/`poc_url` used (it previously recorded
  neither, since the per-attempt token is randomised for false-positive-proofing -- the token itself isn't
  sensitive, so including it doesn't weaken that guarantee, and the report needs *something* concrete to show).

### Fixed
- **The report/summary aggregated every ExploitAttempt row ever persisted for a program, forever** --
  found immediately while visually checking the new PoC section: it prominently showed, as "confirmed"
  findings with generated PoC steps, several bugs already found, explained, and fixed earlier in this same
  session (the dalfox-empty-dict XSS false positive, the SSTI no-baseline false positive, the CORS wildcard
  false positive, the weak-signature `.env`/`.htpasswd` false positive) -- because those buggy runs' rows
  never got deleted, they just kept accumulating alongside every subsequent clean run, and "confirmed" +
  high severity sorted them straight to the top of the report. Fixed at the source rather than by deleting
  rows: `_gather_urls_findings` (`backend/app/api/v1/endpoints/bounty.py`) now scopes findings to the latest
  *completed* run of whichever stage produced them (vulnscan for nuclei/exposure/cors/403bypass, exploit for
  everything else), using `program.stage_status.{stage}.started_at`. A program with incomplete/missing
  stage_status falls back to "include everything" rather than risk hiding real findings. This is a general
  fix, not specific to the PoC feature -- the existing Summary tab (`GET /programs/{id}/summary`) had the
  exact same bug and is fixed by the same change.
- **The same historical-accumulation problem also produced literal duplicate rows** for findings that
  *are* still real and still reproduce on every run (e.g. the SQLi login bypass showed up 3+ times in the
  unscoped findings list, once per re-run). Added `_dedup_findings()` (module+technique+target key) used by
  both `classify_program`'s `top_findings` and `render_html`'s PoC section -- the raw counts
  (`severity_counts`/`module_counts`/`totals`) still reflect every run, only the *display* lists dedupe.

### Verified
- Rendered the report before and after the stage-cutoff fix: 332 accumulated findings (7 high, including
  the stale false positives) collapsed to 30 findings scoped to the latest run (0 high, 1 critical -- the
  real SQLi bypass) once the fix landed; `GET /programs/{id}/summary` confirmed the same before/after via
  its module_counts (`xss`/`ssti`/`cors`/`exposure` present before, entirely gone after -- exactly the
  techniques with known, already-fixed false-positive bugs). Screenshotted the rendered HTML report
  (headless Chrome, both before and after) to confirm the PoC `<details>` sections expand/collapse correctly
  and render real request/response content, not just the fix's effect on the finding count. Backend bounty
  scope suite green (28 tests); `report_worker.py` (the separate Markdown-draft path) re-run end-to-end
  against the new import location with no errors.

---

## 2026-07-20 — Bug Bounty pipeline: browser-driven recon (real SPA execution, not just static parsing)

Closes the gap called out in every entry above since the auth-crawl work: katana/hakrawler/ffuf/feroxbuster/
waybackurls/gau/waymore all parse static HTML/JS text or brute-force paths -- none of them execute
JavaScript, so a modern SPA's real routes and API calls (constructed entirely client-side, often only once
logged in) were invisible to recon no matter how well the rest of the pipeline worked.

### Added
- **`workers/bounty/browser_crawl.py::browser_crawl`** -- loads a seed URL in real headless Chromium
  (Playwright), passively captures every network request the page fires during normal rendering (its own
  XHR/fetch calls included), then clicks through a bounded set (`MAX_INTERNAL_CLICKS = 8`) of pure-
  navigation elements (`a[href]` or anything carrying Angular's `routerLink`, on *any* tag -- Juice Shop's
  basket/account icons are `<button routerlink="...">`, not real links) to trigger more page transitions.
  Deliberately never clicks a plain button with no navigation target (that's exactly where "Add to
  Basket"-style state-changing actions live) and never fills or submits a form -- detection-only, same
  discipline as every other module in this pipeline. Dismisses cookie-consent/welcome-banner overlays first
  (near-universal on real sites, and Angular Material's modal backdrop blocks every subsequent click
  otherwise) via Escape + a generic close/dismiss/accept button selector.
- **Auth-state simulation, not just the header**: carrying `Authorization: Bearer <token>` at the network
  level does *not* make an SPA render its logged-in UI or fire logged-in-only calls (basket, order-history,
  whoami) -- the app's own client-side JS decides that from its own state, almost always read back out of
  `localStorage`. Added `tools.py::login_and_get_session` (alongside the existing `login_and_get_token`,
  now a thin wrapper over it) returning every scalar field found anywhere in the login response, not just
  the token -- e.g. Juice Shop's response also carries a `bid` (basket id) field its own Angular code reads
  separately from the token. `browser_crawl` seeds all of these under their own field names, plus the token
  under every common storage-key convention (`token`, `authToken`, `jwt`, ...), before the first navigation.
- Wired into `recon_worker.py` as a new bounded source (`MAX_BROWSER_CRAWL_HOSTS = 2` -- by far the most
  expensive source in that file) alongside the existing ones; discovered URLs get the same gf-classification
  and persistence path as everything else.

### Fixed (found while validating this feature, same class as the earlier tini fix)
- Confirmed the existing `tini` PID-1 fix (added for `worker-bounty-exploit`'s DOM-XSS module) also needed
  applying to `worker-bounty-recon` now that it drives Chromium too -- rebuilt and redeployed that image;
  verified 0 zombie processes in both containers after a full pipeline run.

### Verified
- Against the Juice Shop program: unauthenticated crawl alone surfaced `/rest/products/search?q=` -- the
  real backing endpoint for the classic search-box challenge -- which no other source (katana, hakrawler,
  ffuf, feroxbuster, historical archives) had ever found, because the app only constructs that request from
  JS when the search box actually receives input. With auth-state seeding, the app rendered its logged-in
  UI (`Logout` present) and additionally fired `/rest/user/whoami`; click-through successfully navigated
  into the basket view, confirming the `/rest/basket/{id}` endpoint pattern exists (though the specific ID
  resolved to `NaN` in this app's own client-side basket-id logic beyond what the generic field-mirroring
  heuristic could replicate -- a documented, honest limit, not silently hidden). Full pipeline re-run: recon
  found 71 assets (`browser_crawl` contributing 27, `authenticated: true`), exploit tested 152 URLs (up
  from 125), 0 zombie processes in either container. Backend bounty scope suite green (28 tests), all 5
  bounty workers healthy.
- Not chased further (would mean hand-tuning payloads to this one app's specific challenge design rather
  than building generally useful detection): the search endpoint's specific DOM XSS trigger didn't fire with
  the existing `<img onerror>`/`<svg onload>` payload set this run -- Juice Shop's actual known vector for
  this challenge is more specific than what a general-purpose two-payload probe covers.

---

## 2026-07-19 — Bug Bounty pipeline: two-identity IDOR/BAC confirmation (found a real critical bug)

The last item from the post-auth improvement list. Every existing IDOR check (`exploit_tools.py::
idor_candidates`, `exploit_ext.py::idor_bac_probe`) deliberately stops at "candidate" -- proving IDOR needs
a *second* identity with no legitimate claim on a resource to compare against, which the pipeline never
held. Unlike every other feature this session, this one is a genuine capability increase (the pipeline now
creates and holds a second account, and compares cross-account access), not a bug fix -- confirmed with the
user via AskUserQuestion before building anything, per the standing rule that active-exploitation
capability increases need an explicit conversation, not an assumed "go ahead."

Two things were confirmed before implementation: (1) the second identity is **auto-registered** by the
pipeline itself via the program's own public registration endpoint (same opt-in-template pattern as
`auth_login_url`), and (2) confirmation is **status/shape-only** -- the pipeline never parses, extracts, or
stores the actual resource content, even for a confirmed hit.

### Added
- **`workers/bounty/idor_confirm.py`**:
  - `generate_test_identity(reference_email)` -- a disposable `asm-bounty-2-<random>@<same-domain>` email +
    random password, never overlapping with the primary test identity.
  - `register_test_identity(registration_url, fields_template, email, password)` -- POSTs a program-
    configured registration payload shape (`{email}`/`{password}` placeholders substituted recursively
    through arbitrary JSON nesting, since real registration schemas vary -- Juice Shop needs a nested
    `securityQuestion`/`securityAnswer`, most apps don't). New opt-in `rules_of_engagement` fields:
    `idor_registration_url`, `idor_registration_fields`. Both must be set, on top of the existing
    `auth_login_url`/`auth_email`/`auth_password` -- absent by default, no behavior change for any program
    that doesn't configure this.
  - `confirm_idor_cross_identity(url, token_a, token_b)` -- fetches the same path-shaped object-reference
    URL (`/resource/{id}`, the same pattern `idor_candidates` already flags) as both identities. Identity B
    was *just* created and owns nothing yet, so it has no legitimate claim on any pre-existing resource --
    if it still gets a full, resource-shaped response, that's a missing ownership check, confirmed
    (`severity: critical`). The shape check (`_looks_like_resource`) is deliberately coarse (200 status,
    non-trivial JSON body) and explicitly rejects a `"data":null`/`{}`/`[]` wrapper envelope (an empty-but-
    200 resource, which passed a naive length check during testing but proves nothing) -- there is no
    field-extraction code path in this module at all, by construction.
- Wired into `exploit_worker.py`'s existing `idor` module: after identity A's auth, if
  `idor_registration_url`/`idor_registration_fields` are set, registers + logs in identity B, then runs the
  cross-identity check against `PATH_ID_RE`-matched candidates from `owned` (bounded separately,
  `MAX_TWO_IDENTITY_IDOR_URLS = 10`, since it's 2 requests per URL on top of everything else). Stage summary
  now reports `two_identity_idor: bool`.

### Verified
- End-to-end against the Juice Shop program: registered a second test identity via its real `/api/Users`
  endpoint, logged in as both, and **found a genuine, confirmed critical vulnerability** -- `GET /rest/
  basket/1` and `/rest/basket/2` (real baskets belonging to other users) are both readable by a completely
  unrelated, seconds-old test account. `/rest/basket/49` (an existing-but-empty basket) correctly produced
  no finding after the `"data":null` refinement, confirming the shape check isn't just "any 200." Ran
  through the real pipeline (not just a standalone script): `bounty_exploit_idor_identity_b registered=true
  authenticated=true`, stage summary `two_identity_idor: true`.
- Zero findings from the *pipeline* run itself (as opposed to the direct validation above): recon hasn't
  discovered any real path-ID-shaped URL for this program yet (`/rest/basket/{id}` is a per-user resource
  Juice Shop only creates at runtime -- the same "crawler doesn't execute the SPA" gap already documented in
  the auth-crawl entry above, not a new one). The mechanism is proven correct against real data; whether it
  fires during an ordinary run depends on recon eventually discovering a concrete numbered/UUID resource
  URL to test, which needs the same headless-crawl improvement already on the list. Backend bounty scope
  suite green (28 tests), all 5 bounty workers healthy.

---

## 2026-07-19 — Bug Bounty pipeline: DOM-based XSS confirmation (real headless browser) + a container-wide zombie-process fix

Closes the second item from the post-auth improvement list: dalfox (`run_dalfox`) only ever sees server-
response reflection, so it's structurally blind to a client-rendered app (Angular/React/Vue) that takes a
param and unsafely binds it into the DOM (`[innerHTML]`, `document.write`, `v-html`, ...) -- exactly the
shape of most modern SPA "XSS challenges."

### Added
- **`workers/bounty/exploit_dom.py::run_dom_xss`** -- for each query param on a candidate URL, injects a
  payload (`<img src=x onerror=...>`, `<svg onload=...>`) carrying a fresh random token, loads the page in
  a real headless browser, and confirms only if that exact token executes as JavaScript. No baseline/
  diffing needed like SSTI's digit-matching -- a browser actually executing a token only *we* could have
  injected has no other explanation. Wired into the existing `xss` module (alongside dalfox), bounded
  separately (`MAX_DOM_XSS_URLS = 8`) since a browser load is far more expensive per-URL than a plain
  request. Uses the exploit-stage auth session (`extra_headers`) via Playwright's `extra_http_headers`.
  Built on **Playwright** (already a dependency in this image for the screenshot feature) rather than
  hand-rolling Chrome DevTools Protocol over a raw WebSocket -- see the fix below for why that mattered.

### Fixed
- **Headless Chromium was leaking permanent zombie processes, container-wide** -- found while validating
  `run_dom_xss` itself (a synthetic true-positive/true-negative test left over a hundred `<defunct>`
  processes after a handful of runs). Root cause: this image's containers run `python -m workers....`
  directly as PID 1, which is not an init and never reaps orphaned processes. Killing a Chromium process
  after each browser-driven check reparents its renderer/GPU/crashpad children to PID 1, where they sit as
  zombies forever (they don't consume CPU, but they permanently hold a process-table slot -- over the
  lifetime of a long-running worker container this is a real, if slow, resource leak, not cosmetic).
  A first attempt at fixing this via raw CDP with `--single-process --no-zygote` chromium flags avoided
  forking child processes but broke the `/json/new` (new-tab) DevTools endpoint outright in this chromium
  build. Rewrote `run_dom_xss` on Playwright instead (its driver manages Chromium's process tree and
  reaps it properly on `browser.close()`) -- cut the leak from ~15-20 zombies/URL down to ~2/browser
  session, but still not zero. The actual fix: added `tini` to `workers/Dockerfile` and set
  `ENTRYPOINT ["tini", "--"]` -- a real init as PID 1 reaps any reparented orphan regardless of which tool
  spawned it. Verified: 3 consecutive full `run_dom_xss` browser lifecycles produced 0 zombies post-fix
  (was still accumulating them with the Playwright-only fix). Benefits any worker using Chromium/Playwright
  once rebuilt, not just this module -- currently rebuilt and deployed for `worker-bounty-exploit` only
  (the one running this new code); other worker images should pick up the same protection on their next
  routine rebuild.

### Verified
- Synthetic test fixture: a genuinely DOM-XSS-vulnerable page (`el.innerHTML = 'results for: ' + query`
  read client-side from `location.search`) → confirmed hit. A safe page (`el.textContent = ...`, same
  shape) → no finding, 3/3 consecutive runs. Full pipeline re-run on the Juice Shop program: 0 zombie
  processes after the run (was accumulating before the tini fix), 0 false DOM-XSS findings on the
  currently-discovered URL set (correctly -- none of Juice Shop's currently-crawled REST endpoints have a
  working DOM XSS sink; the classic search-box DOM XSS challenge lives behind an Angular hash route
  (`#/search?q=`) that a server-side crawl never sees in the first place, a pre-existing, already-documented
  gap, not something this module could fix on its own). Backend bounty scope suite green (28 tests), all 5
  bounty workers healthy.

---

## 2026-07-19 — Bug Bounty pipeline: authenticated crawl + smarter target selection

Follow-up to the previous entry: exploit already had single-identity auth, but recon's own crawl
(katana/hakrawler/ffuf/feroxbuster/API-discovery) and vulnscan (nuclei + detection checks) still ran fully
unauthenticated, so the pipeline still couldn't *discover* most of a real app's authenticated-only surface,
only test the handful of authenticated URLs a human happened to promote manually.

### Added
- **Authenticated recon + vulnscan**, same opt-in `rules_of_engagement.auth_login_url`/`auth_email`/
  `auth_password` used by exploit: `recon_worker.py` and `vulnscan_worker.py` each log in once at the start
  of their own run (workers are separate processes/queue messages, so the token isn't shared across stages
  -- each stage re-authenticates, a few extra cheap login requests per pipeline run) and thread the
  resulting `Authorization: Bearer` header through every tool that supports custom headers: katana/ffuf/
  feroxbuster/hakrawler/httpx (`-H`/`-h` flags), nuclei (`-H`, already redacting `authorization` from its
  own output), and the aiohttp-based sensitive-file/CORS/API-spec/GraphQL checks.
  - Moved `login_and_get_token`/token-extraction from `exploit_ext.py` to the shared `tools.py` so every
    stage can import it without a cross-module dependency on the exploit-specific file.
  - **Deliberately excluded**: `check_403_bypass` (vulnscan) and `idor_bac_probe`'s unauthenticated-access
    check (exploit) -- both specifically measure what an anonymous caller can reach, and authenticating
    them would silently stop measuring that instead of improving it. Probe stage (basic httpx liveness)
    also left unauthenticated -- low value for its purpose, not worth the added surface.
- **Priority-ordered candidate URLs + raised MAX_URLS** (`exploit_worker.py`): reused the same regex buckets
  `bounty_report.py`'s classifier already uses (now exported as `PRIORITY_BUCKETS`) to sort candidate URLs
  so auth/admin/payment/IDOR-shaped endpoints survive truncation instead of being crowded out by bulk CSS/
  JS/asset URLs. Raised `MAX_URLS` 80 -> 200 now that a fixed recon actually finds 100+ real endpoints per
  program; `MAX_URLS_PER_MODULE` (15) remains the real per-module cost throttle, so this mainly widens the
  pool each module's bucket is drawn from, not the runtime.

### Verified
- Full pipeline re-run on the Juice Shop program with the test account from the previous entry: recon and
  vulnscan both logged `authenticated=true`, exploit's `tested_urls` went from 80 to 125 (more candidates
  survive the wider MAX_URLS + priority sort). New findings that only became reachable once authenticated:
  `bac-unauth-privileged` on `/rest/admin/application-configuration` (medium), `mass-assignment` on
  `/api/Users` (medium), plus previously-401 endpoints (`/rest/user/whoami`, `/rest/admin`,
  `/rest/user/reset-password`, `/rest/user/authentication-details`) now crawled and tested at all. The
  `sqli-auth-bypass` critical finding on `/rest/user/login` persists across every re-run, as expected.
  Backend bounty scope suite green (28 tests), all 5 bounty workers healthy.
- Still open: recon's crawl, even authenticated, is static/JS-based and doesn't execute the SPA, so it still
  can't discover the concrete numeric-ID basket/order URLs Juice Shop only creates via runtime interaction
  (add-to-basket, place-order) -- the path-based IDOR detection added in the previous entry is correct but
  still has nothing real to match on this target. That would need a headless-browser-driven crawl, a bigger
  step than header-threading.

---

## 2026-07-19 — Bug Bounty pipeline: closed the auth-wall gap (JSON-body SQLi, path IDOR, single-session auth)

The user pushed back on the "0 findings" result below: they manually test Juice Shop regularly and know
it's full of confirmable bugs (XSS, SQLi, BAC), so a clean run was itself suspicious, not reassuring. That
was the right call — three structural gaps, not tuning, explained it:

### Fixed
- **SQLi/XSS modules only ever look at GET query strings** (`url_has_params`) — Juice Shop's textbook
  `' OR 1=1--` admin login bypass is a POST JSON body with no query string at all
  (`/rest/user/login`, `{"email": "...", "password": "..."}`), so sqlmap/dalfox never attempted it, no
  matter how well recon crawled. Manually confirmed the bypass works against this instance (logs in as
  `admin@juice-sh.op`) before writing the fix. Added `run_login_sqli_bypass()`
  (`workers/bounty/exploit_ext.py`): POSTs classic auth-bypass payloads into a login-shaped JSON body,
  diffed against a baseline garbage-credential POST on the same field names — a hit requires the baseline
  to fail and the payload to succeed (a hard, structural signal). Wired into the `sqli` module against any
  owned URL whose path looks like a login endpoint. **Now fires as a "critical", "confirmed"
  `sqli-auth-bypass` finding on `/rest/user/login`** — the exact bug the user expected to see.
- **IDOR module only matched object references in query param *names*** (`IDOR_PARAM_HINTS`) — modern REST
  APIs (Juice Shop included) put the reference in the *path* (`/rest/basket/6`, `/api/BasketItems/12`), which
  never touched that regex at all. Added `PATH_ID_RE` to `idor_candidates()`
  (`workers/bounty/exploit_tools.py`): matches a resource-name-looking path segment immediately followed by
  a numeric or UUID segment, flagged the same conservative way (`inconclusive`, first-match-only, no
  enumeration). Verified directly: `/rest/basket/6` and `/api/BasketItems/12` now flag, `/rest/products/search`
  correctly doesn't.
- **The entire pipeline was, and by default still is, 100% unauthenticated** — confirmed by grepping for
  any auth/cookie/session concept anywhere in `workers/bounty/*.py` (none existed) and by hitting a
  known-protected endpoint (`/rest/basket/1` → `401 UnauthorizedError`). Most of a real target's interesting
  surface (profile, basket, orders, admin-after-creds) sits behind a login wall the pipeline could never
  see past — this is why manual testing (which logs in first) finds far more than an unauthenticated
  automated pass ever could, independent of any bug. Added **optional single-identity authenticated
  testing**, off by default:
  - `login_and_get_token()` (`exploit_ext.py`) — POSTs program-supplied test credentials to a
    program-supplied login URL, pulls a bearer token out of common JSON response shapes
    (`authentication.token`, `token`, `data.token`, `jwt`, `access_token`).
  - New optional `rules_of_engagement` fields: `auth_login_url`, `auth_email`/`auth_password`,
    `auth_email_field`/`auth_password_field` (default `email`/`password`). Nothing changes for a program
    that doesn't set these.
  - `exploit_worker.py` logs in once per run (if configured) and threads the resulting
    `Authorization: Bearer` header through every module that makes its own HTTP request (dalfox `-H`,
    sqlmap `--headers`, arjun `--headers`, and every aiohttp-based check). **Deliberately excluded**:
    `idor_bac_probe`'s unauthenticated-access check (adding auth would silently change what that specific
    probe measures) and `idor_candidates`/BAC confirmation in general (still requires a *second* identity to
    compare against, which this does not add — that boundary is unchanged).
  - This is a single-identity enhancement only, not multi-identity IDOR confirmation. Both were confirmed
    with the user via AskUserQuestion before building (auth testing is a real capability increase, not a bug
    fix, so it got the same check-in as the earlier full-automation/aggressive-modules decisions).

### Verified
- Registered a real test account on the Juice Shop instance (`asm-bounty-test@example.com`) via its own
  `/api/Users` endpoint, set it as the program's `auth_login_url`/`auth_email`/`auth_password`, re-ran the
  exploit stage: `bounty_exploit_auth authenticated=true` logged, `/api/BasketItems` (401 unauthenticated)
  became reachable for jsonbody testing, and the SQLi login-bypass fires as a critical confirmed finding
  every run. `idor_candidates` path-ID matching verified directly against constructed URLs.
- Known remaining gaps, left for a future increment rather than silently claimed as solved: recon's own
  crawl (katana/hakrawler/ffuf) still runs unauthenticated, so it can't discover the concrete numeric-ID
  basket/order URLs Juice Shop only fills in per logged-in session — path-based IDOR detection is proven
  correct but has nothing real to match yet on this target. Classic Angular DOM-based XSS (e.g. the search
  box) isn't caught by dalfox's server-response-reflection approach; that needs a headless-browser-based
  checker, a different tool category. IDOR/BAC confirmation (vs. candidate-flagging) still deliberately
  requires two identities the pipeline does not hold.

---

## 2026-07-19 — Bug Bounty pipeline: exploitation modules were silently starved of targets (3 more bugs)

Follow-up to the E2E validation below, triggered by the user noticing XSS/SQLi/etc. produced no findings
and asking why. The honest answer was worse than "tuned conservatively" — three real bugs, found by
tracing the question instead of taking the "no findings" result at face value:

### Fixed
- **Katana crawler has been silently broken since it was built** (`workers/bounty/tools.py::run_katana`) —
  the command line passed `-retries 1`; this katana build (v1.6.1) only recognizes `-retry`. An unrecognized
  flag makes katana exit immediately with a CLI-parse error and no output file, and `run_katana` never
  checked the exit code, so this has silently returned `{"urls": {}, "js_files": {}}` on *every* recon run
  since Phase 1, for every program, not just Juice Shop. This is the actual root cause of the XSS/SQLi/SSRF/
  LFI/SSTI modules finding nothing: those modules only test query-parameterized URLs, and katana (the one
  crawler that discovers real in-app links/API calls) had never contributed a single URL — every previously
  "collected" URL came from ffuf/feroxbuster (path brute-forcing, never produces query params) or hakrawler
  (a handful of static JS file links). Fixed the flag; also added exit-code logging so a CLI-parse failure
  like this surfaces as a warning instead of silently reading as "found nothing." Impact on Juice Shop:
  recon assets went from ~22 (all path-guessed, zero params) to 182, including the app's real REST surface
  (`/rest/user/change-password?current=`, `/rest/user/security-question?email=`, `/redirect?to=`,
  `/api/BasketItems`, `/rest/admin`, `/rest/track-order`, dozens more) — the actual attack surface XSS/SQLi/
  SSRF/LFI need query parameters to test against.
- **Dalfox "no vulnerabilities" sentinel was read as a confirmed XSS finding**
  (`workers/bounty/exploit_tools.py::run_dalfox`) — this dalfox build's JSON output for "nothing found" is
  literally `[{}]`, an array containing one empty object, not `[]`. The parser only checked
  `isinstance(poc, dict)` before building a finding from it — an empty dict passes that check trivially, so
  *every* dalfox run that found nothing was recorded as a "confirmed" "high" XSS finding with every evidence
  field `null`/empty (severity defaults to "high" when dalfox doesn't supply one, compounding it). Caught
  because the evidence looked wrong (no param, no PoC URL, no message) on inspection. Fixed by skipping empty
  dicts and requiring at least a `type` or `data`/`poc` field before treating a poc entry as a real finding.
- **SSTI check had no baseline and missed escaped reflection**
  (`workers/bounty/exploit_ext.py::run_ssti`) — flagged `/redirect?to=<%=7*7%>` as confirmed SSTI because
  the digits "49" appeared in the response and the literal payload string didn't. In reality the endpoint
  returned a generic "Unrecognized target URL for redirect" error page that (a) reflects the input
  HTML-escaped (`&lt;%=7*7%&gt;`, so the raw-payload check never fires) and (b) already contains "49"
  somewhere in its boilerplate even for a completely inert param value — confirmed by directly diffing the
  response against a harmless baseline value in the same param. Fixed by adding that baseline check (skip if
  the expected digits appear regardless of payload) and checking for HTML-escaped payload reflection, not
  just the raw string.
- Minor cleanup: katana's `-jc` (in-JS-string link extraction) occasionally pulled a stray literal or
  percent-encoded backslash/quote out of an embedded JSON blob on Juice Shop's credits page (e.g.
  `/api/%5C%22/ftp/legal.md%5C%22`), producing a handful of junk test URLs. Stripped `\`, `%5C`, `%22` from
  each discovered line — never legitimate URL characters in this position.

### Verified
- Re-ran the full pipeline after each fix. Final run: recon assets 182 (up from 0 collected pre-fix),
  exploit tested 80 URLs (up from 18, capped by `MAX_URLS`) across all 11 modules, 0 false "confirmed"
  XSS/SSTI (both gone after the dalfox/SSTI fixes, correctly — this Juice Shop instance's sampled 80 URLs
  don't have a working reflected-XSS or SSTI PoC). Remaining findings are honestly calibrated: nuclei
  info/medium (missing headers, exposed `/metrics`, `/api-docs/swagger.yaml`) plus NoSQL-body and HTTP
  method-switching candidates correctly marked "inconclusive." Backend bounty scope suite green (28 tests).
- Noted for later: `MAX_URLS=80`/`MAX_URLS_PER_MODULE=15` mean this run still only sampled a subset of
  Juice Shop's real endpoint list (150+ unique paths surfaced by the katana fix); widening those bounds or
  prioritizing high-value buckets (auth, admin, payment) is a tuning question, not a bug.

---

## 2026-07-19 — Bug Bounty pipeline: real-target E2E validation against OWASP Juice Shop (4 bugs found + fixed)

First full-auto pipeline run (`run/pipeline`) against a real, live target (the user's local OWASP Juice
Shop test instance, `owasp-juice.com`) rather than a synthetic fixture. DNS/reachability were validated
first from both the host and a worker container (`nslookup`/`getent hosts`/`curl`, all → `172.25.1.212`).
The run surfaced four real bugs that unit tests and the earlier synthetic-fixture testing hadn't caught —
each is a genuine gap in a differently-shaped real target (HTTP-only, SPA catch-all routing, standard
public-CORS config, a promoted-URL target list), not a Juice-Shop-specific quirk:

### Fixed
- **Recon assumed HTTPS everywhere** (`workers/bounty/recon_worker.py`) — katana/hakrawler/ffuf/feroxbuster/
  API-discovery seeded every crawl with a hardcoded `https://{host}`. Juice Shop is HTTP-only, so the seed
  URL failed to connect and every downstream crawler silently returned nothing (`collected=0` URLs from an
  app with dozens of real endpoints). Added `_resolve_base_urls()`, which runs `httpx` once per host (it
  auto-negotiates scheme) and threads the resolved origin through `_collect_urls`/`_discover_paths`/
  `_discover_apis` instead of guessing. Any in-scope internal/staging/on-prem target that isn't HTTPS was
  silently unscannable before this fix.
- **Sensitive-file check defeated by weak signatures** (`workers/bounty/detect.py::check_sensitive_files`) —
  the existing catch-all/SPA guard (`_is_catch_all_200`) only applies to signature-less checks, but `.env`
  (signature `"="`) and `.htpasswd` (signature `":"`) have signatures so trivially weak they match *any*
  HTML page's markup, bypassing the guard entirely. On Juice Shop (an Angular SPA that 200s on literally
  any path, confirmed via a random-nonce probe) this produced `.env` (high) and `.htpasswd` (medium)
  "confirmed" findings whose "matched" content was just the app's index.html. Added a second, unconditional
  guard: skip whenever the catch-all flag is set and the response body itself looks like an HTML shell
  (`<html`/`<!doctype`), regardless of whether a signature matched — a genuine `.env`/`.htpasswd` never
  contains those markers, so this closes the gap for any weak signature, not just these two.
- **CORS check flagged standard, safe `Access-Control-Allow-Origin: *`** (`workers/bounty/detect.py::
  check_cors`) — treated a bare wildcard ACAO as a reflection finding unconditionally. `ACAO: *` without
  `Allow-Credentials: true` is a normal, intentional config for public/no-auth resources (browsers refuse
  credentialed requests against a literal `*` anyway), so this produced 41 near-identical "medium" findings
  on Juice Shop's public JS bundles, `robots.txt`, etc. — 42% of one run's total findings, all noise. Now
  only flags exact reflection of the probe's own attacker-controlled Origin (real evidence of "no allowlist
  at all"), or a wildcard combined with `Allow-Credentials` (spec-invalid, still worth a low-severity flag).
- **Nuclei re-scanned the same origin once per promoted URL target** (`workers/bounty/vulnscan_worker.py::
  run_stage`) — nuclei's target list was built from every `BountyTarget.value` verbatim, including url-type
  targets a human had promoted individually from the Recon tab (19 of them here, all on one host). Nuclei's
  template catalog (misconfig/CVE/tech-detection) is host-level, not endpoint-level, so this repeated the
  full template set 19x against the same origin — and in one run that repetition ran long enough to hit the
  10-minute scan timeout and yield zero results instead of the ~10 legitimate findings a single-origin scan
  produces in under 3 minutes. Now dedupes nuclei's target list to one entry per origin; per-endpoint
  injection testing (xss/sqli/idor/etc.) stays exploit_worker's job, unaffected.
- Related cleanup in the same code path: `_run_detection`'s sensitive-file/CORS base-URL list had the same
  per-promoted-URL-target duplication (producing nonsense concatenated paths like `/security.txt/.env` from
  a promoted `/security.txt` target) — collapsed to one entry per origin there too.

### Verified
- Same program, three full pipeline re-runs as each bug was found and fixed. Final clean run: recon →
  probe → vulnscan (10 findings, ~2.5 min, no timeout) → exploit (8 findings across 11 modules, 18 URLs
  tested) → report, no manual intervention between stages. Final finding set (18 total, zero CORS/sensitive-
  file noise): `prometheus-metrics` on `/metrics` (medium, confirmed — real), 8x missing-security-headers
  (info, confirmed), `swagger-api` on `/api-docs/swagger.json` (info, confirmed), 5x NoSQL-body candidates on
  `/api/v1-v3` + docs endpoints (medium, inconclusive), 3x HTTP method-switching candidates on `/profile`,
  `/api-docs`, `/assets` (low, inconclusive). Backend bounty scope test suite green (28 tests).

---

## 2026-07-18 — Bug Bounty framework parity, Phase 4 (FINAL): smart classifier + HTML report

Phase 4 of 4 — completes the framework-parity effort. Pure backend analysis over already-persisted data
(no worker run, no schema change) plus a frontend surface.

### Added
- `backend/app/services/bounty_report.py`:
  - `classify_program(urls, findings)` — the "smart classifier": severity/module/status counts, top findings,
    and priority target buckets a researcher triages by (IDOR numeric/UUID/API-object, BAC admin/sensitive-
    action/user-mgmt, auth/OAuth, upload, payment, webhook, debug, graphql), matched by regex over the
    program's recon URLs + finding targets.
  - `render_html(program, findings, summary)` — a standalone, self-contained, theme-aware HTML report
    (stat cards, severity bars, findings table with confirmed/candidate status, priority-target table).
- API: `GET /programs/{id}/summary` (classifier JSON) and `GET /programs/{id}/report.html` (the HTML report,
  `text/html`), both computed on demand, admin-gated.
- Frontend: a **Summary** tab (now the default) on the program detail — stat cards, severity distribution,
  priority-target buckets, and an **Open HTML Report** button (fetches with auth, opens the report in a new
  tab). New `bountyAPI.getSummary` / `getReportHtml`.

### Deliberately not done
- **Resume** (the reference's `.done`-file skip-completed) — intentionally skipped: the queue model already
  exposes per-stage `stage_status` and re-runs are idempotent (recon upserts, findings are additive), so a
  resume flag adds little here. Noted rather than silently dropped.

### Verified
- `classify_program` + `render_html` against the Phase-3 program's 15 real findings: summary returns correct
  totals (15 findings / 12 confirmed / 3 candidates), severity distribution, module counts, and priority
  buckets; the HTML report (7.8KB, valid) renders cleanly in a real browser (stat cards, severity bars,
  findings table, priority targets). Frontend Summary tab renders the same data + working report download.
  Backend suite green (311 tests), ruff clean, `tsc --noEmit` clean.

### Framework-parity effort — complete
All four phases done (recon breadth + gf classification → detection modules → aggressive exploit default-ON
→ classifier + HTML report). The bounty pipeline now covers the reference framework's capabilities within
this codebase's queue-worker architecture, with the scope gate absolute throughout and aggressive modules
calibrated to detection/confirmation (never destructive). Tool substitutions (Python gf/qsreplace/LinkFinder/
SecretFinder instead of the binaries; dalfox for XSStrike; custom fuzzing for LFISuite) are documented in
their phase entries.

---

## 2026-07-18 — Bug Bounty framework parity, Phase 3: aggressive exploit modules (default-ON) + gf routing

Phase 3 of 4 — the highest-stakes phase. Per the user's explicit choice (authorized bug-bounty operator):
full framework, aggressive modules **default-ON**. The scope gate stays absolute (nothing outside
`scope_rules` is ever touched, re-validated in the worker); intensity is calibrated to
detection/confirmation like the reference framework itself (sqlmap level 1, dalfox --only-discovery, SSTI
math-eval), never destructive/DoS.

### Added (`workers/bounty/exploit_ext.py`, wired into the exploit worker)
- **SSTI** (`run_ssti`) — `{{7*7}}`/`${7*7}`/`<%=7*7%>`/etc.; a hit requires the *evaluated* result to
  appear and the raw payload not to (so reflection ≠ SSTI). Confirmed.
- **NoSQL** (`run_nosql`) — Mongo-operator injection; flags NoSQL errors as inconclusive candidates.
- **JSON body mutations** (`run_json_body_mutations`) — prototype pollution (`__proto__`), mass-assignment
  (`role/is_admin`), NoSQL body (`$where/$gt/$ne`) POSTed to API endpoints; inconclusive candidates (real
  impact needs an authenticated before/after the pipeline can't do).
- **OAuth/JWT** (`check_oauth_jwt`) — token-in-URL (confirmed), JWT `alg:none` (confirmed, header-decoded),
  OAuth missing-`state` (confirmed) / missing-PKCE (inconclusive), and `redirect_uri` open-redirect
  (confirmed when the attacker URL is reflected into `Location`).
- **IDOR/BAC** (`idor_bac_probe`) — unauthenticated privileged-endpoint access + HTTP method-switching, both
  inconclusive candidates (BAC needs an authorized baseline).
- **gf routing**: each param-injection module now runs on the URLs whose `classify_url` buckets match it
  (xss→xss, sqli→sqli, ssti→ssti, …), falling back to all param URLs when a bucket is empty so coverage
  never depends on classification. Body modules run on API-ish URLs; OAuth on OAuth-ish URLs.
- **Default module set is now all 11** (xss/sqli/ssrf/lfi/idor/csrf/ssti/nosql/jsonbody/oauth/bac) — was
  4 with sqli/ssrf opt-in. Still narrowable + tunable per program via `rules_of_engagement`.

### Verified (against a fixture with each issue planted)
- Direct: SSTI confirmed, OAuth open-redirect + missing-state confirmed, token-in-URL + JWT alg:none
  confirmed, BAC method-switch inconclusive — all with correct confirmed/inconclusive status.
- Full exploit stage: one run produced 15 findings across the routed modules (SSTI/OAuth/BAC + XSS/LFI/IDOR),
  each persisted as ExploitAttempt with the right module/severity/status; nosql/jsonbody/sqli/ssrf correctly
  produced nothing against a target without those flaws (no false positives). All findings on the in-scope
  fixture — scope gate held.

### Still to come
Phase 4 (last): smart classifier (IDOR/BAC/OAuth priority lists + category buckets), HTML report, resume.

---

## 2026-07-18 — Bug Bounty framework parity, Phase 2: WAF, API/GraphQL discovery, sensitive files, CORS, 403-bypass

Phase 2 of 4. High-signal, mostly-detection checks between recon and active exploit, mapped into the
existing stages. New module `workers/bounty/detect.py` (stateless, bounded GET/POST against in-scope
targets; workers persist).

### Added
- **WAF fingerprint** (`detect.run_wafw00f`) — run by the **probe** stage on alive targets (bounded to 15),
  stored in the target's `probe_metadata.waf`.
- **API/GraphQL discovery** — run by **recon**: OpenAPI/Swagger spec hunting (`discover_api_specs`, ~12
  paths) + GraphQL introspection (`graphql_introspection`), recorded as `api_spec`/`graphql` BountyAssets
  (GraphQL flagged with `introspection_open`). Plus **feroxbuster** recursive content discovery added to
  path discovery (bounded to 2 hosts; ffuf still runs on 5).
- **Sensitive-file exposure, CORS misconfiguration, 403-bypass** — run by **vulnscan** on target base URLs +
  a bounded sample of in-scope recon URLs, persisted as `ExploitAttempt` findings (`module` =
  exposure/cors/403bypass). Sensitive files require a content signature or a non-catch-all server; CORS
  flags reflected-origin (high when credentials are allowed); 403-bypass tries path + header tricks.
- New tools already batched into the image in Phase 1 (wafw00f, feroxbuster) are now wired in.

### Fixed (surfaced during verification against the vuln-test fixture)
- **Catch-all/SPA false positives** — a server that answers 200 for every path made signature-less
  sensitive-file checks and path-mutation 403-bypasses fire spuriously (a very common real-world FP source).
  Added `_is_catch_all_200` baseline: on a catch-all host, signature-less file checks are skipped and only
  header-based 403 bypasses (which keep the exact path) are trusted. Verified: against the catch-all
  fixture, detection collapses from 5 findings (3 bogus) to the 2 real ones (`/.env` exposure + reflected
  CORS-with-credentials), and 403-bypass reports the real header bypass, not a path-mutation artifact.

### Verified
- `check_sensitive_files`/`check_cors`/`check_403_bypass`/`graphql_introspection` fire correctly against a
  fixture with each planted issue, and detection findings persist through the vulnscan stage as
  ExploitAttempt rows. WAF/feroxbuster are installed + wired (not exercised — the fixture has neither a WAF
  nor a large content tree).

### Still to come
Phase 3 (aggressive exploit modules default-ON + gf routing), Phase 4 (classifier + HTML report + resume).

---

## 2026-07-18 — Bug Bounty framework parity, Phase 1: recon breadth + gf URL-classification

User wants the bounty pipeline to match a full bug-bounty framework (reference: tanvirahmedcs/Bug-Framework
`bug.sh`, ~17 modules), fully automated, aggressive modules default-ON, built in staged phases. This is
Phase 1 of 4 (foundation): broaden recon and add the URL-classification that lets later exploit stages
target the right URLs. The scope gate stays absolute throughout.

### Added
- **gf-style URL classification** (`recon_ext.py::classify_url`) done in Python from the canonical gf
  parameter lists — no gf binary or pattern-repo dependency. Tags each URL with the buckets its query
  params imply (xss/sqli/ssrf/lfi/idor/redirect/rce/ssti); stored in `BountyAsset.metadata.gf`. This is the
  routing signal Phase 3's exploit modules will consume. (Verified: `?q=x&id=5` → `[idor,sqli,ssti,xss]`,
  `?path=/etc/passwd` → `[lfi,ssrf]`, and the buckets round-trip to the DB.)
- **Extra keyless subdomain sources**: urlscan.io, hackertarget, rapiddns (HTTP, no keys) + **alterx**
  permutation expansion — alongside the existing subfinder/assetfinder/crt.sh/dnsx set.
- **Extra URL sources**: waymore, hakrawler + **uro** near-duplicate dedup, on top of waybackurls/gau/katana.
- **Richer JS mining** (`tools.py`): AWS/GCP/GitHub/Stripe/Slack/Twilio/Mailgun/S3/Firebase secret patterns
  + DOM-XSS sink and declared API-base-URL extraction, recorded as `js_finding` intel per JS file.
- New tools batched into `workers/Dockerfile` (one rebuild for all phases): hakrawler, getJS, alterx (go);
  feroxbuster (installer); uro, waymore, wafw00f (pip). gf/qsreplace/LinkFinder/SecretFinder are done in
  Python instead of as binaries.

### Fixed (surfaced during real-target verification against example.com)
- **Wildcard-DNS false positives**: example.com is wildcard, so alterx's ~2000 permutations all "resolved"
  → 1253 junk subdomains that would've been auto-promoted and tested. Added a wildcard check
  (`recon_worker._is_wildcard`, random-label probe); permutations are dropped for wildcard domains while
  the real OSINT sources are kept. (Verified: `dropped=1998, permuted=0, confirmed=6` real subdomains.)
- **`BountyAsset.source` truncation**: the merged subdomain source label (63 chars) exceeded the column's
  `String(50)`, so persist failed with 0 assets saved. Shortened to `subdomain_enum` (the label can't name
  a single source per host anyway, since candidates are a merge).

### Still to come (Phases 2-4)
WAF fingerprint, API/GraphQL discovery, sensitive-file exposure, CORS, 403-bypass, feroxbuster content
discovery, nuclei multi-pronged (Phase 2); aggressive exploit modules default-ON + gf routing — SSTI,
prototype pollution, NoSQL, mass-assignment, OAuth/JWT, richer IDOR/BAC (Phase 3); smart classifier +
HTML report + resume (Phase 4).

---

## 2026-07-17 — Bug Bounty pipeline: full automation (one-click "Run Full Pipeline")

User found the manual per-stage flow too tedious (they run real engagements, e.g. Underarmour on Bugcrowd)
and wanted to define scope, hit one button, and have the whole pipeline run itself. Confirmed decisions
(AskUserQuestion): full auto **with auto-promote** (in-scope recon findings become testable without manual
review), **one "Run Full Pipeline" button** (not auto-on-activate), **on-demand only** (no scheduling yet).

**The scope gate stays absolute.** `is_target_in_scope` (fail-closed, explicit-deny-wins) is still
re-validated inside every worker; only in-scope things are ever auto-promoted or tested; nothing outside
`scope_rules` is touched. What changed is only the human *review* step, not the scope boundary.
`dos`/`destructive` stay excluded by default and `sqli`/`ssrf` stay opt-in (unchanged).

### Added
- **Recon seeds from scope** (`recon_worker.py::_scope_seed_domains`): recon now derives its seed domains
  from the in-scope domain scope rules (wildcards stripped, `*.acme.com` → `acme.com`) unioned with any
  manual domain targets — so a program only needs its scope defined to run recon; no separate manual target
  entry required. (Fixes the friction the user hit: scope filled but recon skipped for lack of targets.)
- **Auto-chaining** (`bounty_stage.py`): `BountyStageWorker` now publishes the next stage on `completed`
  (never on skipped/failed) when the message carries `auto_chain: true`, via the same `QueueClient` the ASM
  pipeline uses. `NEXT_STAGE`: recon→probe→vulnscan→exploit→report (report terminal). The next stage is set
  `queued` immediately so the UI reflects the hand-off.
- **Auto-promote** (`recon_worker.py::_auto_promote_in_scope`): in an auto run, recon promotes in-scope
  `subdomain` assets → `domain` targets (bounded by `MAX_AUTO_PROMOTE=50`), reusing the `promote_asset`
  scope-check + dedup logic. Promoting the hosts is enough — exploit pulls its candidate URLs from in-scope
  `BountyAsset` rows owned by an approved target, so the URLs come along without promoting thousands of rows.
- **API** `POST /bounty/programs/{id}/run/pipeline` — queues recon with `auto_chain: true`. **Gotcha fixed
  during verification**: this literal route must be declared *before* the parameterized `/run/{stage}`, or
  FastAPI matches "pipeline" as a `{stage}` value (it did, returning a 400) — reordered so the literal wins.
- **Frontend**: prominent rose "Run Full Pipeline" button on the program detail (disabled unless active),
  `bountyAPI.runPipeline`. The existing per-stage buttons + live status pills stay — during an auto run the
  pills advance stage-by-stage via the existing 3s polling.

### Verified (real end-to-end against a controlled `vuln-test` fixture)
- One `run/pipeline` click chained all five stages automatically: recon (auto_promoted=1) → probe → vulnscan
  → exploit (4 findings) → report (4 reports), with **zero** manual promote clicks. Auto-promote created a
  `domain` target with `added_by=auto`.
- Safety: an out-of-scope host (`evil.com`) was rejected at target-add (400) and appeared in **zero**
  targets/assets/findings/reports after a full auto run. Pausing mid-chain on a fresh program stopped it —
  recon completed, probe recorded `skipped · program_not_active`, and vulnscan/exploit/report never fired.
- Backend suite green (311 tests), frontend `tsc --noEmit` clean.

### Incident (operational, not a code change) — logged for the record
During test-fixture cleanup, a "delete all bounty programs" loop **also deleted the user's real `underarmor`
engagement program**, not just the test ones (hard delete + cascade). The full scope was recoverable from
`audit_logs` (every `bounty_program.update` had been captured) and the program was recreated with the exact
5 in-scope / 7 out-of-scope rules (new id `677cc4f5-...`, paused); prior run data (targets/findings/reports)
was not recoverable. Lesson recorded in memory: cleanup must target only tracked test IDs, never bulk-delete.

---

## 2026-07-16 — Bug Bounty pipeline: per-stage run status (progress visibility)

User asked why they had to run each stage blind ("kenapa ga keliatan statusnya dari setiap phase") — the
run/{stage} triggers were fire-and-forget with no feedback on whether a stage was running, done, or
failed. Added live per-stage status tracking, end-to-end.

### Added
- `bounty_programs.stage_status` JSONB column (migration `c7cb7f72c29e`) keyed by stage name, each holding
  `{status: queued|running|completed|skipped|failed, started_at, finished_at, summary, error, reason}`.
- `workers/bounty/bounty_stage.py` — `set_stage_status()` (targeted `jsonb_set` on a single stage key so
  two concurrently-running stages never clobber each other's status) + `BountyStageWorker`, a base that
  wraps `process()` so every bounty worker gets running→completed/failed bookkeeping automatically (and any
  unhandled error still surfaces as `failed` in the UI while still propagating to BaseWorker's retry/DLQ).
  All 5 workers refactored to subclass it and implement `run_stage()` returning a small summary dict
  (`{assets_found}`, `{probed, alive}`, `{findings}`, `{reports_created}`) or `{"skipped": reason}`.
- API: `run/{stage}` marks the stage `queued` immediately (so the UI reflects the click before a worker
  picks it up); `stage_status` returned in the program payload.
- Frontend: a live status pill under each pipeline-stage button — Queued (amber), Running + elapsed (blue
  spinner), a **"Stuck?"** amber warning if a stage has been running >10min (worker crashed without marking
  it failed), Completed + summary (green, e.g. "2/3 alive", "7 findings"), Skipped + reason, Failed (red,
  error in tooltip). The program view polls every 3s while any stage is queued/running, then stops.

### Fixed (found during verification)
- `stage_status` was being stored as a **double-encoded JSON string** instead of an object —
  `cast(json.dumps(payload), JSONB)` encodes twice (once by `json.dumps`, once by SQLAlchemy's JSONB bind),
  so the frontend saw a string and rendered no pill. Switched both the worker helper and the API to
  `type_coerce(payload, JSONB)` (encodes exactly once). Verified the API now returns a proper object.

### Verified
- Backend suite green (311 tests), ruff clean, frontend `tsc --noEmit` clean.
- Real end-to-end: triggered recon+vulnscan+exploit together against the `vuln-test` fixture and watched
  the pills transition live in a real browser — captured a mixed state (Recon "Running 10s", Probe "2/3
  alive", Vuln Scan "Queued", Exploit "Running 10s") and a settled state (Recon "0 assets", Probe "2/3
  alive", Exploit "7 findings", Vuln Scan "Queued" behind another program on the single-concurrency
  worker). Backend status flow polled directly also confirmed queued→running→completed with summary.

### Note on automation (raised by the user, not built)
User asked whether the stages could auto-chain instead of manual per-stage triggers. Explained the honest
split: the **recon → promote-to-target** boundary is intentionally a human gate (recon output must never
auto-expand what's actively attacked — the core safety principle), but `probe→vulnscan→exploit→report`
could safely chain since they only touch already-approved targets. Offered options (chain testing stages /
full auto with recon auto-promote / scheduled) via AskUserQuestion; user dismissed the question — left
unbuilt pending their decision.

---

## 2026-07-15 — Bug Bounty pipeline Stage 5: report worker (module 13) + frontend — feature COMPLETE

The final stage. With this, the full 13-module bug bounty pipeline the user designed is built,
queue-wired, and verified end-to-end: recon → probe → vulnscan → exploit → report, plus a dashboard
section to drive it.

### Added — report worker + API (module 13)
- `workers/bounty/report_templates.py` — pure functions turning a confirmed `ExploitAttempt` into a
  submission-ready Markdown draft (title / summary / steps-to-reproduce / impact / remediation), with
  conservative per-module framing (describes the vulnerability class, not an unverified impact claim).
- `workers/bounty/report_worker.py` (`BountyReportWorker`, queue `bounty.report`) — generates one
  `BountyReport` draft per confirmed finding without an existing report (idempotent re-runs — verified
  a second run created 0). Confirmed-only by default; a program can opt into inconclusive candidates via
  `rules_of_engagement.reportable_statuses`.
- API: `GET .../reports`, `GET .../reports/{id}` (with a rendered `markdown` field ready to paste into a
  HackerOne/Bugcrowd submission), `PUT` (edit a draft / advance status draft→submitted→triaged→resolved→
  paid), `DELETE`. `run/report` added to `RUNNABLE_STAGES`; `bounty.report` added to all three routing
  tables + a `worker-bounty-report` compose service.
- Fix found during verification: `build_report` had two title-assignment branches and only one used the
  specific tested URL — a finding on `/file` was titled as being on the owning target's `/search`. The
  exploit worker now records the exact `target_url` in each finding's evidence, and both title branches
  use it. Re-verified: LFI report now correctly reads "…via `path` on …/file?path=index".

### Added — frontend (`frontend/src/app/dashboard/bounty/`)
- Programs list + create modal, and a program detail page with a pipeline stage-runner (Recon/Probe/Vuln
  Scan/Exploit/Report, disabled unless the program is active), and tabs: Scope (add/remove in-scope &
  out-of-scope rules, read-only rules-of-engagement), Targets (add/remove, rejected client-side-visibly if
  out of scope), Recon (review recon assets + promote to target), Findings (module/severity/status +
  tested URL), Reports (expand to the rendered Markdown + copy). New `bountyAPI` client. Sidebar entry with
  a deliberately distinct **rose** accent (not the ASM brand blue) so continuous passive monitoring vs.
  one-shot authorized active testing never read as the same thing.

### Verified
- Full backend suite green (311 tests), ruff clean, frontend `tsc --noEmit` clean.
- Report worker end-to-end against real findings: 5 confirmed findings → 5 correct Markdown drafts, correct
  per-finding URLs, idempotent re-run.
- **Visually verified the whole section in a real headless browser** (real login, real data): the rose
  sidebar entry, programs list, program detail with the scope editor showing the `vuln-test` in-scope rule
  and conservative RoE defaults, the findings tab (XSS/LFI/CSRF with severity colors + confirmed badges +
  specific URLs), the reports tab, and an expanded report showing the full submission-ready Markdown
  (LFI PoC with the `../etc/passwd` payload and the real `/etc/passwd` response as proof) + Copy Markdown.

### Bug bounty pipeline — final state
All five stages built and independently verified (Stages 1-5, this date). The scope gate (`is_target_in_
scope`, fail-closed, explicit-deny-wins) is enforced at the API layer and re-validated inside every worker
at execution time; recon output never auto-expands what's testable; active-exploit aggressiveness is
per-program and conservative by default (sqli/ssrf opt-in, IDOR never extracts). Deliberately still out of
scope for v1 (unchanged from the Stage 1 plan): no auto-scope-sync from platform APIs, no destructive/DoS
by default, no exfiltration/persistence beyond PoC, and no integration with the ASM Organization/Asset
tables.

---

## 2026-07-15 — Bug Bounty pipeline Stage 4: exploit worker (modules 7-12)

The highest-stakes stage — active payload-sending confirmation (XSS/SQLi/SSRF/LFI/IDOR-BAC/CSRF). Built
last and deliberately, on top of a scope gate already proven three times over (recon/probe/vulnscan). The
whole safety architecture established at the start of this feature is the point of this entry, so it's
documented in full below.

### Added
- `workers/bounty/exploit_tools.py` — bounded, safe-by-default wrappers per module: `run_dalfox` (XSS —
  dalfox only reports on a working PoC, so a hit is genuinely confirmed), `run_sqlmap` (SQLi — **detection
  only**, no `--dump`/`--os-shell`/etc.; `--level`/`--risk` come from the caller, default 1/1, never a
  hardcoded aggressive value), `run_ssrf` (**no-op unless the program supplies an `oob_domain`** — blindly
  firing SSRF payloads at internal services with no way to confirm is exactly what this guard prevents;
  even with OOB configured, results are `inconclusive` since the platform injects but doesn't itself poll
  the listener), `run_lfi` (bounded path-traversal set, only reports on a matched file signature —
  non-destructive), `run_arjun` + `idor_candidates` (**IDOR flags an object-reference param and STOPS —
  there is literally no enumeration/extraction code path**; real confirmation needs two authorized
  identities the platform deliberately doesn't hold, so candidates are `inconclusive` for manual follow-up),
  `run_csrf` (detection-only: GET the page, flag state-changing POST forms missing an anti-CSRF token).
- `workers/bounty/exploit_worker.py` (`BountyExploitWorker`, queue `bounty.exploit`) — **two independent
  gates before anything is tested**: every URL must (1) pass `is_target_in_scope` against the program's
  *current* `scope_rules`, AND (2) belong to a host covered by an explicitly human-approved `BountyTarget`
  (`_owning_target_id`). Recon output (`BountyAsset`) can never expand what's testable on its own — a
  discovered URL is only touched if a human already approved its parent domain as a target. Which modules
  run is per-program (`rules_of_engagement.exploit_modules`), defaulting to the confirmation/detection-based,
  non-destructive set `["xss", "lfi", "csrf", "idor"]` — **sqli and ssrf are opt-in only** (heaviest / need
  extra setup). Everything bounded (max URLs/run, max URLs/module) so a run stays finite regardless of scope
  width.
- Tools added to `workers/Dockerfile` (pinned): dalfox `v2.9.2` (Go), sqlmap `1.10.7` (git clone to
  `/opt/sqlmap`, run as a script), arjun `2.2.7` (pip). `bounty.exploit` added to all three routing tables +
  a new `worker-bounty-exploit` compose service. `run/exploit` added to the API's `RUNNABLE_STAGES`.
- Design note — tool substitutions from the user's original 13-module table: dalfox stands in for
  dalfox+XSStrike (XSStrike is Python2-era and unmaintained); custom bounded fuzzing stands in for LFISuite
  (also abandoned). These are the modern, maintained equivalents; noted here the same way the README-drift
  substitutions are, so the table and the code don't silently diverge.

### Verified
- Full backend suite green (311 tests), ruff clean.
- **Real end-to-end run against a controlled, deliberately-vulnerable target** (a throwaway stdlib HTTP
  server run on the internal docker network as host `vuln-test`, reflecting input unsanitized + serving a
  path-traversal `open()` + a token-less POST form — a verification fixture, not part of the product):
  - **XSS confirmed** — dalfox produced a working PoC URL (`...q=test<audio ... ondurationchange=alert(1) ...>`).
  - **LFI confirmed** — `../../../../../../etc/passwd` read back real passwd content (`root:x:0:0:...`),
    matched signature captured with a short excerpt (proof of read, not the whole file).
  - **CSRF confirmed** — the token-less POST form flagged.
  - **sqli/ssrf correctly did NOT run** (not in the default module set) — visible in the run log.
  - **Scope enforcement, both layers**: the API rejected an out-of-scope URL target up front (400); and the
    critical defense-in-depth case — after narrowing a program's `scope_rules` so its 3 already-added
    targets fell out of scope, a re-run logged `bounty_exploit_no_in_scope_targets` and touched nothing,
    proving the worker re-validates against *current* scope and never trusts that a target was valid when it
    was added.
- Infra note: repeated worker-image rebuilds this session filled the host disk to 100%, which crashed
  RabbitMQ (`enospc` on its WAL). Recovered by pruning Docker build cache (~62GB) — no data loss; all
  services healthy afterward. Unrelated to the feature, logged here for the record.

### Not yet built
`bounty.report` (module 13) and the frontend — the last remaining pieces.

---

## 2026-07-15 — Bug Bounty pipeline Stage 3: vulnscan worker (module 6, nuclei)

Third build stage on the bug bounty pipeline (see the Stage 1/2 entries below for full context). Reuses
`workers/scanner/nuclei_worker.py`'s proven execution engine (template management, JSONL result parsing)
but with a deliberately different tag policy from the passive ASM pipeline's `SAFE_EXCLUDED_TAGS`.

### Added
- `workers/bounty/tools.py::run_nuclei` — standalone nuclei subprocess wrapper adapted from `nuclei_worker.
  py::_run_nuclei`/`_parse_results_file`; returns raw parsed JSONL, leaves mapping a result back to a specific
  `BountyTarget`/`ExploitAttempt` to the caller (same tools.py/worker split as every other module).
- `workers/bounty/vulnscan_worker.py` (`BountyVulnscanWorker`, queue `bounty.vulnscan`) — re-fetches the
  program + all its `BountyTarget` rows, skips anything `status != "active"`, not `is_target_in_scope`, or
  probe-confirmed dead (`is_alive is False`; unprobed targets with `is_alive is None` still get scanned).
  **Tag policy is the key design decision here**: `BOUNTY_DEFAULT_EXCLUDED_TAGS = ["dos", "destructive",
  "unsafe"]` — deliberately *narrower* than the ASM pipeline's `SAFE_EXCLUDED_TAGS`, which also excludes
  `intrusive`/`bruteforce`. This pipeline exists for active, authorized confirmation (nuclei-templates'
  thousands of `intrusive`-tagged templates cover real SQLi/SSTI/deserialization/RCE-via-OOB checks), so
  those run by default; `dos`/`destructive` stay off unless a program's `rules_of_engagement.
  allowed_extra_tags` explicitly lists them — the same per-program escalation dial already established for
  SQLi aggressiveness in the exploit stage design. Template breadth/severities/rate-limit/timeout are all
  read from `rules_of_engagement` per-invocation (falling back to the existing `deep_authorized` profile's
  template dirs, matching the user's original "broader vulnerability coverage" request), never hardcoded.
  Maps each nuclei result's `matched-at`/`host` back to the exact `BountyTarget` it came from via the
  already-shared `workers/scanner/scanner_common.py::host_from_target` helper; a result nuclei attributes to
  a host that wasn't actually one of the targets handed to it is logged and dropped, never guessed at, since
  `ExploitAttempt.target_id` is a non-nullable FK — confirmed this path actually fires in the verification
  run below (2 results dropped, not mis-attributed).
- `GET /api/v1/bounty/programs/{id}/findings` and `run/vulnscan` added to `RUNNABLE_STAGES`.
- `bounty.vulnscan` added to all three routing tables + a new `worker-bounty-vulnscan` docker-compose
  service sharing the same `nuclei-templates` volume as `worker-nuclei` (refreshing templates from either
  container is a harmless, idempotent no-op if already current).

### Verified
- Full backend suite green (311 tests), ruff clean. (`workers/` isn't mounted into the `api` container, so
  `make lint`'s `ruff check app/ workers/` has actually been a no-op for the *entire* `workers/` tree since
  before this session — pre-existing, unrelated to this feature; verified these files by direct Python
  import inside a running worker container instead, and confirmed clean syntax.)
- Real end-to-end run against `example.com`, scoped to `ssl`/`dns`/`http/exposures` templates for a fast
  test: 19 real findings persisted as `ExploitAttempt` rows (DNS WAF detection, weak cipher suites,
  deprecated TLS, etc.), all correctly linked to the right `target_id` and retrievable via `GET .../findings`.

### Not yet built (later stages, per the approved plan)
`bounty.exploit` (modules 7-12 — XSS/SQLi/SSRF/LFI/IDOR/CSRF, the highest-risk, most-new-code stage, built
last and deliberately on top of this now three-times-proven scope gate), `bounty.report` (module 13), and
the frontend.

---

## 2026-07-15 — Bug Bounty pipeline Stage 2: recon + probe workers (modules 1-5)

Second build stage on the bug bounty pipeline (see the Stage 1 entry below for full context/rationale).
Per the approved plan's staged build order: "`bounty.recon` + `bounty.probe` — lowest risk, highest existing-
code reuse" — built now that Stage 1's scope gate is independently proven. `bounty.vulnscan`/`bounty.exploit`/
`bounty.report` are still not built; nothing in this stage sends payloads or touches anything beyond passive
recon and a plain HTTP/TLS probe.

### Added
- `workers/bounty/tools.py` — stateless CLI/HTTP wrappers for all 5 recon/probe modules: subfinder +
  assetfinder + crt.sh + dnsx (module 1, subdomain enum — dnsx-confirmed only, so recon surfaces real assets
  not raw guesses), waybackurls + gau + katana (module 2, URL collection — waybackurls falls back to the
  Wayback CDX API directly if the binary isn't installed), subjs + a `<script src>` scrape fallback plus
  LinkFinder/SecretFinder-style regex passes (module 3, JS analysis — secret matches keep only the pattern
  *label*, never the matched text itself), ffuf (module 4, path/endpoint discovery, reusing the existing
  wordlist-resolution helper), httpx (module 5, live-host probing). Reuses `workers/scanner/discovery_worker.py`'s
  `tool_path()` tool-detection cache rather than duplicating it — a stateless filesystem lookup, not tied to
  the ASM Asset schema, so importing it doesn't violate the pipeline-independence principle.
- `workers/bounty/recon_worker.py` (`BountyReconWorker`, queue `bounty.recon`) — re-fetches the program and
  its domain-type `BountyTarget` rows from the DB at execution time (never trusts the queue message alone),
  skips anything not `status == "active"` or that fails `is_target_in_scope` against the program's *current*
  `scope_rules` (which can have changed since the target was approved), then runs all 4 recon modules per
  domain and upserts results into `BountyAsset` (`ON CONFLICT DO NOTHING`, using `pg_insert(Model.__table__)`
  per the SQLAlchemy 2.0 upsert gotcha in this file's own CLAUDE.md). Bounded throughout (max domains/run,
  max katana seed hosts, max JS files analyzed, max ffuf hosts) so one message can't run unbounded regardless
  of how wide a program's scope is — a recon budget, not a scope restriction.
- `workers/bounty/probe_worker.py` (`BountyProbeWorker`, queue `bounty.probe`) — probes explicit `BountyTarget`
  rows only (never `BountyAsset`, the unreviewed suggestion list), re-validates scope per-target before
  probing (a target can fall out of scope if `scope_rules` is edited after approval), writes liveness
  (`last_probed_at`/`is_alive`/`probe_metadata`) back onto `BountyTarget` itself — same pattern as `Asset.
  liveness_status` in the ASM schema, not a separate history table.
- Migration `5b14029650b2` — `BountyTarget.last_probed_at`/`is_alive`/`probe_metadata`, `BountyAsset.metadata`
  (a 4th `asset_type` value, `secret`, added at the application level only — no DB constraint to migrate).
  Same autogenerate-drift issue as the Stage 1 migration; manually stripped down to just these 4 `add_column`
  calls before applying.
- `POST /api/v1/bounty/programs/{id}/run/{stage}` (`stage` ∈ `recon`, `probe` only — `vulnscan`/`exploit`/
  `report` aren't accepted since no worker exists for them yet), `GET .../assets` and `POST .../assets/{id}/
  promote` (the only path from `BountyAsset` to `BountyTarget` — always an explicit human action, gated by
  the same scope check every other target-creation path uses). `run/{stage}` refuses anything but an
  `active` program (409), matching the check the worker repeats on the other end of the queue.
- `bounty.recon`/`bounty.probe` added to all three queue routing tables (`workers/base_worker.py::EXCHANGE_MAP`,
  `workers/queue_client.py`, `backend/app/core/queue_client.py`) on a new `asm.bounty` topic exchange, kept
  separate from `asm.scan` at the RabbitMQ level too. `waybackurls`/`subjs` added to `workers/Dockerfile`
  (pinned to their tagged releases, `v0.1.0`/`v1.0.1`, matching this file's existing pinning convention).
  Two new worker services, `worker-bounty-recon`/`worker-bounty-probe`, in `docker-compose.yml`.

### Verified
- Full backend suite green (311 tests), ruff clean on every new/changed file.
- Real end-to-end run against `example.com` (IANA's reserved test domain — safe to query/probe/fuzz, no
  real backend, no authorization concerns): created a program, added `example.com` as an in-scope target,
  activated it, triggered recon — subfinder+assetfinder+crt.sh+dnsx genuinely found 6 real subdomains
  (`www`, `dev`, `m`, `support`, `products`, apex), all persisted to `BountyAsset`. Triggered probe — httpx
  confirmed `example.com` alive with a full TLS grab, status 200, title, and tech-detect (Cloudflare),
  written back onto the `BountyTarget` row. Promoted a discovered subdomain to a target successfully.
  Re-confirmed both negative cases still hold on a program that's actually run recon/probe: an out-of-scope
  target is still rejected, and flipping the program back to `paused` makes `run/recon` refuse with 409.

### Not yet built (later stages, per the approved plan)
`bounty.vulnscan` (module 6, nuclei reuse with a more permissive tag policy), `bounty.exploit` (modules 7-12
— XSS/SQLi/SSRF/LFI/IDOR/CSRF, built last and most deliberately, on top of this now-proven scope gate),
`bounty.report` (module 13), and the frontend.

---

## 2026-07-15 — New pipeline: Bug Bounty active-testing (Stage 1 — data model, scope gate, CRUD API)

User requested a second pipeline, structurally separate from ASM, for **authorized bug bounty engagements**
(targets sourced from HackerOne/Bugcrowd programs) — active vulnerability confirmation (XSS/SQLi/SSRF/
LFI/IDOR/CSRF/RCE-via-nuclei), not the existing pipeline's passive signature detection. Per this session's
active-exploitation authorization policy, no code was written until authorization context (legitimate bug
bounty, not unauthorized testing) and technique scope were explicitly confirmed with the user, including two
resolved aggressiveness questions: SQLi/fuzzing intensity is a **per-program configurable** dial (`rules_of_
engagement`), never a fixed global max; IDOR/BAC **stops at first confirmation** with minimal evidence
rather than continuing to enumerate other users' data. Full 13-module design and staged build order recorded
in the approved plan (data model → scope gate → CRUD API → recon/probe → vulnscan → exploit → report).

This entry covers **Stage 1 only**: "get the safety gate solid and independently verified before anything
can execute." No scanning/exploitation code exists yet — that's later stages, deliberately.

### Added
- `backend/app/db/models/bounty_models.py` — `BountyProgram`, `BountyTarget`, `BountyAsset`,
  `ExploitAttempt`, `BountyReport`. Deliberately independent of the ASM `Organization`/`Asset` schema (no FK
  either direction) so nothing passively-discovered elsewhere can bleed into what's actively testable, and
  nothing found here bleeds into the ASM inventory. `BountyAsset` (recon output) is intentionally never
  auto-promoted to `BountyTarget` (human-approved testable list) — silent scope expansion via discovery is
  the exact failure mode this separation exists to prevent.
- Migration `b8f8af802a62` — the 5 new `bounty_*` tables only. Alembic's autogenerate run also surfaced a
  large amount of pre-existing, unrelated schema drift on `web_endpoints`/`workspaces`/etc. (accumulated
  before this session); that drift was manually stripped from the generated migration so it wasn't silently
  applied alongside this feature — it's still live drift and someone should generate/review a dedicated
  migration for it separately.
- `backend/app/db/migrations/script.py.mako` — this Alembic template file was completely missing from the
  repo, which silently broke `alembic revision --autogenerate` (and therefore `make migrate-create`)
  entirely, for any feature, not just this one. Recreated from the standard Alembic template; unrelated to
  bug bounty but was blocking this migration from being generated at all.
- `backend/app/services/bounty_scope.py` — `is_target_in_scope(value, scope_rules)`, the single
  safety-critical function this whole feature depends on: fail-closed (no rules defined → not in scope),
  explicit out-of-scope rules always beat an in-scope match, domain/IP-CIDR/URL-glob rule types. 28 unit
  tests in `backend/tests/unit/test_bounty_scope.py` covering all three rule types, the deny-wins invariant,
  and fail-closed defaults.
- `backend/app/api/v1/endpoints/bounty.py`, mounted at `/api/v1/bounty` — CRUD for programs and targets,
  gated behind `RequireRole(["owner", "admin"])`. Programs are created `paused` (nothing runs until a human
  flips status to `active` — not built yet, since nothing can run yet). Adding a `BountyTarget` re-validates
  against `is_target_in_scope` server-side and rejects with 400 if the value doesn't match the program's own
  `scope_rules` — so a target can never exist in this table without also being scope-valid, even before any
  worker exists to double-check it again at execution time.

### Verified
- 28/28 new scope tests pass; full backend suite (311 tests) green, no regressions.
- End-to-end smoke test against the real API (real login, real workspace): created a program with an
  in-scope wildcard plus an explicit out-of-scope carve-out, confirmed the in-scope target was accepted,
  and confirmed both the explicit carve-out and an unrelated domain were rejected with 400 — the deny-wins
  and fail-closed behavior holds through the actual HTTP surface, not just in unit tests.

### Not yet built (later stages, per the approved plan)
`bounty.recon`/`bounty.probe` workers (subdomain enum, URL/JS collection, path discovery, live-host probing),
`bounty.vulnscan` (nuclei reuse with a more permissive tag policy than the ASM pipeline), `bounty.exploit`
(XSS/SQLi/SSRF/LFI/IDOR/CSRF — built last, on top of this now-proven scope gate), `bounty.report`, and the
frontend. No run/execute endpoint exists yet — Stage 1 is data + gate + CRUD only, by design.

---

## 2026-07-15 — Frontend consistency pass: DNS Intel, Network Intel, sidebar nav

User asked for a full frontend "revamp." Before touching any code, audited every page in a real browser
(Overview, Organizations, Assets, Risk Scores, Scans, Screenshots, DNS Intel, TLS/SSL, Network Intel,
Settings, API Keys, Search, Organization Detail) and cross-checked the design tokens (`tailwind.config.ts`,
`layout.tsx`) against the `ui-ux-pro-max` design-system tool's own "enterprise security" recommendation.
**Finding: the base system (Geist Sans/Mono, the brand-blue scale, severity/grade colors) already matches
professional-enterprise-security best practice almost exactly** — no palette or typography replacement was
warranted, and doing one anyway would have been wasted risk for no real gain. The actual problem was
uneven polish across pages, not the foundation. Scoped down to 3 concrete, real issues found during the
audit; user confirmed proceeding with exactly those.

### Fixed
- **DNS Intel** (`frontend/src/app/dashboard/dns/page.tsx`): the Records column rendered *every* key in
  the `dns_records` JSONB blob as a gray chip, including record types with zero entries (`mx: 0`, `ns: 0`,
  `txt: 0`, `aaaa: 0`, `cname: 0` on nearly every row) — and, on closer inspection while fixing it,
  `discovery_sources`/`discovery_evidence` (worker-side bookkeeping fields sharing the same JSONB blob, not
  real DNS data) were being rendered as if they were record types too. Now only real record types
  (a/aaaa/mx/txt/ns/cname) with at least one actual entry render, as a colored brand badge; a host with
  none shows a plain "No records" instead of a wall of zero-value chips.
- **Network Intel** (`frontend/src/app/dashboard/intel/page.tsx`): the `Risk` column showed a muted dash on
  literally every row — by design, per the existing code comment, since the no-key `network_baseline`
  enrichment never populates `risk_score`/`is_malicious` (reserved for a future intel-feed source; see
  CLAUDE.md's enrichment-scope decision, deliberately not touched here). Now the column only renders when
  at least one row on the current page actually has a value — reappears on its own the moment a real
  scored source starts writing to this table, no code change needed then. The `Source` column (constant
  `network_baseline` string repeated on every single row today) moved from a dedicated column to a small
  caption under the asset value, freeing a full column of pure repetition while keeping the field visible
  for whenever a second source exists to actually distinguish.
- **Sidebar nav** (`frontend/src/components/layout/Sidebar.tsx`): `isActive()` used plain
  `pathname.startsWith(href)`, so a parent route and a nested child both lit up at once — e.g. "Settings"
  (`/dashboard/settings`) and "API Keys" (`/dashboard/settings/api-keys`) were both highlighted
  simultaneously while on the API Keys page. Now resolves the single most specific (longest-href) match
  across both nav sections, so only one item is ever active.

### Verified in a real browser
Rebuilt the frontend (`target: production`, no hot-reload) and confirmed all three fixes with fresh
screenshots against real `pasarjaya.co.id` data: DNS Intel now shows compact `A 1`-style badges or "No
records" instead of the zero-value wall; Network Intel's Risk column is correctly absent for this org
(no scored rows) and Source reads as a quiet caption; the API Keys page now highlights only "API Keys" in
the sidebar, not both it and "Settings". `npx tsc --noEmit` clean throughout.

### Explicitly not done
- No color/typography/token replacement — confirmed already correct via the design-system tool, would
  have been unnecessary risk.
- Settings page structure — audited, found genuinely plain but not wrong for a settings page; left as-is.

---

## 2026-07-15 — Attack Surface: Network Clusters view replaces the node-link graph as default

Follow-up to the same-day graph density fixes: user asked to move away from the node-link "mind map"
entirely, not just tune it further. Presented a concept mockup (published as a Claude artifact, built with
the `artifact-design` skill) showing a grouped-by-shared-IP list view instead; user approved it as-is
("nah boleh tuh seperti itu"). The mockup's own "Graph (legacy)" toggle affordance was treated as tacit
approval to keep the existing graph reachable rather than deleting a feature verified earlier the same day
— nothing working was thrown away.

### Added
- **`GET /organizations/{org_id}/network-clusters`** (`organizations.py`) — new endpoint. Groups subdomain
  assets by shared resolved IP (only hosts with at least one resolved IP are considered — unresolved hosts
  have no network position to cluster by, same scope boundary as the earlier discovery-noise tuning work).
  IP groups with 2+ hosts become a cluster (host list with real `http_status`, aggregated distinct
  `Technology` names, open-finding severity counts, and a top-5 findings preview ordered by the existing
  severity-rank pattern); everything else is a standalone host. Unlike the persisted
  `shares_infrastructure` relationship rows (capped at 20 per IP to bound pairwise-edge growth), this is a
  pure display grouping with no O(n²) concern, so no cap was needed.
- **`frontend/src/components/charts/NetworkClusters.tsx`** (new) — renders `{clusters, standalone,
  summary}` using existing primitives (`Collapsible`/`CollapsibleContent` from the Grouped Findings work,
  `SeverityBadge`) rather than reinventing them: each cluster is an expandable row (IP, host count, tech
  chips, severity summary → host list + top findings + full tech stack); standalone hosts as a flat list
  below.
- **`frontend/src/app/dashboard/attack-surface/page.tsx`**: new `view: "clusters" | "graph"` toggle,
  **defaulting to `"clusters"`**. The existing graph data-fetching/rendering block (tech-dedup + degree
  sizing, shipped earlier today) is completely untouched, just gated behind the "Graph (legacy)" tab and
  now only fetches when that tab is actually selected (previously fetched unconditionally).
- `frontend/src/types/index.ts`: `NetworkCluster`/`StandaloneHost`/`NetworkClustersResponse` types.

### Verified against real production data + real browser
- Direct invocation of `get_network_clusters` against `pasarjaya.co.id`: **8 clusters, 23 clustered hosts,
  25 standalone hosts, 25 total IPs** — exact match to hand-computed real numbers from planning. Largest
  cluster (`223.27.156.70`) returned exactly the 6 real hosts predicted in advance
  (admretail/admantrian/crm/perawatangerai/retail/rusunawa).
- `npx tsc --noEmit` clean. Frontend rebuilt (`target: production`, no hot-reload) before browser checks.
- Real-browser check (user provided fresh login credentials again for this explicit purpose): Clusters
  loads as the default view showing all 8 real clusters sorted by host count with correct severity-colored
  pills; expanding the largest cluster showed the real host list with HTTP status, real critical CVE
  findings (CVE-2026-44631/29167/34182/42535) with correct affected-host attribution, and the full
  real shared-tech-stack chip list; switching to "Graph (legacy)" rendered the untouched graph correctly
  (226 nodes/287 relationships, same as the earlier same-day verification) with zero console exceptions.
  Full backend suite: 283 passed, 1 skipped (same pre-existing unrelated skip).

---

## 2026-07-15 — Attack Surface Map: dedupe tech nodes, size by importance, quieter default view

User asked for redesign input on the Attack Surface Map (shipped earlier this session): at real density
(605 nodes / 672 edges for `pasarjaya.co.id`) it rendered as an unreadable "hairball" — every node the same
size, and every label invisible at the default fit-to-screen zoom (`min-zoomed-font-size` cutoff, combined
with how zoomed-out `fit:true` has to go to fit 600+ nodes). Investigation found a concrete, quantified
root cause worth fixing at the data layer: the Technology-node loop in `get_attack_surface_graph` keyed
each node as `f"tech-{tech.name}-{tech.asset_id}"` — one node **per (technology, asset) pair**, not one
shared node per technology. Real data: "Apache HTTP Server" alone is on 30 assets in `pasarjaya.co.id`,
producing 30 separate identical nodes instead of 1 shared one with 30 edges fanning in.

### Fixed
- **`backend/app/api/v1/endpoints/organizations.py::get_attack_surface_graph`**: Technology nodes now keyed
  by name only (case-insensitive), with an `asset_count` on each node. "Apache HTTP Server" is now 1 node
  with `asset_count: 28`, not 28+ duplicates — confirmed real data drop from 196 tech nodes to 45 distinct
  technologies for this org.

### Changed
- **`frontend/src/app/dashboard/attack-surface/page.tsx`**: `tech`/`finding` node-type toggles now default
  **off** (were all-on) — the initial view is topology-focused (org/domain/ip/port + real relationships),
  with tech/findings one click away. Real effect: default node count for `pasarjaya.co.id` dropped from 605
  to 226 (edges 672 → 287).
- **`frontend/src/components/charts/AssetRelationshipGraph.tsx`**:
  - Node size now scales with degree (edge count touching the node) instead of a flat per-type constant —
    hubs (a shared IP, a widely-used technology) visibly stand out; clamped so one mega-hub can't swallow
    the canvas.
  - Label visibility is now content-driven, not purely zoom-driven: `org` and `tech` nodes (low-cardinality
    after the dedup fix) always show their name; `domain`/`ip`/`port` only label once they're an actual hub
    (degree ≥ 3). Previously every label was governed solely by `min-zoomed-font-size`, which suppressed
    *all* of them at the zoom level 600+ nodes force. Also lowered that zoom threshold (8 → 4) so it stops
    fighting the new content-driven filtering.
  - `tech`'s color (`#0284c7`/`#38bdf8`) was visually confusable with `org`'s (`#0ea5e9`/`#38bdf8` — literally
    the same border color) — changed to a distinct teal (`#0d9488`/`#2dd4bf`).
- **Not changed this pass** (explicit, per the user's own framing — try the above first): the "cose"
  force-directed layout algorithm itself.

### Verified against real production data + real browser
- Direct invocation of `get_attack_surface_graph` against `pasarjaya.co.id`: confirmed the single "Apache
  HTTP Server" tech node has `asset_count: 28` with exactly 28 edges pointing at it, zero dangling edges.
- `npx tsc --noEmit` clean.
- Real-browser check (user provided fresh login credentials again for this explicit purpose; the frontend
  is a `target: production` Docker build with no hot-reload, so a rebuild was required to pick up the
  frontend changes — done via `docker compose build frontend && docker compose up -d frontend`): confirmed
  node count dropped 605 → 226 with tech/finding off by default (visible in the Graph Summary sidebar: 0
  Technologies, 0 Findings), IP nodes render at clearly varying sizes matching real degree differences,
  zoomed-in screenshot confirmed domain labels render legibly (`disbangan.pasarjaya.co.id` fully readable),
  and toggling Tech back on showed 45 distinct technology nodes in a clearly-different teal color from the
  org node's blue, with size variation matching `asset_count`. Full backend suite: 283 passed, 1 skipped
  (same pre-existing unrelated skip).

---

## 2026-07-15 — Fixed overlapping category labels in report bar charts

Follow-up to the same-day PDF redesign: user spotted `cors_misconfiguration` and `exposed_admin_panel`
visually colliding with their own bar in "Top Finding Categories". Root cause: raw category values are
unbroken snake_case tokens (no spaces), so the renderer had no natural point to wrap the fixed-width label
column onto a second line — it just overflowed into the bar next to it.

### Fixed
- **`report_service.py`**: new `_humanize_label()` (+ a small acronym list — CVE/TLS/CORS/HSTS/SPF/DMARC/
  DNSSEC/EOL/API/IP/DNS/SSL/CSP kept upper-case, everything else title-cased) converts raw tokens like
  `cors_misconfiguration` → `CORS Misconfiguration` before they ever reach the template. Registered as a
  `humanize` Jinja filter, applied to the Findings table's Category column and the Asset Inventory table's
  Asset Type column too, for consistency — not just the chart labels that prompted the fix.
- **`report_pdf.html`**: `.bar-label` widened (118px → 132px) with `overflow-wrap`/`word-break` so a label
  that's still long after humanizing wraps onto a second line inside its own column instead of colliding
  with the bar, rather than relying on humanization alone to always produce a short-enough string.

### Verified against real production data
Regenerated the `pu.go.id` executive report (the exact org/categories the user flagged) and visually
confirmed: "CORS Misconfiguration" and "Exposed Admin Panel" now wrap cleanly onto two lines with zero
overlap into the bar track; "Known CVE", "Old TLS Version", "Missing HSTS", "EOL Software" all render with
correct acronym casing; Asset Inventory now shows "Subdomain"/"IP" instead of raw lowercase. Full backend
suite: 283 passed, 1 skipped (same pre-existing unrelated skip).

---

## 2026-07-15 — PDF report visual redesign

Follow-up to the executive narrative feature, same day: user felt the report still looked plain/flat
("data doang") and asked for a real visual pass. Full rewrite of `backend/app/templates/report_pdf.html`'s
CSS/structure — no `report_service.py` data changes, purely presentational.

### Changed
- **Cover band**: full-width dark navy→slate gradient header replacing the plain white header row —
  organization name, workspace/date/report-type metadata, and a larger grade badge with a subtle ring
  border, all in one cohesive block instead of a thin bottom-bordered strip.
- **Executive summary callout**: the narrative paragraph (shipped earlier today) now sits in a distinct
  tinted panel with a colored left accent bar and an "EXECUTIVE SUMMARY" label, instead of a bare paragraph
  floating between the header and the stat tiles.
- **Section headers**: consistent `.section-title` treatment (bold heading + full-width rule, optional
  right-aligned context text) replacing plain `<h2>` tags with inconsistent visual weight.
- **Stat tiles**: color-coded top borders per severity (critical/high/medium/low) instead of uniform gray
  borders — the tile itself now visually pre-empts what its number means before you read the label.
- **Tables**: dark header row (was light gray), zebra-striped body rows, wrapped in a rounded `.panel`
  container. Findings table: title/URL/evidence restructured into a clearer visual stack per row.
- **Compliance Mapping table** (real bug fix, not just polish): the previous table used
  `{% if loop.first %}` to show the CIS Control name only on a safeguard's first row, leaving confusing
  blank cells on every subsequent row for a multi-safeguard control. Replaced with a distinct bold/tinted
  "control-row" spanning all columns (showing the Control name + its total finding count) followed by
  indented safeguard rows underneath — matches how the data is actually grouped instead of fighting the
  table's row-per-record shape.
- **Pagination**: added `break-inside: avoid` on table rows — long finding rows (title + URL + evidence
  block) no longer split awkwardly across a page boundary.

### Also investigated (no change needed)
User asked to remove scheduled/automatic daily reports (reasoning: unbounded recurring generation would
accumulate storage for no benefit). Confirmed this is **already gone** from the codebase —
`workers/scheduler/scheduler.py::_generate_daily_summaries` and the `report.daily` queue it used to publish
to don't exist anywhere in the current code, and `scheduler.py::_register_jobs` registers no daily-report
job. `CLAUDE.md`'s documented gotcha entry about this is stale and should be dropped next time that file is
touched — no removal work was needed here.

### Verified against real production data
Regenerated real reports for both `pasarjaya.co.id` (executive) and `pu.go.id` (compliance, 355 findings
across 38 pages) through the same direct-service-invocation technique used throughout today (no session
token available) and visually inspected the rendered PDFs page-by-page: cover band, executive summary
callout, color-coded stat tiles, severity/category bars, the restructured compliance table (4 real CIS
Controls rendering correctly with per-safeguard severity badges), and the paginated findings table (confirmed
row-splitting fix by inspecting the exact page boundary that previously split a row). Full backend suite:
283 passed, 1 skipped (same pre-existing unrelated skip).

---

## 2026-07-15 — Report executive narrative

User asked to enhance reporting, calling out that report content was "just data" (tables/numbers, no
synthesis). Investigation found a concrete instance of exactly that: `_fetch_latest_risk_score()` already
computes the full 9-category risk breakdown (network/DNS/web/TLS/exposure/patch-hygiene/info-leakage/
reputation/misconfiguration scores) for every report, but `report_pdf.html` only ever rendered the overall
grade/score badge — the per-category breakdown was fetched and silently discarded, never shown anywhere.
Presented 4 concrete enhancement options (surface the unused category breakdown; a written executive
narrative; score trend vs. previous report using the already-built `/score-history` endpoint; an EPSS/KEV-
prioritized remediation list); user picked the narrative.

Separately, user asked to remove scheduled/automatic daily reports (reasoning: recurring generation would
accumulate storage over time for no benefit — on-demand only). Investigation found this is **already gone**
— `CLAUDE.md`'s documented gotcha about `workers/scheduler/scheduler.py::_generate_daily_summaries`
publishing to an unconsumed `report.daily` queue no longer matches the code: that function, the publish
call, and the `report.daily` queue reference don't exist anywhere in the current codebase, and
`scheduler.py::_register_jobs` has no daily-report job registered. No removal work was needed; `CLAUDE.md`'s
gotcha entry is now stale and should be dropped next time that file is touched.

### Added
- **`backend/app/services/report_narrative.py`** (new) — `build_executive_narrative()`, a deterministic,
  templated paragraph synthesizing already-computed report fields (risk score/grade, the worst-scoring of
  the 9 categories if below a healthy threshold, open finding counts by severity, the top finding category,
  a remediation call-to-action gated on critical/high findings actually being present). Explicitly **not**
  an LLM call — every sentence traces directly to a field already in `report_data`, so it's always
  explainable and never asserts something the underlying numbers don't support. Reuses the exact category
  label wording already established in `frontend/src/app/dashboard/risks/page.tsx::CATEGORY_LABELS`.
- **`report_service.py`**: `_build_report_data()` now always includes a `narrative` field (all report
  types — the plain `executive` report benefits from this most, since it has no findings table to fall
  back on).
- **`report_pdf.html`**: narrative renders as a lead paragraph directly under the header/score badge,
  before the Summary tiles.
- **Tests**: `backend/tests/unit/test_report_narrative.py` (8 cases) — grade/score inclusion, worst-category
  callout only below the healthy threshold, no-risk-score and zero-findings degradation, severity-count
  phrasing, top-category phrasing, remediation sentence gated correctly.

### Verified against real production data
Generated a real `executive` report for `pasarjaya.co.id`: narrative read *"pasarjaya.co.id's overall
security posture is rated D (42/100) as of 2026-07-14. The most significant risk driver is TLS Security
(0/100), the lowest-scoring category. There are currently 792 open findings, including 95 critical and 333
high severity. Known cve accounts for the largest share of open findings (593). Prioritizing remediation of
critical and high severity findings is recommended to improve the organization's overall risk posture."* —
every number in it cross-checked against the same report's own Summary/category data. Rendered to PDF and
visually confirmed correct placement/formatting. Full backend suite: 283 passed, 1 skipped (same
pre-existing unrelated skip).

---

## 2026-07-13 — Attack-surface graph: fixed relationship data, wired the graph to it

Third of three requested ASM product features. Original framing was "wire the existing graph to the real
`AssetRelationship` endpoint" — investigation found that would have made the graph *worse*: the table only
ever gets 2 relationship types written to it, and one is a real bug.

### Fixed
- **`workers/correlation/correlation_worker.py::_build_relationships`**: removed the `has_finding` block
  entirely. It matched a Technology row to a Finding via `finding.asset_id`, then wrote a relationship from
  that same asset back to `finding.asset_id` — source and target were always identical.
  **Confirmed empirically: 137/137 existing `has_finding` rows were self-loops.** Structurally, this could
  never have worked: `AssetRelationship` is strictly Asset↔Asset, and neither `Technology` nor `Finding`
  rows are asset-backed nodes, so "Technology → Finding" was never really representable in this schema —
  not just a coding slip. The 137 existing self-loop rows were deleted (this table isn't read by any
  frontend page today, so this had zero visible impact — pure dead-row cleanup).

### Added
- **New relationship type `shares_infrastructure`**: sibling subdomains resolving to the same IP (from
  already-collected `Subdomain.ip_addresses`, no new scanning). Real shared-hosting/blast-radius signal —
  two subdomains on the same box mean a compromise of one plausibly reaches the other. Capped at 20
  subdomains per shared IP to avoid an O(n²) edge explosion on CDN/shared-hosting IPs where "same IP" stops
  meaning anything.
- **`GET /organizations/{org_id}/attack-surface-graph`** (`organizations.py`) — new org-wide graph
  endpoint. Real `AssetRelationship` edges (`resolves_to`, `shares_infrastructure`) plus presentation-only
  Technology/Finding nodes built directly from `Technology`/`Finding` tables (not real relationship rows —
  same reasoning as above: neither is an asset-backed node). Same asset/finding caps and critical/high-only
  finding filter the frontend already used, just computed server-side now.
- **Frontend**: `frontend/src/app/dashboard/attack-surface/page.tsx` now calls the single new endpoint
  instead of 3 parallel `/assets`+`/findings` fetches and ~90 lines of client-side graph construction — the
  only client-side addition left is the synthetic org root node and its "contains" edges (purely
  structural, not real data, so no reason to round-trip them). `npx tsc --noEmit` clean.

### Verified against real production data
- Direct invocation of the fixed `_build_relationships()` against `pasarjaya.co.id`: **0 self-loops**,
  40 `resolves_to`, 29 `shares_infrastructure` — including a real, predicted-in-advance shared-hosting
  group (`103.82.242.226` shared by `cdn-sirupa`/`admin-sirupa`/`api-sirupa`/`sirupa.pasarjaya.co.id`).
  Persisted via the existing `_persist_relationships()` and confirmed via direct SQL: `has_finding` now 0
  rows platform-wide, `shares_infrastructure` 29 rows for this org, 0 self-loops across the whole table.
- Direct invocation of the new `GET /organizations/{id}/attack-surface-graph` endpoint: 497 nodes (25 ip,
  176 domain, 196 tech, 100 finding), 339 edges (28 resolves_to, 15 shares_infrastructure, 196 runs, 100
  has_finding) — **zero dangling edges** (every edge's source/target resolves to a node in the same
  response).
- Full backend unit suite: 275 passed, 1 skipped (same pre-existing unrelated skip as before).

### Real-browser verification (follow-up, same day)
The gap noted for all three features — no legitimate session token available for a CDP browser
click-through — was closed once the user provided real login credentials for this explicit purpose (not a
self-mint/bypass; a normal `POST /auth/login` through nginx, same as any real user). Confirmed visually via
headless Chrome: the Attack Surface Map renders 605 nodes / 672 relationships for `pasarjaya.co.id` with the
correct type breakdown (1 org, 200 domains, 25 IPs, 279 tech, 100 findings) in the sidebar summary, node
color-coding matches the legend, and the page loads with zero console exceptions.

### Explicitly not done
- `IP → Port` relationships — structurally not representable without making `Port` an asset-backed entity;
  would be a real schema change, not attempted.
- No new scanning/data collection — `shares_infrastructure` uses only already-collected data.

---

## 2026-07-13 — CIS Controls v8 compliance report mapping

Second of three requested ASM product features (after change/diff detection below). `compliance`/`custom`
report types previously aliased straight to `technical` with zero framework mapping
(`report_service.py::DETAILED_REPORT_TYPES` comment admitted this). User picked CIS Controls v8 over
ISO 27001/SOC2/PCI-DSS after being shown that real finding categories (53 distinct values) are almost
entirely technical/infrastructure (TLS, DNS auth, exposed panels, CVEs, misconfig) rather than
policy/governance — a technical control catalog fits the actual data far better than a governance-heavy
framework would.

### Added
- **`backend/app/services/compliance_mapping.py`** (new) — `CATEGORY_TO_CIS_SAFEGUARD`, an exhaustive
  1:1 map from every category already in `risk_engine.py::FINDING_CATEGORY_MAP` (reused as the category
  taxonomy source rather than re-deriving one — that map is what the risk engine itself already relies on,
  and a past incident already caught/fixed categories missing from it) to a CIS Controls v8
  Control+Safeguard. `get_cis_mapping()` lookup, case-insensitive.
- **`report_service.py`**: `compliance` report type now gets a real `compliance` section (additive to the
  existing full findings list, not a replacement) — findings grouped by CIS Control/Safeguard with
  per-safeguard severity breakdowns and a coverage summary ("X of 8 mapped Controls have open findings").
  Uses its own uncapped `GROUP BY category, severity` query (not the 500-row-capped display findings list),
  so totals stay accurate for orgs with more open findings than that cap.
- **`report_pdf.html`**: new "Compliance Mapping — CIS Controls v8" section, same conditional-block pattern
  as the existing Findings/Recent Scans sections.
- **Tests**: `backend/tests/unit/test_compliance_mapping.py` (8 cases) — exhaustiveness check (every
  `FINDING_CATEGORY_MAP` key has a CIS entry and vice versa, guards the same kind of drift a past incident
  caught in the risk-scoring map), lookup correctness, case-insensitivity. Full suite: **275 passed, 1
  skipped** (unrelated pre-existing skip — a worker-side test module not importable from the `api`
  container's Python path).

### Verified against real production data
- Generated a real `compliance`-type report for `pu.go.id` (116 assets, 355 open findings) via direct
  service invocation (no session token available this round — see Feature 1's verification note below for
  why). Compliance section correctly produced 4 populated CIS Controls (Data Protection 60, Secure
  Configuration 159, Access Control Management 7, Continuous Vulnerability Management 129) — **sum of all
  control totals + unmapped_count (0) == 355**, exact match to the summary's `total_findings`, confirming
  zero findings lost or double-counted in the grouping.
- Rendered the actual PDF (WeasyPrint) and visually inspected the output — the new section renders
  correctly with proper severity-colored badges, matching the verified numbers exactly.

### Real-browser verification (follow-up, same day)
User provided real login credentials for this explicit purpose (normal `POST /auth/login`, not a
bypass). Confirmed in a headless-Chrome session: the Reports page's Compliance Report tile shows the
updated description ("Findings mapped to CIS Controls v8 safeguards"), and the two real compliance reports
generated during verification appear correctly in the Recent Reports list for `pu.go.id`.

---

## 2026-07-13 — Scan change/diff detection ("What Changed Since Last Scan")

First of three requested ASM product features. Investigation found the backend groundwork was more built
than expected but had two real, previously-undiscovered gaps:
- **`Scan.new_assets`/`new_findings`/`removed_assets` columns (`models.py:681-683`, `default=0`) were read
  by two endpoints and shown on two frontend pages, but never written anywhere in the entire codebase** —
  every scan ever run silently showed "0 new," regardless of reality.
- `correlation_worker.py::_detect_changes`'s docstring claimed it detects "resolved findings" — it didn't;
  no resolved-finding change type existed, and nothing auto-resolves a finding that isn't redetected
  (resolution stays human-driven by design, not attempted here).

### Added
- **`workers/correlation/correlation_worker.py`**: `_detect_changes` now persists real counts onto the
  `Scan` row after computing them — `new_findings` counts **all severities** (a separate, deliberately
  broader definition than the existing crit/high-only filter that feeds `notify.send` alerts, which is
  untouched).
- **`backend/app/api/v1/endpoints/scans.py`**: new `_scan_changes()` helper, wired into `_scan_to_dict`'s
  `detailed=True` payload (`GET /scans/{id}`) — read-only diff against the org's previous completed scan:
  new assets, removed assets (offline since then), new findings (all severities, with a per-severity
  breakdown), and **findings a human resolved since then** (new capability — purely additive, doesn't
  change resolution behavior). No new tables; reuses the existing `ScanFinding.change_type`/`Asset.first_
  seen`/`last_seen` comparison pattern `_detect_changes` already established.
- **Frontend**: new "What Changed Since Last Scan" section on `frontend/src/app/dashboard/scans/[id]/
  page.tsx`, four collapsible categories reusing the existing `components/ui/Collapsible.tsx` (built for
  the Grouped Findings feature). First-scan-for-this-org case shows an explicit empty state instead of a
  confusing all-zero diff. `npx tsc --noEmit` clean.

### Verified against real production data, two ways
- Direct invocation of `_scan_changes()` against an already-completed historical scan pair for
  `pasarjaya.co.id` — computed new_assets=1, removed_assets=1, new_findings=15 (all `info` severity),
  resolved_findings=0 — exact match to a manual SQL cross-check.
- Triggered a fresh live scan on the same org (270+ subdomains) specifically to confirm the counter-
  persistence fix fires on a real run end-to-end, not just in the read-only helper. Nuclei took a long time
  across many sequential batches (single replica); `worker-nuclei` was scaled to 2 replicas mid-flight at
  the user's request. Once complete: `new_assets=0, removed_assets=1, new_findings=101` (critical 8/high
  30/medium 15/low 4/info 44) — **persisted `Scan` columns matched a fresh direct SQL count exactly**, and
  a second `_scan_changes()` invocation against this same scan matched too, including the empty-list
  (`new_assets=0`) and full-severity-spread cases the first check didn't exercise.

### Real-browser verification (follow-up, same day)
Initially skipped — no legitimate way to obtain a session token existed in-session (querying user
credentials and directly minting a JWT were both correctly blocked by the permission classifier as out of
scope for a verification task). Closed once the user explicitly provided real login credentials for this
purpose: logged in normally via `POST /auth/login` through nginx, then confirmed in headless Chrome that
the "What Changed Since Last Scan" section on the Scan Detail page for the fresh live scan
(`7889d812-...`) renders exactly the verified numbers — New Assets 0, Removed Assets 1 (`202.148.26.203`,
type `ip`), New Findings 101 (expanded to show real critical CVE findings with correct severity badges and
affected hosts), Resolved Findings 0 — and that each category expands/collapses correctly.

---

## 2026-07-13 — Stop persisting unresolved dns_bruteforce/dns_permutation guesses as Assets

Follow-up to the Grouped Findings triage work: checked the Assets inventory next and found the same
volume-noise pattern there. Some orgs showed 200+ subdomains, most of which don't actually exist —
`pasarjaya.co.id` had 437 subdomain assets but 388 (89%) were `liveness_status='unresolved'`, all still
`status='active'` so all visible in the default Assets view. Broken down by discovery source across all 5
active orgs: `dns_permutation` (env-prefix guesses like `dev-api.x.com` off already-known labels) had a
**0.0% real-world hit rate — 0 out of 1070 candidates, platform-wide**; `dns_bruteforce` (wordlist guesses)
was ~3.5%. Passive/observed sources (crt.sh, subfinder, assetfinder, tls_san_mining, wayback) were left
untouched — their misses can still be dangling-CNAME/subdomain-takeover signal, unlike a pure wordlist miss.

### Added
- **`workers/discovery/dns_candidates.py`**: `GENERATED_ONLY_SOURCES` constant and
  `is_unconfirmed_generated_guess(sources, liveness_status)` — true only when *every* discovery source for
  a host is `dns_bruteforce`/`dns_permutation` and it never resolved (`liveness_status == "unresolved"`). A
  host corroborated by any passive source is always kept regardless of liveness.
- **`workers/tests/test_dns_candidates_guess_filter.py`** (new, 7 cases): pure-generated miss pruned,
  resolved-generated kept, passive-corroborated-but-unresolved kept, empty/no-source input never pruned.

### Changed
- **`workers/scanner/discovery_worker.py`** (`process()`): the `persisted_hosts` loop (feeding
  `_persist_assets`) now skips hosts matching `is_unconfirmed_generated_guess()` before the Asset/Subdomain
  upsert runs — they no longer become permanent inventory rows. The existing `DiscoveredAsset` audit-trail
  table (`_persist_discovered_assets`) is untouched — these attempts are still recorded there for
  drill-down, just with `asset_id = NULL` since no real Asset backs them (already-existing `SET NULL` FK
  behavior, no schema change). `update_scan_phase` gains a new `generated_misses_skipped` counter for
  scan-detail visibility. Scan performance is unaffected — DNS resolution/HTTP probing still runs on these
  candidates as before (a small % of `dns_bruteforce` guesses do occasionally resolve); only the *storage*
  of confirmed misses changed.

### Data cleanup (existing rows, confirmed with the user before running)
Since this fix only prevents *new* noise, existing bogus rows were still cluttering the 5 active orgs today
— soft-deleted (`deleted_at = now()`, same reversible mechanism already used for org deletion, and already
respected by every `Asset` read path via `Asset.deleted_at.is_(None)`) rather than hard-deleted. Queried
production DB directly for exact matches before touching anything: 856 Asset rows total (`pu.go.id` 234,
`pasarjaya.co.id` 164, `ACME Corp` 160, `comika.id` 154, `kpi.go.id` 144) had `liveness_status='unresolved'`
and *every* discovery source in `validation_sources->evidence->discovery->sources` was one of
`dns_bruteforce`/`dns_permutation`. Verified FK cascade safety first (`subdomains.asset_id` → `CASCADE`,
`discovered_assets.asset_id` → `SET NULL`, `findings.asset_id` → `CASCADE`); found only 3 `findings` rows
would cascade, all three on `ACME Corp` (`app.acme-test.example` — an `.example` TLD, i.e. seed/demo data,
not a real customer). Ran the soft-delete; visible subdomain counts dropped immediately:
`pasarjaya.co.id` 437→273, `pu.go.id` 309→75, `kpi.go.id` 265→121, `comika.id` 172→18, `ACME Corp` 160→0
(that org had no real subdomains at all — every one of its "subdomains" was an unresolved generated guess).

### Explicitly not changed
- Passive-source discovery (crt.sh, subfinder, assetfinder, wayback, tls_san_mining) and any host they
  corroborate, even if currently unresolved — kept as-is, preserved for subdomain-takeover investigation.
- `dns_bruteforce`/`dns_permutation` candidate generation and DNS/HTTP resolution attempts themselves are
  unchanged — only whether a confirmed miss gets promoted to a permanent Asset row.

---

## 2026-07-13 — Grouped/deduplicated findings view

A real end-to-end validation scan (fresh `pasarjaya.co.id` org, run right after the risk-engine redesign
finished) surfaced a concrete triage problem: 536 `version_cve_correlation` findings, but only 41 distinct
CVEs behind them — each CVE repeats ~13-25x because the same outdated software version runs on many hosts.
Not a false-positive/accuracy problem (every row is a real, individually-true finding on a specific host) —
a display/triage volume problem. Added an opt-out-able grouped view that collapses repeats of the same
underlying issue into one row, expandable to the individual findings, without touching detection logic.

### Added
- **`GET /findings/grouped`** (`backend/app/api/v1/endpoints/findings.py`) — new endpoint, same filter
  surface as the existing `GET /findings` (org_id/severity/status/category/search/has_cve/min_cvss), groups
  by `Finding.template_id` (already indexed; confirmed universal and safe across every scanner, not just
  version_cve_correlation — category/severity are confirmed uniform per template_id in real data). The 3
  real `scanner=''`/`template_id IS NULL` rows (manually-seeded, non-scanner findings) get
  `COALESCE`'d into their own singleton groups rather than colliding into one bucket. Returns per-group
  `finding_count`/`asset_count`/`max_cvss`/`first_seen`/`last_seen` plus a representative sample finding
  (Postgres `DISTINCT ON`, most-recently-seen member) used for the heading. Extracted the existing
  severity-counts block out of `list_findings` into a shared `_compute_severity_counts()` helper so the
  severity stat tiles report byte-identical numbers in both views.
- **`backend/app/services/finding_grouping.py`** (new) — `_group_heading()`: raw `title` is unsafe as a
  group-level label for CVE-bearing groups (it embeds the matched version string, varies per host —
  confirmed one real CVE's template_id spans 8 distinct title variants), so CVE groups head with the
  uppercased CVE ID instead (stable across all members), with the sample title shown as an explicit
  "e.g., ..." example rather than implied-canonical. Non-CVE groups (confirmed single-variant per
  template_id in real data) show the raw title verbatim.
- **Frontend**: new Grouped/Flat toggle on the Findings page (`frontend/src/app/dashboard/findings/page.tsx`),
  **defaults to Grouped** (confirmed with the user — directly serves the motivating problem; accepted
  trade-off that per-row bulk actions now need a group expanded first), persisted per-browser via
  `localStorage`. New `GroupedFindingRow.tsx` (`components/tables/`) renders each group as a `Collapsible`
  row (severity/CVE badge, heading/subheading, finding+host counts, last-seen), lazily fetching a group's
  members on expand via the *existing, unmodified* `GET /findings?template_id=...` (zero new backend code
  needed for this — that endpoint already supported `template_id` filtering). New
  `components/ui/Collapsible.tsx` wraps `@radix-ui/react-collapsible` — confirmed already an installed
  dependency with zero usages anywhere in the app before this (first radix-based primitive in the
  frontend); added matching keyframes to `tailwind.config.ts`.
- **Tests**: `backend/tests/unit/test_finding_grouping.py` (7 cases — CVE heading uppercasing, singular vs
  plural subheading framing, non-CVE verbatim-title path, the singleton-fallback no-scanner-row case, a
  defensive empty-input case). Full suite: **267 passed, 1 skipped** (was 260).

### Fixed (prerequisite, found while verifying this in a browser)
- **`frontend/next.config.js`**: the dev-mode `/ws/:path*` rewrite crashed `next dev` outright (Next's
  rewrite validator rejects `ws://` destinations — only `/`, `http://`, `https://` are accepted). Confirmed
  via grep this rewrite was also dead code regardless: both real WebSocket call sites
  (`lib/useRealtimeEvents.ts`, `lib/api.ts`) always `new WebSocket(NEXT_PUBLIC_WS_URL)` directly from the
  browser, bypassing Next's server-side rewrite proxy entirely — removed the rewrite rather than trying to
  fix its destination.

### Verified against real production data
- Hit `GET /findings/grouped` directly against the fresh `pasarjaya.co.id` org: **68 groups, 645 total
  findings** — cross-checked against a direct `SELECT COUNT(DISTINCT COALESCE(template_id, 'finding-'||
  id::text))` / `COUNT(*)` query, exact match.
- Verified the lazy-expansion path for a real 25-member CVE group
  (`GET /findings?template_id=version_cve_cve-2026-42535`): returned exactly 25 items, matching the
  group's `finding_count` exactly.
- `npx tsc --noEmit` clean, `npm run lint` clean (only pre-existing warnings in unrelated files).
- Dev server verified to build and serve the Findings page with zero compile/runtime errors (1518 modules)
  after the `next.config.js` fix above.
- **Real browser click-testing, not just API/type-check verification**: no browser-automation tool was
  available directly, so this was driven manually via Chrome DevTools Protocol (headless `google-chrome
  --remote-debugging-port` + raw CDP websocket calls) — visually confirmed against the fresh
  `pasarjaya.co.id` org: the Grouped view renders on load by default exactly as designed ("68 issues (645
  findings)" header, correct severity tiles, CVE headings uppercased with an "e.g., ..." sample subheading
  for multi-finding groups, non-CVE headings showing the verbatim title + `template_id`), clicking a
  severity tile correctly filters both the header count and the row list ("4 issues (87 findings)" for
  Critical), and the Grouped/Flat toggle correctly switches to the original unmodified flat table (645
  individual rows, "645 findings" header) and back. Two more real, pre-existing local-dev gaps were found
  and fixed along the way (unrelated to this feature, needed to even reach an authenticated page):
  `frontend/.env.local` never existed, so `NEXT_PUBLIC_API_URL` fell back to an unreachable `localhost:8000`
  (the API container's port isn't published to the host — dev only worked before via the fully-Dockerized
  `docker compose` stack, never via standalone `npm run dev`); worked around for this session only via a
  transient `.env.local` pointing at the API container's internal Docker IP, removed afterward since it's
  not gitignored and the IP isn't stable across container recreation — a real, durable fix (e.g. publishing
  a host port, or documenting the correct local-dev API URL) is a separate, pre-existing gap worth raising
  with the team, not fixed here.

### Explicitly not in scope
Any change to detection logic or finding volume — display-only aggregation. Bulk actions operating on a
whole group at once (a reasonable follow-up, needs a new bulk-update endpoint). A DB-backed integration
test harness for the new endpoint (would be the first one in the repo; the GROUP BY/DISTINCT ON SQL
correctness was verified against real data manually instead, matching this session's established practice).

---

## 2026-07-12 — Risk Engine Redesign, Stage 4 (final): Likelihood × Impact matrix

Fourth and final stage of the NIST/OWASP-aligned risk-engine redesign (Stage 1: asset/org criticality
multiplier; Stage 2: CVSS score/vector data flow; Stage 3: SSVC escalation). Stage 4's originally-stated
goal: "Full restructure to an explicit Likelihood × Impact matrix, replacing the ad-hoc
`critical_penalty`/`high_penalty` global score-cap heuristic."

### Investigation before implementation (2 Explore agents + a Plan agent, all grounded in live code/DB)
- **A large hidden blast-radius constraint**: `RiskScore`'s ORM has 9 dedicated integer columns
  (`network_security_score`, etc.) *in addition to* the JSONB `score_breakdown` — `risk_worker.py`
  writes them via hardcoded lookups, and `report_service.py` reads them **directly by column name**,
  never touching the JSONB. A genuine "full restructure" of category scoring would require a migration
  and touch report generation — a materially bigger, riskier change than anything Stages 1-3 did.
- **Real signal distributions overturned the naive design**: across 1,335 real open findings on the 3
  target orgs, critical+high severity = 45.6% of everything (not a small minority — severity alone
  barely discriminates). `Asset.criticality` is 98.1% constant at 5 for these orgs (Stage 1's own
  org-ceiling finding recurring). SSVC fields are still 100% NULL on every real persisted finding (Stage
  3's code is correct, but no rescan has touched these rows yet). The only signal that actually
  discriminates today is exploit intelligence (KEV/EPSS) and, secondarily, CVSS score.

### Decision: scope kept to a "narrow" replacement, not a full restructure
Kept the entire 9-category weighted-sum scoring, `CATEGORY_WEIGHTS`, the `RiskScore` DB schema, and
`report_service.py` completely untouched — zero migration, zero blast radius there. Replaced **only** the
ad-hoc global cap block with a principled per-finding Likelihood×Impact classification, whose worst
org-wide rating drives a new, still-simple cap. A "full" restructure (rewriting category-scoring math,
requiring a schema migration) was designed and rejected as disproportionate for stage 4 of 4 given Stages
1-3's established size/risk cadence — left as a possible future Stage 4a (schema/report decoupling) /
Stage 4b (math rewrite) split, not attempted now.

Two more decisions confirmed via AskUserQuestion before implementation:
1. **Keep an asset/org-criticality shift on the Impact axis.** Verified this correctly rates all 8 real
   CISA-KEV-confirmed findings on `kpi.go.id` as Critical (2 of them are only medium-severity, CVSS
   5.4-6.1, but are confirmed actively exploited — getting this right matters more). **Accepted, stated
   trade-off**: an ordinary high-severity finding with zero exploit intelligence on a criticality≥4 asset
   (the dominant ~98% case in real data) now caps 10 points harsher than before this stage (74 vs. 84).
2. **Confidence excluded from the Likelihood axis.** Live data showed `VERSION_MATCH_CONFIDENCE=0.3` is a
   fixed per-detection-method constant applied to 69% of real non-KEV high-EPSS findings; a naive "low
   confidence demotes Likelihood" rule would have silently suppressed exactly the population Stage 3
   exists to elevate. Confidence keeps its existing, separate multiplicative role in
   `compute_severity_penalty()` — not removed, just not double-applied here.

### Added
- **Impact axis** (`ImpactLevel`, `compute_impact_level()`): CVSS-driven using NVD's own published
  Qualitative Severity Rating Scale boundaries (≥9.0 Critical, 7.0-9.0 High, 4.0-7.0 Medium, <4.0 Low),
  falling back to severity label when no CVSS exists (43.6% of real findings), then shifted one tier by
  `criticality_multiplier` per decision 1 above.
- **Likelihood axis** (`LikelihoodLevel`, `compute_likelihood_level()`): driven by `exploit_boost`, which
  can only take one of 6 discrete real values (`{1.0, 1.2, 1.25, 1.3, 1.5, 1.75}` from
  `exploit_intel.py`/`version_cve_intel.py`'s `max()`-combination) — cleanly partitioned at `>=1.5` (High,
  KEV) and `>1.0` (Medium, EPSS/SSVC).
- **`MatrixRating` + `_RISK_MATRIX`**: OWASP's own published Risk Rating Methodology 3×3 table, extended by
  one Impact column the same monotonic way OWASP's docs describe for a 4th tier — an explicit lookup
  table, not a formula.
- **Replaced the 4-branch ad-hoc cap** (`critical_penalty >= 75 → 60`, etc.) with a scan over every
  finding's matrix rating org-wide, capping at thresholds derived from `score_to_grade`'s own existing
  boundaries (`_RATING_CAPS = {CRITICAL: 59, HIGH: 74, MEDIUM: 89}` — one less than the grade cutoffs
  90/75/60, not fresh hand-picked numbers).
- Per-finding `impact`/`likelihood`/`matrix_rating` added to the existing (never-persisted) `penalties`
  audit dict — same transparency precedent Stages 2-3 already established, no `score_breakdown` shape
  change (that dict is iterated generically by 3 frontend components; a new non-category key would render
  as a bogus category row).
- `OrgRiskScore.score_version` bumped `"1.2"` → `"1.3"`.
- **`score_version` now exposed in both `/scores/history` and `/{org_id}/score-history` API responses** —
  purely additive JSON keys, zero shape change, no frontend touch required. Stages 1-3's formula bumps
  were completely invisible to any frontend/API code before this; a full visual chart annotation for the
  methodology discontinuity remains a named, separate follow-up (needs frontend sign-off per this
  project's own convention, not done here).
- **Tests**: 35 new cases in `test_risk_engine.py` (`TestComputeImpactLevel`'s boundary/fallback/shift
  coverage, `TestComputeLikelihoodLevel`'s 6-value coverage, `TestRiskMatrix`'s 12-cell literal coverage,
  cap-tier-in-isolation tests, a penalties-dict shape test). Two existing tests updated for the new cap
  values (`test_single_high_finding_cannot_reach_grade_a` 84→89, `test_multiple_criticals_approach_f`
  60→74). **Two more existing tests required a real fix, not just a number bump**: `test_old_finding_decays`
  and `test_low_confidence_finding_shifts_category_score_less_than_high_confidence` asserted that decay/
  confidence always move `overall_score` — but the new matrix rating is deliberately driven only by
  severity/CVSS/exploit-intel/criticality, not decay or confidence, so a cap that fires identically for
  both variants now masks that difference at the overall-score level (the underlying category score still
  differs correctly, proven by keeping/adding category-level assertions). This is judged correct, not a
  regression: an OWASP-style risk rating for "how bad is this vulnerability" isn't supposed to fade with
  time the way a decaying penalty sum does — a stale, still-open Critical-rated finding isn't safer for
  having sat open 90 days. Full suite: **260 passed, 1 skipped** (was 225 before this stage).

### Verified against real production data
- Baseline: `kpi.go.id` 60/C, `pasarjaya.co.id` 44/D, `pu.go.id` 45/D (all `score_version 1.2`).
- **All 8 real CISA-KEV-confirmed findings on `kpi.go.id` classify `MatrixRating.CRITICAL`** — including
  the 2 medium-severity/CVSS-5.4-6.1 ones, via the criticality-shift escalating Impact from Medium→High,
  combined with Likelihood=High (KEV) — the exact scenario decision 1 above was made to get right.
- **Contrast case, real data**: a genuine ordinary high-severity/no-CVSS/criticality-5/no-exploit-intel
  finding on `kpi.go.id` (the dominant ~98% real case) classifies `MatrixRating.HIGH`, not `CRITICAL` —
  concrete proof this design differentiates confirmed-exploited findings from ordinary ones instead of
  just relabeling severity.
- Published a real `risk.compute` for all 3 orgs — predicted movement matched exactly: `kpi.go.id`
  **60/C → 59/D** (a real, small, fully explainable grade-boundary crossing); `pasarjaya.co.id`/`pu.go.id`
  unaffected at 44/D and 45/D (category-weighting saturation already dominates before any cap applies,
  same pattern Stage 2/3 documented). `score_version` confirmed `"1.3"` in the DB and in both API
  responses (`/scores/history` and `/organizations/{id}/score-history`).
- Full regression suite: **260 passed, 1 skipped**, no regressions. Deployed by restarting `api` and
  `worker-risk`.

### Explicitly not in scope for this stage
Any change to the 9-category weighted-sum scoring mechanics, `CATEGORY_WEIGHTS`, `RiskScore`'s DB schema,
or `report_service.py` (the rejected "full restructure" option). A frontend chart annotation/visual marker
for the score-methodology discontinuity. **This is the last of the originally-planned 4 stages** — no
Stage 5 implied by this entry; any further risk-engine work (e.g. a future Stage 4a/4b split, or acting on
SSVC `Exploitation=active` once real coverage data exists) would be a new, separately-scoped effort.

---

## 2026-07-12 — Risk Engine Redesign, Stage 3: SSVC (Exploitation/Automatable) escalation

Third of the 4-stage NIST/OWASP-aligned risk-engine redesign (Stage 1: asset/org criticality multiplier;
Stage 2: CVSS score/vector data flow, no formula change). Stage 3's goal: integrate SSVC (Stakeholder-
Specific Vulnerability Categorization, CISA's framework) into scoring.

### The gap found before writing this stage's plan
CISA publishes an SSVC assessment (`Exploitation`: none/poc/active, `Automatable`: yes/no) inside a
`"CISA ADP Vulnrichment"` container in `cve.circl.lu`'s `containers.adp[]` array — the SAME array
`version_cve_intel.py::_extract_cvss()` already walks for CVSS data. Confirmed live for real CVE IDs this
platform's `version_cve_correlation` feature (M21) already flags. `_extract_cvss()`'s `key.lower().
startswith("cvssv")` filter walked right past this data and silently discarded it — fetched, not merely
unfetched. SSVC only ever applies to `version_cve_correlation` findings (nuclei templates carry EPSS, a
separate signal, but nothing SSVC-shaped).

### Decision (via AskUserQuestion, before implementation)
Unlike Stage 2 (which deferred its only candidate formula change — a Scope-Changed multiplier — because
CVSS's own base score already partially counts Scope), this stage ships a real, small escalation
multiplier: `Automatable=yes` and `Exploitation=poc`. `Exploitation=active` deliberately contributes
nothing — CISA's own KEV catalog already represents "confirmed active exploitation" for the same
real-world fact (`exploit_intel.py`'s `KEV_BOOST`, already the dominant 1.5-1.75x signal), and escalating
on both would double-count. The difference in verdict from Stage 2 reflects a real difference in the
underlying facts: `Automatable` has zero existing analog anywhere in the codebase (confirmed via grep) —
genuinely new information, not a re-emphasis.

### Added
- **`_extract_ssvc()`** (`backend/app/services/version_cve_intel.py`) — parses CISA's
  `{"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "poc"}, {"Automatable": "yes"}, ...]}}}`
  shape (`options` is a list of single-key dicts, not a flat dict). `_extract_record()` gains two keys
  (`ssvc_exploitation`, `ssvc_automatable`), same pass-through pattern as `cvss_score`. No migration —
  `VersionCveCache.cves` is schemaless JSONB.
- **`SSVC_POC_BOOST = 1.25`, `SSVC_AUTOMATABLE_BOOST = 1.3`, `compute_ssvc_boost()`** — escalation-only,
  floor 1.0, ordered below `KEV_BOOST` (1.5) so a CISA-confirmed KEV entry never loses to an SSVC-only
  status. Combined via `max()` with the existing EPSS/KEV `exploit_boost` in
  `workers/risk/risk_worker.py::_load_findings()` — same established mechanism as KEV-vs-EPSS, not a new
  one. `compute_severity_penalty()`/`FindingInput`/`risk_engine.py` untouched this stage.
- SSVC data stored in each finding's `proof` JSONB (`coverage_worker.py::_scan_version_cve`), not a new
  `Finding` column — mirrors the existing `confidence_score` precedent (arguably the most load-bearing
  per-finding scoring input in the engine, and it's never had its own column either). No changes needed to
  `make_finding()`, `persist_findings()`, or `content_refresh_updates()` as a result.
- `OrgRiskScore.score_version` bumped `"1.1"` → `"1.2"` (a real formula change this time; Stage 2 correctly
  didn't bump it since it made none).
- **Tests**: 12 new cases in `test_version_cve_intel.py` (`TestExtractSsvc`'s real-shaped/malformed/absent
  coverage, `TestComputeSsvcBoost`'s escalation/ordering/regression-guard-on-`active` coverage) and 2 new
  cases in `test_scan_pipeline_state.py` (`_scan_version_cve` proof-threading, with-data and
  missing-data-defaults-to-None). Full suite: **225 passed, 1 skipped** (was 213 before this stage).

### Verified against real production data
- Forced a live cache refresh (deleted the 6 already-cached products' rows, re-ran `_scan_version_cve` for
  all 3 real orgs) rather than waiting out the 7-day staleness window — confirmed real, fresh CIRCL fetches
  in the logs and in the cache table, including the exact `CVE-2026-49975` → Exploitation=poc/Automatable=yes
  values hand-verified during planning.
- **Real coverage**: of 54 cached CVEs across the 3 orgs' 6 products, 50 (93%) had SSVC data at all — 2
  `poc`, 1 `active`, 47 `none`; 24 `Automatable=yes`.
- **The empirical KEV-overlap cross-check that justified excluding `Exploitation=active`**: the single
  real `Exploitation=active` CVE found (`CVE-2026-9082`) **is already in CISA's own KEV catalog**
  (`is_kev=true`, EPSS=0.846) — 100% overlap in this sample, directly confirming the double-counting
  concern was real, not hypothetical. Meanwhile all 24 `Automatable=yes` CVEs have near-zero EPSS (mostly
  0.002-0.01) and **zero** KEV overlap — confirming `Automatable` surfaces real signal EPSS/KEV miss
  entirely, not a duplicate of either.
- **Proved the exploit_boost combination mechanism directly** against these exact real (CVE, SSVC, KEV)
  triples: `CVE-2026-49975` (poc/yes, not KEV) → boost 1.3; `CVE-2026-44631` (automatable-only, not KEV) →
  boost 1.3; `CVE-2026-9082` (active/yes, IS KEV) → `max(1.3, 1.5) = 1.5`, KEV correctly wins, no stacking.
- Published a real `risk.compute` for all 3 orgs — `score_version` confirmed `"1.2"`; overall scores
  unchanged (`kpi.go.id` 60, `pasarjaya.co.id` 44, `pu.go.id` 45) since their currently-*persisted* findings
  predate this fix (their `proof` blobs don't yet carry SSVC keys) — expected to move on the next real scan
  that rediscovers them, same "code is correct, needs a rescan to touch existing rows" pattern as Stage 2's
  nuclei-vector finding.
- Full regression suite: **225 passed, 1 skipped**, no regressions. Deployed by restarting `worker-scanner`
  (runs `coverage_worker.py`) and `worker-risk`.

### Explicitly not in scope for this stage
`Exploitation=active` contributing to scoring (excluded — confirmed correct via the KEV-overlap check
above, not just deferred pending it). A real `Finding` column for SSVC data (proof JSONB only). Stage 4
(full Likelihood×Impact matrix replacing the ad-hoc global `critical_penalty`/`high_penalty` cap) —
untouched, unplanned in detail. SSVC's own decision structure is inherently matrix-shaped (Exploitation ×
Automatable × Mission impact) — this stage's additive multiplier is a deliberate placeholder, the same way
Stage 1's criticality multiplier preceded a more complete future restructure.

---

## 2026-07-12 — Risk Engine Redesign, Stage 2: CVSS vector data flow + parser (no formula change)

Second of the 4-stage NIST/OWASP-aligned risk-engine redesign (Stage 1: asset/org criticality
multiplier). Stage 2's stated goal: "parse `Finding.cvss_vector` for CVSS Environmental-style C/I/A
sub-metrics to refine Impact." Investigation before implementation found the groundwork in worse shape
than expected — reframed this stage the same way Stage 1 was reframed, as "connect what's already there"
more than "build new."

### The gap found before writing this stage's plan
- **`Finding.cvss_vector` was 100% NULL across all 1,576 real findings** — nothing anywhere wrote it.
- **`Finding.cvss_score` was ALSO NULL for the majority — all 822 `version_cve_correlation` findings**
  (Milestone 21's version-to-CVE feature, 52% of all real findings). The matched CVE's real `cvss_score`
  was already known at persist time (`coverage_worker.py::_scan_version_cve` already used it to derive
  `severity`, and stashed it in the finding's `proof` JSONB) — but never passed to `make_finding()` as a
  real column value, because `scanner_common.py`'s `make_finding()`/`persist_findings()` had no
  `cvss_score`/`cvss_vector` parameter at all (only `cve_ids` was ever added, M21). This meant
  `risk_engine.py`'s existing CVSS-blending code — already shipped, already used by nuclei findings —
  **never fired for 822 of 1,576 real findings**, not a Stage-2-specific bug but a prerequisite gap
  Stage 2's own goal depended on closing first.
- Only nuclei-sourced findings (614 of 1,576, 22 with a non-null score) ever got `cvss_score` populated,
  via nuclei_worker.py's own separate persistence path — and it never read the sibling `cvss-metrics`
  (vector) field sitting in the same template classification dict as the already-read `cvss-score`
  (confirmed live: 6,551 mounted nuclei templates carry both).
- **Frontend/API were already fully wired for display, dead code today**: `findings.py`'s
  `_finding_to_dict()` already returns `cvss_vector`; `FindingDetailModal.tsx` already conditionally
  renders the raw vector string. No frontend/API changes needed this stage — populating the column
  activates existing dead code automatically.

### Decision (via AskUserQuestion, before implementation)
Ship the data-flow fix + a CVSS vector parser (C/I/A + Scope extraction) with **zero scoring-formula
changes this stage**. A candidate follow-up — a small Scope-Changed (`S:C`) escalation multiplier,
mirroring `exploit_boost`'s shape — was explicitly designed and then deferred: CVSS's own base-score
formula already applies an internal 1.08x multiplier for Scope-Changed vulnerabilities, so a second,
separate multiplier from the same signal would be a deliberate re-emphasis of an already-partially-counted
factor, not new information the way asset criticality was in Stage 1. Keeping this stage formula-free
also kept the real-data verification clean: any score movement observed is attributable purely to
"previously-missing CVSS data now flowing," never conflated with a new formula hook. A full CVSS
Environmental re-scoring (per-asset CR/IR/AR fields, the FIRST.org modified-impact formula) was
considered and rejected outright for this stage — bigger than either remaining stage in the original plan,
not requested.

### Added
- `make_finding()`/`persist_findings()` (`workers/scanner/scanner_common.py`) gained `cvss_score`/
  `cvss_vector` parameters, threaded into the INSERT values and — critically — added to
  `content_refresh_updates()`'s field list (previously missing both), so a finding's CVSS data actually
  refreshes on rediscovery instead of freezing at whatever was inserted first (proven by a new real-Postgres
  integration test, not just asserted).
- `coverage_worker.py::_scan_version_cve()` now passes `cvss_score=cve.get("cvss_score")` — pure plumbing,
  the value was already computed and already stashed in `proof`.
- `nuclei_worker.py` now also reads `classification.cvss-metrics` (alongside the pre-existing
  `cvss-score` read) and persists it as `cvss_vector`, including in its own separate
  `content_refresh_updates()` list, which was missing it too.
- **New `parse_cvss_vector()`** (`risk_engine.py`): CVSS 3.0/3.1 only (~95% of real template vectors:
  4,501 are 3.1, 1,718 are 3.0, identical C/I/A encoding) → `CvssImpactMetrics(confidentiality, integrity,
  availability, scope_changed)`. CVSS 2.0 (different `N/P/C` encoding, 297 templates) and CVSS 4.0
  (different `VC/VI/VA`+`SC/SI/SA` structure, 29 templates) fail closed to `None` rather than being
  misparsed — verified against the real edge cases found in the mounted template corpus (a handful of
  quoted vectors, one with no `CVSS:x.y/` prefix at all). `FindingInput.cvss_vector` and
  `risk_worker.py::_load_findings()` thread the raw string through; `_compute_category_score()` parses it
  per finding and stashes the result into the (in-memory-only, never persisted) per-finding `penalties`
  audit dict for future-stage use. `compute_severity_penalty()` itself is untouched — takes no new parameter.
- **New `workers/scripts/backfill_version_cve_cvss.py`** (`--dry-run`/`--org-id`) — reuses data already
  sitting in each finding's `proof` JSONB, no CIRCL re-fetch needed. Idempotent (`cvss_score IS NULL AND
  proof->>'cvss_score' IS NOT NULL`).
- **Tests**: 11 new cases in `test_risk_engine.py` (`TestParseCvssVector`'s valid/invalid-schema/edge-case
  coverage, plus a regression-guard proving an otherwise-identical finding scores byte-identically with vs.
  without a populated `cvss_vector` — the load-bearing proof that this stage really is formula-risk-free,
  not just an assumption), 4 new cases in `test_scan_pipeline_state.py` (`make_finding` and
  `NucleiWorker._parse_finding()` threading), and 1 new real-Postgres integration test in
  `workers/tests/test_finding_upsert_integration.py` proving the `content_refresh_updates` fix actually
  works, not just compiles. Full suite: **213 passed, 1 skipped** (was 202 before this stage).

### Verified against real production data
- **Baseline**: `kpi.go.id` 60/C, `pasarjaya.co.id` 44/D, `pu.go.id` 45/D (all `score_version 1.1`, carried
  over from Stage 1) — 154/535/97 `version_cve_correlation` findings per org, 0% with `cvss_score` in all
  three.
- **Backfill**: dry-run first, then applied for real, scoped to the three target orgs. **154/154 on
  `kpi.go.id`, 516/535 on `pasarjaya.co.id`, 61/97 on `pu.go.id`** actually had a usable score in `proof`
  (the remainder genuinely have no CVSS score in CIRCL's own data — not a bug). Verified directly: 0
  mismatches between the newly-populated `cvss_score` column and `proof->>'cvss_score'` across all three orgs.
- **A real `risk.compute` published through RabbitMQ for each org showed zero overall-score movement** —
  investigated rather than assumed safe: `patch_hygiene` (where `known_cve` findings map) was already
  capped at **0/F for all three real orgs** (`MAX_PENALTY_PER_CATEGORY = 100.0`; each org already has
  60-580+ open critical/high findings in that one category alone, blowing past the cap regardless of any
  per-finding CVSS-blend adjustment). This is the same "cap saturation masks a marginal formula change"
  pattern found repeatedly this engagement (Stage 1's `kpi.go.id`, M21) — not a sign the fix didn't work.
  **Proved the mechanism directly instead**: ran `compute_severity_penalty()` against real (severity,
  cvss_score) pairs pulled from these exact orgs' findings — e.g. a real "medium"/6.6 pair went from a
  penalty of 8.0 to 12.25 (+53%), a real "low"/3.7 pair from 3.0 to 6.125 (+104%), a real "high"/8.8 pair
  from 15.0 to 18.5 (+23%) — confirming the blend is real and meaningfully sized per-finding, even though
  these three orgs' aggregate scores don't currently expose it.
- **Nuclei vector wiring verified against a live, real vulnerability**: ran the actual `nuclei` binary
  (not a mock) against a real production host (`automation.pu.go.id`, an internal n8n workflow-automation
  instance) with the exact template already on file for a previously-detected finding
  (`CVE-2026-21858`, an unauthenticated RCE, CVSS 10.0). Real live tool output confirmed
  `classification.cvss-metrics` present alongside `cvss-score` in the actual JSON result (not just in the
  static template file). Piped that real output through the updated `NucleiWorker._parse_finding()`
  directly: correctly extracted `cvss_score: 10.0` and `cvss_vector:
  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"`; `parse_cvss_vector()` on that exact real vector
  correctly resolved to Confidentiality=High, Integrity=High, Availability=None, Scope Changed=True. This
  finding predates the fix, so its stored `cvss_vector` stays empty until the next scan rediscovers it
  (nuclei findings have no retrievable backfill source, unlike `version_cve_correlation`'s `proof` field —
  stated plainly here, not papered over).
- Full regression suite: **213 passed, 1 skipped**, no regressions. Deployed by restarting `worker-nuclei`,
  `worker-scanner` (runs `coverage_worker.py`), and `worker-risk`.

### Explicitly not in scope for this stage
Any scoring-formula change from the parsed C/I/A/Scope data (deferred, see Decision above), full CVSS
Environmental re-scoring with per-asset CR/IR/AR fields (rejected for this stage), and Stage 3 (SSVC
`Exploitation`/`Automatable` integration) / Stage 4 (Likelihood×Impact matrix replacing the ad-hoc global
cap) — untouched, unplanned in detail.

---

## 2026-07-12 — Risk Engine Redesign, Stage 1: Asset/Org criticality wired into scoring

After M18-21's detection-tuning pass, the conversation turned to whether `risk_engine.py`'s scoring model
itself should reflect established frameworks rather than its own hand-tuned formula. Agreed direction:
align with **NIST** (SP 800-30/CSF's Risk = Likelihood × Impact, informed by CVSS's own Environmental
metric group for asset-CIA-requirement weighting) and **OWASP** (Risk Rating Methodology's Impact
sub-factors). This is a 4-stage plan, done incrementally with real verification at each step:
1. **Wire asset/org criticality into the existing formula as a multiplier ← this entry**
2. Parse `Finding.cvss_vector` for CVSS Environmental-style C/I/A sub-metrics (not started)
3. Integrate SSVC `Exploitation`/`Automatable` (already flowing through `cve.circl.lu` responses via M21's
   `version_cve_intel.py` but currently discarded) (not started)
4. Full restructure to an explicit Likelihood × Impact matrix, replacing the ad-hoc
   `critical_penalty`/`high_penalty` global score-cap heuristic (not started)

### The gap found before writing this stage's plan
`Asset.criticality`/`environment` and `Organization.criticality`/`environment` already existed in the
schema (1-5 scale, `models.py`). `Organization.criticality` already had a working edit path
(`organizations/[id]` UI → `PATCH` endpoint) — but **`risk_engine.py` used neither field anywhere**
(confirmed via full-file grep, zero matches), and **`Asset.criticality` had no write path at all**
(read-only: filter, CSV export, graph display only). Same "capacity exists in the schema/API but was
never wired into the logic that matters" pattern found repeatedly this engagement (M6, M10, M18).

### Added
- **`PATCH /assets/{asset_id}`** (`backend/app/api/v1/endpoints/assets.py`) — the first-ever write path
  for `Asset.criticality`/`environment`. `require_analyst`-gated, audits via the same
  `bg.add_task(audit_log, ...)` pattern as `organizations.py`'s `update_organization`, stamps
  `asset.labels["criticality_source"] = "manual"` so nothing downstream ever overwrites a human's choice.
- **`workers/asset_criticality.py`** (new) — `infer_asset_criticality(hostname, is_root_domain,
  org_criticality)`, a hostname-keyword classifier (styled like `web_crawl_worker.py`'s existing
  `AUTH_PATH_RE`/`ADMIN_PATH_RE` tables) giving new assets a sensible non-manual default instead of being
  stuck at the schema default of 3 forever: dev/staging/uat keywords → de-escalate; auth/payment/admin
  keywords or root-domain or prod/www → escalate; otherwise falls back to the org's own criticality.
  Environment keywords are checked *first*, deliberately — `api-staging.foo.com` must still classify as
  low-value (a staging payment box is still disposable infrastructure).
- Hooked at **asset-creation time** in `workers/scanner/discovery_worker.py::_persist_assets` — computed
  only for the `pg_insert(...).values(**asset_values)` INSERT path, deliberately excluded from the
  `set_={...}` conflict-update dict, so re-running discovery on an existing asset never touches a
  previously-set `criticality`/`labels` again.
- **`workers/scripts/backfill_asset_criticality.py`** (new, `--dry-run` capable, optional `--org-id`) —
  one-off backfill for the pre-existing stuck-at-3 population, idempotent (targets only
  `criticality == 3 AND labels->>'criticality_source' IS NULL`, so it never overwrites a manual PATCH or a
  prior backfill run).
- **`risk_engine.py`**: `CRITICALITY_MULTIPLIERS = {1: 0.70, 2: 0.85, 3: 1.00, 4: 1.15, 5: 1.30}`,
  `compute_criticality_multiplier()`, `combine_criticality(asset, org) = max(asset or 3, org or 3)`.
  `compute_severity_penalty()` gained a trailing `criticality_multiplier` param, applied **unclamped**
  (unlike `exploit_boost`'s floor) — a genuinely low-value asset's findings must actually shrink, not just
  fail to grow. `FindingInput.criticality` defaults to 3 (multiplier 1.0) so a finding with no criticality
  signal scores identically to before this field existed. `workers/risk/risk_worker.py::_load_findings()`
  now joins `Asset.criticality` (safe inner join — `Finding.asset_id` is `NOT NULL`) and fetches
  `Organization.criticality` once per org, combining via `max()`.
- `OrgRiskScore.score_version` bumped `"1.0"` → `"1.1"` — a free forensic marker (field already existed,
  was dead) for "which formula produced this row." No migration, no chart-annotation work, matching
  M14/M18/M21 precedent for scoring-formula changes.
- **Tests**: 18 new cases in `backend/tests/unit/test_risk_engine.py` (multiplier table, `combine_criticality`
  direction/fallback cases, penalty scaling both up *and down* — the below-1.0 case unlike `exploit_boost` —
  and an integration test through the full `compute()` pipeline proving criticality 1 vs 5 moves both
  category and overall scores in the right direction) and 9 new cases in `test_scan_pipeline_state.py`
  for `infer_asset_criticality`'s keyword-precedence/escalation/baseline-clamping behavior. Full suite:
  **202 passed, 1 skipped** (was 184 before this stage).

### Verified against real production data
- **Baseline** (pre-deploy): `kpi.go.id` 60/C, `pasarjaya.co.id` 51/D, `pu.go.id` 47/D — all `score_version 1.0`.
- **The "no-op" check wasn't one — for a real reason, not a bug.** All three real target orgs already had
  `Organization.criticality = 5` set via the pre-existing (previously scoring-inert) org edit UI. Wiring it
  into scoring for the first time immediately, correctly moved their scores: `pasarjaya.co.id` 51→43,
  `pu.go.id` 47→45. `kpi.go.id` stayed at exactly 60 — not because nothing changed, but because its raw
  weighted score already sat above the pre-existing `critical_penalty>=75→cap 60` ceiling both before and
  after (confirmed via its 34 open criticals / 83 open highs comfortably clearing that threshold either
  way). This *is* the intended real-world behavior of Stage 1: any org that had already configured a
  criticality the platform was silently ignoring now finally gets it reflected.
- **Asset-level escalation/de-escalation**, proven via real `PATCH /assets/{id}` + a real `risk.compute`
  published through RabbitMQ (not a direct function call) + inspecting the actual `risk_scores` row:
  attempted on `pu.go.id` first, but that org's `Organization.criticality` is already 5 (the ceiling), so
  `combine_criticality`'s `max()` made any single-asset PATCH there a true no-op by design — switched to
  `ACME Corp` (`org_criticality=4`, a lower floor) to get a real signal:
  - Asset at its natural `criticality=4`: `misconfiguration` category score 52.
  - Escalated to 5 via the real endpoint → real `risk.compute` → category score dropped to **46** (worse,
    matching the expected 1.15x→1.30x multiplier jump).
  - De-escalated to 1 → category score returned to **52**, unchanged from the criticality=4 baseline —
    proving the org's floor genuinely protects against a single low asset value dragging a score down
    below what the org's own setting already guarantees (`max()`, not average).
  - All test-asset mutations reverted to their original values after verification (`pu.go.id`'s
    `apigw.pu.go.id` back to criticality 3/no labels, ACME's `app.acme-test.example` back to 4/no labels),
    each followed by a real recompute confirming the restore.
- **Backfill**: dry-run inspected first (sane output — `dev.`/`staging.`/`uat.` hosts → 2, `payment.`/`api.`/
  `admin.`-style hosts → 5, plain subdomains → org baseline), then applied for real, scoped to the three
  target orgs only: **293 assets updated on `kpi.go.id`, 866 on `pasarjaya.co.id`, 350 on `pu.go.id`**
  (1,509 total). Recomputing afterward showed scores essentially unchanged (`kpi.go.id` 60, `pu.go.id` 45,
  `pasarjaya.co.id` 43→44) — expected, since all three orgs' `Organization.criticality` already sits at the
  ceiling (5), so `max(asset, org)` is still dominated by the org value regardless of what any individual
  asset was just backfilled to. **This is an important, honest limitation to flag**: for these three real
  orgs specifically, Stage 1's asset-level granularity has no scoring effect *today* — it only becomes
  load-bearing if the org-level criticality is ever lowered below 5, or for any future org onboarded at the
  schema default. The backfilled values are still correct and useful independent of scoring (asset-list
  filtering/display, and the floor for whenever org criticality changes).
- Full regression suite: **202 passed, 1 skipped**, no regressions. Deployed by restarting `api`,
  `worker-discovery`, `worker-risk` (`workers/` and `backend/app` are volume-mounted, but running processes
  need a restart to reload changed modules).

### Explicitly not in scope for this stage
CVSS vector parsing, SSVC integration, and replacing the ad-hoc global `critical_penalty`/`high_penalty`
cap are Stages 2-4 — untouched here.

---

## 2026-07-12 — Milestone 21: Version-to-CVE correlation (highest-risk item of the 4-part plan)

Final item of the detection-tuning plan (M18 endpoint-cap → M19 API/GraphQL → M20 ffuf depth → **this**).
Flagged from the start as the noisiest, most false-positive-prone of the four — a detected version
falling inside a CVE's published affected range is not proof of exploitability (a vendor can backport a
fix without bumping the version string) — so this was built last, deliberately, once the lower-risk items
were already shipped and verified.

### Added: keyless CVE-by-version correlation via cve.circl.lu
- **New table** `version_cve_cache` (migration `017_version_cve_cache`) caching up to ~20 recent CVEs per
  product (bounded — `cve.circl.lu` paginates at 10/page and some products have 600+ historical CVEs;
  recent ones are what a missing nuclei template is most likely to be). Different refresh model from
  `eol_intel`'s fetch-once-forever: a product's CVE list genuinely grows over time, so a cached entry
  refreshes if older than 7 days.
- **New module** `backend/app/services/version_cve_intel.py`: `PRODUCT_VENDOR_MAP` (17 products this
  platform has actually detected with real version data — Apache, OpenSSL, PHP, Nginx, WordPress, Drupal,
  etc.), real version-range matching (`version_in_range`) against CIRCL's actual `{"version": "2.4.17",
  "lessThanOrEqual": "2.4.67", "status": "affected"}` shape (verified against the live API before writing
  the parser — confirmed `"unaffected"` entries must never match, and CVSS commonly lives in
  `containers.adp[].metrics[]`, not `containers.cna`, in real records).
- **New scanner-family check** `_scan_version_cve` in `coverage_worker.py`, wired the same safe way as
  `_scan_eol` (Technology-table read, no cross-worker race — see M19's GraphQL note for why that
  distinction matters). Every finding is explicitly framed as "**Potential** CVE-XXXX" in its title, never
  asserted as confirmed, and carries `confidence_score: 0.3` in `proof` — lower than nuclei's own
  low-confidence CVE tier (0.5, M7's A2) since there's no template/response confirmation at all here,
  purely a version comparison. This confidence value feeds `risk_engine.py`'s existing confidence-based
  penalty dampening (already built for nuclei's own low-confidence matches) — no scoring-engine change
  needed, just correctly populating a signal it already knows how to use.

### Fixed (prerequisite, found while building this): `cve_ids` silently dropped for every non-nuclei finding
- **File**: `workers/scanner/scanner_common.py` (`make_finding`, `persist_findings`)
- `make_finding()` never had a `cve_ids` parameter at all, and `persist_findings()` (used by every
  `coverage_worker.py` check) separately hardcoded `"cve_ids": []` regardless of what a finding dict
  contained. Harmless until now — only `nuclei_worker.py` populated `Finding.cve_ids`, through its own,
  entirely separate persistence path. Version-correlation findings are the first non-nuclei source that
  needs this populated (so M14's EPSS/KEV case-insensitive lookup and `cve_id`-based finding filtering
  apply to them too) — added the parameter and made `persist_findings` actually read it.

### Verified against real production data, not just synthetic tests
- Ran `_scan_version_cve` directly against all 3 previously-validated orgs. Real, plausible matches: e.g.
  `pu.go.id`'s and `kpi.go.id`'s Apache HTTP Server instances (2.4.41–2.4.62, already known-outdated from
  M15) matched several real 2026-era CVEs at CVSS 7.3–9.8. Total: **97 findings on `pu.go.id`, 154 on
  `kpi.go.id`, 535 on `pasarjaya.co.id`** (786 combined) — a large volume, expected given how many
  subdomains across these orgs run the same outdated Apache line; each is a distinct, individually
  accurate (asset, CVE) pair, not a duplication bug (spot-checked in the DB).
- **Confirmed the confidence dampening is real, not cosmetic**: traced `risk_engine.py`'s actual penalty
  math — `compute_severity_penalty()` multiplies by `confidence` before the result ever reaches a
  category's total, so each 0.3-confidence finding contributes ~30% of a full-confidence one. Verified
  this by recomputing risk scores for all 3 orgs after persisting: `pu.go.id` 72→60, `pasarjaya.co.id`
  score also moved. The drop is real but explainable — `risk_engine.py` has a *separate*, pre-existing
  global cap (`critical_penalty`/`high_penalty` aggregate thresholds, independent of any one category's
  floor) that a large volume of even-dampened critical/high findings can still cross in aggregate. This
  is existing, unchanged scoring architecture working as designed, not a new bug — but it is a real,
  user-visible effect worth knowing about before treating this feature as "safe to ignore."

### Verification
- 27 new unit tests in `backend/tests/unit/test_version_cve_intel.py` (version-range matching against the
  real verified API shape, CVSS extraction from the real `adp` container path, cache-hit vs.
  cache-stale-triggers-refetch branching via a fake DB) plus 2 in `test_scan_pipeline_state.py`
  (`make_finding` now threads `cve_ids` through, still defaults to `[]` when omitted).
  `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 184
  passed (was 157), 1 skipped, no regressions.
- Restarted `worker-scanner`/`worker-discovery` (`workers/` bind-mounted read-write, no rebuild needed).

### Not yet decided — flagged for the user, not assumed
- Whether 786 findings across 3 orgs in one pass is the right volume, or whether this should be scoped
  down (e.g. `deep_authorized`-only, similar to `fuzz`/`js_analysis_enabled`'s profile gating) or bounded
  more tightly (`version_cve_max_products`, currently 100). Currently ungated — runs for every scan type
  that reaches the scanner-family dispatch, matching `_scan_eol`'s own precedent, not specially restricted.

---

## 2026-07-12 — Milestone 20: ffuf content-discovery depth (recursion + extension fuzzing)

Third item of the 4-part detection-tuning plan (M18 endpoint-cap → M19 API/GraphQL → **this** →
version-to-CVE correlation). The ffuf wordlist itself was already expanded from ~28 to ~200 words earlier
this session (`workers/fuzz_wordlist.py`, shared between both call sites) — this pass looked at the actual
`ffuf` invocation flags themselves, since a bigger wordlist alone doesn't add "depth": ffuf was only ever
fuzzing exactly one directory level, with no extension-widening, in both `web_crawl_worker.py::_run_ffuf`
and `discovery_worker.py::_fuzz_endpoints`.

### Added: bounded recursion + sensitive-file extension fuzzing, `deep_authorized` only
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/scanner/discovery_worker.py`,
  `backend/app/services/scan_profiles.py`
- Verified ffuf's real `-recursion`/`-recursion-depth`/`-e` flags directly (`ffuf -h`) before wiring
  anything, then live-smoke-tested the exact combination against a real target (`pu.go.id`) before
  shipping: the full 198-word list × 11 variants (bare + 10 extensions) = 2,178 requests completed in 48s,
  comfortably inside the existing 120s `-maxtime` budget with headroom to spare.
- `-recursion -recursion-depth 2`: lets ffuf descend into directories it actually finds (bounded to 2
  levels so it can't run away) — this is the literal "depth" the wordlist expansion alone didn't add.
  `-e .bak,.old,.zip,.tar.gz,.sql,.log,.swp,.orig,.save,.config`: widens every wordlist entry with common
  backup/config-file suffixes a bare directory-name guess wouldn't catch on its own (e.g. `config` alone
  vs. `config.bak`/`config.old`).
- Both bounded by the *same* existing `-maxtime`/`-rate` budget every fuzz run already had — this makes
  better use of that existing time budget, not a bigger one. New config keys (`fuzz_recursion_depth`,
  `fuzz_extensions`) default to off (`0`/`""`) so every other profile's behavior is unchanged; only
  `deep_authorized` opts in.

### Verification
- 1 new test in `backend/tests/unit/test_scan_policy.py`, exercising the real end-to-end merge chain
  (established M18 practice, not `apply_scan_profile()` in isolation): confirms `full` gets both new
  values and `quick` doesn't inherit either.
  `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 157
  passed (was 156), 1 skipped, no regressions.
- Restarted `api` (profile change), `worker-crawl` and `worker-discovery` (both ffuf call sites).

---

## 2026-07-12 — Milestone 19: API surface coverage — OpenAPI/Swagger spec mining + GraphQL introspection

Second item of a 4-part detection-tuning plan (M18 endpoint-cap → **this** → content-discovery depth →
version-to-CVE correlation). Investigated what nuclei-templates already covers before building anything:
confirmed real Swagger/OpenAPI *exposure* templates already run via the existing `http/exposures`/
`http/misconfiguration` profile dirs (39 real graphql-related templates exist in the checkout, including
playground/voyager/apollo-sandbox exposure checks), and the crawler already recognizes and prioritizes
`/graphql`/`/swagger`/`/api-docs`-shaped paths (`API_PATH_RE`/`GRAPHQL_PATH_RE`/`SWAGGER_PATH_RE` in
`web_crawl_worker.py`, existing +30 score boost). What's genuinely missing: nothing sends a real GraphQL
`__schema` introspection query (checked — the closest existing template is a weaker
field-suggestion-from-error-message heuristic), and nothing parses a *found* OpenAPI/Swagger spec's body
to extract the routes it documents.

### Added: OpenAPI/Swagger spec parsing → new crawl candidates
- **File**: `workers/crawler/web_crawl_worker.py` (`_analyze_api_specs`)
- Fetches already-crawled Swagger/OpenAPI-shaped URLs and, **only if the response is a genuine spec
  document** (has a `"swagger"`/`"openapi"` key, or a non-empty `"paths"` dict — not just a URL that
  happens to match `/swagger|openapi/`), extracts every documented route as a new crawl candidate. API
  routes are almost never linked from HTML, so a link-following crawler structurally can't find them any
  other way; a real spec enumerates them directly. Mirrors `_analyze_js_endpoints`'s established pattern
  exactly: extracted URLs flow through the same `_validate_urls` → `_persist_endpoints` →
  `_publish_selected_nuclei` path as every other crawler-discovered endpoint (tagged
  `source="api_spec_extracted"`), and a `low`-severity `exposed_api` finding is persisted when a real spec
  is confirmed (already a recognized `risk_engine.py` category — `EXPOSURE_MGMT` — no scoring change
  needed).
- **The JSON-validation gate is load-bearing, not a formality**: manually verified against real data first
  — `pasarjaya.co.id` has 2 already-discovered Swagger-shaped URLs (`/api-docs`, `/api/swagger.json`, both
  HTTP 200), and both return a generic app-level JSON error (`{"status":400,"message":"Gagal akses ke
  server.",...}`), not a real spec. Without the structural check, both would have been wrongly flagged as
  exposed API documentation. Re-ran the real check against these exact two URLs post-build: correctly 0
  findings, 0 extracted endpoints — confirms the filter holds against the actual production data it was
  designed around.

### Added: GraphQL introspection query check
- **File**: `workers/crawler/web_crawl_worker.py` (`_analyze_graphql_endpoints`)
- Sends a real `query IntrospectionQuery { __schema { types { name } } }` POST to already-crawled
  `/graphql`-shaped URLs; a `data.__schema.types` array in the response means introspection is
  unauthenticated-accessible — exposing the entire schema (types/fields/mutations) as a map of the API.
  Persists a `medium`-severity `exposed_api` finding when confirmed.
- **Deliberately built inside `web_crawl_worker.py` itself, not as a `coverage_worker.py` scanner-family
  check** (which is the established pattern for `_scan_eol`/`_scan_tls`/etc.) — caught this during review,
  before shipping: a discovery-phase scanner-family dispatch and the crawl worker's own `WebEndpoint`
  persistence are two independently-scheduled, concurrently-published queue consumers (`scan.crawl` and
  `scan.scanner` are both published from `discovery_worker.py` around the same time, with no ordering
  guarantee between them). A `graphql` scanner-family check querying `WebEndpoint` rows for
  `endpoint_type="graphql"` would very likely run before the crawl worker had persisted any — the exact
  "looks wired but isn't" pattern already found and fixed repeatedly this session (M6 batch-size, M10
  depth/concurrency, M18 scan_profile), just narrowly avoided here by running the check in the same
  worker pass that already computed `endpoint_type` in memory, with no cross-worker dependency at all.

### Verification
- 4 new unit tests in `backend/tests/unit/test_scan_pipeline_state.py`, using a lightweight fake
  `aiohttp.ClientSession` (no new test dependency): the real false-positive rejection case above, a
  genuine spec's routes extracted correctly, GraphQL introspection-enabled correctly flagged, and a
  disabled-introspection response correctly producing no finding. All 17 tests in the file pass (verified
  via the file's own documented transient-`pytest`-in-`worker-nuclei` method).
- Re-ran `_analyze_api_specs` directly against `pasarjaya.co.id`'s 2 real Swagger-shaped URLs post-build
  (not just the unit test) — see above.
- No real `/graphql`-typed endpoint exists in any org scanned so far, so `_analyze_graphql_endpoints`
  wasn't re-verified against live production data the way the spec check was — only the unit-tested
  synthetic cases. Will confirm against a real target if/when one turns up.
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 156
  passed, 1 skipped, no regressions (this file's tests aren't part of that count).
- Restarted `worker-crawl` only (both new methods live entirely in that worker; no `coverage_worker.py`/
  `discovery_worker.py` change survived, per the race-condition finding above).

---

## 2026-07-12 — Milestone 18: "quick"/"vuln" scans have been silently running as deep_authorized

User asked for more/better-tuned detection methods to catch findings that might be slipping through.
Started narrow (a `deep_authorized` crawl-endpoint cap that was lower than "default"'s) and, while
verifying the fix through the real merge chain (the established practice since Milestone 6, which is
exactly what surfaced this), found something far more serious underneath.

### Found and fixed: `crawl_nuclei_max_targets` was backwards for the most-thorough profile
- **File**: `backend/app/services/scan_profiles.py`
- `deep_authorized` (the profile behind `full`/`vuln` scans) capped nuclei-scanned crawl endpoints at
  **25** — *below* the plain `default` profile's **30**. Confirmed against a real scan: `kpi.go.id` had
  112 crawled endpoints score high enough to be nuclei-eligible; only 25 got scanned, 87 legitimately
  interesting endpoints were crawled but never vulnerability-checked. Raised to 100 — in proportion to
  this profile's other budgets vs. "default" (concurrency/bulk_size run ~2.5x default's), not to the
  code-level uncapped fallback (200), to keep scan wall-clock time bounded.

### Found and fixed (far more severe): `DEFAULT_SCAN_POLICY` hardcoded `scan_profile: "deep_authorized"`
- **File**: `backend/app/services/scan_service.py`
- While re-verifying the fix above through `_effective_config()`'s full merge chain, "default" scan type
  resolved to `crawl_nuclei_max_targets: 100` — deep_authorized's *new* value, not default's own 30. Traced
  it to `DEFAULT_SCAN_POLICY["scan_profile"] = "deep_authorized"`, sitting in the exact same
  scan-type-agnostic dict this file already documents fixing for `crawl.depth` (Milestone 9-era) and
  `rate_limits.nuclei_concurrency`/`nuclei_bulk_size` (Milestone 10) — merged in via `_policy_to_config()`
  *before* `apply_scan_profile()` ever resolves a profile, so a hardcoded value here wins over every scan
  type's own intent unconditionally. `scan_profile` itself had never been audited for this same pattern.
- **Confirmed against real production data, not just the trace**: every persisted `scans.config` for a
  `quick`-type scan showed `scan_profile: "deep_authorized"`, never `"safe"`. A user requesting a
  lightweight, narrow-footprint "quick" scan has been silently getting the full authorized/deep profile
  instead — all severities including info, `automatic_scan` template auto-selection,
  `network_safe`+`cloud_exposure`+`takeover` nuclei profiles, ffuf content-fuzzing, JS analysis. This is a
  real operational/authorization-scope concern, not just a config nicety: "safe" mode exists specifically
  for cases calling for a narrower footprint, and that guarantee has not been holding.
- **Audited every other key in the same policy dict for the identical pattern** (systematic diff:
  `_policy_to_config(DEFAULT_SCAN_POLICY)`'s output against every scan type's own `DEFAULT_SCAN_CONFIG`,
  not a one-off manual check) and found **7 more** silently clobbered `quick`/`vuln` settings:
  `scan_timeout` (900 forced instead of `quick`'s 300s), `crawl_nuclei_batch_size` (8 instead of 5),
  `crawl_max_targets`/`crawl_max_total_urls` (200/2500 instead of 100/1000), `automatic_scan`/
  `use_tech_tags` (forced `True` instead of `quick`'s `False`/`False`), and `enrichment_enabled` (forced
  `True` instead of both `quick`'s and `vuln`'s own `False`). Removed all 8 keys from `DEFAULT_SCAN_POLICY`
  the same way `depth`/`nuclei_concurrency`/`nuclei_bulk_size` were already removed — each scan type's own
  `DEFAULT_SCAN_CONFIG` value now flows through unclobbered unless an org explicitly overrides it via
  `Organization.scan_policy` (the legitimate use for this layer).
- **A second, independent instance of the same bug class**: `_policy_to_config()`'s
  `enrichment_enabled`/`enrichment_baseline` mappings hardcoded a `, True` fallback
  (`enrichment.get("enabled", True)`) — every *other* key in that function defaults to bare `None` so an
  unset org policy doesn't clobber anything. Removing `"enabled"` from `DEFAULT_SCAN_POLICY`'s own
  `enrichment` dict alone wasn't sufficient; the function's own default silently reintroduced identical
  clobbering from a different spot. Fixed both defaults to bare `None`, matching every other key's pattern.

### Verification
- Systematic diff script (not spot-checks): compared `_policy_to_config(DEFAULT_SCAN_POLICY)`'s output
  key-by-key against every scan type's own `DEFAULT_SCAN_CONFIG` entry, confirmed zero remaining conflicts
  after the fix.
- 4 new tests in `backend/tests/unit/test_scan_policy.py`, all exercising the real end-to-end
  `_effective_config()` merge chain (not `apply_scan_profile()` in isolation): the crawl-cap ordering,
  all 8 previously-clobbered `quick` keys resolving correctly in one assertion pass, `vuln`'s
  `enrichment_enabled`, and a bare `"default"` scan type resolving to the `"default"` profile.
  `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 156
  passed (was 152), 1 skipped, no regressions.
- Restarted `api` (only container that imports `scan_service.py` — no worker does, scan config is fully
  resolved at scan-creation time before the first queue message is published).
- Created a real "quick" scan through the live API against `pu.go.id` (already scanned repeatedly this
  session, low incremental risk) and confirmed the persisted `scans.config`: `scan_profile: "safe"`,
  `scan_timeout: 300`, `automatic_scan: false`, `use_tech_tags: false`, `crawl_max_targets: 100`,
  `enrichment_enabled: false` — every value now matches "safe"'s intent, a complete reversal from what
  every prior "quick" scan in this database actually persisted.

---

## 2026-07-12 — Milestone 17: Mining already-collected IP/TLS data for uncovered attack surface

User asked whether the platform's already-collected IP asset data could be mined further for uncovered
attack surface. Investigation found two real, previously-unwired sources of already-collected data, plus
confirmed one existing "gap" (ASN→CIDR expansion never auto-scanning) is a deliberate, correct safety
decision that should stay as-is — not a bug to fix.

### Added: TLS certificate SAN mining as a new subdomain-discovery source
- **File**: `workers/scanner/discovery_worker.py` (`_fetch_known_tls_sans`, `_discover_subdomains_with_sources`)
- The `subdomains.tls_sans` column (populated by M11.6's TLS fix) was written but never read back for
  anything. Verified against real data before building: `pu.go.id` had **37 genuine same-root-domain
  hostnames** sitting in already-fetched certificate SAN data that weren't yet tracked as discovered
  subdomains (`ciptakarya.pu.go.id`, `lisensijakon.pu.go.id`, `automation.pu.go.id`, etc.) — real,
  previously-uncovered attack surface, sitting in data the platform already had. Also confirmed the
  necessary filtering: `pasarjaya.co.id`'s SAN data looked like 75 "new" hostnames at first, but every one
  was noise from a shared mail-hosting certificate listing unrelated third-party customer domains
  (`mail.airetalent.com`, `correo.ateneatelecomunicaciones.com`, etc.) — none were genuinely
  `*.pasarjaya.co.id`.
- Wired as a new discovery source (`tls_san_mining`) feeding into the exact same candidate pipeline as
  `dns_bruteforce`/`dns_permutation`/`wayback` — `_add_discovery_candidate`'s existing domain-suffix check
  is what discards the shared-hosting noise, so SAN-mined candidates get the identical
  resolve→validate→persist treatment (and the identical scope safety) as every other passive/generated
  source. No new risk profile: this reads data already sitting in this org's own `subdomains` rows, makes
  no new requests to anything.
- Fetched once per scan (not once per root domain) and reused across the domain loop.

### Added: reverse-DNS lookups against this org's own already-confirmed IP assets
- **File**: `workers/scanner/discovery_worker.py` (`_fetch_known_ip_assets`, `_discover_reverse_dns_targets`)
- The existing `reverse_dns` discovery source only ever looked at `organizations.ip_ranges` — a manual,
  opt-in field with a real settings-page UI, but empty for every real org scanned this session (hence
  `reverse_dns_candidates: 0` in every prior scan's phase_status). Extended it to also PTR-lookup this
  org's own already-confirmed `Asset` rows of type `ip` (resolved from a validated in-scope host in a
  prior scan) — no scope expansion at all, since we already have standing to touch these exact IPs; it
  just extracts more information (potential co-hosted vhosts) from IPs already ours to see.
  Verified live against `pu.go.id`'s 31 known IPs: got 20 real PTR responses back, correctly all
  `scope_match: false` — its infrastructure is AWS/GCP/Biznet-hosted without custom reverse-DNS zones, so
  no same-domain hostnames were discoverable this way for this particular org. Expected, not a bug;
  confirms the check runs and labels results correctly rather than manufacturing false positives.
- Kept the existing safety posture unchanged: reverse-DNS discoveries are still `"selected": False` /
  `skip_reason: "reverse_dns_not_auto_scanned"`, same as before and same as ASN-expansion candidates —
  deliberately not auto-scanned regardless of source, matching this platform's established
  authorization-conscious posture.

### Confirmed as correct, deliberately not touched: ASN→CIDR expansion never auto-scans
- `_expand_asn_targets`'s discovered CIDR prefixes always carry `"selected": False,
  skip_reason: "asn_prefix_not_auto_scanned"` — this looked like it could be the same "wired but inert"
  pattern found repeatedly in earlier milestones, but it isn't: an ASN discovered from a target's IP is
  very often a **hosting provider's** ASN, not a dedicated block the org itself owns — auto-scanning the
  whole CIDR would touch unrelated third parties sharing that provider. This is a deliberate authorization
  safeguard, left exactly as-is.

### Caveat surfaced during this work: `DiscoveredAsset` candidates have no review UI at all
- Confirmed there is no frontend page and no dedicated API endpoint for browsing individual
  `DiscoveredAsset` candidate rows (only an aggregate count/breakdown via `scans.py`'s
  `_discovered_asset_summary`, rendered on the Scan Detail page as a `by_type` line item). This means the
  new `reverse_dns`-sourced candidates (and the pre-existing `asn_expansion`/original `reverse_dns`
  candidates) will show up as a **count** on the next scan's detail page, but there's no way to actually
  browse/promote individual candidate hostnames from the product today. Pre-existing gap, not introduced
  by this change — flagging since it directly limits how useful the reverse-DNS side of this work is until
  a review UI exists. Not built now (out of scope for what was asked); suggest as a follow-up.

### Verification
- 4 new unit tests in `backend/tests/unit/test_scan_pipeline_state.py`: SAN-mining domain-filter behavior,
  `_fetch_known_tls_sans`/`_fetch_known_ip_assets` query-shape contracts (fake DB session, no real
  network), and reverse-DNS's known-IP merge with a faked `getnameinfo` (patched on the *real* running
  loop, not by replacing `asyncio.get_running_loop()` itself — the code under test wraps the call in
  `asyncio.wait_for()`, which needs the genuine loop's timer machinery). All 13 tests in the file pass
  (verified via the same transient-`pytest`-in-`worker-nuclei` method this file's own docstring documents).
- Both new functions additionally run-tested directly against real production data (not just mocked) inside
  `worker-discovery`: SAN mining produced the 37 genuine `pu.go.id` candidates described above; reverse-DNS
  produced 20 real, correctly-labeled PTR results.
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 152
  passed, 1 skipped, no regressions (this file's tests aren't part of that count — they live in the
  workers-dependent file).
- Restarted `worker-discovery` (`workers/` bind-mounted read-write, no rebuild). Did **not** trigger a new
  full scan to watch brand-new subdomains land end-to-end — the downstream resolve/validate/persist chain
  these candidates feed into is unchanged, already-proven code (exercised across every scan validated in
  Milestones 12-16), so the risk specific to this change is fully contained in candidate generation, which
  was verified directly. Will confirm end-to-end on whichever real scan the user validates next, per the
  established workflow.

---

## 2026-07-12 — Milestone 16: Fixed nuclei's own `*-eol` template categorization (M15 follow-up)

Follow-up from Milestone 15: user asked whether nuclei's own generic `*-eol` templates (e.g. `php-eol`,
seen live on `pasarjaya.co.id`'s Findings page as "PHP End-of-Life - Detect") or the new endoflife.date
cross-reference should be the primary EOL data source. Recommended endoflife.date as authoritative (exact
per-cycle dates vs. nuclei's coarse "old version detected" heuristic; broader coverage — works for any
product in the `technologies` table, not just whatever templates happen to exist), with nuclei's own
`*-eol` templates kept as a secondary in-scan signal rather than removed. User approved fixing the
categorization bug flagged in M15's "found but not fixed" note.

### Fixed: `*-eol` nuclei templates fell through to the wrong default category
- **File**: `workers/scanner/nuclei_worker.py` (`CATEGORY_MAP`, `_map_category`)
- Confirmed the real template's tags first (`php-eol` carries `["tech", "php", "eol"]`) rather than
  assuming. `"eol"` wasn't a `CATEGORY_MAP` tag key and `_map_category`'s keyword-matching had no bucket
  for it either, so every `*-eol` finding fell through to the `cors_misconfiguration` default — the same
  failure mode M12 fixed for `http-*` templates, just a different unhandled tag.
- Added `"eol": "eol_software"` to `CATEGORY_MAP` (primary path, via the existing tags loop) and a
  `["-eol", "eol-", "outdated"]` keyword-matching fallback (for templates that might reference EOL/outdated
  status without carrying the exact `"eol"` tag) — verified both paths against the real `php-eol` template
  data and a regression check that M12's `http-*` fix still holds.
- `eol_software` already resolves correctly in `risk_engine.py`'s `FINDING_CATEGORY_MAP` → `PATCH_HYGIENE`
  (added in Milestone 15 for the new endoflife.date-based check) — no risk_engine.py change needed; this
  fix simply lets nuclei's own EOL detections land in the same, already-correct category.

### Backfilled: 27 pre-existing miscategorized findings
- Recomputed `category` for every `nuclei`-sourced finding from its real `template_id`/`tags` via the fixed
  `_map_category()` (same method as M12's backfill — only rows that genuinely disagree with the corrected
  logic are touched). All 27 flipped from `cors_misconfiguration` → `eol_software`: 10 on `pu.go.id`, 17 on
  `pasarjaya.co.id` — the same two orgs M15's new check had already found real EOL software on.
- Scoped across all organizations (confirmed via `AskUserQuestion` before running — a cross-org bulk UPDATE
  needs explicit scope confirmation each time, per the auto-mode classifier, same as M12's precedent).
- Triggered a fresh `risk.compute` for both orgs afterward: `pu.go.id` 71→72; `pasarjaya.co.id` stayed at
  50 (moving findings from Misconfiguration's 5% weight to Patch Hygiene's 10% weight roughly canceled out
  at the rounded-score level — the categorization is what mattered here, not necessarily the aggregate
  number).

### Verification
- Added `test_map_category_resolves_eol_templates` to `backend/tests/unit/test_scan_pipeline_state.py`
  (tag-based match, keyword-fallback match without the tag, a second product name) — verified by installing
  `pytest` transiently inside `worker-nuclei` per this file's established (documented in its own
  module-level docstring) collection workaround; all 9 tests in the file pass.
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 152
  passed, 1 skipped, no regressions (this file doesn't add to that count — its tests live in the
  workers-dependent file, not `test_eol_intel.py`).
- Restarted `worker-nuclei` (`workers/` bind-mounted read-write, no rebuild needed) so future scans persist
  correctly-categorized `*-eol` findings going forward.

---

## 2026-07-11 — Milestone 15: End-of-Life Software Enrichment (new scanner-family check)

User asked whether already-collected findings/data could be enriched further. Investigation (with the
user's sign-off before building) found a concrete, high-value gap: `risk_engine.py`'s `outdated_software`/
`eol_software` scoring categories (Patch Hygiene) had existed since early in the project but had **zero**
real findings feeding them anywhere in the database, despite the platform already collecting rich
technology+version data (the `technologies` table, populated by httpx/nuclei tech-detect) that was never
cross-checked against real end-of-life status. Confirmed against the live endoflife.date API (not assumed)
that several already-detected versions in the database were genuinely, meaningfully overdue — an OpenSSL
1.0.2k with no security patches since 2019, PHP 7.4.x (EOL since Nov 2022), Drupal 7 (EOL Jan 2025).

### Added: keyless EOL lookup + cache, new `eol` scanner-family check
- **New table** `eol_intel` (migration `016_eol_intel`) — caches endoflife.date's per-product-cycle EOL
  data (`product`, `cycle`, `eol_date`, `latest_version`). Same shape/spirit as the existing
  `exploit_intel` table (M14), but a different refresh model: EPSS shifts daily and needs scheduled
  refresh, but a cycle's EOL date is fixed once published, so a product's cycle list is fetched from
  endoflife.date **exactly once** (the first time any of its cycles is looked up) and never re-fetched —
  keeping the platform's no-paid/keyless-enrichment posture (see CLAUDE.md) while adding real signal.
  Design explicitly walked through with the user first: cache-aside by product (not per finding/category —
  category is a many-to-one grouping label, CVSS/EOL data is inherently per-CVE/per-product), background
  worker-driven rather than blocking any API request.
- **New module** `backend/app/services/eol_intel.py`: `PRODUCT_SLUG_MAP` (Technology.name → endoflife.date
  product slug, ~28 products covering everything actually detected plus common pre-emptive coverage),
  per-product version→cycle normalizers (`_default_cycle` = major.minor for most products; `_openssl_cycle`
  handles OpenSSL's own inconsistent convention — 1.0.x/1.1.x track major.minor.**patch**, 3.x tracks
  major.minor only, verified against the real API before writing the rule), `get_eol_status()` (cache-first:
  only hits endoflife.date if the product has never been cached at all).
- **New scanner-family check** `_scan_eol` in `workers/scanner/coverage_worker.py`, wired into
  `discovery_worker.py`'s existing `scanner_families` dispatch (`scan.scanner` queue, no new RabbitMQ
  topology needed) alongside tls/dns/takeover/cloud/git_secrets. Unlike every other scanner-family check,
  this makes **no requests to the scanned org's own infrastructure at all** — it cross-references the
  `technologies` table already populated earlier in the scan against the (cached) EOL data. Persists
  `eol_software` findings (severity `high` if EOL >365 days ago, `medium` otherwise) with the real
  eol_date/latest_version in `proof`, reusing risk_engine.py's already-existing (previously dead)
  `eol_software` → `PATCH_HYGIENE` category mapping — no risk_engine.py change needed.

### A real bug caught by testing before deploying: `is_eol` computed wrong
- Initial version set `is_eol = (eol_date is not None)` — wrong: a cycle can have a *future* eol_date
  (e.g. PHP 8.3, eol 2027-12-31) and isn't EOL yet. Caught immediately by running the real lookup against
  live data before wiring it into the scanner (PHP 8.3.28 came back `is_eol: True` with a 2027 date, plainly
  wrong). Fixed by comparing `eol_date` against today's date, and — since this product's cycle list is
  never re-fetched under the fetch-once design — recomputing `is_eol` from the stored `eol_date` at every
  read rather than trusting a stored boolean that would otherwise go stale once a future eol_date arrives.

### Verification
- 24 new unit tests in `backend/tests/unit/test_eol_intel.py` (cycle normalization against real verified
  API cases, `get_eol_status` cache-hit/cache-miss branching via a fake DB, the future-eol-date regression
  above). `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` —
  152 passed (was 128), 1 skipped, no regressions.
- Ran the real `_scan_eol` check directly against all 3 previously-validated orgs (`pu.go.id`, `kpi.go.id`,
  `pasarjaya.co.id`) — not a synthetic test. Found real EOL software: 14 findings on `pu.go.id` (Nginx
  1.14/1.24, PHP 7.2/7.4, Drupal 7, OpenSSL 1.0.2k/1.1.1k, WordPress 6.8.2), 23 on `pasarjaya.co.id`
  (mostly PHP 7.4.x, several OpenSSL 1.0.2k/1.1.1n/1.1.1p/3.1.3 instances), 0 on `kpi.go.id` (its detected
  stack is genuinely current — correctly produced no false positives). Restarted `worker-scanner`/
  `worker-discovery` (`workers/` is read-write bind-mounted, no image rebuild needed) so future real scans
  pick this up automatically.
- Triggered a fresh `risk.compute` for both affected orgs: `pasarjaya.co.id` dropped 56→48 (Patch Hygiene
  wasn't already floored, so this is a real, consequential scoring change); `pu.go.id` stayed at 71 (Patch
  Hygiene was already floored at F/0 from M14's KEV-boosted Zimbra criticals — more findings piling onto an
  already-zeroed category doesn't move the number further, expected).
- Confirmed visually in the real web UI (Playwright): Findings page shows "End-of-life software: PHP 7.4.33"
  etc. with correct category/severity/asset and real "2 minutes ago" timestamps; Risk Scores page's Patch
  Hygiene category correctly shows the combined finding count and updated grade.

### Found but not fixed (out of scope for this pass, noted for later)
- Nuclei already has its own generic `*-eol` templates (e.g. `php-eol`, seen live on `pasarjaya.co.id`'s
  Findings page as "PHP End-of-Life - Detect") that detect end-of-life software via banner/response
  fingerprinting independently of this new Technology-table cross-reference — and they fall through
  `_map_category`'s keyword matching to the wrong default (`cors_misconfiguration`) since `"eol"` isn't one
  of its keyword buckets. Two different EOL-detection paths now coexist for the same underlying condition
  (not literally duplicate rows — different fingerprints — but redundant signal). Worth a follow-up to
  either fix that template family's categorization or reconcile/dedupe against this new check.

---

## 2026-07-11 — Milestone 14: EPSS/KEV exploit-intel lookup silently broken by CVE-ID casing

User asked why some findings still weren't showing a CVSS score / exploit-intel badge. `cvss_score` gaps
turned out to be a genuine, separate upstream-data limitation (some nuclei templates just don't declare
`classification.cvss-score` even when they reference a real CVE — no code fix available there). The
exploit-intel (EPSS score / CISA KEV) gap was a real, high-impact bug.

### Fixed: EPSS/KEV lookup was case-sensitive; almost every real CVE finding missed it
- **File**: `backend/app/services/exploit_intel.py` (`get_exploit_intel`)
- `exploit_intel.cve_id` is always canonical uppercase (straight from the EPSS/CISA KEV upstream feeds).
  `Finding.cve_ids`, however, is usually **lowercase** — nuclei's own `classification.cve-id` template
  metadata (the primary extraction path in `nuclei_worker.py`) uses lowercase, and only the secondary
  fallback path (regex-matching the template filename when metadata is empty) uppercases. `get_exploit_intel`
  did a plain case-sensitive `ExploitIntel.cve_id.in_(cve_ids)`, so any finding with a lowercase CVE ID
  silently got no EPSS score and no KEV flag — not "missing data," a string-casing mismatch.
  **12 of 15** real CVE-tagged findings platform-wide were affected. Confirmed via the live scans validated
  in Milestones 12-13: the Zimbra "Unrestricted File Upload" finding (CVE-2022-41352, a *critical* finding
  on both `pu.go.id` and `kpi.go.id`) is CISA KEV-listed with a 95.5th-percentile EPSS score, and the
  Memcached Command Injection finding (CVE-2022-27924, `pu.go.id`) is KEV-listed **with confirmed
  ransomware-campaign use** — neither fact was surfacing anywhere, despite the real intel already sitting
  in the `exploit_intel` table.
- Fixed by normalizing case inside the lookup itself (not by changing how `cve_ids` are stored) — no
  backfill needed, since exploit intel is deliberately looked up live at read/scoring time, never frozen
  onto a `Finding` row (EPSS shifts daily; see the module's own docstring). `get_exploit_intel` now queries
  by uppercased CVE ID and maps the result back to every casing variant actually present in the caller's
  input list, so all four call sites (`risk_worker.py`'s scoring pass, and `findings.py`'s list/detail/CSV
  export endpoints) work unchanged.
- Verified live through the real API (not just a unit test): `GET /findings/{id}` for the kpi.go.id Zimbra
  finding now returns `epss_score: 0.95478`, `epss_percentile: 0.9986`, `is_kev: true` — all previously
  `null`/`false`.

### Verification
- Added `TestGetExploitIntel` (4 cases: lowercase-vs-uppercase-row match, already-uppercase match, the
  same CVE referenced with two different casings across findings, empty input) to
  `backend/tests/unit/test_exploit_intel.py` — this file needs no `workers.*` import, so unlike the
  scanner-worker tests it runs in the normal `api`-container regression suite.
  `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 128
  passed (was 124), 1 skipped, no regressions.
- Restarted `api` and `worker-risk` (both import `risk_engine.py`/`exploit_intel.py` from the read-only-
  mounted `backend/app`, cached in the running process) to apply the fix, then triggered a fresh
  `risk.compute` for all 4 orgs with CVE-tagged findings. `pu.go.id`: 72→71 (small drop — the
  now-correctly-applied KEV/ransomware boost outweighed the earlier miscategorization fix's small gain).
  `kpi.go.id`/`pasarjaya.co.id`/ACME Corp: unchanged — `kpi.go.id`'s Patch Hygiene category was already
  floored at grade F/0 from raw severity alone (the boost still matters for score-recovery resistance and
  for the now-correct EPSS/KEV badges, just doesn't move an already-floored category further),
  `pasarjaya.co.id`'s one CVE finding was already correctly-cased, and ACME Corp has no CVE findings at all.

---

## 2026-07-11 — Milestone 13: Second Live-Scan Validation (kpi.go.id) + risk category-map audit

Follow-up validation of another real scan (`5218afce-ed64-4b9b-bab9-9ef5c23ecf88`, org `kpi.go.id`, `full`).
Confirmed Milestone 12's two fixes hold under a second real scan: `takeover` phase completed cleanly
(0 candidates this time — no CNAME matched a known provider, so it correctly short-circuited rather than
crashing), and no `http-*` nuclei template was miscategorized. Findings/scan_findings/risk_scores counts
all agreed at 95; 2 legitimate critical findings (Zimbra Collaboration unrestricted file upload,
CVE-2022-41352, on both `webmail.kpi.go.id` and `mail.kpi.go.id`). What looked like duplicate findings on
manual inspection (25× "HTTP Missing Security Headers" on one asset, etc.) were verified to be genuinely
distinct `affected_url`s (25 different crawled endpoints) — not a dedup bug, same pattern confirmed in
Milestone 12.

### Fixed: 3 finding categories missing from risk_engine's scoring map entirely
- **File**: `backend/app/services/risk_engine.py` (`FINDING_CATEGORY_MAP`)
- Went looking for siblings of Milestone 12's `_map_category` bug by diffing every literal `category="..."`
  string used across `workers/scanner/*.py` against this map's keys. Found three real gaps where a finding
  category is produced by a scanner but was never added to the map — meaning any finding with that exact
  category silently fell through to the generic `ScoreCategory.MISCONFIGURATION` default bucket instead of
  its correct, more specific category:
  - `dmarc_misconfiguration` (coverage_worker.py's DNS scanner — "DMARC policy is monitoring only, `p=none`")
    → added as `ScoreCategory.DNS_HEALTH`, matching its sibling `missing_dmarc`. This one wasn't just
    latent: it had already produced 1 real finding in this scan, previously being scored under the wrong
    (5%-weighted) category instead of DNS Health's 10% weight.
  - `tls_misconfiguration` (coverage_worker.py's TLS scanner — certificate hostname/SAN mismatch) → added
    as `ScoreCategory.TLS_SECURITY`.
  - `cloud_public_exposure` (coverage_worker.py's cloud scanner — publicly-readable discovered bucket) →
    added as `ScoreCategory.EXPOSURE_MGMT`.
  - The latter two are currently latent (zero findings of either category exist anywhere in the database
    yet — neither check has fired on real data so far) but would have hit the exact same silent
    miscategorization the moment either one did.
- Recomputed `kpi.go.id`'s risk score after the fix (overall score unchanged at 70/C — a single low-severity
  finding moving 5%→10% category weight wasn't enough to move the rounded total, but its DNS Health category
  breakdown now correctly shows `finding_count: 12` including the DMARC finding, and Misconfiguration
  correctly dropped to 5).

### Fixed (incidental): stale test masked by the same api-container collection gap
- **File**: `backend/tests/unit/test_scan_pipeline_state.py`
- While re-verifying Milestone 12's test additions, ran the full file again and confirmed
  `test_port_worker_uses_ip_address_id_for_ports` (flagged but not yet fixed in M12) is a stale assertion,
  not a product bug: `port_worker.py::_persist_ip_assets`'s `assets` insert payload gained
  ownership/scope-confidence fields at some point after the test was written, and the test's expected dict
  was never updated. Updated the assertion to match the real, current payload. Added a module-level
  docstring explaining why this file can't run through the standard `api`-container regression command and
  how to actually exercise it (transient `pytest` install inside a worker container, since `workers/` isn't
  importable in `api` and no worker container has `pytest` installed).

### Verification
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 124
  passed, 1 skipped, no regressions.
- Re-ran `test_scan_pipeline_state.py` directly (transient `pytest` inside `worker-nuclei`, same method as
  Milestone 12): all 8 tests pass.
- `backend/app` is read-only mounted into worker containers but the running process still caches the old
  module in memory — restarted `worker-risk` and `api` (both import `risk_engine.py`) to pick up the
  category-map fix for real, then triggered a fresh `risk.compute` for `kpi.go.id` and confirmed the
  corrected breakdown via `psql`.

---

## 2026-07-10 — Milestone 12: End-to-End Scan Validation (2 real bugs found via a live scan)

User ran a real `full` scan against `pu.go.id` through the web UI (scan `6a8ef245-6886-493a-b670-c31f4950daaf`)
and asked for a full pipeline validation, start to finish. Every stage completed and all cross-table
counts were internally consistent (findings/scan_findings/risk_scores.total_findings all agreed at 128;
risk score computed_at matched scan completed_at to the second) — except one phase had failed outright,
and one category looked suspicious on inspection. Both traced to real, previously-undiscovered bugs.

### Fixed: subdomain takeover check crashes the instant it has real candidates to check
- **File**: `workers/scanner/coverage_worker.py` (`_subzy_scan`)
- The `takeover` phase showed `status: "failed"`, `last_error: "'NoneType' object is not iterable"`.
  Reproduced directly against the real scan data: `subzy` is invoked with `--hide_fails`, and when zero
  candidates come back vulnerable (the overwhelmingly common outcome), it writes the literal JSON `null`
  to its output file instead of `[]`. `json.loads("null")` → Python `None`, and the subsequent `for record
  in records:` crashes. Fixed with `records = json.loads(...) or []`.
  Checked every other scan in the database's history: **8 of 9 prior "completed" takeover phases had
  `targets_total: 0`** — no CNAME in any previously-scanned org happened to match a known
  takeover-provider pattern, so `subzy` never actually ran with real input before. This `pu.go.id` scan
  was the first time the phase had real candidates (224, one matching an AWS ELB CNAME) — and it crashed
  immediately. The feature had never been exercised end-to-end with real data until this scan; it is now.

### Fixed: nuclei `http-*` templates miscategorized as `exposed_admin_panel`, platform-wide
- **File**: `workers/scanner/nuclei_worker.py` (`_map_category`)
- Noticed while sanity-checking the category breakdown: "HTTP Missing Security Headers" (18× in this
  scan) was tagged `exposed_admin_panel` instead of `missing_hsts`. Root cause: `_map_category()` had a
  "check template ID prefix" loop matching `CATEGORY_MAP`'s keys (`http`, `dns`, `ssl`, `network`,
  `misconfiguration`, `cve`, ...) against `template_id.startswith(prefix)`. Those keys model nuclei's tag
  taxonomy, not a template-naming convention — but a large fraction of real nuclei template IDs happen to
  literally start with `"http-"` (`http-missing-security-headers`, etc.), so they all got swallowed into
  `CATEGORY_MAP["http"] = "exposed_admin_panel"` before the (correct, more specific) tag-matching and
  keyword-matching logic below it ever ran. Removed the prefix loop; verified every previously-working
  case (CVE templates via their real `"cve"` tag, IIS/misc templates via the existing keyword fallback)
  still resolves correctly with it gone.
  Quantified impact: **53 findings platform-wide** (18 in `pu.go.id`, 35 in `pasarjaya.co.id`) were
  miscategorized this way, corrupting the Exposure Management vs. Web Security category-weight split in
  those orgs' risk scores.

### Backfilled: recategorized the 53 pre-existing miscategorized findings
- Recomputed `category` for every `nuclei`-sourced finding in the database from its real `template_id` +
  `tags` using the fixed `_map_category()` logic (not a hand-rolled query — the actual function, so only
  rows that genuinely disagree with the corrected logic are touched). All 53 flipped from
  `exposed_admin_panel` → `missing_hsts`, matching the manually-quantified count exactly. Confirmed scoped
  across all organizations (not just `pu.go.id`) after finding the bug also affected `pasarjaya.co.id` —
  scoping the backfill to only the org under investigation would have silently left that org's data wrong.
- Triggered a fresh `risk.compute` for both affected orgs afterward so their currently-displayed risk
  score/category breakdown reflects the corrected data immediately, instead of waiting for each org's next
  scheduled scan. `pu.go.id`: 71→72 (Grade C, unchanged). `pasarjaya.co.id`: recomputed to 56 (Grade D).

### Verification
- Reproduced both bugs against real production data before fixing (standalone scripts run inside the
  `worker-scanner`/`worker-nuclei` containers against the actual `pu.go.id` dataset), and re-ran the same
  repro after the fix to confirm the crash/miscategorization is gone.
- Added two unit tests to `backend/tests/unit/test_scan_pipeline_state.py` (`_map_category` no longer lets
  the `http`/`dns`/`ssl`/etc. prefix shadow keyword matching; CVE-tagged templates still resolve to
  `known_cve` via their tag). Note: this test file cannot be collected in the `api` container (`workers`
  package isn't mounted there — pre-existing, already documented) or run via any worker container (no
  `pytest` installed there) — verified instead by installing `pytest` transiently inside `worker-nuclei`
  and running the file directly; both new tests pass. Incidentally found the pre-existing
  `test_port_worker_uses_ip_address_id_for_ports` in the same file already fails independent of this
  change — investigated as a follow-up (below).
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 124
  passed, 1 skipped, no regressions.
- `workers/` is bind-mounted read-write into worker containers (unlike `backend/app`, which workers mount
  read-only) — restarted `worker-scanner`/`worker-nuclei` (no image rebuild needed) to pick up both fixes
  for real ongoing scans.

### Follow-up: chased down every remaining loose end flagged above
- **Fixed a stale test, not a product bug**: `test_port_worker_uses_ip_address_id_for_ports` asserted an
  outdated, narrower shape for `port_worker.py::_persist_ip_assets`'s `assets` insert payload.
  `_persist_ip_assets` had grown ownership/scope-confidence fields (`confidence`, `is_in_scope`,
  `scope_status`, `ownership_confidence`, `ownership_reason`, `exposure_status`, `liveness_status`,
  `validation_sources`, `last_verified_at`, a richer `metadata.validation`) at some point after this test
  was written, and the mismatch was invisible because this test file can't be collected in the `api`
  container (see new module-level note in the file) so it's never run in routine checks. Updated the
  test's expected payload to match the real, current implementation — the production code was already
  correct. Added a module-level docstring note explaining how to actually run this file (transient
  `pytest` install inside a worker container) since there's currently no way to exercise it otherwise.
- **Confirmed nuclei's 3 timed-out batches were benign, not data loss**: traced `_run_nuclei`'s timeout
  path — on `asyncio.TimeoutError` it kills the subprocess but then calls `_parse_results_file()`, which
  reads whatever nuclei had already streamed to its `-jsonl` output before being killed. The `0` raw/
  persisted findings logged against the timed-out batches is the genuine partial-recovery count (that
  specific batch of endpoints hadn't matched anything yet when the timeout fired), not evidence that
  results were dropped. Working as designed.
- **Checked nikto_worker.py's own `_map_category` for the same bug class**: it's structurally different
  (pure substring matching against `description`/`url`, no shared prefix/tag dict), so it was never
  exposed to the nuclei bug's failure mode. Left as-is — nikto is also confirmed dead code (no
  `worker-nikto` service, nothing publishes `scan.nikto`), consistent with the Milestone 7 decision not to
  invest further verification effort there.
- **Cross-checked every category `_map_category` can now produce against `risk_engine.py`'s
  `FINDING_CATEGORY_MAP`**: all of them (`known_cve`, `exposed_admin_panel`, `missing_hsts`,
  `expired_certificate`, `cors_misconfiguration`, `missing_spf`, `subdomain_takeover`, `debug_endpoint`,
  `exposed_git`, `exposed_service`, `default_credentials`, `exposed_api`, `outdated_software`) resolve to a
  real `ScoreCategory` — no nuclei finding silently falls through to the ungraded default bucket.
- Re-ran the full test file after the fix: all 8 tests pass (was 7/8). Re-ran
  `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — still
  124 passed, 1 skipped, no regressions from the test-file edit.

---

## 2026-07-10 — Milestone 11: Dashboard Data Audit (9 clarity/data-wiring bugs)

User asked for a frontend/dashboard audit — is the displayed data correct and clear, revamp if needed.
A full page-by-page tour (Playwright) found the underlying data model and design were sound; every
issue was a data-wiring or serialization bug, not a design problem, so no revamp was needed. All 9 fixed:

### Fixed: Overview/Risk Scores KPIs reading from the wrong or missing fields
- **Files**: `backend/app/api/v1/endpoints/scores.py`, `frontend/src/app/dashboard/page.tsx`,
  `frontend/src/app/dashboard/risks/page.tsx`
- `GET /scores` was missing `medium`/`low`/`info`/`total_findings` from its serialization entirely.
  `GET /organizations/{id}`'s `total_findings` is a live-counted field sibling to `risk_score`, not
  nested inside it — the Overview page was reading `score?.total_findings` (always undefined) instead
  of `scoreData?.total_findings`. Both fixed; "Open Findings" and "Total Findings" now render real
  numbers instead of "—".

### Fixed: Category Breakdown rendering array indices ("0","1","2"...) instead of category names
- **File**: `frontend/src/app/dashboard/risks/page.tsx`
- `GET /scores/breakdown`'s real shape is `{breakdown: {category: {...}, ...}, factors: [...], overall,
  grade}` — the frontend read a nonexistent `category_scores` key, fell back to `factors` (a sparse
  array with no category name as its own key), and `Object.entries()` on an array yields numeric-string
  indices. Fixed to read `breakdown.breakdown`; the existing `CATEGORY_LABELS` mapping needed no changes.

### Fixed (clarity, not a bug): Assets list Technologies/HTTP/TLS Expiry blank for ~96% of rows
- **File**: `frontend/src/app/dashboard/assets/page.tsx`
- Verified via direct SQL cross-referencing `liveness_status` before changing anything: the blank cells
  are legitimately unresolved/dns_only hosts that were never probed — every truly "alive" host already
  had complete data. Not a backend sync bug. Added an explicit "Not resolved" / "No HTTP response" label
  in place of a bare "—" so the distinction between "never probed" and "probed, nothing found" is visible.

### Fixed: Attack Surface graph always showing "IPs: 0"
- **File**: `frontend/src/app/dashboard/attack-surface/page.tsx`
- The graph's asset fetch used `page_size=200` sorted by `last_seen desc`; IP-type assets are touched far
  less often than subdomains (a port scan runs once vs. constant DNS/HTTP rechecks), so they consistently
  sorted outside the window and were never fetched — not a rendering bug, just never present in the
  dataset. Added a second targeted `asset_type=ip` fetch merged into the node set by ID.

### Fixed: DNS Intel page never received the detailed fields it was designed to show
- **File**: `backend/app/api/v1/endpoints/assets.py`
- The frontend already called `/assets` expecting a richer `dns_records`/`security_headers`/
  `redirect_chain`/`tls_info` payload via an `expand=dns` contract that was never implemented
  server-side — `_asset_to_dict()`'s existing `detailed=True` gate was correct but never triggered by
  the list endpoint. Added the `expand` query param and wired it through.

### Fixed: TLS Issuer/Version columns always empty
- **File**: `workers/scanner/discovery_worker.py`
- Existing code read `tls.get("issuer", {}).get("organization", "")` and `tls.get("version", "")` —
  neither key exists in httpx's real `-tls-grab -json` output, confirmed by running httpx directly
  inside the worker container against a live target rather than assuming the schema. Real fields are
  flat: `issuer_org` (array), `issuer_cn`, `issuer_dn`, `tls_version`. Fixed accordingly. Forward-fixing
  only — raw TLS JSON was never historically persisted, so there's nothing to backfill.

### Fixed: Network Intelligence table showed only Source + permanently-empty Risk Score/Tags/Categories
- **Files**: `backend/app/api/v1/endpoints/intel.py`, `frontend/src/app/dashboard/intel/page.tsx`
- `risk_score`/`tags`/`categories` are structurally always null/empty for the no-key `network_baseline`
  enrichment (see CLAUDE.md's documented no-paid-API-keys decision) — the table's only non-empty content
  was the `source` label, for all 26 rows. The actually-populated data (ASN/ISP/BGP prefix/cloud
  provider/CDN/hosting flags) sat unrendered inside the `data` JSONB column, which the `/intel` endpoint
  didn't even serialize into the API response. Added `data`, `categories`, `asset_id`, `asset_value` to
  the endpoint response; rebuilt the table around Asset/Source/ASN-ISP/BGP-Prefix/Cloud-Hosting columns,
  keeping Risk as a compact fallback column for whenever a real-scored intel source is added later.

### Fixed: Reports page overstated Compliance/Custom report capability
- **File**: `frontend/src/app/dashboard/reports/page.tsx`
- Card copy claimed "PCI-DSS, SOC2, ISO 27001 mapping" and "select specific sections" — per
  `report_service.py::DETAILED_REPORT_TYPES`, both are undocumented aliases of the technical report with
  no real framework-mapping or section-picker logic. Reworded to state the actual behavior (full findings
  list, same detail as Technical) rather than fabricated capability, matching Milestone 5's earlier
  "Threat Intelligence" → "Network Intelligence" honesty-over-cosmetics precedent.

### Verification
- `npx tsc --noEmit` clean on every touched frontend file.
- `docker compose exec api pytest tests/unit -q --ignore=tests/unit/test_scan_pipeline_state.py` — 124
  passed, 1 skipped, no regressions.
- Rebuilt and redeployed the `frontend` container (production build, no dev volume mount — code changes
  don't take effect without this) and restarted `api` (mounted read-write but no `--reload`, so the
  `/intel` serialization change needed a restart too).
- Re-toured all 7 affected pages via Playwright post-deploy against real seeded data
  (`pasarjaya.co.id`, 866 assets): confirmed Open Findings=173 and Category Breakdown showing real
  category names on Overview/Risk Scores, IPs=26 on the Attack Surface graph, "Not resolved"/"No HTTP
  response" labels and populated DNS/TLS data on Assets/DNS Intel/TLS pages, real ASN/ISP/BGP
  prefix/GCP+Hosting badges on Network Intel, and corrected copy on Reports.

---

## 2026-07-10 — Milestone 10: Tool Parameter Tuning (+ a pre-existing "quick" scan bug found while tracing it)

User asked for a fine-tuning pass over the actual CLI parameters of already-integrated tools (not new
tools) for the `deep_authorized` profile, benchmarked loosely against what a mature commercial ASM
product would tune for. Four concrete targets identified from reading every tool invocation in the
worker codebase:

### Fixed: katana crawl depth was too shallow to ever trigger known-files discovery
- **File**: `backend/app/services/scan_service.py` (`DEFAULT_SCAN_CONFIG["full"]["crawl_depth"]`)
- `web_crawl_worker.py::_run_katana` only passes `-kf all` (known-files discovery: robots.txt,
  sitemap.xml, etc. — a cheap, high-signal endpoint source) when `crawl_depth >= 3`. The `full`/`vuln`
  scan types (which resolve to the `deep_authorized` profile, the platform's "thorough" option) were
  only ever getting `crawl_depth=2`, so this profile never actually got known-files discovery. Raised to
  3 (within `CONFIG_LIMITS["crawl_depth"]`'s existing 1-4 range).

### Fixed: nuclei concurrency/bulk-size were well below nuclei's own defaults for the "deep" profile
- **Files**: `backend/app/services/scan_service.py` (`DEFAULT_SCAN_CONFIG["full"]`/`["vuln"]`),
  `backend/app/services/scan_profiles.py` (`SCAN_PROFILES["deep_authorized"]`, kept in sync)
- Both were hardcoded to 6 (host-parallelism-per-template and template-parallelism, respectively) —
  nuclei's own built-in defaults are 25/25. Raised to 20, the ceiling `CONFIG_LIMITS` already enforces
  (didn't raise the ceiling itself — that's a separate, more consequential call affecting every profile
  including `safe`, not in scope here). The actual protection against overwhelming a target is the
  separate per-second `-rate-limit` flag, not these two — so this mainly buys back scan wall-clock time
  without changing how aggressively any single target gets hit per second.

### Fixed: nmap `--version-light` was hardcoded on even for the authorized/deep profile
- **Files**: `workers/scanner/coverage_worker.py` (`_nmap_enrich_services`), `backend/app/services/scan_profiles.py`
- `--version-light` skips nmap's more thorough version-detection probes for speed. This only ever runs
  against a small, already-bounded set of discovered ports (`service_fingerprint_max_targets`, capped at
  50, each with its own 45s timeout) — the accuracy trade is worth it specifically for `deep_authorized`,
  since more precise service/version fingerprinting feeds directly into Patch Hygiene risk scoring. Made
  the flag conditional on a new `nmap_use_version_light` config key (default `True`, matching prior
  behavior for every other profile; `deep_authorized` sets it `False`). Named
  `nmap_use_version_light` rather than `nmap_version_light` to avoid colliding with the existing
  per-service dict key of that name (`coverage_worker.py` already uses `item["nmap_version_light"]` to
  store nmap's raw output text — same word, different thing, would have been a confusing shadow).

### Fixed: subfinder's own default cuts off passive-source enumeration early for a thorough scan
- **File**: `backend/app/services/scan_profiles.py`
- subfinder's own `-max-time` default (10 minutes) was left as-is even for `deep_authorized`. Raised to
  15 for this profile specifically via a new `subfinder_max_time` config key (previously unset anywhere
  in the config chain, so this was a clean addition with no competing layer to fix).

### Found and fixed while tracing the above: `DEFAULT_SCAN_POLICY` was silently overriding "quick" scans' own tuning
- **File**: `backend/app/services/scan_service.py`
- While verifying the `crawl_depth` and `concurrency`/`bulk_size` changes would actually reach a real
  scan (the established "trace every layer" discipline from Milestones 6-9), found that
  `DEFAULT_SCAN_POLICY["crawl"]["depth"]=2` and `DEFAULT_SCAN_POLICY["rate_limits"]["nuclei_concurrency"/
  "nuclei_bulk_size"]=6` are **scan-type-agnostic** — `_policy_to_config()`'s output is merged in *after*
  `DEFAULT_SCAN_CONFIG[scan_type]` in `create_and_queue()`, so it always wins regardless of scan type.
  This meant `"quick"` scans (meant to be fast: `crawl_depth=1`, `concurrency=15`, `bulk_size=15` in
  `DEFAULT_SCAN_CONFIG["quick"]`) were **already** silently getting `crawl_depth=2`, `concurrency=6`,
  `bulk_size=6` instead — a real, previously-undiscovered bug, independent of anything asked for in this
  pass, that would have gotten *worse* had `DEFAULT_SCAN_POLICY`'s values simply been raised in place to
  match the new `deep_authorized` tuning (quick scans would have inherited `crawl_depth=3`/`concurrency=20`
  too). Fixed the same way as Milestone 7's `fuzz` key: removed the offending keys from
  `DEFAULT_SCAN_POLICY` entirely (documented why) so each scan type's own `DEFAULT_SCAN_CONFIG` value
  flows through unclobbered, then raised `deep_authorized`'s values in the one place that's actually
  scan-type-scoped.

### Verification
- `docker compose exec api pytest tests/unit -q` — 124 passed, 1 skipped (pre-existing, unrelated), no
  regressions.
- Created two real scans through the actual API (not isolated function calls) — one `full`, one `quick`
  — and inspected persisted `scans.config`: `full` now shows `crawl_depth=3, concurrency=20, bulk_size=20,
  nmap_use_version_light=false, subfinder_max_time=15`; `quick` now correctly shows its own
  `crawl_depth=1, concurrency=15, bulk_size=15` for the first time (previously silently 2/6/6 due to the
  bug above).

---

## 2026-07-10 — Milestone 9: Finding Content Freezes on Rescan (and a live nuclei cve_ids bug found via UI QA)

Direct follow-up to Milestone 7's A1 fix and to a bug the *frontend* verification pass for Milestone 8
surfaced live (see below) — both point at the same underlying gap.

### Fixed: Finding content (severity, proof, cve_ids, evidence, ...) never refreshed on rescan
- **Files**: `workers/scanner/scanner_common.py` (new `content_refresh_updates()`),
  `workers/scanner/nuclei_worker.py`, `workers/scanner/nikto_worker.py`
- Milestone 7's `status_preserving_conflict_updates()` correctly protects triage fields
  (`status`/`is_risk_accepted`/`resolved_at`) on a Finding upsert — but every *other* column was left
  completely out of the `ON CONFLICT DO UPDATE SET` clause for `nuclei_worker.py`/`nikto_worker.py`,
  meaning Postgres left them untouched. In practice: a finding's `severity`, `proof` (which is where
  Milestone 7's confidence score and Milestone 8's EPSS/KEV lookups live), `cve_ids`, `cvss_score`,
  `evidence`, `request_raw`/`response_raw`, `title`, `description`, `remediation`, and `references` all
  froze at whatever they were the *first* time a finding was ever persisted — even though every
  subsequent rescan re-parses genuinely current values for all of them. This silently starved the
  Milestone 7/8 work of any value for **recurring** findings (the majority of findings in any repeat-scan
  deployment), which is exactly what an unrelated frontend verification pass for Milestone 8 just
  caught live (below).
- Added `content_refresh_updates(stmt, fields)` in `scanner_common.py`: builds SET-clause fragments from
  the attempted-insert row (`stmt.excluded.<column>`) for a caller-specified list of mutable content
  fields, layered on top of (not replacing) `status_preserving_conflict_updates()`. Wired into all three
  upsert call sites: `scanner_common.py::persist_findings` (extended its existing partial
  severity/proof/evidence refresh to also cover title/description/category/subcategory/affected_url/
  remediation/references), `nuclei_worker.py::_persist_findings` and `nikto_worker.py::_persist_findings`
  (had *no* content refresh at all — added title/description/severity/category/cve_ids/cvss_score/
  affected_url/evidence/request_raw/response_raw/proof/remediation/references). `nikto_worker.py` is
  still dead/unwired code (no consumer, per Milestone 7's note) — fixed anyway, same reasoning as before.
- Deliberately **not** included in the refresh set: `template_id` (part of the fingerprint itself — can
  never actually differ between two rows that conflict on the same fingerprint, so refreshing it would
  be a no-op) and every triage-owned field (`is_false_positive`, `false_positive_reason`,
  `risk_acceptance_reason`, `risk_accepted_until` — these were never in any upsert's SET clause at all,
  so they were already implicitly protected; confirmed, not just assumed).
- **Verified against real Postgres** (not just the isolated helper): 2 new tests in
  `workers/tests/test_finding_upsert_integration.py` — `test_content_refreshes_on_rescan` (persist a
  finding at severity=low/proof.confidence=unknown, re-persist the same fingerprint at severity=critical/
  proof.confidence=high, confirm the row now shows the *new* values) and
  `test_content_refresh_does_not_override_protected_status` (mark a finding false_positive, re-persist
  with a corrected severity, confirm severity updates **and** status stays false_positive — the two
  behaviors have to compose correctly, not just each work in isolation). Re-ran all 4 of Milestone 7's
  original upsert tests too — still passing, confirming the content-refresh addition didn't reintroduce
  the status-reset bug it was built to avoid.

### Found via frontend visual QA (Milestone 8's Playwright setup) and fixed: nuclei sometimes never populates `cve_ids` at all
- **File**: `workers/scanner/nuclei_worker.py` (new `CVE_ID_PATTERN` fallback in `_parse_finding`)
- Set up a real headless-browser verification pass for the Milestone 7/8 frontend badges (see below) and
  immediately found a live example: a finding titled "React Server Components - Denial of Service" with
  `template_id: "CVE-2025-55184"` — the template's own ID *is* the CVE number — had `cve_ids: []` in the
  database. Nuclei's own `info.classification.cve-id` metadata field was simply never populated by this
  particular template's author, and `_parse_finding` only ever read from that structured field. Meanwhile
  `_map_category()`'s cruder `if "cve" in template_lower` keyword check correctly classified it as
  `known_cve` — the two code paths disagreed, and the more important one (the one Milestone 7 confidence
  scoring and Milestone 8 EPSS/KEV lookups actually key off) lost. Added a regex fallback
  (`CVE-\d{4}-\d{4,}`, case-insensitive) against `template_id` and the template's `name` field, used only
  when nuclei's own classification metadata came back empty.
- This fix alone doesn't retroactively repair already-persisted findings (upserts didn't refresh
  `cve_ids` until the fix directly above landed in this same milestone) — did a one-time, user-approved,
  narrowly-scoped `UPDATE` backfilling `cve_ids` for existing findings in the test org whose `template_id`
  matches the CVE pattern but whose `cve_ids` was empty (1 row). Going forward, both fixes in this
  milestone compose: new/corrected CVE IDs get extracted *and* actually stick on rescan.

### Added: frontend surfacing for Milestone 7 confidence + Milestone 8 EPSS/KEV, with real screenshot verification
- **Files**: `frontend/src/types/index.ts`, `frontend/src/components/ui/SeverityBadge.tsx` (new
  `KEVBadge`, `EPSSBadge`, `ConfidenceIndicator`), `frontend/src/app/dashboard/findings/page.tsx`,
  `frontend/src/components/modals/FindingDetailModal.tsx`
- Both milestones' data was reaching the API with no UI to render it — added a pulsing red "Actively
  Exploited" (KEV) badge inline on the finding title (a "· Ransomware" variant when
  `kev_known_ransomware`), an EPSS percentage badge (only shown for scores > 0, orange when ≥ 50%), a
  compact confidence dot+label (only for "high"/"low" — "unknown" is the majority case and would just be
  table noise), and an "EPSS Percentile"/"Match Confidence" tile in the finding detail modal.
- **This deployment's frontend is a production Next.js build** (`docker-compose.yml`'s `frontend`
  service: `target: production`, no source volume mount) — needed `docker compose build frontend` +
  `docker compose up -d --no-deps frontend` to actually deploy, not the restart-only pattern that works
  for the bind-mounted workers/api.
- **Set up real browser-based visual verification for this session** (previously not possible — no
  browser/screenshot tool was available): installed Playwright + Chromium in a scratch directory,
  scripted a real login → navigate → screenshot flow against the live app. This is what caught the
  `cve_ids` gap above — a `grep`-level check of the compiled bundle had confirmed the *code* shipped
  correctly, but only an actual rendered screenshot revealed the badges had no real data to attach to
  for this org's findings. After both fixes above (parsing fallback + backfill), re-ran the same
  screenshot and confirmed the EPSS badge, CVE badge, and EPSS Percentile tile all render correctly on
  both the findings list and the detail modal.

### Verification
- `docker compose exec api pytest tests/unit -q` — 124 passed, 1 skipped (pre-existing, unrelated), no
  regressions.
- `workers/tests/test_finding_upsert_integration.py` — 6/6 passing individually (4 from Milestone 7 +
  2 new for this milestone).
- Real screenshots (list view + detail modal) confirmed the fix end-to-end: EPSS badge and percentile
  now visible for a finding whose `cve_ids` was previously empty due to the nuclei parsing gap.

---

## 2026-07-10 — Milestone 8: Exploit Intelligence (EPSS + CISA KEV)

User asked for the risk-scoring data to be "richer from an attack-surface perspective" — specifically,
whether real-world exploit likelihood could feed into prioritization, not just static severity/CVSS.
Chose EPSS + CISA KEV: both keyless, publicly-published, free datasets (fits the existing "no paid/
keyed third-party enrichment" decision documented in CLAUDE.md).

### Added: `exploit_intel` table + daily refresh (EPSS + CISA KEV)
- **Files**: `backend/app/db/models/models.py` (new `ExploitIntel` model),
  `backend/app/db/migrations/versions/015_exploit_intel.py` (new), `backend/app/services/exploit_intel.py`
  (new), `workers/scheduler/scheduler.py`
- New table keyed by `cve_id`: `epss_score`/`epss_percentile`/`epss_date` (FIRST.org's probability a
  CVE is exploited in the wild in the next 30 days) and `is_kev`/`kev_date_added`/
  `kev_known_ransomware`/`kev_due_date` (CISA's catalog of *confirmed* actively-exploited CVEs). Global
  reference data, not tied to any org/workspace, and deliberately **not** frozen onto a `Finding` at
  scan time — EPSS scores shift daily and a finding can stay open for weeks, so it's looked up live at
  scoring/read time instead.
- New scheduler job `exploit_intel_refresh` (every 24h, `EXPLOIT_INTEL_REFRESH_HOURS` env override),
  runs once ~1 minute after worker startup too (the table starts empty on a fresh deploy/migration —
  waiting a full interval would leave scoring/API reads silently unpopulated for up to a day).
  Downloads EPSS's bulk CSV (`epss.cyentia.com/epss_scores-current.csv.gz`, ~346k CVEs, no API key) and
  CISA's KEV JSON feed (`cisa.gov/.../known_exploited_vulnerabilities.json`, ~1,635 CVEs, no API key),
  batch-upserts EPSS (2000 rows/batch), and does a full is_kev reset + re-mark for KEV each run so a
  CVE removed from the upstream catalog (rare, but possible) doesn't keep an escalated boost forever.
- **Migration note**: `make migrate-create` (`alembic revision --autogenerate`) turned out to be broken
  in this repo — `backend/app/db/migrations/` is missing `script.py.mako` entirely (never copied in when
  the alembic environment was set up), so autogenerate fails outright. Separately, autogenerate also
  detected a large, pre-existing, unrelated drift between `models.py` and applied migrations across many
  tables (server defaults, NOT NULL constraints, index names) — none of which this migration should
  touch. Wrote `015_exploit_intel.py` by hand instead (matching the style of prior hand-written
  migrations in this repo, e.g. `012_discovered_assets.py`), which is also just the safer path given the
  drift. Every migration in this repo up to now was very likely written by hand for the same reason —
  worth knowing before assuming `make migrate-create` works.

### Added: exploit-likelihood boost in risk scoring — escalation-only, a different axis from confidence
- **Files**: `backend/app/services/risk_engine.py` (`FindingInput.exploit_boost`,
  `compute_severity_penalty`), `workers/risk/risk_worker.py::_load_findings`
- `compute_severity_penalty()` now multiplies in `exploit_boost` (`max(1.0, exploit_boost)` — a value
  below 1.0 is never honored) alongside the existing `confidence`/`decay` factors. This is deliberately
  a **different concept** from Milestone 7's `confidence`: confidence is about whether a specific match
  is trustworthy (can reduce a penalty); exploit intel is about how urgently a *real* finding should be
  prioritized (can only ever escalate one). Boost values: KEV-listed → ×1.5; KEV-listed with confirmed
  ransomware use → ×1.75; EPSS ≥ 0.5 (no KEV) → ×1.2; anything else (including a low or absent EPSS
  score) → ×1.0 — a low EPSS score is not evidence a finding is safe to deprioritize, so the floor is
  1.0, never lower. `risk_worker.py::_load_findings` collects every CVE across an org's active findings
  in one batch query (`get_exploit_intel`), not per-finding, before computing each finding's boost.
- Verified against real EPSS/KEV data pulled by the actual scheduler job (not synthetic): `CVE-2024-3400`
  (a real, well-known actively-exploited Palo Alto GlobalProtect vulnerability) correctly resolves to
  `is_kev=True, kev_known_ransomware=True, epss_score≈0.99999` → boost `1.75`. Confirmed this measurably
  moves a *category* score through the full `compute()` pipeline (75 → 56 for an identical synthetic
  "high"-severity `known_cve` finding, boost 1.0 vs 1.75) — deliberately checked at the category level,
  not overall score: a single finding's effect on the *overall* blended score can get masked by
  `risk_engine.py`'s existing severity-based ceiling caps (e.g. any critical finding present caps
  `overall_score` at 79 regardless of the weighted category average) or simply rounds away at very low
  finding counts — neither is a bug in this feature, just how a 9-category weighted blend behaves with
  a single low-weight data point, and it's exactly why Milestone 7's own confidence test checked the
  category score too, not just the overall number.

### Added: EPSS/KEV surfaced on findings (live join, not frozen at scan time)
- **File**: `backend/app/api/v1/endpoints/findings.py`
- `GET /findings`, `GET /findings/{id}`, and `GET /findings/export?format=json` now include
  `epss_score`/`epss_percentile`/`is_kev`/`kev_known_ransomware` per finding — worst-case across all of
  a finding's CVEs (same "max wins" reasoning as the scoring boost). Batch-fetched once per request
  (`get_exploit_intel` over every CVE ID in the response set), not per-finding, to avoid an N+1 query
  pattern. Verified live: `GET /findings` on the test org returns the new fields correctly (all
  `epss_score: null, is_kev: false` for its current findings — none happen to have a KEV/high-EPSS CVE
  yet, a legitimate result, not a failure).

### Added: frontend surfacing for M7 confidence + M8 EPSS/KEV (previously API-only)
- **Files**: `frontend/src/types/index.ts`, `frontend/src/components/ui/SeverityBadge.tsx` (new
  `KEVBadge`, `EPSSBadge`, `ConfidenceIndicator`), `frontend/src/app/dashboard/findings/page.tsx`,
  `frontend/src/components/modals/FindingDetailModal.tsx`
- All of Milestone 7's `confidence` field and this milestone's `epss_score`/`is_kev`/
  `kev_known_ransomware` fields were reaching the API but had no UI to render them — the dashboard
  looked identical before and after both milestones. Added: a pulsing red "Actively Exploited" (KEV)
  badge inline on the finding title in the findings table and prominently in the detail modal header
  (a "· Ransomware" variant when `kev_known_ransomware`); an EPSS percentage badge (only shown for
  scores > 0, orange when ≥ 50%); a compact confidence dot+label (only rendered for "high"/"low" —
  "unknown" is the majority case and would just be table noise); an "EPSS Percentile" and "Match
  Confidence" tile in the detail modal's meta grid when present.
- **Frontend is a production Next.js build in this deployment** (`docker-compose.yml`'s `frontend`
  service builds `target: production` with no source volume mount — contrary to CLAUDE.md's "run
  locally for dev" note, this environment runs it containerized), so unlike the workers/api (bind-mounted,
  `restart` picks up changes), these changes needed `docker compose build frontend` +
  `docker compose up -d --no-deps frontend` to actually deploy, not just a restart.
- Verified: `npx tsc --noEmit` and `npm run lint` both clean (lint warnings present are 100%
  pre-existing, in files this change didn't touch — `next/image` suggestions, a couple of
  `useEffect` exhaustive-deps warnings). Confirmed the compiled production bundle actually contains the
  new code (`grep -rl "Actively Exploited" .next/static/chunks/` matched a real chunk file, not stale
  cached output). `npm test` was **not** run — `jest` is referenced in `package.json`'s `test` script
  but was never added as an actual dependency, a pre-existing gap unrelated to this change. Could not
  visually screenshot the rendered page — no browser/screenshot tool available in this environment;
  verification here is type-check + lint + build-artifact content check + the already-verified API
  data contract, not a literal visual confirmation. Flagging this limitation explicitly rather than
  claiming a visual check that didn't happen.

### Verification
- New unit tests: `backend/tests/unit/test_exploit_intel.py` (16 tests — date parsing, boost
  calculation including the "never reduces below 1.0" guarantee, worst-case-wins across multiple CVEs,
  KEV+ransomware escalation, dict serialization) plus 3 new tests in `test_risk_engine.py` (penalty-level
  boost scaling, floor-at-1.0 guarantee, and the category-score-level pipeline test described above).
  Backend unit suite: 105 → 124 passed, 1 skipped (pre-existing, unrelated), no regressions.
- Ran the actual scheduler job against live upstream data (not a mock): `exploit_intel_refresh_completed
  epss_rows=346522 kev_rows=1635` in ~36 seconds; confirmed both counts landed in Postgres
  (`SELECT count(*), count(*) FILTER (WHERE is_kev) FROM exploit_intel` → `346522, 1635`) and spot-checked
  real, recognizable KEV+ransomware+near-max-EPSS entries (e.g. `CVE-2024-3400`) to sanity-check the
  data isn't just structurally valid but factually correct.
- Published a real `risk.compute` message through RabbitMQ (not a direct function call) and confirmed
  `worker-risk` processed it end-to-end with the new `exploit_boost` lookup in the hot path, no
  exceptions, against the test org's real 173 findings.

---

## 2026-07-10 — Milestone 7: Finding Validity & Coverage Gaps

User asked whether the core pipeline is mature and whether new tools are needed for finding validity.
Two research passes (read-only) separated this into two distinct questions: **A** — is the *existing*
detection trustworthy (evidence, false-positive handling, triage), and **B** — are there attack-surface
categories genuinely absent, not just improperly wired. User chose full scope: fix both, plus wire the
two "looks built, isn't active" capabilities the research turned up.

### Fixed: Finding triage status silently reset to "open" on every rescan (A1)
- **Files**: `workers/scanner/scanner_common.py` (new `status_preserving_conflict_updates()`),
  `workers/scanner/nuclei_worker.py::_persist_findings`, `workers/scanner/nikto_worker.py::_persist_findings`
- The triage workflow — `POST /findings/{id}/false-positive`, `/accept-risk`, `/reopen`, full DB fields
  for all of it — was already fully built. But all three independent Finding-upsert call sites
  unconditionally reset `status` back to `"open"` in their `ON CONFLICT DO UPDATE` clause on every
  rescan that re-matched the same fingerprint, silently undoing the analyst's call the moment the same
  issue was seen again. This made the entire triage feature useless for periodic scans. Added one
  shared helper (`status_preserving_conflict_updates`, SQLAlchemy `case()`/`and_()`/`or_()` against
  `Finding.__table__.c`) and wired it into all three sites instead of each re-deriving `{"status":
  "open"}` independently — the same "same logic duplicated per worker file" shape flagged repeatedly in
  Milestone 6. Semantics: `false_positive` never flips back to `open`; `accepted` with an active (null
  or future) `risk_accepted_until` stays; an *expired* acceptance reopens; `resolved` reappearing is a
  real regression and reopens. `nikto_worker.py` is presently dead/unwired code (`QUEUE="scan.nikto"`,
  no `worker-nikto` service exists) — fixed anyway so the bug can't resurface if it's ever wired up.
- **Verified against real Postgres**, not just the helper called in isolation (new
  `workers/tests/test_finding_upsert_integration.py`, 4 tests, all passing): insert a finding, mark it
  `false_positive`/active-`accepted`/expired-`accepted`/`resolved`, re-run the real upsert, assert the
  correct status-preservation/reopen behavior in each case.

### Fixed: CVE finding confidence field existed and was already scored, but hardcoded to 1.0 everywhere (A2)
- **Files**: `workers/scanner/nuclei_worker.py` (new `_cve_confidence()`), `workers/risk/risk_worker.py`,
  `backend/app/api/v1/endpoints/findings.py`
- `risk_engine.py::FindingInput.confidence` already existed and was already multiplied into the penalty
  calculation, with a passing unit test — `workers/risk/risk_worker.py::_load_findings` just always set
  it to `1.0`. This was "wire an existing scored field," not build a confidence subsystem from scratch.
  `_cve_confidence()` cross-checks a CVE template's own tags (normalized through the existing
  `_tech_tags()`/`TECH_TAG_ALIASES`) against the specific asset's fingerprinted tech stack (from
  `tech_map`, already threaded through for the `-tags` filter). No CVE, no product tag on the template,
  or no fingerprint data for that asset → `"unknown"`/1.0 (missing data isn't evidence of a false
  positive, so it must not silently penalize). Tags intersect → `"high"`/1.0. Tags present on both sides
  but disjoint → `"low"`/0.5 (halved, never dropped). Surfaced as `proof.confidence` (transparent, not
  hidden) and now as a top-level `confidence` field on `GET /findings`.
- **Real scoring behavior change, called out explicitly**: a low-confidence CVE match now measurably
  reduces its own penalty contribution to the org's risk score. This is the entire point of wiring the
  field, but it does mean the same finding set can now produce a different score than before this fix —
  worth knowing if comparing scores across the cutover.
- Verified via 4 new unit tests (`test_scan_policy.py` ×3 covering the config-layering fix below,
  `test_risk_engine.py` ×1 proving confidence actually shifts a *category* score through the full
  `compute()` pipeline, not just the raw penalty function) — backend unit suite: 101 → 105 passed.
  Confirmed end-to-end against a real scan: `proof->>'confidence'` populates on nuclei findings (this
  particular validation scan didn't happen to hit a CVE-tagged template on a fingerprinted asset, so its
  own findings show `"unknown"` — the field is present and populated, not silently absent, which is what
  matters).

### Fixed: ffuf content/directory fuzzing was fully implemented but disabled everywhere (B3)
- **Files**: `backend/app/services/scan_profiles.py`, `backend/app/services/scan_service.py`,
  `workers/fuzz_wordlist.py` (new, shared)
- `discovery_worker.py::_fuzz_endpoints` and `web_crawl_worker.py::_run_ffuf` were both real, working
  implementations — gated by `config.get("fuzz", False)`, and every layer of config forced it off. Same
  multi-layer shape as Milestone 6's batch-size bug: `SCAN_PROFILES["deep_authorized"]` had no `fuzz`
  key at all; `DEFAULT_SCAN_CONFIG["full"]` hardcoded `False` (wins over the profile via
  `profile.update(incoming)`); `DEFAULT_SCAN_POLICY["crawl"]["fuzz"]` hardcoded `False` for *every* scan
  type via `_policy_to_config()`, applied before the profile is even resolved. Added `fuzz: True` to
  `deep_authorized` (the authorized/deep profile — the one place this belongs, not `safe`/`quick`), and
  removed the two hardcoded `False`s that silently clobbered it. `quick`/`safe` correctly remains
  unaffected (verified by a new test).
- **Additional finding while checking the wordlist**: the actual worker image has neither
  `/usr/share/wordlists/dirb/common.txt` nor a seclists path installed, confirmed by checking the live
  `worker-crawl` container — so the ~28-word Python-literal "fallback" in both files was not a rarely-
  hit deliberate minimum, it was *unconditionally* the entire fuzzing wordlist, and it was duplicated
  identically in two files. Consolidated into one shared module (`workers/fuzz_wordlist.py`) and
  expanded to 198 curated words (admin panels, backup/config/VCS exposure, CMS-specific paths, cloud/
  infra hints, dev/staging paths, monitoring endpoints, CI/CD, DB admin tools) — same spirit as the DNS
  wordlist expansion in Milestone 6. Bundling a real external wordlist via a `Dockerfile` `COPY` is a
  better long-term answer but needs a worker image rebuild; noted as a follow-up, not done here.
- Verified end-to-end against a real "full" scan's persisted `scans.config` (`fuzz: true`) and against
  its actual crawl-phase results: `endpoint_sources.ffuf: 149` — ffuf genuinely found 149 endpoints in
  the validation scan.

### Implemented: cloud storage bucket-name enumeration (B4) — after the intended nuclei route was proven not to work
- **Files**: `workers/discovery/bucket_candidates.py` (new), `workers/scanner/coverage_worker.py`
  (`_discover_cloud_buckets`, merged into the existing `_scan_cloud`)
- The plan was to wire nuclei's `cloud/enum/aws-s3-bucket-enum.yaml` template via `-var wordlist=<file>`.
  Empirically verified this does not work: the template is `self-contained`/`attack: batteringram` with
  no `payloads:` block. Tried `-esc` (required for self-contained templates at all), `-var`/`-V`, `-dast`,
  and a locally-patched copy of the template with an explicit `payloads: {wordlist: <file>}` block added
  — every combination fails with `"Could not run nuclei: no templates provided for scan"` (0 templates
  actually load), versus a normal template which loads and runs cleanly in the same environment/nuclei
  version (v3.11.0). Rather than wire in a call that would silently do nothing, implemented bucket
  enumeration directly: `bucket_candidates.py` generates bounded candidate names from the org's own
  root domains/company name (same reasoning and shape as `dns_candidates.py`'s DNS bruteforce
  candidates), and `_discover_cloud_buckets` probes each with a capped-concurrency HEAD request,
  persisting an `Asset` (`cloud_bucket`) only for a *confirmed* hit (200 open, or 403 exists-but-
  protected) — a non-hit is not a discovery. Merges into the existing `_scan_cloud`/`_cloud_probe`
  pipeline, so a newly-discovered bucket gets the same public-exposure check every already-known bucket
  asset already gets, with no new finding-persistence machinery needed.
- Verified manually: a real, known-public bucket name (`commoncrawl`) correctly returns 403 (exists,
  protected); a made-up name derived from the test org's brand (`pasarjaya`) correctly returns 404
  (filtered, not persisted as a false discovery).

### Added: real `.git` exposure confirmation + secrets scanning (B1)
- **Files**: `workers/secrets_scan.py` (new, shared), `workers/scanner/coverage_worker.py`
  (`_scan_git_secrets`), `workers/scanner/discovery_worker.py`, `backend/app/services/risk_engine.py`,
  `frontend/src/app/dashboard/scans/[id]/page.tsx`
- `exposed_git` was previously pure keyword-matching on nuclei/nikto template names ("git"/"env"/
  "config"/"backup") — no confirmation that a `.git` directory is actually exposed. New scanner family
  `git_secrets` (same self-contained detect→tool→persist shape as the existing `_scan_tls`/
  `_scan_takeover`, deliberately *not* reactive to nuclei/nikto's own findings since those run
  concurrently off the same fan-out with no ordering guarantee) fetches `.git/HEAD` directly, confirms
  via a real `ref: refs/...` or 40-hex-SHA response body (not just a 200 status), and if confirmed also
  fetches `.git/config` and runs both through a shared secrets-regex pass.
- New module `workers/secrets_scan.py` (also used by B2 below — one shared regex set, not duplicated):
  curated patterns for AWS access keys, generic API-key/secret/token assignments, JWTs, PEM private-key
  headers, Slack tokens, Google API keys. **Secrets are never stored in full** — only a masked value
  (first 4 + last 4 characters) plus a SHA-256 hash for correlation. This is a deliberate safety
  decision, not an implementation detail: `Finding.evidence`/`proof` are returned over the API to
  anyone with finding-read access, so storing a live credential verbatim would create a new secret-
  sprawl point inside this platform's own database.
- New `credential_exposure` finding category, added to `risk_engine.py::FINDING_CATEGORY_MAP`
  (`INFO_LEAKAGE`). Runs alongside the other scanner-family checks in every profile (not gated to
  `deep_authorized` only) — it's two capped, read-only GETs per host, no heavier than nuclei/nikto's
  existing keyword-matched checks that already run in every profile including `safe`.
- Verified against a real full scan: `git_secrets` phase completed cleanly across 200 real hosts with
  zero crashes (SSL cert errors, DNS failures, and connection errors all handled gracefully) and
  correctly reported 0 confirmed exposures (the org genuinely has none exposed — a clean negative
  result, not a bug).

### Added: JavaScript analysis in the crawl pipeline (B2)
- **File**: `workers/crawler/web_crawl_worker.py` (`_analyze_js_endpoints`)
- No prior handling of `.js` file *content* — they were crawled as URLs like anything else but never
  fetched and parsed. New step runs right after `_validate_urls()`: filters crawled `.js` files down to
  the scan's own root domain(s), fetches each (size- and concurrency-capped), and runs them through the
  same shared `secrets_scan.py` module as B1 for endpoint/secret/subdomain extraction.
  - Extracted **endpoints** are resolved against the JS file's own origin, re-validated, tagged
    `source="js_extracted"`, and merged into the existing `_persist_endpoints`/`_publish_selected_nuclei`
    flow — they get the exact same nuclei-targeting/scoring treatment as every other crawler-discovered
    endpoint, no parallel machinery.
  - Extracted **secrets** become `credential_exposure` findings via the same masked-value/hash approach
    as B1.
  - Extracted **subdomains** are surfaced only as an observability field in `phase_status`
    (`js_extracted_candidate_subdomains`), not auto-created as `Asset` rows — a string literal inside a
    third-party-served `.js` file hasn't gone through the scope/ownership validation gate
    (`asset_validation.py`) every other asset-creation path in this codebase goes through; auto-creating
    from it could put an unrelated URL "in scope" without that check ever running.
- Verified against a real full scan: 35 `.js` files analyzed, 3 extracted endpoints flowed all the way
  through to persisted `web_endpoints` rows with `source='js_extracted'` (confirmed via direct query),
  0 candidate subdomains this run (no `.js` file happened to reference one — an acceptable, expected
  outcome, not a failure).

### Explicitly deferred: active exploitation confirmation (A3)
Reflected-XSS proof-of-concept execution, boolean/time-based SQLi confirmation, or any other active-
exploitation-style verification is **not** in this milestone's scope. Everything implemented here (git
HEAD/config fetch, JS body fetch, bucket-name probing, ffuf path fuzzing) is a read-only GET; active
confirmation means sending payloads specifically to prove exploitability, a materially different
authorization posture that needs its own explicit conversation, not a decision folded into this pass.
Documented here as a known limitation.

### Added: `workers/` test infrastructure (didn't exist at all before this)
- **Files**: `workers/tests/test_secrets_scan.py`, `workers/tests/test_bucket_candidates.py`,
  `workers/tests/test_finding_upsert_integration.py` (all new)
- Discovered while trying to test the new pure-Python modules: `workers/` is not mounted into the `api`
  container at all (only `./backend:/app`), which is *why* the pre-existing `test_scan_pipeline_state.py`
  fails to import `workers.scan_state` (a known, already-documented, out-of-scope issue) — and it means
  `workers/` has never had any test coverage of its own, despite being the majority of this platform's
  actual scanning logic. Added 18 unit tests (regex correctness for the new secrets patterns including
  adversarial near-misses like AWS's own example key and common placeholder values; bucket-candidate
  bounding/dedup) plus 4 integration tests against real Postgres for the A1 fix. Run via
  `docker compose exec <worker> python3 -m pytest workers/tests/ -v` — `pytest`/`pytest-asyncio` were
  installed ad-hoc for this verification, not added to the permanent image/`requirements-workers.txt`;
  wiring that (plus a `make test-workers` target) so this runs automatically in CI is a real follow-up,
  not done in this pass. The integration tests must currently be run one at a time (`::test_name`), not
  as a whole file in one invocation — `workers/db.py`'s async engine is a module-level singleton bound
  to whichever event loop opens its first connection, which conflicts with pytest-asyncio's per-test
  event loop on the second test in the same process. This is a test-harness artifact, not a product bug
  (each test passes cleanly in isolation, which is what actually proves the fix).

### Verification
- Backend unit suite: 101 → 105 passed, 1 skipped (pre-existing, unrelated), no regressions —
  re-run after every fix in this milestone.
- New `workers/tests/`: 18 unit tests + 4 integration tests (real Postgres), all passing.
- Full real scan through the actual API (not isolated function calls): persisted `scans.config` showed
  `fuzz: true`, `js_analysis_enabled: true`, `nuclei_batch_size: 8`, `crawl_nuclei_batch_size: 8` all
  correct; crawl phase completed with `js_files_analyzed: 35`, `endpoint_sources.ffuf: 149`,
  `endpoint_sources.js_extracted: 3` (confirmed as real `web_endpoints` rows); `git_secrets` phase
  completed cleanly across 200 hosts with a correct zero-finding result; `cloud_exposure` phase
  (including the new brand-based bucket discovery) completed cleanly with a correct zero-finding result;
  nuclei findings show a populated `proof.confidence` field.

---

## 2026-07-10 — Milestone 6: Scan Pipeline Maturity (Recon → Enumeration → Enrichment → Vuln Scanning)

User reprioritized after Milestone 5: before selling readiness or platform self-security bugs, the
core scanning pipeline itself needed a deeper pass — specifically the concern that real findings could
be silently missed somewhere across discovery/enumeration/enrichment/nuclei, not just that the tools
were "installed" (Milestone 4 already covered that). This pass re-audited config resolution end-to-end
rather than tool presence, and found five distinct places where scan behavior was quietly weaker than
intended, plus a re-occurring config-layering bug that took two extra rounds of fixing to actually land.

### Fixed: Nuclei never ran `info`-severity templates
- **Files**: `workers/scanner/nuclei_worker.py` (`DEFAULT_SEVERITIES`), `backend/app/services/scan_profiles.py`
  (`"default"`, `"deep_authorized"`, `"endpoint"` profiles' `severities` lists)
- None of the three severities lists included `"info"`. Quantified the actual impact by checking the
  installed nuclei-templates tree: the `exposed-panels` category is 98% info-tagged and `exposures` is
  49% info-tagged — meaning nearly all templates in those categories, plus most missing-security-header/
  cookie/CSP checks across the whole template set, never ran regardless of how many templates were
  installed or how often they were updated. Added `"info"` to all three profiles' severities and to
  `DEFAULT_SEVERITIES`. `_apply_runtime_caps()` in `scan_service.py` still strips `"info"` back out for
  `"deep_authorized"` unless `nuclei_include_info_templates` is explicitly set — added that flag to the
  profile so the strip doesn't silently re-undo this fix (same "safety net catches its own fix" shape as
  the batch-size issue below).

### Fixed: On-demand ("full"/"vuln") scans only covered top-100 ports
- **File**: `backend/app/services/scan_profiles.py`
- `"deep_authorized"` (the profile behind `full`/`vuln` scan types) had `"ports": "top-100"` — too
  narrow for a scan meant to be the thorough/authorized option. Changed to `"top-1000"`.

### Fixed: DNS bruteforce wordlist was too thin
- **File**: `workers/discovery/dns_candidates.py` (`DEFAULT_DNS_WORDS`)
- 30 words, missing entire categories of common subdomain naming conventions. Expanded to 205
  (verified no duplicates): remote-access/infra-mgmt, internal/dev-tooling, API/gateway patterns,
  environment/lifecycle variants, business/customer-facing names. The existing `max_hosts=100` cap in
  `generate_bruteforce_hosts` is unchanged and still applies.

### Fixed: Nuclei ran one target per subprocess instead of batching — enforced redundantly across
  **seven independent layers**
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/scanner/discovery_worker.py`,
  `backend/app/services/scan_profiles.py`, `backend/app/services/scan_service.py`
- Nuclei batch size was effectively 1 (one host or one URL per subprocess invocation) across the
  pipeline. That isolation already exists more cheaply at two other layers — nuclei's own per-template
  timeout and `nuclei_worker.py::_run_nuclei`'s `TimeoutError` handler, which still parses whatever
  partial JSONL results were written before a batch-level timeout kills the process — so batch-size-1
  bought nothing but paying nuclei's template-load/init overhead once per host/URL instead of once per
  batch (observed: ~35 single-target batches × 2.5–6 min each on a full org scan). Raised the batch
  size to 8 throughout, but doing so required finding and fixing it in **seven separate places**, not
  one, because the same setting was independently re-declared at every layer of the config-resolution
  chain:
  1. `web_crawl_worker.py::_publish_selected_nuclei` — hardcoded clamp ceiling `min(x, 1)` → `min(x, 10)`.
  2. `scan_profiles.py` `SCAN_PROFILES["deep_authorized"]` — `nuclei_batch_size` 4→8, `crawl_nuclei_batch_size` 1→8.
  3. `scan_service.py::PROFILE_RUNTIME_CAPS["deep_authorized"]` — was silently re-clamping back down to
     the old values regardless of what the profile said; fixed to 8/8.
  4. `discovery_worker.py` — had its own separate hardcoded severity info-strip and a `min(x, 4)` batch
     ceiling for root-host nuclei batches, independent of layers 1–3; both removed/raised.
  5. `scan_service.py::DEFAULT_SCAN_POLICY["budgets"]` — hardcoded `nuclei_batch_size=4`,
     `crawl_nuclei_batch_size=1`. This dict feeds `_policy_to_config()`, which is merged into
     `apply_scan_profile()`'s `config` argument *before* the profile is applied.
  6. `scan_service.py::DEFAULT_SCAN_CONFIG["full"]` and `["vuln"]` — same stale hardcoded values, merged
     in the same way for the two scan types that actually use the `deep_authorized` profile.
  7. `scan_service.py::create_nuclei_asset_scan()` — a separate scan-creation method (for re-scanning
     already-discovered assets directly) with its own hardcoded `endpoint_config` override
     (`nuclei_batch_size: 1`) and its own local ceiling clamps (`host_batch_size` capped at 4,
     `endpoint_batch_size` capped at 1), entirely independent of the profile system.

  **Root cause of why this took three passes to actually fix**: `apply_scan_profile()` has
  `profile.update(incoming)` semantics — the `incoming` config (built from `DEFAULT_SCAN_CONFIG` +
  `DEFAULT_SCAN_POLICY` + org policy + request body, *before* `apply_scan_profile` runs) always wins
  over `SCAN_PROFILES` defaults. Layers 2–3 were fixed and verified correct first, by calling
  `apply_scan_profile()`/`PROFILE_RUNTIME_CAPS` directly in a Python shell — which looked completely
  correct in isolation (`nuclei_batch_size: 8` came back every time). That verification was **not
  sufficient**: it never went through `create_and_queue()`, so it never touched layers 5–7, which
  silently fed the *old* values back in as `incoming` and overwrote the fix before it ever reached a
  real scan. This was only caught by inspecting the persisted `scans.config` JSONB column for actual
  API-created scans, which still showed `nuclei_batch_size=4, crawl_nuclei_batch_size=1` for scans
  created *after* the layer-2/3 fix and container restart. Lesson reinforced (a running theme across
  this whole audit): a fix that "looks correct" when a function is called directly, in isolation, is
  not the same as a fix verified against what the real API-driven code path actually persists to the
  database. All seven layers are now fixed and re-verified against a real scan's persisted config (see
  Verification below).

### Fixed: Correlation worker redundantly recomputed the full org graph on every nuclei batch
- **File**: `workers/correlation/correlation_worker.py`
- `process()` ran dedupe → `_build_relationships` → `persist_relationships` → `update_org_stats` →
  `index_to_opensearch` on **every** intermediate correlation message — up to ~40-50 times per scan
  (once per nuclei/port/crawl/enrich/scanner batch), instead of once when the scan actually finished.
  Gated all of that behind `if is_terminal:`; intermediate messages now just log and return.
  `_build_relationships` was also O(F×T) (nested loop over every finding × every tech row); rebuilt as
  a single `tech_by_asset_id` dict (`setdefault`, preserving the original "first match wins" semantics
  of the `break`), making it O(F+T).

### Verification
- `pytest tests/unit` (backend): 101 passed, 1 skipped (pre-existing `test_scan_pipeline_state.py`
  packaging issue, unrelated, out of scope) — run after every fix pass, including after the final
  layer 5–7 fix + `docker compose restart api`.
- Full end-to-end scan (`4390b279`, 3048s, run before the layer 5–7 discovery above — so it validates
  the severity/port/DNS/correlation fixes but *not yet* the fully-corrected batch size):
  - 79 new info-severity findings appeared that would previously never have run:
    `cors_misconfiguration` (20), `exposed_admin_panel` (25), `exposed_git` (2), `missing_hsts` (30) —
    alongside the pre-existing high/medium findings (`exposed_service` ×5 high, `known_cve` ×1 high,
    `old_tls_version` ×2 high + ×9 medium, `debug_endpoint` ×1 medium, `missing_dmarc` ×1 medium).
  - Port variety rose to 15 distinct ports including several outside a top-100 range (81, 100, 888,
    1723, 2000, 3000, 8009, 8291, 8443) — direct evidence the top-1000 port range is taking effect.
  - Correlation worker log showed exactly one `correlation_completed` (changes=270) versus dozens of
    fast `correlation_intermediate` entries for the same scan — the fan-in fix is live.
  - Risk score moved 69→64 (still grade C) — a legitimate decrease reflecting the newly-surfaced
    findings that were previously missed entirely, not noise.
- Batch-size fix, once layers 5–7 were found and corrected: created a fresh scan (`cb0b0cef`) through
  the real API and inspected its persisted `scans.config` directly via `psql` — confirmed
  `nuclei_batch_size=8, crawl_nuclei_batch_size=8` (previously 4/1 for every scan created before this
  final round, including two scans — `ec85fa67` and one accidental duplicate, `0645a3b4`, triggered by
  a `curl` command whose local output-file write failed after the HTTP request had already gone
  through — both of which therefore completed with the old 4/1 batching, not a new bug, just scans
  that were in flight before the fix landed). `cb0b0cef`'s nuclei phase reached `expected_batches=9`
  (4 endpoint batches covering 25 crawled targets, ~6.25 targets/batch) versus the old baseline of ~35
  single-target batches for a comparable full-org scan — batching is confirmed working end-to-end this
  time, verified against the database record of a real scan rather than an isolated function call.

---

## 2026-07-09 — Milestone 5: Frontend Hardening

### Fixed: Frontend dependencies could not be installed from a clean clone
- **Files**: `frontend/package.json`, `frontend/package-lock.json` (newly committed — had never been
  in git history for this repo)
- A truly clean `npm install` (empty `node_modules`, no lockfile) crashed with `TypeError: Invalid
  Version` inside npm's arborist dependency resolver, reproduced identically on npm 9.2.0 and a
  freshly-installed npm 10.9.8 — not a local npm-version quirk. Root cause: two incompatible major
  versions of `glob` (v7 via `rimraf`, v10.x nested under the old `eslint-config-next@14.2.3` →
  `@next/eslint-plugin-next`) coexisted with nothing pinning either, and today's registry state
  tripped a hard crash comparing them. Fixed by bumping `eslint-config-next` to `14.2.35` (matching
  the `next` patch below) — install now completes cleanly. Committed the resulting
  `package-lock.json` so this can't recur silently; Docker builds were only surviving before this by
  reusing whatever uncommitted local lockfile happened to exist on a given machine.

### Fixed: Next.js and axios pinned at versions with disclosed CVEs
- **File**: `frontend/package.json`
- `next` was exact-pinned at `14.2.3` (no `^`/`~`), which has a long list of disclosed advisories
  including authorization bypass, SSRF via middleware, cache poisoning, and XSS — `npm audit` flagged
  it critical. `axios` (handles every authenticated request in this app) was pinned at `1.7.2`, with
  25+ disclosed advisories (SSRF, prototype pollution, credential leakage) — flagged high. Bumped to
  `next@14.2.35` and `axios@1.18.1` (patches within the same major/minor, not `npm audit fix --force`'s
  breaking-change path). Verified: critical severity is gone entirely and axios has zero remaining
  findings. 5 vulnerabilities remain (1 moderate, 4 high) — all require a `next` 14→15 major version
  bump to fully resolve, which is a bigger, separate migration effort intentionally left out of this
  pass rather than forced blind.

### Fixed: `tsc --noEmit` and `npm run lint` didn't actually work
- **Files**: `frontend/.eslintrc.json` (new), `frontend/src/app/auth/login/page.tsx`
- `npx tsc --noEmit` failed with 20 `TS2688` errors before reaching this repo's own code — turned out
  to be corrupt `@types/d3-*` install artifacts (empty directories) from the same broken-install root
  cause above; resolved itself once the install was fixed. `npm run lint` dropped into an interactive
  "configure ESLint?" wizard — there was no committed ESLint config at all despite `eslint-config-next`
  being a devDependency and `make lint` documenting this command. Added `.eslintrc.json` extending
  `next/core-web-vitals` (the Next.js standard default). Running it for the first time surfaced one
  real error (unescaped apostrophe in `auth/login/page.tsx`, fixed) and several accepted warnings
  (missing `next/image` usage, a couple of `useEffect` exhaustive-deps gaps) left as-is — fixing those
  would mean broader behavioral changes outside this pass's scope. Zero test files exist anywhere in
  the frontend (`*.test.*`/`*.spec.*`) — noted, not addressed here.

### Fixed: Frontend called two backend endpoints that didn't exist
- **Files**: `backend/app/api/v1/endpoints/notifications.py`, `backend/app/api/v1/endpoints/admin.py`
- `DELETE /notifications/rules/{id}` (`lib/api.ts::notificationsAPI.deleteRule`) is wired to a real,
  live "Delete" button on `dashboard/notifications/page.tsx` with no `.catch()` — a user would confirm
  the delete, get no error, and the rule would silently stay. `PUT /admin/users/{id}`
  (`adminAPI.updateUser`) was declared but unreachable from any page (not yet user-facing, but the
  contract was already committed to). Added both endpoints (mirroring the existing
  `keys.py::delete_key` workspace-scoped-lookup-then-404 pattern), plus `PUT /notifications/rules/{id}`
  to close the same gap for the already-declared `updateRule`. Verified live: create → PUT (200) →
  DELETE (204) → DELETE again (404, not a silent no-op); admin role update rejects invalid roles (400)
  and applies valid ones (200).

### Changed: Relabeled the "Threat Intelligence" page
- **Files**: `frontend/src/app/dashboard/intel/page.tsx`, `frontend/src/components/layout/Sidebar.tsx`
- The page presented a full threat-intel UI (search, a "Malicious Only" filter, a Malicious/Benign
  status column) backed by an enrichment pipeline that is no-key ASN/RDAP/network-baseline data only
  (documented in `CLAUDE.md`) — the malicious-only filter could structurally never match anything
  real. Per user decision: relabeled to "Network Intelligence" (page title, sidebar label, empty-state
  copy), removed the "Malicious Only" filter and the Malicious/Benign status column entirely rather
  than leave a claim the data can't back up. `GET /intel` and its data model are unchanged — this was
  a labeling/UX fix only.

### Verification
`rm -rf node_modules && npm install` completes cleanly from scratch (the core proof, not a workaround).
`npx tsc --noEmit` and `npm run lint` both complete non-interactively with 0 errors. `docker compose
build frontend` succeeds using the committed lockfile; rebuilt `api` picked up the new endpoints.
`docker compose exec api pytest tests/unit -v` — 101 passed, 1 skipped (pre-existing, unrelated), no
regressions. All key dashboard pages (`/dashboard/intel`, `/dashboard/notifications`,
`/dashboard/reports`, `/auth/login`) return 200 through nginx.

---

## 2026-07-09 — Milestone 4: Scanning Tool Gaps Closed

Assessed every scanning tool the platform installs against what actually runs at runtime. Recurring
pattern found: a purpose-built tool gets installed, a weaker hand-rolled check ships instead, and the
tool is only referenced to populate a decorative `"<tool>_available"` status field that never gates
behavior.

### Added: Real tlsx integration for weak_cipher / old_tls_version
- **File**: `workers/scanner/coverage_worker.py` (`_scan_tls`, new `_tlsx_enrich`)
- `risk_engine.py::FINDING_CATEGORY_MAP` already had `weak_cipher`/`old_tls_version` keys mapped to
  `TLS_SECURITY`, but nothing ever populated them — `_scan_tls` only ever called Python's stdlib
  `ssl` module, never the installed `tlsx` binary (its `"tlsx_available"` field was decorative).
  Confirmed the gap is real by running `tlsx` directly against `sirupa.pasarjaya.co.id`: it still
  accepts TLS 1.1. Kept the existing Python-`ssl`-based expired/expiring/hostname-mismatch checks as
  they are; added a batched `tlsx -l <hosts> -tv -cipher -ve -ce -ct weak -ex -ss -mm -un -json`
  call for version/cipher enumeration, feeding the two previously-orphaned categories.

### Added: Real subzy integration for subdomain takeover
- **File**: `workers/scanner/coverage_worker.py` (`_scan_takeover`, new `_subzy_scan`)
- Same shape of gap: `_takeover_probe` did a hardcoded CNAME-prefix + substring match against a
  static ~15-entry `TAKEOVER_PROVIDERS` dict; `subzy` (76 actively-maintained fingerprints) was
  installed but unused. Kept the CNAME-based candidate narrowing (`_takeover_candidates`) as a cheap
  pre-filter, replaced the probe with a batched `subzy run --targets ... --vuln --hide_fails` call.
  Falls back to the old marker-match probe if the `subzy` binary is ever unavailable.
- **Gotcha found**: this subzy build's JSON output has a broken `"vulnerable"` boolean — observed
  `false` even when `"status": "vulnerable"` and the CLI console output flags it VULNERABLE. Code
  trusts `status`, not `vulnerable`. Also observed subzy flag a live, legitimate production host as
  a false-positive takeover candidate in ad-hoc testing outside the CNAME pre-filter — the two-stage
  (CNAME-narrow, then subzy-confirm) design is a deliberate mitigation, not just an optimization.

### Fixed: Subfinder never used its own premium-source support
- **Files**: `workers/scanner/discovery_worker.py` (new `ensure_subfinder_provider_config`, called
  from `DiscoveryWorker.setup()`), `docker-compose.yml` (`worker-discovery` environment)
- `_run_subfinder` already looked for a provider-config YAML and passed `-pc` — the file was just
  never generated, so subfinder always ran keyless/free-tier only despite `SHODAN_API_KEY`,
  `CENSYS_PAT`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` sitting configured in `.env`. Also found these
  keys were never even passed into any container's environment in `docker-compose.yml` — fixed that
  too. `DiscoveryWorker.setup()` now writes `/etc/subfinder/provider-config.yaml` from whichever of
  those four env vars are set (verified: all four populated correctly, log confirms
  `subfinder_provider_config_written sources=['shodan','censys','virustotal','alienvault']`).
  `ABUSEIPDB_API_KEY` has no subfinder source (it's an IP-reputation key) — left alone, consistent
  with the no-third-party-enrichment decision already in `CLAUDE.md`.

### Fixed: nuclei-templates volume pointed at the wrong path
- **Files**: `docker-compose.yml`, `workers/scanner/nuclei_worker.py` (new `setup()` override)
- The `nuclei-templates` named volume mounted at `/opt/nuclei-templates`, but nuclei's real template
  path (`NUCLEI_TEMPLATES_PATH`) is `/root/nuclei-templates` — completely disconnected, so templates
  only ever refreshed at image build time. Fixed the volume path and added a `-update-templates` run
  in `NucleiWorker.setup()` so a container restart refreshes templates without a full rebuild.
  Verified: the volume now contains real template content at the correct path, and the startup log
  confirms `nuclei_templates_refreshed`.

### Removed: nikto and masscan (installed, zero usage)
- **File**: `workers/Dockerfile`
- `nikto` was git-cloned with its own perl dependency chain but had no consuming worker service
  (`nikto_worker.py` was never wired to a queue). `masscan` had zero code references anywhere.
  Removed both; confirmed gone from the rebuilt image.

### Fixed: Zero version pinning on every Go-based scanning tool
- **File**: `workers/Dockerfile`
- `subfinder`, `httpx`, `nuclei`, `naabu`, `dnsx`, `tlsx`, `katana`, `gau`, `ffuf`, `subzy`,
  `assetfinder` were all `go install pkg@latest`, and `amass` was `@master` — every image rebuild
  could silently change scan behavior with no record of which tool version produced a given finding.
  Pinned to current tagged releases (subfinder v2.14.0, httpx v1.10.0, nuclei v3.11.0, naabu v2.6.1,
  dnsx v1.2.3, tlsx v1.2.2, katana v1.6.1, gau v2.2.4, ffuf v2.1.0, subzy v1.2.1, assetfinder v0.1.1,
  amass v4.2.0). Amass stays on the `v4` module path already in use rather than jumping to the new
  `v5` major (bigger, separate decision) — `use_amass` is never set `True` anywhere in the codebase
  today, so this only removes the supply-chain risk without changing whether/how it's enabled.
  Verified all pinned versions installed correctly in the rebuilt image.

### Fixed: Worker healthcheck was a no-op
- **Files**: `workers/base_worker.py` (heartbeat task in `run()`), `workers/Dockerfile`,
  `workers/scheduler/scheduler.py` (`_health_check`)
- `HEALTHCHECK` was `python -c "import sys; sys.exit(0)"` — always healthy regardless of actual
  state. `BaseWorker.run()` now touches `/tmp/worker_heartbeat` every ~20s while its RabbitMQ
  connection is alive; `HEALTHCHECK` now fails if that file goes stale (`find ... -mmin -1`).
  `scheduler` doesn't subclass `BaseWorker` (its own `ScanScheduler`/APScheduler loop), so it needed
  the same heartbeat touch added separately to its existing `_health_check()` — caught this because
  after rebuilding, every `BaseWorker` service came up `(healthy)` but `scheduler` came up
  `(unhealthy)` until this was added. All 12 worker-family containers confirmed genuinely healthy
  after the fix.

### Found (during rebuild): scheduler's healthcheck went unhealthy after the fix above
- **File**: `workers/scheduler/scheduler.py` (`_health_check`)
- `ScanScheduler` doesn't subclass `BaseWorker` (its own APScheduler-driven loop), so the new
  heartbeat never ran there — every `BaseWorker` service came up `(healthy)` after rebuild but
  `scheduler` came up `(unhealthy)`, since it shares the same Dockerfile/HEALTHCHECK. Added the same
  heartbeat touch to `scheduler`'s existing `_health_check()` (already runs every 60s and already
  logged `queue_connected`). Confirmed healthy after rebuild.

### Found (during verification): takeover summary mislabeled the "0 candidates" case
- **File**: `workers/scanner/coverage_worker.py` (`_scan_takeover`)
- The live verification scan had zero takeover candidates (no CNAME matched a known provider), so
  `_subzy_scan` correctly returned `subzy_ran=False` — but `_scan_takeover` then reported
  `tool: "http_marker_match"`, implying the fallback path ran, when really neither path had anything
  to check. Added a third `"no_candidates"` label so the summary distinguishes "subzy unavailable,
  fell back" from "nothing to scan" — a real diagnostic-accuracy bug caught by actually running the
  fix against live data instead of stopping at "the code doesn't error."

### Verification — confirmed end-to-end against a real fresh scan on `pasarjaya.co.id`
Rebuilt all worker images (Go tool compilation cached across services after the first build; static
checks — pinned versions present, nikto/masscan gone, provider-config populated with all 4 configured
keys, nuclei templates on the correctly-pathed volume, every worker-family container including
`scheduler` reporting real heartbeat-backed health — all passed before the live scan). Then ran a full
scan (`29b04b2d-f122-4be7-9c4c-f513097463f9`, ~59 min) and confirmed real, previously-invisible
findings appeared:
- **11 new `old_tls_version` findings across 8 hosts** — including 2 `high`-severity TLS 1.0
  acceptances (`e-office.pasarjaya.co.id`, `ams.pasarjaya.co.id`) and 9 `medium` TLS 1.1 acceptances
  (`sirupa`, `e-tax`, `bod`, `admin-sirupa`, `api-sirupa`, `cdn-sirupa`, `e-learning` subdomains,
  plus e-office/ams also on 1.1). Zero of these existed before this milestone — Python's `ssl` module
  alone never checked for them.
- `risk_scores.tls_security_score` for this org: **100 → 0** — previously "perfect" only because
  nothing was ever measured; now honestly reflects that 8 of its hosts run deprecated TLS.
  `overall_score` stayed at 69/C this run (already capped there by Milestone 1's high-severity
  aggregate guard from unrelated findings), but `tls_security_score` no longer silently masks this
  category the next time other categories improve.
- Subdomain count: **377 → 497** (+120) on a re-scan of the same organization, consistent with
  subfinder now querying Shodan/Censys/VirusTotal/OTX instead of free sources only (not a fully
  isolated A/B test, but directionally consistent with the fix).
- `takeover` phase: 0 candidates this run (no CNAME matched a known provider) — correctly labeled
  `tool: "no_candidates"` after the fix above, rather than falsely implying a fallback ran.

---

## 2026-07-09 — Milestone 3: Queue Routing Drift Fixed, Daily Reports Removed

### Fixed: `backend/app/core/queue_client.py` missing `scan.scanner`
- **File**: `backend/app/core/queue_client.py`
- Added the missing `scan.scanner` entry to `ROUTING_CONFIG`, matching `workers/queue_client.py`
  and `workers/base_worker.py::EXCHANGE_MAP` exactly. Previously, publishing to `scan.scanner` from
  backend/API code would `KeyError`.

### Removed: Scheduled daily report generation (product decision — reporting stays manual-only)
- **Files**: `workers/scheduler/scheduler.py`, `workers/queue_client.py`, `backend/app/core/queue_client.py`
- `scheduler.py::_generate_daily_summaries` was a real, active cron job (08:00 UTC daily) publishing
  a `report.daily` message per active workspace, but no worker anywhere consumed that queue — every
  message was silently dropped. Rather than build a consumer, the user decided report generation
  should stay manual-only (`POST /api/v1/reports/generate`, already built and working). Removed the
  `daily_reports` job registration and the `_generate_daily_summaries` method entirely, and dropped
  the now-unused `report.daily` entry from both `ROUTING_CONFIG` copies (the unused `CronTrigger`
  import was also removed from `scheduler.py`).
- Verified: `scheduler` restarted cleanly, job count dropped from 8 → 7, `daily_reports` no longer
  appears in `scheduler_health`'s `next_runs`. Both routing-config copies confirmed identical
  (11 matching keys, `scan.scanner` present, `report.daily` gone) via direct import inside the `api`
  and `worker-scanner` containers.

---

## 2026-07-09 — Milestone 2: Nuclei/Scanner Phase Status Stuck After Completion

### Fixed: Racy phase-status write let "completed" get overwritten back to "running"
- **File**: `workers/scan_phase.py` (`update_scan_phase`)
- Turned out `nuclei_worker.py` already had logic to compute `"completed"` from the shared Redis
  counters (`nuclei_done >= nuclei_expected`) — the original diagnosis that it was simply missing
  was wrong. The real bug: with concurrent batch workers, a batch that read the counter *before*
  the last increment can still finish writing `"running"` to `phase_status` *after* the batch that
  legitimately completed the phase — a read-modify-write race with no compare-and-swap. Added a
  monotonic guard: once a phase's persisted status is terminal (`completed`/`failed`/`skipped`), a
  later non-terminal write for the same phase is now a no-op. This protects every phase that goes
  through this shared helper, not just nuclei.

### Fixed: `scanner` umbrella phase had no completion logic at all
- **File**: `workers/scanner/scanner_common.py` (`publish_scanner_completion`)
- Unlike nuclei, this one really was missing entirely — it incremented the `scanner_done` Redis
  counter but never touched `phase_status`, so the `scanner` phase stayed `queued` forever even
  after all 5 sub-families (tls/dns_security/takeover/cloud_exposure/service_fingerprint) finished.
  Added the same "compute status from counts, call `update_scan_phase`" pattern nuclei already used
  — now protected from the same race by the guard above.

### Verified against a real fresh scan (not simulated)
- Re-ran a full scan on `pasarjaya.co.id` (scan `e935923b-4403-42c0-8072-3074498f47ec`, ~78 min,
  32 nuclei batches + 5 scanner sub-families) through the actual fixed worker code. Result:
  `phase_status.nuclei.status` and `phase_status.scanner.status` both `"completed"`; `scan_phase_runs`
  confirms `nuclei` at 32/32 and `scanner` at 5/5 `expected_tasks`/`completed_tasks`. No manual DB
  state manipulation this time — this ran end-to-end through the real pipeline.

---

## 2026-07-09 — Milestone 1: Risk Scoring False-Negative Fixed

### Fixed: Exposed DB/remote-admin ports under-rated as medium
- **File**: `workers/scanner/coverage_worker.py` (`RISKY_PORTS`)
- SMB, MSSQL, Oracle, NFS, MySQL, RDP, PostgreSQL, and Kibana were hardcoded `medium` despite being
  the same class of risk as VNC/Redis/Elasticsearch/MongoDB, which were already `high`. Bumped all
  eight to `high`. FTP stays `low`, Docker API stays `critical` — both already correctly calibrated.

### Fixed: Nuclei findings falling into the wrong risk category
- **File**: `workers/scanner/nuclei_worker.py` (`_map_category`)
- Templates that didn't match any prefix/tag/keyword rule defaulted to `"exposed_service"`
  (→ Network Security, 15% weight) — asserting a network-exposure claim that's often wrong. A
  Laravel `_ignition`-class debug finding fell through to this default instead of landing in
  Info Leakage, diluting Network Security alongside real port exposures. Added a `debug`/`ignition`/
  `stacktrace`/`trace` keyword branch → `debug_endpoint` (Info Leakage), and changed the blind
  default to `"cors_misconfiguration"` (Misconfiguration, the lowest-weighted category at 5%) —
  a much safer "we don't know" home than falsely claiming network risk.

### Added: Aggregate HIGH-severity score cap
- **Files**: `backend/app/services/risk_engine.py`, `backend/tests/unit/test_risk_engine.py`
- The only existing safety net capped the grade when `CRITICAL`-severity penalty totals were large;
  there was no equivalent for `HIGH`. Structurally, categories with zero findings contribute their
  full weight as if perfect, so a handful of real HIGH-severity exposures spread across categories
  could still average out near 100. Added a parallel `high_penalty` aggregate with two cap tiers
  (`>= 45` → capped at 69, `>= 15` → capped at 84), same pattern as the existing critical cap.
  Added 3 regression tests, including one that reproduces the real scenario below.

### Verified against real scan data (not just unit tests)
- Scan `1f1de107-4b96-40d5-8f3e-d5f9ceacba42` (`pasarjaya.co.id`) had scored **90/Grade A** despite
  MySQL exposed on 4 IPs, RDP exposed, and a Laravel debug endpoint. Restarted `worker-scanner`/
  `worker-nuclei`/`worker-risk` with the fix, confirmed the fixed severity/category logic directly
  against the real template IDs and ports involved, updated the existing findings to match what a
  fresh scan would now persist, and re-triggered `risk.compute` through the real `RiskWorker` code
  path (not a reimplementation). Result: **69/Grade C**, `network_security_score` 52→25,
  `info_leakage_score` 100→92, `high_count` 1→6. `docker compose exec api pytest
  tests/unit/test_risk_engine.py -v` — 42/42 passed.

---

## 2026-07-09 — ASM Output Assessment (scan 1f1de107, pasarjaya.co.id)

### Found: Risk score is a false-negative — Grade A despite internet-exposed DB/RDP/debug (not fixed)
- **Files**: `workers/scanner/coverage_worker.py`, `backend/app/services/risk_engine.py`
- A full scan surfaced genuinely poor exposures — MySQL (3306) exposed on 4 public IPs, RDP (3389)
  exposed, and a Laravel `_ignition` debug endpoint (CVE-2021-3129 class, unauthenticated RCE) — yet
  the org scored **90 / Grade A**. Root cause: `coverage_worker.py` hardcodes exposed MySQL and RDP
  as `medium` (`RISKY_PORTS`, lines ~57-58), the Laravel debug finding lands as `medium` too, and the
  risk engine's per-category weighted aggregation (`exposed_service → NETWORK_SECURITY`, 15% weight;
  MEDIUM penalty 8) dilutes a handful of mediums across categories so the overall stays near 100.
  Internet-exposed database and RDP should be High (RDP is a top ransomware vector); `_ignition`
  debug should be High/Critical. As-is, the ASM under-rates its own findings — the headline grade
  would tell a user they're fine when they are not. Logged for a follow-up scoring/severity pass.

### Found: Phase status stuck after scan completes (cosmetic, not fixed)
- **Files**: `workers/scan_phase.py`, `workers/scanner/nuclei_worker.py`, `workers/scanner/coverage_worker.py`
- Scan `1f1de107` finalized correctly (status `completed`, correlation + risk ran, all queues drained
  to 0, no DLQ) but `phase_status.nuclei` stayed `running` (its `ScanPhaseRun` shows 35/35 completed
  with a `completed_at` set — only the `status` field never flipped) and the `scanner` umbrella phase
  stayed `queued` (its sub-families tls/dns_security/takeover/cloud_exposure/service_fingerprint all
  completed, but the umbrella row was never updated). Purely a state-label bug — the scan detail UI
  would show a completed scan with phases that look stuck. No functional stall.

---

## 2026-07-09 — Reporting: Fixed Download Button Sending No Auth Header

### Fixed: Download button returned "Authentication required" in the browser
- **Files**: `frontend/src/app/dashboard/reports/page.tsx`
- The `download_url` fix earlier today made `<a href={report.download_url}>` point at a real
  endpoint, but a plain anchor click is a bare browser navigation — it never carries the
  `Authorization` header the API requires (`get_current_user` only accepts `Authorization: Bearer`
  or `X-API-Key`, no cookie/session fallback), so every click 401'd with `{"detail": "Authentication
  required"}`. Should have been caught in the earlier change by testing the real click-through
  instead of `curl` with a manually-attached token. Replaced the anchor with a button that calls the
  already-existing `reportsAPI.download()` (goes through the axios instance, which does attach the
  token via `frontend/src/lib/api.ts`'s request interceptor), turns the blob response into an object
  URL, and triggers the save via a temporary anchor with `download` set.

---

## 2026-07-09 — Reporting: Fixed Download + PDF Export

### Fixed: Dead download button on the Reports page
- **Files**: `backend/app/api/v1/endpoints/reports.py`
- `GET /reports` and `GET /reports/{id}` never returned `download_url`, so the frontend's
  `<a href={report.download_url}>` always fell back to `#`. Now both responses include
  `download_url` (null until the report reaches `completed`).

### Fixed: report_type and generation options were silently ignored
- **Files**: `backend/app/api/v1/endpoints/reports.py`, `backend/app/services/report_service.py` (new)
- `ReportGenerateRequest` only accepted `org_id`/`report_type`/`format`; the frontend's
  `date_range_days`, `include_charts`, `include_evidence` were dropped by Pydantic and
  `report_type` never changed the generated content. Moved report generation out of the endpoint
  file into a new `report_service.py` (matches this repo's services convention) and implemented:
  `executive` (summary + risk grade only) vs. `technical`/`compliance`/`custom` (full finding list +
  recent scans — the latter two alias to `technical`, no fake compliance-framework mapping or
  section-picker UI exists yet, see `CLAUDE.md`), `date_range_days` filtering on findings/scans,
  and `include_evidence` stripping of raw evidence fields.

### Added: PDF report export
- **Files**: `backend/app/services/report_service.py`, `backend/app/templates/report_pdf.html` (new),
  `backend/app/api/v1/endpoints/reports.py`, `backend/Dockerfile`, `backend/requirements.txt`
- `reportlab`/`weasyprint`/`jinja2` were installed but never used despite `Report.format` supporting
  `"pdf"`. Report generation now renders a Jinja2 HTML template through WeasyPrint (CSS-only bar
  charts, no new charting dependency) and uploads the PDF to the MinIO `reports` bucket; the
  download endpoint streams it back. `format` now defaults to `"pdf"` instead of `"json"`.
- `backend/Dockerfile` needed `libpango`/`libcairo`/`libgdk-pixbuf`/`fontconfig`/`fonts-dejavu-core`
  added — WeasyPrint has no PDF backend without them on `python:3.12-slim`.
- Hit and fixed a real WeasyPrint/pydyf incompatibility during testing: weasyprint 62.3 declares
  `pydyf>=0.10.0` with no upper bound, so pip resolves `pydyf==0.12.1`, which breaks
  `Stream.transform()` (`AttributeError: 'super' object has no attribute 'transform'`) on every PDF
  render. Pinned `pydyf==0.11.0` in `requirements.txt` until weasyprint is upgraded past this.
- Verified end-to-end against a live stack: registered a user, seeded assets/findings/a risk score,
  generated Executive and Technical PDFs, confirmed Executive omits the findings/scans sections,
  confirmed Technical's finding table respects `include_evidence`, confirmed CSV/JSON downloads and
  workspace-scoped 404s still work.

### Found: pre-existing issues noticed while testing (not fixed, out of scope)
- `backend/tests/unit/test_scan_pipeline_state.py` fails to collect in the `api` container
  (`ImportError: cannot import name 'scan_state' from 'workers'`) — the `workers/` package isn't
  mounted into the `api` container, only `backend/app` is, so this test can't import it there.
- `ruff`/`mypy` referenced by `make lint`/`make type-check` aren't in `requirements.txt` and aren't
  installed in the `api` image.
- Ambient mypy noise across the backend from SQLAlchemy declarative `Column`-typed attributes with
  no `sqlalchemy.ext.mypy.plugin` configured (e.g. `app/core/database.py`'s `AsyncSessionLocal()`
  being `Optional` at the type level, or reassigning a `Result` variable to its `.scalar_one_or_none()`
  value) — pre-existing, not introduced by this change.

---

## 2026-07-09 — CLAUDE.md Onboarding Doc + Architecture Audit

### Added: CLAUDE.md for Claude Code
- **Files**: `CLAUDE.md`
- New onboarding doc covering common commands (build/test/lint/migrate), pipeline/worker
  architecture, risk scoring, config conventions, and known README/docs drift.

### Found: Queue routing tables can drift (not yet fixed)
- **Files**: `backend/app/core/queue_client.py`, `workers/queue_client.py`, `workers/base_worker.py`
- `backend/app/core/queue_client.py::ROUTING_CONFIG` is missing the `scan.scanner` entry present in
  `workers/queue_client.py::ROUTING_CONFIG` and `workers/base_worker.py::EXCHANGE_MAP`. Publishing to
  `scan.scanner` from backend/API code would currently `KeyError`. Logged as a gotcha in `CLAUDE.md`;
  no code change made yet.

### Found: `report.daily` queue has no consumer (not yet fixed)
- **Files**: `workers/scheduler/scheduler.py`
- `scheduler.py::_generate_daily_summaries` publishes a `report.daily` message per workspace on a
  schedule, but no worker declares `QUEUE = "report.daily"` and it's absent from `EXCHANGE_MAP` — the
  messages are silently dropped (no queue bound to the `asm.report` exchange). On-demand reports via
  `POST /api/v1/reports/generate` are unaffected (separate `BackgroundTasks` path). Logged as a
  gotcha in `CLAUDE.md`; no code change made yet.

---

## 2026-06-07 — Endpoint Nuclei Isolation

### Changed: Isolated high-signal endpoint nuclei batches
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/scanner/nuclei_worker.py`, `backend/app/services/scan_service.py`, `backend/app/services/scan_profiles.py`, `frontend/src/components/modals/ScanModal.tsx`, `frontend/src/app/dashboard/scans/[id]/page.tsx`
- Endpoint nuclei batches now run one selected URL per batch so slow or timing-out endpoints do not block unrelated high-signal endpoints.
- Full-scan and nuclei-assets endpoint configs now use endpoint batch size `1` while keeping the endpoint timeout cap at 600 seconds.
- Nuclei phase summaries now include endpoint status counters for completed, timeout, failed, running, queued, and not-scanned endpoint targets.
- Scan detail UI now displays endpoint completed/timeout/failed counters inside the nuclei phase summary.

---

## 2026-06-06 — Nuclei Runtime Tuning

### Changed: Bounded but longer nuclei batches
- **Files**: `workers/scanner/nuclei_worker.py`, `workers/crawler/web_crawl_worker.py`, `backend/app/services/scan_service.py`, `backend/app/services/scan_profiles.py`, `frontend/src/components/modals/ScanModal.tsx`, `frontend/src/app/dashboard/scans/[id]/page.tsx`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/types/index.ts`, `docker-compose.yml`, `.env.example`, `PLAN_ASM_CORE_V2.md`
- Raised default host nuclei batch timeout cap to 900 seconds so deep/full profile runtime matches the configured `scan_timeout`.
- Raised endpoint nuclei batch runtime from 300 to 600 seconds while keeping smaller endpoint batches and liveness validation.
- Endpoint nuclei batches that time out now persist partial timeout evidence and mark affected endpoints as `timeout` instead of `completed`.
- Scan detail UI now shows nuclei summary fields for targets scanned, findings, inactive endpoint skips, suppressed info findings, and timeout batches.
- Exposed `NUCLEI_MAX_BATCH_TIMEOUT` and `NUCLEI_ENDPOINT_MAX_BATCH_TIMEOUT` through `.env.example` and `worker-nuclei` Compose environment.

---

## 2026-06-06 — Scanner Coverage Expansion Milestone 5 Start

### Added: Non-destructive scanner family plumbing
- **Files**: `workers/scanner/coverage_worker.py`, `workers/scanner/scanner_common.py`, `workers/task_coordinator.py`, `workers/queue_client.py`, `workers/base_worker.py`, `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `docker-compose.yml`, `workers/Dockerfile`, `workers/requirements-workers.txt`, `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/organizations.py`, `frontend/src/app/dashboard/scans/[id]/page.tsx`, `frontend/src/components/modals/ScanModal.tsx`
- Added `scan.scanner` queue support and a `worker-scanner` service for TLS, DNS security, takeover, cloud exposure, and service fingerprint scanner families.
- Task coordination now waits for scanner-family batches before terminal correlation, preventing scans from completing before Milestone 5 checks finish.
- Full scans now include the scanner module by default; scanner checks remain non-destructive and info-only observations are stored as phase evidence instead of findings.
- Added `tlsx`, `subzy`, and `dnspython` to the worker image/tooling plan.
- Port scan results now queue service fingerprint coverage for selected open ports; discovery queues TLS, DNS, takeover, and cloud exposure coverage.
- Endpoint nuclei batches now validate URL liveness with `httpx` before running nuclei and mark inactive endpoints as failed instead of leaving them running.
- Nuclei profiles are now explicit (`web_baseline`, `endpoint_high_signal`, `network_safe`, `tls_dns`, `takeover`, `cloud_exposure`, `exposure_misconfig`) and mapped from central scan profiles to improve medium/high signal coverage without enabling unsafe tags.
- Cloud exposure probes now normalize internal discovered bucket values such as `aws_s3:<bucket>` into non-destructive public-read probe URLs.
- Scan detail UI now summarizes scanner-family coverage phases.
- Docker smoke scan `b8108741-768b-49b2-bb8a-bf23f4f1bbfa` validated discovery-to-scanner queueing, TLS/DNS/service summaries, bounded `nmap -sV --version-light`, and surfaced missing SQLAlchemy import/JSON metadata issues in takeover/cloud coverage that were patched.
- Clean post-patch smoke scan `f25c2e69-c2da-468a-bc5e-64c455c484dc` completed successfully with TLS, DNS security, takeover, and cloud exposure scanner families all marked completed.

---

## 2026-06-06 — Asset Endpoint Pagination

### Added: Paginated asset endpoint tab
- **Files**: `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`
- Asset endpoint API now supports `page`, `page_size`, `total`, and `pages` while keeping the legacy `limit` parameter for compatibility.
- Asset detail endpoint tab now loads 25 endpoints per page with total range text and previous/next controls, improving usability for assets with thousands of crawled endpoints.

---

## 2026-06-05 — Crawl Root Endpoint Coverage

### Fixed: Empty endpoint tabs for reachable crawl roots
- **Files**: `workers/crawler/web_crawl_worker.py`, `frontend/src/types/index.ts`, `PLAN_ASM_CORE_V2.md`
- Crawler now includes each crawl target root URL as a low-score `root_probe` endpoint after validation, so reachable subdomains do not appear empty when no child paths are discovered.
- Added `root` endpoint classification for crawl target roots; these remain low priority and do not bypass endpoint selection thresholds.

---

## 2026-06-04 — Endpoint Intelligence V2 Milestone 4

### Added: First-class endpoint intelligence lifecycle
- **Files**: `backend/app/db/migrations/versions/014_endpoint_intelligence_v2.py`, `backend/app/db/models/models.py`, `workers/crawler/web_crawl_worker.py`, `workers/scanner/nuclei_worker.py`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/services/scan_service.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/app/dashboard/scans/[id]/page.tsx`, `frontend/src/types/index.ts`, `PLAN_ASM_CORE_V2.md`
- Extended `web_endpoints` with score, score reasons, endpoint type, source list/count, selected state, selected reason, scan status, and last scanned timestamp.
- Crawler now merges Katana, GAU, and FFUF sources, classifies endpoint types, scores endpoints with explicit reasons, and selects bounded endpoint nuclei targets deterministically by score and URL tie-breaker.
- Nuclei endpoint batches now update endpoint scan status from queued/running to completed and persist `last_scanned_at`.
- Asset endpoint UI now shows endpoint score, source list, classification, selected state, score reasons, and scan status; scan detail shows endpoint coverage summary from the crawl phase.

---

## 2026-06-04 — Discovery Engine V2 Milestone 3 Start

### Added: Normalized discovery inventory and provider health
- **Files**: `backend/app/db/migrations/versions/012_discovered_assets.py`, `backend/app/db/migrations/versions/013_discovered_assets_per_scan_unique.py`, `backend/app/db/models/models.py`, `backend/app/api/v1/endpoints/scans.py`, `workers/db_models.py`, `workers/scanner/discovery_worker.py`, `frontend/src/app/dashboard/scans/[id]/page.tsx`, `docker-compose.yml`, `.env.example`, `PLAN_ASM_CORE_V2.md`
- Added per-scan `discovered_assets` records for raw subdomain, CIDR, reverse-DNS, and cloud-storage candidates with source, status, selected state, skip reason, first/last seen timestamps, and JSON-safe evidence.
- Discovery phase summaries now include source health for passive providers, generated DNS sources, reverse DNS, ASN expansion, and cloud checks, and scan detail UI surfaces provider health states.
- Removed Shodan, SecurityTrails, Censys, and Chaos API integrations from discovery so default discovery relies on open-source tools and unauthenticated public sources.
- Removed VirusTotal, AbuseIPDB, OTX, and CriminalIP API configuration/plugin paths from enrichment so the default runtime stays no-key and open-source/public-source focused.
- Added safe ASN-to-prefix candidate expansion, bounded reverse DNS candidate extraction, and conservative ownership confidence without auto-scanning those candidates by default.
- Added cloud object storage candidate generation and safe exposure checks for S3, GCS, and Azure Blob.
- Fixed discovery evidence persistence by normalizing datetimes and other scanner values before writing JSONB.
- Runtime smoke validation completed with scan `c2c0dbc0-ac67-45fe-bdca-703ad2f55de5`, which discovered 26 subdomains, persisted source-health data, and completed successfully after the JSONB fix.

### Added: Discovery source evidence and wildcard control
- **Files**: `workers/scanner/discovery_worker.py`, `workers/discovery/dns_candidates.py`, `workers/discovery/__init__.py`, `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/app/dashboard/scans/[id]/page.tsx`, `frontend/src/types/index.ts`, `PLAN_ASM_CORE_V2.md`
- Discovery now keeps per-host source evidence across subfinder, assetfinder, crt.sh, optional amass, Wayback, Common Crawl, DNS brute force, and DNS permutations.
- Added bounded Wayback/Common Crawl passive host extraction plus bounded DNS brute-force and conservative permutation generation.
- Added wildcard DNS probes and suppression for generated-only candidates that match wildcard fingerprints, preventing wildcard domains from inflating downstream scan targets.
- Discovery now records unresolved candidates with explicit validation evidence and persists resolved DNS-only hosts, giving target selection clearer skip reasons and better asset coverage.
- Discovery phase summaries now expose source breakdown, generated candidate count, wildcard DNS report, and wildcard skipped count.
- Asset detail now shows discovery evidence for persisted assets, and scan detail now shows discovery source distribution and wildcard suppression data.
- Added migration `011_unique_scan_findings` and nuclei persistence conflict handling so the same finding cannot be linked to one scan multiple times.
- Nuclei phase summaries and scan counters now use deduplicated `scan_findings` links, keeping `findings_found`, phase `findings`, and result rows consistent.
- Tightened crt.sh host filtering to accept only exact root-domain matches or proper subdomain suffixes.

---

## 2026-06-03 — Scan Pipeline Progress and Result UI

### Added: Asset validation worker and analyst review workflow
- **Files**: `backend/app/db/migrations/versions/010_scope_controls_asset_review.py`, `backend/app/db/models/models.py`, `backend/app/services/asset_validation.py`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/api/v1/endpoints/organizations.py`, `backend/app/core/queue_client.py`, `backend/tests/unit/test_asset_validation.py`, `workers/validation/asset_validation_worker.py`, `workers/base_worker.py`, `workers/queue_client.py`, `workers/scheduler/scheduler.py`, `docker-compose.yml`, `.env.example`, `frontend/src/app/dashboard/assets/page.tsx`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/app/dashboard/organizations/new/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`, `frontend/src/lib/api.ts`, `frontend/src/types/index.ts`
- Added organization allow/deny scope patterns and asset analyst review fields with an idempotent migration.
- Added `asset.validate` queue routing, a dedicated validation worker, Compose service, and scheduler refresh job for periodic ownership/scope revalidation.
- Validation now merges DNS/HTTP/TLS evidence with RDAP/ASN evidence from RDAP.org and Team Cymru, while preserving analyst-approved or analyst-rejected decisions.
- Added asset review API actions for approve, reject, and needs-review decisions, plus organization API action to queue validation against existing assets.
- Asset inventory now supports review filtering; asset detail now shows review status and review actions; organization create/edit now exposes scope controls and manual validation queueing.

### Added: Asset validation and scope confidence milestone
- **Files**: `backend/app/db/migrations/versions/009_asset_validation.py`, `backend/app/db/models/models.py`, `backend/app/services/asset_validation.py`, `backend/app/services/scan_profiles.py`, `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/api/v1/endpoints/scans.py`, `frontend/src/app/dashboard/assets/page.tsx`, `frontend/src/app/dashboard/assets/[id]/page.tsx`
- Added asset validation fields for `scope_status`, `ownership_confidence`, `ownership_reason`, `exposure_status`, `liveness_status`, validation evidence, and last verified timestamp.
- Discovery now validates hosts with DNS, HTTP, TLS, redirect, and organization root-domain evidence before persisting assets.
- Target selection now gates downstream nuclei/crawl/screenshot candidates on validation state by default and records skipped validation targets in scan target selections.
- Targeting now carries DNS-only validation evidence for resolved but non-live hosts, replacing generic `missing_validation` skips with actionable liveness reasons.
- Port-discovered IP assets now receive baseline validation state and evidence.
- Asset list/detail APIs and UI now expose validation state, confidence, and evidence reasons.
- Existing assets were backfilled with historical validation state from subdomain/IP data.

### Added: Durable scan observability milestone
- **Files**: `backend/app/db/migrations/versions/008_scan_observability.py`, `backend/app/db/models/models.py`, `workers/scan_phase.py`, `workers/scan_observability.py`, `workers/scanner/discovery_worker.py`, `workers/crawler/web_crawl_worker.py`, `workers/scanner/nuclei_worker.py`, `backend/app/api/v1/endpoints/scans.py`, `frontend/src/app/dashboard/scans/[id]/page.tsx`
- Added durable `scan_phase_runs` and `scan_target_selections` tables for phase timelines, target coverage, and selected/skipped target evidence.
- Scan phase updates now upsert durable phase summaries alongside existing `phase_status` JSONB.
- Discovery, crawl, and nuclei now persist selected targets with phase, profile, score/reasons, and downstream metadata.
- Added authenticated scan detail response fields: `phase_runs`, `target_summary`, `target_selections`, and `why_no_findings`.
- Added `/dashboard/scans/[id]` to show phase timeline, target coverage, target selections, and no-finding explanations.
- Completed the remaining Milestone 1 observability gaps for current workers: port, screenshot, and enrichment now record target selections; screenshot/enrichment phase summaries include success/failed counts; correlation now writes intermediate and terminal phase summaries.
- Expanded no-finding explanations for completed nuclei with no findings, active safety exclusions, endpoint budget caps, and recorded scan errors.
- Fixed scan target selection upserts to merge duplicate targets within a batch before `ON CONFLICT`, preventing DiscoveryWorker cardinality violations and retry exhaustion.
- Sanitized nuclei finding text/JSON evidence before persistence so binary responses, such as favicons containing NUL bytes, no longer break PostgreSQL inserts.
- Nuclei batches that time out with no parsed findings now record a phase warning and complete as partial coverage instead of raising worker exceptions and retrying until scan failure.
- Suppressed low-value info-level nuclei findings such as technology, favicon, WAF, fingerprint, and WordPress plugin detection so they do not pollute vulnerability results by default.
- Bounded nuclei runtime by lowering deep/endpoint batch sizes, capping endpoint nuclei target budgets, and enforcing worker-side maximum batch timeouts for stale scan configs.
- Switched nuclei persistence to JSONL streaming output and reduced default full-scan nuclei batches so timed-out batches are less likely to drop findings before results are flushed.
- Reworked deep nuclei execution to be vulnerability-first: UI defaults, backend caps, discovery batching, and crawl-fed endpoint scans now avoid large stale batches and prioritize critical/high/medium/low coverage over info inventory.
- Added a nuclei-only scan path for already-discovered assets and high-signal crawled endpoints, exposed through the organization scan API and Scan Modal as `Nuclei Assets`.

### Fixed: Accurate nuclei and crawl task accounting
- **Files**: `workers/task_coordinator.py`, `workers/crawler/web_crawl_worker.py`, `workers/scanner/nuclei_worker.py`
- Crawl-fed endpoint nuclei batches now increment scan `total_tasks`, preventing progress from jumping too far ahead during deep scans.
- Nuclei phase status now tracks aggregate expected/completed/remaining batches, targets scanned, and findings instead of treating each batch as the whole phase.

### Changed: Scan progress and result visibility
- **Files**: `backend/app/services/scan_progress.py`, `backend/app/api/v1/endpoints/scans.py`, `backend/app/api/v1/endpoints/organizations.py`, `frontend/src/app/dashboard/scans/page.tsx`, `frontend/src/app/dashboard/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Scan APIs now merge Redis runtime counters into `phase_status` and include task counts, scan profile, failures, new asset/finding counts, and duration fields.
- Dashboard scan rows now show concrete batch/task progress such as `nuclei 0/16 batches` instead of only a coarse percentage label.

### Changed: Richer asset result presentation
- **Files**: `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/app/dashboard/findings/page.tsx`, `backend/app/api/v1/endpoints/findings.py`
- Asset detail now exposes and displays richer port fingerprints, normalized technologies, and endpoint crawl score reasons.
- Findings CSV export is now wired in the frontend and supports comma-separated severity filters.

### Fixed: Pipeline observability coverage
- **Files**: `docker-compose.yml`, `.env.example`, `infrastructure/prometheus/prometheus.yml`
- API metrics are enabled by default through Compose, and Prometheus now scrapes port, crawl, and enrichment workers.

---

## 2026-06-02 — Scanner Tool Command Hardening

### Fixed: Discovery and crawl command correctness
- **Files**: `workers/scanner/discovery_worker.py`, `workers/crawler/web_crawl_worker.py`
- Discovery tools now resolve binaries from either `PATH` or `/go/bin`, preventing false `tool_not_available` states when runtime PATH differs.
- Subfinder now applies provider config via `-pc` when configured or mounted, and supports bounded all-source mode through scan config.
- HTTP probing now captures richer ASM context from httpx, including IP, CNAME, ASN, CDN/WAF, favicon, JARM, method, redirect location, websocket, pipeline, HTTP/2, CPE, content type, and redirect chain.
- Katana now enforces scoped crawling with `-fs fqdn` by default, host rate limits, parallelism limits, and per-domain page caps.
- FFUF now uses the correct v2 `-maxtime` flag, keeps redirect/auth/server-error discoveries instead of filtering redirects, and enables per-host auto-calibration.

### Fixed: Port and nuclei command hardening
- **Files**: `workers/scanner/port_worker.py`, `workers/scanner/nuclei_worker.py`, `workers/Dockerfile`
- Naabu now uses explicit duration timeouts, verifies discovered ports, displays CDN/WAF data, and safely falls back when unsupported `top-*` values are supplied.
- Open web ports from Naabu are now fingerprinted with httpx to populate service name, web server/product, title/banner, TLS info, and technology-derived version context.
- Nuclei now follows same-host redirects by default, caps response read/save sizes, redacts secret-like fields from evidence, disables stdin, and can store response artifacts when explicitly enabled.
- Worker images now symlink all installed scanner binaries into `/usr/local/bin`, not only a subset.

---

## 2026-06-02 — Core Scan Profile & Target Candidate Engine

### Added: Central scan profiles for vulnerability scanning
- **Files**: `backend/app/services/scan_profiles.py`, `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/organizations.py`, `backend/app/api/v1/endpoints/scans.py`, `workers/scanner/nuclei_worker.py`
- Added shared scan profiles: `safe`, `default`, `deep_authorized`, `endpoint`, and `limited`.
- Full, vuln-only, and manual nuclei scans now default to `deep_authorized`, while still excluding destructive/intrusive tags such as `dos`, `bruteforce`, `intrusive`, `destructive`, and `unsafe`.
- Nuclei command generation now consumes profile-provided template directories before falling back to legacy `vuln_depth` mapping.
- Automated organization scans and manual nuclei scans now accept `scan_profile`.

### Added: Target candidate builder for downstream scanner selection
- **Files**: `backend/app/services/scan_profiles.py`, `workers/scanner/discovery_worker.py`, `workers/crawler/web_crawl_worker.py`
- Discovery now builds grouped scanner candidates for standard web targets, limited web targets, crawl targets, network targets, screenshots, and technology maps.
- Targeting summaries are written to `phase_status["targeting"]`, including candidate counts and HTTP status skip reasons.
- Crawl-fed endpoint nuclei batches now use the `endpoint` profile, and auth/error/rate-limited web batches use the `limited` profile.

### Changed: Scan profile controls in frontend
- **Files**: `frontend/src/components/modals/ScanModal.tsx`, `frontend/src/app/dashboard/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`, `frontend/src/types/index.ts`
- Scan modals now expose Safe, Default, and Deep Authorized profile choices.
- Organization settings now include a default scan profile selector that writes to `scan_policy.scan_profile`.
- Frontend scan phase types now include targeting summary fields.

---

## 2026-06-02 — Repository Audit & Runtime Hardening

### Added: Audit report and Docker build hygiene
- **Files**: `AUDIT.md`, `backend/.dockerignore`, `frontend/.dockerignore`, `workers/.dockerignore`
- Added a repository audit report covering backend tests, frontend build, dependency vulnerabilities, Docker/Compose checks, RabbitMQ queues, and remaining pipeline risks.
- Added service-level `.dockerignore` files so Docker builds exclude local env files, caches, test output, and generated build artifacts.

### Fixed: Operational targets and API route matching
- **Files**: `Makefile`, `.env.example`, `frontend/next.config.js`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/api/v1/endpoints/findings.py`
- `make logs-workers` and `make workers-scale` now reference the current worker services, including port, crawl, enrichment, screenshot, notification, and scheduler workers.
- `.env.example` now matches the Compose frontend default API base path: `/api/v1`.
- Moved the Next.js external package setting under the supported experimental key for Next 14, removing the production build warning.
- Asset and finding detail routes now require UUID path conversion, preventing static endpoints such as `/assets/export` and `/findings/export` from being intercepted by dynamic `{id}` routes.

---

## 2026-06-02 — API Timeline Query & Queue Runtime Fixes

### Added: Production scan policy, phase status, and enrichment worker
- **Files**: `backend/app/services/scan_service.py`, `backend/app/db/migrations/versions/007_scan_policy_phase_status.py`, `workers/enrichment/enrichment_worker.py`, `workers/task_coordinator.py`, `workers/scanner/port_worker.py`, `docker-compose.yml`, `Makefile`, `frontend/src/app/dashboard/scans/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Organizations now support a JSON `scan_policy` that is merged into scan config with bounded safety limits for nuclei, crawl, fuzz, and enrichment settings.
- Scans now persist per-phase `phase_status` so UI and API consumers can see concrete pipeline phase state instead of relying only on coarse progress percentages.
- Added a dedicated `worker-enrichment` service that enriches IP assets with no-key ASN/RDAP baseline data.
- `.env.example` now documents `ENRICHMENT_CONCURRENCY` for first-time setup.
- Task coordination now waits for enrichment batches before terminal correlation, preventing scans from completing before IP intelligence is persisted.
- Endpoint crawl selection now scores high-signal URLs from Katana, GAU, and FFUF before feeding bounded endpoint targets into nuclei.
- **Impact**: Full scans now preserve IP/ASN/org/country enrichment data, expose clearer phase progress, and send better-targeted endpoint nuclei batches.

### Fixed: Nginx stale upstream DNS after service rebuilds
- **File**: `infrastructure/nginx/nginx.conf`
- Nginx now uses Docker DNS (`127.0.0.11`) with a short TTL and dynamic `proxy_pass` targets for API and frontend services.
- **Impact**: Recreating or rebuilding `api`/`frontend` no longer leaves Nginx proxying to an old container IP and returning `502 Bad Gateway`.

### Fixed: Enrichment worker dependency imports
- **File**: `workers/requirements-workers.txt`
- Worker images now include `pydantic` and `pydantic-settings`, matching shared backend configuration dependencies used by workers.
- **Impact**: `worker-enrichment` no longer logs `No module named 'pydantic'`.

### Fixed: Asset detail client-side crash
- **File**: `frontend/src/app/dashboard/assets/[id]/page.tsx`
- Asset detail now normalizes `open_findings` from either a count or API summary array before rendering badges and sidebar metrics.
- **Impact**: Assets with open finding objects in the detail response no longer trigger a React client-side exception.

### Fixed: Crawl endpoint persistence on oversized archive URLs
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/Dockerfile`
- Crawl persistence now skips URLs and hosts that exceed database column limits and clamps bounded display fields before upsert.
- GAU passive URL collection now runs with bounded per-host concurrency instead of sequentially processing every host.
- Optional FFUF fuzzing now runs inside the crawl phase after live web discovery, so fuzzed paths are validated, persisted as `web_endpoints`, and can feed endpoint-level nuclei scans.
- Crawl progress updates are now monotonic, so late crawl completion cannot move a scan backward from a higher progress percentage.
- Nuclei batches generated from crawled endpoints now use a dedicated HTTP-only endpoint template profile with a bounded endpoint scan timeout.
- **Impact**: Passive GAU/Katana results with extremely long historical URLs no longer fail the entire crawl task or leave scans stuck near completion.

### Fixed: Nuclei timeout reported as zero findings
- **Files**: `workers/scanner/nuclei_worker.py`, `workers/scanner/discovery_worker.py`, `workers/crawler/web_crawl_worker.py`, `backend/app/services/scan_service.py`, `frontend/src/components/modals/ScanModal.tsx`
- Nuclei worker now parses partial result files after timeout and treats empty timed-out batches as worker errors instead of silently completing with zero findings.
- Technology detections are still logged, but no longer become a global `-tags` filter by default. This restores coverage for generic exposure, misconfiguration, takeover, default-login, CVE, and vulnerability templates that manual nuclei runs would include.
- Full scan defaults now use smaller nuclei batches and longer scan timeout, reducing repeated batch timeouts on large crawled endpoint sets.

### Fixed: PostgreSQL timeline aggregation errors
- **Files**: `backend/app/api/v1/endpoints/organizations.py`, `backend/app/api/v1/endpoints/assets.py`, `backend/app/api/v1/endpoints/findings.py`
- Timeline and trend endpoints now use a stable literal date bucket for `date_trunc`, preventing PostgreSQL `GroupingError` failures when frontend refreshes organization metrics after scan execution.

### Fixed: RabbitMQ local disk alarm blocking scan queue publishes
- **File**: `infrastructure/rabbitmq/rabbitmq.conf`
- RabbitMQ disk watermark now uses a fixed `2GB` threshold instead of `1.5x` available memory, preventing local/dev environments with usable disk space from blocking AMQP publishers.

---

## 2026-06-01 — Organization Automation Controls & Tech-Aware Scanning

### Added: Dedicated endpoint crawling phase
- **Files**: `workers/crawler/web_crawl_worker.py`, `workers/scanner/discovery_worker.py`, `workers/task_coordinator.py`, `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/006_web_endpoints.py`, `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `docker-compose.yml`
- Added a separate `scan.crawl` worker phase that runs after live web discovery and before expanded nuclei endpoint scans.
- Crawl combines Katana for active crawling and GAU for passive URL collection, validates candidates with httpx, normalizes/deduplicates URLs, and stores scoped results in the new `web_endpoints` table.
- Discovery now queues crawl batches for `ok` and `redirect` web assets instead of doing inline crawling, keeping discovery faster and making crawl progress trackable through coordinator counters.
- Interesting endpoint selection now feeds bounded nuclei batches for API/auth/admin/upload/config-style paths without scanning every discovered URL.
- Asset detail now includes an Endpoints tab with URL, source, HTTP status, content type, title, and API/auth/parameter/interesting indicators.
- Added the `worker-crawl` Docker service and `CRAWL_CONCURRENCY` setting; worker images now include `gau`.
- Added a default GAU config at `workers/config/gau.toml`, copied it to `/root/.gau.toml` in worker images, and made the crawl worker invoke GAU with an explicit config path.

### Fixed: Scan lifecycle edge cases and scheduler restart behavior
- **Files**: `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`, `workers/scheduler/scheduler.py`, `docker-compose.yml`, `.env.example`
- Discovery now marks screenshot work as complete when no screenshot task is queued, including scans with the screenshot module enabled but zero discovered subdomains.
- Port worker now marks port batches complete even when an empty IP batch is received, preventing malformed/manual queue messages from leaving a scan waiting forever.
- Discovery updates `total_tasks` from the actual downstream batch count so UI progress reflects queued port, nuclei, and screenshot work more accurately.
- Scheduler no longer queues a full scan two minutes after every restart by default. Set `RUN_FULL_SCAN_ON_START=true` to keep that behavior.
- Scheduled scans now skip organizations that already have an active scan or a recent completed scan within the configured interval, reducing duplicate automated scans after deploys or scheduler catch-up.
- Workers now cap RabbitMQ prefetch to their configured concurrency, so heavy scan workers do not reserve more unacked messages than they can process.
- Scan cancellation now records `completed_at`, keeping terminal scan rows consistent for reporting and UI sorting.

### Changed: HTTP status-aware scan routing and asset triage
- **Files**: `workers/scanner/discovery_worker.py`, `backend/app/api/v1/endpoints/assets.py`, `frontend/src/app/dashboard/assets/page.tsx`, `frontend/src/app/dashboard/assets/[id]/page.tsx`, `frontend/src/types/index.ts`
- Discovery now classifies probed web services as `ok`, `redirect`, `auth_required`, `not_found`, `rate_limited`, `server_error`, `probe_failed`, or `other`.
- Katana and ffuf only crawl/fuzz `ok` and `redirect` targets, avoiding noisy 404/auth/error surfaces.
- Nuclei now skips default scans for 404 targets and routes auth/server/rate-limited targets through a bounded limited profile.
- Asset APIs expose `http_status_class` and support filtering assets by HTTP status class.
- Asset list and detail views now show HTTP status badges and include an HTTP class filter.

### Added: Technology-aware nuclei pre-scan
- **Files**: `workers/scanner/discovery_worker.py`, `workers/scanner/nuclei_worker.py`, `frontend/src/components/modals/ScanModal.tsx`
- HTTP probing now normalizes `httpx -tech-detect` output, persists detected technologies in the `technologies` table, and passes a technology map to nuclei batches.
- Nuclei now converts only curated technologies (for example Next.js, React, WordPress, Apache, Nginx, Jenkins, Grafana) into template tags while keeping automatic scan enabled, avoiding the broad tag explosion that previously made scans run too long.

### Added: Per-organization automatic scan control
- **Files**: `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/005_org_auto_scan.py`, `backend/app/api/v1/endpoints/organizations.py`, `workers/scheduler/scheduler.py`, `frontend/src/app/dashboard/organizations/new/page.tsx`, `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Organizations now have an `auto_scan_enabled` setting. It can be set during organization creation and changed from the organization edit dialog.
- The scheduler now requires both workspace-level `auto_scan_enabled` and organization-level `auto_scan_enabled` before queueing default quick/full automated scans.

---

## 2026-05-25 — Scanning Pipeline Lifecycle & UI Reliability Fixes

### Added: Transactional outbox for reliable scan queue publishing
- **Files**: `backend/app/services/outbox_service.py`, `backend/app/db/migrations/versions/003_outbox_events.py`, `backend/app/db/models/models.py`
- Scan creation now persists queue publish events in `outbox_events` within the same database transaction as the `Scan` row. A background dispatcher publishes pending events to RabbitMQ with retry/backoff and marks scans failed after repeated publish failures.
- Coordinator Redis preparation is idempotent per outbox event, preventing retry attempts from double-counting expected worker batches.
- Queue publishers now declare durable queues and bindings before publishing, so outbox-dispatched scan messages are retained even if a worker is temporarily stopped.
- **Impact**: Prevents silent-stuck scans when the API commits a scan but crashes or loses RabbitMQ connectivity before publishing the queue message.

### Changed: API and scheduler scan creation now enqueue via outbox
- **Files**: `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/scans.py`, `workers/scheduler/scheduler.py`
- Organization-triggered scans, manual nuclei scans, and scheduled scans now create outbox events instead of publishing directly from the request/scheduler path. Manual scan Redis coordinator setup is performed by the outbox dispatcher before publishing the nuclei message.

### Fixed: Port scan persistence used the wrong foreign key
- **File**: `workers/scanner/port_worker.py`
- Port results were inserted with `ports.ip_id = assets.id`, but the schema requires `ports.ip_id` to reference `ip_addresses.id`.
- **Impact**: Port scan results could fail persistence with FK errors and push worker messages into retry/DLQ.
- **Fix**: Upsert `IPAddress` records for IP assets first, then persist `Port` rows using the returned `ip_addresses.id`. Port worker now persists discovered IP assets even when no open ports are found and uses the Go tool path in Docker so `naabu` is available at runtime.

### Fixed: Scan lifecycle could hang or overwrite cancelled scans
- **Files**: `workers/scan_state.py`, `workers/base_worker.py`, scanner workers, `workers/correlation/correlation_worker.py`
- Workers did not consistently skip terminal scans, max-retry failures did not mark scans failed, and terminal correlation could overwrite `cancelled`/`failed` status as `completed`.
- **Fix**: Added shared lifecycle helpers for running/failed/completed transitions, terminal status guards, max-retry failure propagation, and completion that only applies to active scans.

### Fixed: Pipeline terminal coordination ignored port scan completion
- **Files**: `workers/task_coordinator.py`, `workers/scanner/discovery_worker.py`, `workers/scanner/port_worker.py`
- Redis terminal checks only waited for nuclei and screenshot completion, so a full scan could complete before port batches finished.
- **Fix**: Added `port_expected`/`port_done` counters and included them in the atomic terminal Lua check. Expected counters are now registered before queue publish to avoid fast-worker races.

### Changed: Scan status and API/UI contract normalized
- **Files**: `backend/app/services/scan_service.py`, `backend/app/api/v1/endpoints/scans.py`, `backend/app/api/v1/endpoints/organizations.py`, `frontend/src/app/dashboard/scans/page.tsx`
- Scan creation now transitions to `queued` after successful publish, active scan limits include `queued`, manual scans validate workspace ownership, `/scans` supports `search`, and failed scan errors are visible in the scans table.

### Added: Frontend realtime scan cache updates
- **Files**: `frontend/src/lib/useRealtimeEvents.ts`, `frontend/src/app/dashboard/page.tsx`, `frontend/src/app/dashboard/scans/page.tsx`
- Added a WebSocket hook that listens for scan, score, and finding events and invalidates relevant React Query caches while keeping polling as fallback.

### Added: Focused scan pipeline regression tests
- **Files**: `backend/tests/unit/test_scan_pipeline_state.py`, `backend/tests/unit/test_outbox_service.py`
- Added unit coverage for scan lifecycle transitions, terminal-scan completion guards, failure event emission, and port persistence using `ip_addresses.id` for `ports.ip_id`.

### Fixed: Runtime API/WebSocket URL defaults
- **Files**: `docker-compose.yml`, `infrastructure/nginx/nginx.conf`
- Frontend default API URL pointed at `/api` while FastAPI routes are mounted at `/api/v1`, and `/ws` proxied to the wrong backend path.
- **Fix**: Default `NEXT_PUBLIC_API_URL` is now `/api/v1`; Nginx `/ws` and `/ws/` proxy cleanly to `/api/v1/ws/`.

### Fixed: Nuclei scans could run far too long
- **Files**: `workers/scanner/nuclei_worker.py`, `workers/scanner/discovery_worker.py`, `workers/base_worker.py`, `backend/app/db/models/models.py`, `backend/app/db/migrations/versions/004_unique_finding_fingerprint_org.py`, `frontend/src/components/modals/ScanModal.tsx`, `docker-compose.yml`
- Nuclei template path pointed to an empty `/opt/nuclei-templates` directory, so workers did not constrain scans to the intended template directories. Full scans also added broad technology tags and allowed one-hour batch runtime.
- **Fix**: Pointed workers at `/root/nuclei-templates`, restricted default template directories, disabled tech-tag broadening unless explicitly enabled, reduced default nuclei concurrency/bulk size, added bounded scan/template timeouts, and lowered full-scan nuclei batch size.
- Worker concurrency now holds the semaphore for the full message processing lifetime, preventing nuclei batches from exceeding the configured worker concurrency under queue bursts.
- Default web UI scans now use nuclei automatic tech-aware scanning plus ASM-safe exposure/misconfiguration templates. Full scans still include CVE/vulnerability directories, but no longer run the entire template repository without a path filter.
- Finding persistence now has the required unique constraint on `(fingerprint, org_id)`, so nuclei/nikto upserts do not fail and requeue forever when a vulnerability is found.

### Fixed: Unit-test regressions in CIDR validation and critical risk scoring
- **Files**: `backend/app/core/security.py`, `backend/app/services/risk_engine.py`
- CIDR validation no longer accepts a bare IP as a network. Risk scoring now caps the overall score when effective critical-finding penalty is high, so critical exposure meaningfully affects the posture score even when category weights are narrow.

---

## 2026-05-22 — 3 Bug Fixes: Findings Persist, UnboundLocalError, JSON List Parse

### Fixed: Findings upsert fails — `ON CONFLICT` requires unique index, not btree
- **File**: Database schema / `workers/scanner/nuclei_worker.py`
- `pg_insert(Finding.__table__).on_conflict_do_update(index_elements=["fingerprint", "org_id"])` requires a **unique** constraint or unique index on those columns in PostgreSQL. The existing `ix_finding_fingerprint` was a regular (non-unique) btree index, so every insert threw `InvalidColumnReferenceError: there is no unique or exclusion constraint matching the ON CONFLICT specification`.
- **Impact**: **Root cause of findings not appearing in the UI**. The finding was parsed correctly from nuclei JSON output, but the database upsert failed. The `message_processing_error` exception was caught by the BaseWorker and the message was requeued (infinite retry loop).
- **Fix**: Replaced index `ix_finding_fingerprint` with unique index `uq_finding_fingerprint_org` via `CREATE UNIQUE INDEX`.

### Fixed: `UnboundLocalError: cannot access local variable 'findings'`
- **File**: `workers/scanner/nuclei_worker.py:146`
- When `findings_raw` was empty (nuclei found zero vulnerabilities), the `findings` variable was never assigned before `log.info("nuclei_scan_completed", findings=len(findings))` referenced it.
- **Impact**: When nuclei found nothing (e.g., zero findings), the log line threw `UnboundLocalError`, the message was requeued with retry, and the correlation terminal message was never sent. Scan stayed "running" forever despite having zero findings.
- **Fix**: Initialize `findings = []` before the `if findings_raw:` branch.

### Fixed: Nuclei JSON output lines may be arrays, not objects
- **File**: `workers/scanner/nuclei_worker.py:273-281`
- `nuclei -json-export` can output JSON arrays on a single line. `json.loads(line)` returned a list, which was passed to `_parse_finding()` as `raw` — calling `raw.get("template-id")` on a list raised `AttributeError`.
- **Fix**: Check `isinstance(parsed, list)` → `results.extend(parsed)`. Also guard `_parse_finding()` with `isinstance(raw, dict)`.

---

## 2026-05-22 — Port Worker Race Condition Fix

### Fixed: Race condition causes scan to complete before port worker's nuclei tasks finish
- **File**: `workers/scanner/port_worker.py`
- Port worker queued additional `scan.nuclei` messages for discovered IPs (via `_queue_nuclei()`) and incremented `nuclei_expected` AFTER the discovery worker already finished its nuclei batches. If the discovery-based nuclei + screenshot completed first, the terminal condition `nuclei_done >= nuclei_expected && screenshot_done == 1` would trigger prematurely — scan marked "completed" while port worker hadn't even started queuing its nuclei tasks yet.
- **Impact**: Scan status showed "done" but nuclei worker was still running. Results from port-discovered IPs were orphaned.
- **Fix**: Removed `_queue_nuclei()` entirely from port worker. Discovery worker already queues nuclei for all discovered subdomains (which cover standard HTTP/HTTPS via httpx probing). Port scanning now focuses solely on port discovery and persistence. Non-standard port coverage (e.g. 8080, 8443) was never actually done by `_queue_nuclei` (it only queued `http://IP` and `https://IP`), so no coverage is lost.

### Fixed: Manual scan Redis coordinator silently fails on error
- **File**: `backend/app/api/v1/endpoints/scans.py`
- Coordinator setup (Redis keys for `nuclei_expected`, `screenshot_done`) was wrapped in `try/except Exception: pass` — if Redis was unavailable, the keys were never created and the manual scan would hang at "running" forever with zero error feedback.
- **Fix**: Removed inner `try/except` so Redis errors propagate to the outer error handler, which marks the scan as `failed` with a descriptive message and returns HTTP 500.

---

## 2026-05-21 — Redis Coordinator Fix, Manual Nuclei, Pipeline Finalization

### Fixed: `register_script` is NOT async in redis-py 5.x (blocks ALL pipeline completion)
- **File**: `workers/task_coordinator.py`
- `await r.register_script()` raised `TypeError: object AsyncScript can't be used in 'await' expression`. `register_script()` is synchronous in redis-py 5.x — it returns an `AsyncScript` whose `__call__` is awaitable, but `register_script` itself is not.
- **Impact**: **Root cause of every scan stuck at "running"**. Neither nuclei nor screenshot workers could call `mark_terminal_if_all_done` — the terminal correlation message was never sent. Messages were requeued infinitely (77+ backlog in `scan.nuclei`).
- **Fix**: Remove `await` from `r.register_script()`.

### Fixed: Discovery worker never finalizes when zero downstream work queued
- **File**: `workers/scanner/discovery_worker.py`
- When discovery finds 0 assets, no nuclei/screenshot batches are published, `add_nuclei_expected` is never called, and no downstream worker exists to call `mark_terminal_if_all_done`. The scan stays "running" forever even though nothing will ever process it.
- **Fix**: Added `_finalize_if_no_work()` — sets `screenshot_done=1` and atomically calls `mark_terminal_if_all_done`, publishing the terminal correlation message if it wins the race. `_queue_downstream` now returns `nuclei_queued` boolean.

### Fixed: Nuclei worker doesn't update scan status to "running"
- **File**: `workers/scanner/nuclei_worker.py`
- Manual nuclei scans stayed stuck in "pending" because the nuclei worker never called `_update_scan_status`. Added status→running + `started_at` update at the start of `process()`.

### Fixed: Missing `UUID` import in scans endpoint
- **File**: `backend/app/api/v1/endpoints/scans.py`
- `UUID` was used in type hints but only `import uuid` was present — no `from uuid import UUID`. Caused `NameError` on container restart.

### Added: Manual nuclei scan endpoint
- **File**: `backend/app/api/v1/endpoints/scans.py`
- `POST /scans/manual` — accepts `org_id`, `targets` (list of URLs/domains), `vuln_depth`. Creates scan record, publishes directly to `scan.nuclei` queue, sets up Redis coordinator keys. Returns `201` with `scan_id`.

### Added: Manual scan tab in frontend ScanModal
- **File**: `frontend/src/components/modals/ScanModal.tsx`
- New "Manual Nuclei" tab alongside existing "Automated" tab. User enters targets (one per line in textarea), clicks "Run Nuclei" which calls `POST /scans/manual`.

### Fixed: Edit organization button does nothing
- **File**: `frontend/src/app/dashboard/organizations/[id]/page.tsx`
- Edit button only toggled `editing` boolean but no UI was rendered. Added full edit modal with fields: name, description, domains, IP ranges, ASNs, company, industry, criticality, environment. Calls `PUT /organizations/{id}`.

---

## 2026-05-21 — Scanning Pipeline Overhaul: 4 Bug Fixes + Katana/FFUF + Scan Modal

### Fixed: Findings never persisted (constraint name mismatch)
- **File**: `workers/scanner/nuclei_worker.py`
- `on_conflict_do_update(constraint="uq_finding_fingerprint_org")` referenced a non-existent constraint. The `findings` table only has a regular index on `(fingerprint, org_id)`, not a named unique constraint. Every finding insert threw `UndefinedObjectError` and was dead-lettered.
- **Fix**: Changed to `index_elements=["fingerprint", "org_id"]` — uses the existing index.
- **Impact**: **Primary root cause** of zero findings in the UI.

### Fixed: Scheduler-triggered scans produced zero downstream work
- **File**: `workers/scheduler/scheduler.py`
- Config published by `_schedule_full_scans()` was missing the `modules` key → `config.get("modules", [])` returned `[]` → all stage checks failed → nothing queued.
- **Fix**: Added `"modules": ["discovery", "port", "nuclei", "screenshot"]` to full scan config.

### Fixed: Port worker column/constraint names mismatch
- **File**: `workers/scanner/port_worker.py`
- `asset_id`→`ip_id`, `port`→`port_number`, `service`→`service_name`, removed non-existent `org_id`. Constraint `uq_port_asset_port_protocol` → `index_elements`.

### Fixed: Quick scan module names incompatible with worker checks
- **File**: `workers/scheduler/scheduler.py`
- `modules: ["dns", "http", "tls"]` → `["discovery", "nuclei"]`.

### Fixed: Stale `DEFAULT_MODULES` in scan service
- **File**: `backend/app/services/scan_service.py`
- Removed dead `nikto`, `probe`, `dns`, `enrich` module names. Updated all scan types to match actual worker checks.

### Added: Tech-aware nuclei routing
- **Files**: `discovery_worker.py`, `nuclei_worker.py`
- Discovery passes `tech_map: {url: [nginx, php, ...]}` with nuclei tasks. Worker adds tech names as `-include-tags` filters. Always includes `cve` + `vulnerabilities` tags.

### Added: Katana endpoint crawling
- **File**: `discovery_worker.py` — new `_crawl_endpoints()`
- Runs `katana` against httpx-alive URLs to discover JS files, API routes, hidden paths. Results added to nuclei targets. Toggle via `config.crawl` (default: `true`).

### Added: FFUF directory/endpoint fuzzing
- **File**: `discovery_worker.py` — new `_fuzz_endpoints()`
- Optional `ffuf` fuzzing to discover `/admin/`, `/.git`, `/.env`, `/backup/`, API paths. Auto-calibrates to filter 404/redirects. Uses wordlist at `/usr/share/wordlists/dirb/common.txt`, SecList, or built-in 50-entry fallback. Toggle via `config.fuzz` (default: `false`).

### Added: Frontend Scan Modal with type + toggles
- **File**: `frontend/src/components/modals/ScanModal.tsx` (new)
- Replaced one-click "Run Scan" button with a modal: scan type selector (full/quick/discovery/vuln), pipeline preview, endpoint crawling toggle (katana), directory fuzzing toggle (ffuf), advanced options. Integrated into org detail page.

### Added: Proper URL scheme routing
- **File**: `port_worker.py`
- Port worker now sends both `https://ip` and `http://ip` (not only `http://`). Discovery uses URLs with scheme from httpx results.

---

## 2026-05-19 — Pipeline Completion & Screenshot Fixes

### Fixed: Scan marked "completed" while nuclei still running
- **Files**: `correlation_worker.py`, `screenshot_worker.py`
- Added `is_terminal` flag. Only screenshot sends `is_terminal=True`. Correlation completes scan only on terminal messages.

### Fixed: NGINX screenshot proxy returning 404/301
- **File**: `infrastructure/nginx/nginx.conf`
- Changed `location /storage/` → `location ^~ /storage/` to force prefix matching over regex.

### Fixed: Frontend screenshot field name mismatches
- **File**: `frontend/src/app/dashboard/assets/[id]/page.tsx`
- `s.created_at`/`s.taken_at` → `s.captured_at`. `s.screenshot_url` → `s.url`.

### Added: Global screenshots gallery endpoint
- **File**: `backend/app/api/v1/endpoints/screenshots.py` (new)
- `GET /screenshots` with pagination, org filtering, domain search, workspace scoping.

### Fixed: Screenshots gallery page crash
- **File**: `frontend/src/app/dashboard/screenshots/page.tsx`
- `new Date(undefined)` from mismatched field names crashed the page with `RangeError`.

### Fixed: crt.sh 502 errors with retry logic
- **File**: `discovery_worker.py`
- Added 3 attempts with exponential backoff and rotating User-Agent.

### Fixed: Redis counter race on scan completion
- **File**: `workers/task_coordinator.py`
- Atomic Lua script `mark_terminal_if_all_done` ensures only one worker (the last nuclei batch or screenshot) sends the terminal message.

### Fixed: RabbitMQ `ChannelInvalidStateError` on long scans
- **File**: `base_worker.py`
- Increased heartbeat to 300s. Added `ChannelInvalidStateError` handler + try/except around all ack/reject calls.

### Added: Vuln depth selection
- **Files**: `nuclei_worker.py`, `frontend/src/app/dashboard/page.tsx`
- Critical/default/full nuclei template depth configurable per scan.

### Fixed: Workers ignore `modules` list
- **File**: `discovery_worker.py`
- Vuln scans no longer run discovery. Module list gates all downstream stages.

---

## 2026-05-19 — Auto-Scan Toggle & Progress Bar Fix

### Added: Auto-scan enable/disable
- **Files**: `frontend/src/app/dashboard/settings/page.tsx`, `workspaces.py`, `scheduler.py`
- New `auto_scan_enabled` checkbox in Settings. Scheduler filters based on workspace settings.

### Fixed: Progress bar stuck at 0%
- **Files**: All workers
- Each worker now sets `progress_pct` at its stage. Changed to `func.greatest()` to prevent progress from going backwards.

### Fixed: RabbitMQ exchange bindings lost on restart
- **File**: `base_worker.py`
- Added `EXCHANGE_MAP` and auto-bind queue to exchange on every startup.

### Fixed: OpenSearch excessive RAM usage
- **File**: `docker-compose.yml`, `correlation_worker.py`
- JVM heap 1GB→512MB. Index replicas set to 0 (single node).

### Added: Scan phase label in progress bar
- **File**: `frontend/src/app/dashboard/scans/page.tsx`, `frontend/src/app/dashboard/page.tsx`
- Phase label: Queued → Starting → Discovery → Port → Vuln scan → Screenshots → Finalizing.

### Fixed: Empty error messages in discovery logs
- **File**: `discovery_worker.py`
- Added type+message to error logging for crtsh/assetfinder/timeout errors.

### Fixed: Nuclei worker `ModuleNotFoundError: No module named 'app'`
- **File**: `docker-compose.yml`
- Added missing `./backend/app:/app/app:ro` volume to nuclei worker.

### Added: New Scan modal on dashboard
- **File**: `frontend/src/app/dashboard/page.tsx`
- Dashboard "New Scan" button now opens modal with org selector + scan type.

---

## 2026-05-19 — Worker Pipeline Fixes

### Fixed: `worker-port` not running
- **File**: `docker-compose.yml`
- Port worker service was defined but never started. Pipeline stalled after discovery.

### Fixed: RabbitMQ exchange bindings missing
- **File**: `infrastructure/rabbitmq/definitions.json`
- Manually declared bindings for all exchanges. Root cause unknown (definitions.json loading issue).

### Fixed: httpx using Python CLI instead of Go binary
- **File**: `workers/Dockerfile`
- Python `httpx` pip package installed a broken CLI at `/usr/local/bin/httpx` that shadowed the ProjectDiscovery Go binary. `http_probed alive=0` despite valid subdomains.
- **Fix**: `rm -f /usr/local/bin/httpx` after pip install. Prepend `/go/bin` to PATH.

### Fixed: SQLAlchemy 2.0 `pg_insert` ORM incompatibility
- **Files**: 9 worker files
- `pg_insert(Model)` → `pg_insert(Model.__table__)` to bypass ORM bulk persistence path.

### Fixed: Go tools shadowed by Python CLI entrypoints
- **File**: `workers/Dockerfile`
- `PATH=/go/bin:...:$PATH` (prepend instead of append) to avoid future collisions.

### Fixed: Stale Python bytecache causing old constraint name error
- **File**: `workers/scanner/discovery_worker.py`
- `__pycache__` retained old constraint name. Cleared cache for clean reload.

### Changed: All worker services replicas set to 1
- **File**: `docker-compose.yml`
- Development resource optimization. Removed `deploy.replicas` blocks.

---

## 2026-05-18 — API Trailing Slash Fix

### Fixed: Trailing slash mismatch on 10 root endpoints
- **Files**: 10 backend endpoint files
- `@router.get("/")` → `@router.get("")`. Frontend axios calls without trailing slash got 405.

### Added: Changelog scripts + make targets
- **Files**: `scripts/changelog.sh`, `Makefile`
- CLI helper and make targets for changelog management.

---

## 2026-05-17 — Frontend Build Fixes

### Fixed: Missing/nonexistent dependencies
- Removed `@radix-ui/react-badge` (never existed in npm). Downgraded `@tanstack/react-table` to 8.16.0 (CJS-compatible). Added `geist@1.3.1`.

### Fixed: Missing config files
- Created `tsconfig.json`, `postcss.config.js`, `next-env.d.ts`.

### Fixed: Broken imports in dashboard
- Removed dead component imports. Fixed `GradeRing` import path.

### Fixed: TypeScript errors
- Extracted inline const maps into typed `Record<string, ...>` variables.

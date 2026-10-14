# Explanation

Understanding-oriented material: the reasoning behind decisions already reflected elsewhere as
diagrams, tables, and field lists. Read this when you want to know *why* something is built the way it
is, not just what it is — for the structural facts themselves, see [ARCHITECTURE.md](./ARCHITECTURE.md),
[PIPELINES.md](./PIPELINES.md), [FRONTEND.md](./FRONTEND.md), and [API_REFERENCE.md](./API_REFERENCE.md).

## Why two pipelines, not one

`BountyProgram`/`BountyTarget`/`BountyAsset`/`ExploitAttempt`/`BountyReport` (see
[DATA_MODEL.md](./DATA_MODEL.md)) never reference `Organization`/`Asset` at all — a deliberate schema
split, not an oversight: ASM is passive, continuous, monitoring-oriented, and its `Asset` rows can
appear without a human ever explicitly approving each one. Bug Bounty is active testing against real,
live targets and must never let passive discovery silently expand what's touched — a `BountyAsset`
(recon suggestion) is never auto-promoted to a `BountyTarget` (the human-approved, actually-testable
list), and every worker in the exploit chain re-validates scope at execution time regardless of what an
earlier stage already checked. See [the scope gate](#the-scope-gate-the-load-bearing-safety-property)
below for the full model, and [PIPELINES.md](./PIPELINES.md) for the structural diagram.

## The scope gate (the load-bearing safety property of the whole Bug Bounty pipeline)

Two independent gates stand between a recon suggestion and anything actually being tested, and both are
re-checked at execution time rather than trusted from an earlier stage:

1. **`is_target_in_scope(url, program.scope_rules)`** — explicit out-of-scope rules always beat an
   in-scope match (fail-closed).
2. **The URL's host must belong to a `BountyTarget` a human explicitly approved** (`_owning_target_id`).
   Recon output (`BountyAsset`) can never expand what's testable on its own — a discovered URL is only
   ever touched if a human already approved its parent domain/URL as a target.

Both checks happen *inside the worker, at execution time, on every stage* — not trusted from upstream —
so narrowing `scope_rules` mid-program takes effect immediately, and a bug or bypass in an earlier stage
can't cascade into testing something out of scope. This is the property the whole Bug Bounty pipeline's
safety rests on; see [PIPELINES.md#the-scope-gate](./PIPELINES.md) for the structural flowchart.

## Recon vs. modern client-side apps

Every static crawler (katana, waybackurls, gau) only parses HTML/JS text — none of them execute
JavaScript, so a modern SPA's real routes and API calls (built entirely client-side, often carrying real
per-user resource IDs) are invisible to them. `browser_crawl.py` drives a real headless browser instead:
loads the app, passively captures every network request it fires, clicks through internal links
(`a[href]`/`[routerlink]` only — never a plain button, to avoid triggering a state-changing action), and
also types into any search-style input it finds and captures the resulting URL, since a hash-routed
SPA's `#/search?q=...` route is built entirely client-side and never touches the network at all.
`exploit_dom.py`'s param injection correspondingly parses query params from either the real query string
or a hash-fragment-embedded one, for the same reason — a static crawler alone would have left this whole
class of route (and the injection points inside it) completely invisible to every downstream stage.

## Why ASM and Bug Bounty are two fully separate dashboard shells

Not one shared sidebar with a Bug Bounty item mixed in, and not a cosmetic choice: the two products have
genuinely different mental models (ASM is continuous, passive monitoring; Bug Bounty is a deliberate,
authorized, one-shot active-testing engagement), and mixing their navigation risked making either one
feel like an afterthought bolted onto the other. `dashboard/layout.tsx` picks the shell purely from the
route (see [FRONTEND.md](./FRONTEND.md#two-dashboards-one-codebase) for the routing flowchart) as a
UX-side mirror of the API's `RequireProduct` — the redirect just avoids flashing a route's content before
the API would 403 it anyway; the API remains the actual enforcement boundary. Bug Bounty's rose accent
throughout its shell is deliberate too: visually distinct from ASM's palette so the "this is active
testing, not passive monitoring" distinction stays visible at a glance, not just in the URL.

## Theming and accessibility

Found the theme infrastructure already half-scaffolded and disconnected before this work: `theme:
"dark" | "light"` existed in the store (persisted, but never read to toggle anything), Tailwind's
`darkMode: ["class"]` was configured but no component used a `dark:` variant, and `globals.css` already
defined unused `--severity-*`/`--grade-*` CSS vars that nothing consumed (`SeverityBadge.tsx` had its own
third, independent copy of the same color mapping using literal Tailwind classes instead). Rather than
build a new theme system, the fix was to actually wire up what was already there: `globals.css`'s
`:root` now holds light-theme values by default, the unchanged dark palette moved under a `.dark` class
block, and every severity/grade color reference in the app reads the same shared tokens.

Similarly, modals and header dropdowns were hand-rolled `fixed inset-0` divs and manual
`mousedown`-outside-click listeners, despite `@radix-ui/react-dialog` and
`@radix-ui/react-dropdown-menu` already being dependencies, unused, in the codebase. Rewiring onto Radix
wasn't a rewrite for its own sake — it's where the missing accessibility behavior (focus trap,
Escape-to-close, return-focus-on-close, `role="dialog"`/`role="menu"`, arrow-key nav) came from, without
reimplementing any of it by hand. `MotionConfig reducedMotion="user"` on the whole app was the same
logic applied to animation: respect a setting the OS already exposes, rather than assume every user wants
every transition.

## Why product entitlement is chosen once, at registration

A self-serve registration with no `invite_token` always creates a brand-new `Workspace` — product
entitlement (`Workspace.enabled_products`) is chosen once, at that moment, rather than being a per-user
setting layered on later. An invited join (`POST /workspaces/invite` + `register()` with `invite_token`
— see [Platform self-security](#platform-self-security-what-was-found-what-wasnt) below) doesn't get its
own product choice either, for the same underlying reason: it inherits the *existing* workspace's
`enabled_products` rather than letting the request assert its own, since a request can't be trusted to
self-assign entitlement. Either way, entitlement is server-side truth — enforced via `RequireProduct` and
embedded in the JWT `products` claim so most requests don't need an extra DB lookup to check it. See
[API_REFERENCE.md#product-entitlement](./API_REFERENCE.md) for the enforcement mechanics.

## Self-hosted Scalar API reference, not the CDN default

FastAPI's built-in Swagger UI and every common Scalar integration default to loading their JS/CSS from
`cdn.jsdelivr.net`. That default is incompatible with this platform's own NGINX CSP (`script-src
'self'`) — not a style preference, a hard block; a CDN-loaded script simply won't execute under this
policy, confirmed directly by the same mechanism blocking Scalar's default web font host
(`fonts.scalar.com`) in testing. Loosening the CSP just to allow one docs page would reduce XSS
protection for every page under it, a bad trade for a security product's own tooling. Beyond the CSP:
a CDN load is also a supply-chain surface (a compromised CDN or upstream package executes in the browser
of anyone viewing the API docs), an availability dependency on a third party the platform doesn't
control, and — demonstrated directly while building this — an unpinned `@latest` URL that can silently
change the served bundle without a corresponding code change to review. Vendoring the bundle locally at
a pinned version avoids all four at once, consistent with the platform's own self-hosted design (no
dependency on external services it doesn't have to have).

## Platform self-security: what was found, what wasn't

An earlier full-repo assessment flagged three suspected issues.

**`POST /workspaces/invite` was a complete no-op stub — fixed (2026-07-28).** It now generates a signed,
stateless invite JWT (`type=workspace_invite`, carrying `wid`/`role`, 7-day expiry — the exact same
pattern `/auth/forgot-password`'s reset token already used, so no new DB table/migration was needed).
`register()` consumes `invite_token` to join that workspace at the granted role instead of creating a
new one. Delivery is deliberately not email: the token/link is returned directly in the API response for
an owner/admin to share however they like, sidestepping the second issue below entirely rather than
depending on it. Known, accepted limitation: not single-use or revocable, matching the reset-token
pattern's own simplicity level — anyone holding the link can join at the granted role until it expires.

**`worker-notification`'s missing `SMTP_*` env vars remain unfixed, deliberately.** The current phase is
dev-environment-treated-as-production with no real SMTP credentials available to verify delivery
against — wiring the env vars through without a way to confirm actual mail delivery would just be
unverified code sitting there. Revisit once real SMTP access exists.

The third suspected issue — a cross-tenant data leak — was investigated exhaustively (every endpoint
file, the JWT/API-key auth dependency layer, the correlation worker's cross-org shared-IP queries) and
**not found**; every query checked was correctly scoped by `workspace_id`. One related hardening gap did
surface during that audit:
`findings.py::bulk_action`'s bulk `UPDATE` statements don't re-assert `workspace_id` in their own `WHERE`
clause the way the rest of the codebase consistently does (only the pre-check `SELECT` does) — not
currently exploitable (the pre-check already validates every ID belongs to the caller's workspace before
the update runs), but worth hardening to match the pattern used everywhere else, for defense in depth
rather than because a real gap was demonstrated.

**Bug Bounty pipeline audit (2026-10-14): found, fixing in progress.** An 8-angle code-review +
security-review pass over the then-uncommitted `workers/bounty/*` changes (interactsh integration,
source-map analysis, password-reset-reuse check, PII redaction, priority scoring) — every item below
verified by reading the actual code, several independently re-found by 2-3 separate review passes.
Treat this as a todo list, not a resolved record, and update this entry (don't just delete lines) as
items actually get fixed. #1-3 below are done (same day); #4-10 are still open.

Ranked by severity:

1. **~~SSRF against our own scanning infra via JS source-map fetch.~~ Fixed 2026-10-14.**
   `workers/bounty/tools.py`'s `_fetch_sourcemap_json` followed a `//# sourceMappingURL=` reference taken
   from the *target's own* JS response via `urljoin()` and fetched it with no scope/host/private-IP
   check — unlike every other live-request path in this pipeline. A target serving
   `//# sourceMappingURL=http://169.254.169.254/...` turned passive JS analysis into SSRF against the
   worker container. Fixed with a new `_is_safe_to_fetch()` guard (resolves the hostname, rejects
   private/loopback/link-local/reserved/multicast addresses and non-http(s) schemes), applied before
   fetching any source-map candidate URL — same `is_private`/`is_loopback`/`is_link_local` convention
   already used in `workers/enrichment/enrichment_worker.py` and
   `workers/validation/asset_validation_worker.py`. Live-verified inside the worker container against
   `169.254.169.254`, `127.0.0.1`, `localhost`, a private `10.x` address, `file:///etc/passwd`, and the
   `garage` service's own internal hostname — all correctly blocked; a real public domain still passes.
2. **~~False-positive exploit finding auto-notifies Slack/Discord/email with no human gate.~~ Fixed
   2026-10-14.** `exploit_ext.py::confirm_password_reset_reuse` marked "confirmed"/"high" from HTTP
   status code alone (200-299) on two *live* password-reset attempts — many reset-confirm APIs return a
   uniform 200 regardless of token validity (anti-enumeration), which made the two-call test meaningless.
   Fixed by adding a negative-control request with a never-issued token before concluding: if that
   baseline *also* gets a 2xx back, the endpoint's status code can't be trusted to mean anything, so the
   finding downgrades to `"inconclusive"` (same convention already used elsewhere in this file for
   exactly this kind of ambiguity) instead of `"confirmed"` — which keeps it out of
   `notify_critical_findings`'s auto-notify path (that still filters on `status == "confirmed"`).
3. **~~SSRF confirmation false-positives across co-located endpoints.~~ Fixed 2026-10-14.**
   `exploit_tools.py::run_ssrf`'s OOB token was `param+hostname` only — two endpoints on the same host
   sharing a param name (`url=`, `callback=`) got identical tokens, so one real callback marked every
   attempt sharing that token as confirmed. Fixed by keying the token off a hash of the full URL instead
   of just the hostname, so every (URL, param) pair gets a distinct token; the matching side
   (`_confirm_ssrf_via_interactions`) needed no change since it just parses whatever token was embedded
   in the stored payload. Verified the two URLs from the original failure scenario now produce distinct
   tokens.
4. **~~The "reuse OOB session across runs" feature is a no-op.~~ Addressed (honestly) 2026-10-14.**
   Pinned `interactsh-client@v1.3.1` has an upstream bug (verified against the actual Go source for that
   tag, and confirmed *still present on upstream's own main branch* -- not something a version bump
   fixes): session-file loading YAML-unmarshals the file *path string*, not its contents, error
   discarded — a fresh random domain is minted every run regardless. Patching and building our own
   binary from source was judged disproportionate effort for what's an operator-convenience feature,
   not a correctness one (SSRF confirmation accuracy is unaffected either way). Fixed the actual harm
   instead: the frontend tooltip no longer promises reuse "until it expires" (it now states the known
   limitation plainly), and `interactsh_session.py`'s docstring + `start_session()`'s log line document
   the bug and stop claiming `resumed=True`. Session persistence itself is left in place, dormant, for
   if/when this gets fixed upstream or someone does patch-build a fixed binary.
5. **~~interactsh-client subprocess leaks on exception.~~ Fixed 2026-10-14.** The subprocess in
   `exploit_worker.py` was only stopped at the tail of a `TemporaryDirectory` block; an exception from
   any of the ~15 intervening modules skipped cleanup, orphaning a process that polls `oast.fun`
   indefinitely. Fixed by wrapping that whole stretch (lfi through the password-reset-reuse check) in
   `try`/`finally`, with the interactsh teardown moved into the `finally` — structurally confirmed via
   AST inspection (exactly one `try` in `run_stage`, with a non-empty `finally`), so `stop_and_collect()`
   now runs no matter what raises in between.
6. **~~`authenticated` status flag is wrong after a header refactor.~~ Fixed 2026-10-14.**
   `recon_worker.py` and `vulnscan_worker.py` both derived `authenticated = bool(extra_headers)`, which
   stopped meaning "login succeeded" once `extra_headers` started being pre-seeded from `custom_headers`
   regardless of outcome. Both now use the actual login-result variable (`auth_token` /  `token`,
   initialized to `None` so it's safe to read even when no login was attempted) instead — matching
   `exploit_worker.py`'s already-correct separate-boolean pattern.
7. **~~Unchecking every module in the new UI silently runs all of them.~~ Fixed 2026-10-14.**
   `vulnscan_worker.py` treated an empty `vulnscan_modules` list the same as "unset" and fell back to
   running everything. Found the identical bug in `exploit_worker.py::_resolve_modules` for
   `exploit_modules` too (same `and requested` truthiness check) and fixed both the same way: check
   `isinstance(x, list)` alone, so a present-but-empty list is respected as "run nothing" and only an
   absent/non-list value defaults to the full set.
8. **~~`read_body_capped` reads past its own cap.~~ Fixed 2026-10-14.** Chunk size was hardcoded to 65536
   regardless of the caller's `max_bytes`, checked only between chunks. Now capped to
   `min(65536, max_bytes - total)` per read.
9. **~~Redaction leaves secret/PII fragments unmasked in some shapes.~~ Fixed 2026-10-14.**
   `bounty_redaction.py`'s JSON key-value matcher didn't handle backslash-escaped quotes, and PII inside
   a JSON array value or in `key=value` form/query-string shape was only partially caught. Fixed the
   escaped-quote case by switching the JSON value character class to `(?:\\.|[^"\\])*`. Fixed the
   grouped-digits case (covers both the array-value and form/query-string shapes at once, since it's a
   content-based pass that runs before the keyed patterns can partially consume the value) with a new
   `_ID_NUMBER_GROUPED_RE` that matches any space/dot/dash-grouped digit sequence but only actually
   redacts it if the digit count (separators stripped) is exactly 15 or 16 — same length discipline as
   the existing contiguous-run pattern, so grouped dates/IPs/money amounts aren't swept up as false
   positives. Live-verified all 6 cases from the original finding plus two negative controls (an IP, a
   date) — see `backend/app/services/bounty_redaction.py`.
10. **~~An inserted default-fill line demotes a docstring to dead code.~~ Fixed 2026-10-14.**
    `vulnscan_worker.py::_run_detection` had a new first statement pushing its existing docstring to
    second position. Moved the default-fill line after the docstring.

All 10 items above are now fixed (2026-10-14), each rebuilt and verified against a running container
(all affected services reached `healthy`, no import/syntax errors) before being marked done here.

Lower-priority cleanup also surfaced and is **not yet done** (sequential `aiohttp.ClientSession`s where
one-reused would do, `sorted()[:50]` where `heapq.nsmallest` would do, the same `extra_headers`
extraction snippet copy-pasted into 4 worker files — which is also *why* finding 6 above only hit some
of them and not others — and a second, parallel "which modules are enabled" convention introduced
alongside the pre-existing one): a one-time sweep candidate, not a correctness risk, so lower priority
than the 10 above were.

Checked and ruled out during the same pass: the MinIO→Garage migration itself (bucket bootstrap,
anonymous-screenshots-only access, the narrowed nginx proxy — see the How-to guide); the interactsh
session secret *is* returned unredacted to workspace admins via the bounty program API, but so are the
pre-existing `auth_password`/`auth_email` fields in the same JSONB blob, by the same design — not a new
privilege-boundary gap, just worth a defense-in-depth fix eventually; `interactsh-client` is invoked
with an argument list (no shell), so no command injection; generated report HTML doesn't embed
`rules_of_engagement`, so credentials don't leak through the researcher-facing report artifact.

## Docs vs. reality — corrections this documentation set has already made once

Documentation drifts from code by default, not by accident — this list exists so the same wrong claims
don't quietly get reintroduced by someone trusting an old doc over the code:

- An earlier version of this documentation (and the root `README.md`) implied Shodan/VirusTotal/
  AbuseIPDB/OTX threat-intel integration. **This was never true.**
  `backend/app/integrations/enrichment/engine.py` is explicitly a no-op plugin engine kept for import
  compatibility; the real enrichment path (`workers/enrichment/enrichment_worker.py`) is keyless
  ASN/RDAP/network-baseline only, by design — there are no intel API keys in `.env.example`. Don't
  reintroduce provider-keyed enrichment without checking this decision with the project owner first.
- Earlier docs didn't mention Bug Bounty at all — it's now roughly half the platform's endpoint surface
  and worker fleet.
- The root `README.md`'s "Adding Scanner/Enrichment Integrations" section used to describe a
  `BaseScannerPlugin`/`BaseEnrichmentPlugin` interface that doesn't exist in code
  (`backend/app/integrations/scanners/` is an empty package). The real extension point is
  `workers/scanner/*.py` / `workers/crawler/` — one file per tool/stage, wired directly into the queue
  chain.
- `docs/API_REFERENCE.md` used to claim `compliance`/`custom` reports had "no real framework-mapping
  built yet" — wrong as of 2026-07-15; `compliance_mapping.py` has real CIS Controls v8 mapping. Fixed
  2026-07-26, during the same audit that found this documentation set itself had drifted.
- `docs/PRD.md`'s roadmap used to list a cross-tenant leak as "not yet actioned" without reflecting that
  it had actually been investigated and not found — see
  [Platform self-security](#platform-self-security-what-was-found-what-wasnt) above.

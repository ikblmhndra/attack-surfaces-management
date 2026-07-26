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

A self-serve registration always creates a brand-new `Workspace` — there is no "join an existing
workspace" flow in code today (`RegisterRequest.invite_token` exists in the schema but is currently
unread/dead in `register()` — see [Platform self-security](#platform-self-security-what-was-found-what-wasnt)
below). Because of that, product entitlement (`Workspace.enabled_products`) is chosen once, at
registration, rather than being a per-user setting layered on later: one registration, one new
workspace, one product choice, enforced server-side via `RequireProduct` and embedded in the JWT
`products` claim so most requests don't need an extra DB lookup to check it. See
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

An earlier full-repo assessment flagged three suspected issues. Two were confirmed real by reading the
code directly and remain unfixed as of this writing: `POST /workspaces/invite` is a complete no-op stub,
and `worker-notification`'s Docker Compose environment block omits every `SMTP_*` variable, so email
notifications silently never send regardless of `.env` configuration. The third — a suspected
cross-tenant data leak — was investigated exhaustively (every endpoint file, the JWT/API-key auth
dependency layer, the correlation worker's cross-org shared-IP queries) and **not found**; every query
checked was correctly scoped by `workspace_id`. One related hardening gap did surface during that audit:
`findings.py::bulk_action`'s bulk `UPDATE` statements don't re-assert `workspace_id` in their own `WHERE`
clause the way the rest of the codebase consistently does (only the pre-check `SELECT` does) — not
currently exploitable (the pre-check already validates every ID belongs to the caller's workspace before
the update runs), but worth hardening to match the pattern used everywhere else, for defense in depth
rather than because a real gap was demonstrated.

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

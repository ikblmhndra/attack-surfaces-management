# Product Requirements Document (PRD)

**Status**: living document, describing the product as it actually exists (2026-07-21), not an
aspirational pre-build spec. Where a requirement is met, it says so; where it isn't yet, it's marked
explicitly rather than implied.

## 1. Vision

A self-hosted platform a security team fully owns and controls — no data leaves their infrastructure,
no per-seat SaaS pricing — that covers both sides of external security posture work from one login:

1. **Know what you have and how exposed it is**, continuously, without anyone having to remember to run
   a scan (Attack Surface Management).
2. **Prove exploitability, safely and within explicit authorization**, when passive discovery isn't
   enough and a real bug bounty engagement calls for active testing (Bug Bounty).

The two are related but intentionally not the same product wearing two hats — see
[docs/ARCHITECTURE.md#why-two-pipelines-not-one](./ARCHITECTURE.md#why-two-pipelines-not-one). A
workspace picks one or both at signup.

## 2. Problem statement

- Security teams and MSSPs need continuous visibility into an organization's internet-facing footprint
  — subdomains, IPs, ports, endpoints, TLS/DNS posture — without manually re-running discovery tooling
  and manually eyeballing diffs.
- Raw scanner output (nuclei findings, open ports, expired certs) doesn't answer "how worried should I
  be, and about what, first" — it needs weighting, deduplication, decay over time, and a single
  score/grade a non-specialist stakeholder can track.
- Bug bounty hunters and internal red teams need a way to go from "here's my authorized scope" to "here
  are confirmed, reproducible findings with step-by-step PoCs" without hand-running the same recon → probe →
  exploit → writeup sequence for every engagement, while never risking testing something out of scope.

## 3. Target users / personas

| Persona | Uses | Primary need |
|---|---|---|
| Security team / SOC analyst | ASM | Continuous exposure visibility, prioritized findings, risk trend over time |
| MSSP managing multiple client orgs | ASM | Multi-tenant isolation (workspace → organization), per-org scoring, white-label-able dashboard |
| Internal red team | ASM + Bug Bounty | Both continuous monitoring of their own org *and* active testing against explicitly-approved scope |
| Bug bounty researcher (HackerOne/Bugcrowd/independent) | Bug Bounty | Fast recon-to-report pipeline for an authorized program, with scope enforcement that can't be accidentally bypassed |
| Platform owner / admin | Both | User/workspace management, audit trail, notification routing |

## 4. Use cases

Mermaid has no native UML use-case notation (no actor/oval/system-boundary primitives), so this uses
the standard workaround: actors as boxes, use cases as pill/stadium shapes, grouped inside a
system-boundary subgraph — same information a formal use-case diagram carries.

### ASM

```mermaid
flowchart LR
    analyst["Security Analyst"]
    mssp["MSSP Operator"]
    admin["Platform Admin"]

    subgraph asm["ASM"]
        uc1(["Onboard an organization"])
        uc2(["Trigger a scan"])
        uc3(["Review risk score and trend"])
        uc4(["Triage a finding<br/>accept / false-positive / reopen"])
        uc5(["Configure notification rules"])
        uc6(["Export a report"])
        uc7(["Browse the attack-surface graph"])
        uc8(["Manage users and API keys"])
    end

    analyst --> uc2
    analyst --> uc3
    analyst --> uc4
    analyst --> uc7
    mssp --> uc1
    mssp --> uc3
    mssp --> uc6
    admin --> uc5
    admin --> uc8
```

### Bug Bounty

```mermaid
flowchart LR
    researcher["Bug Bounty Researcher"]
    admin["Platform Admin"]

    subgraph bounty["Bug Bounty"]
        uc1(["Create a program and define scope"])
        uc2(["Run the full pipeline<br/>recon to report"])
        uc3(["Promote recon suggestions<br/>to approved targets"])
        uc4(["Review confirmed findings"])
        uc5(["Generate a shareable<br/>HTML / PoC report"])
        uc6(["Receive a critical-finding<br/>notification"])
        uc7(["Narrow scope mid-program"])
    end

    researcher --> uc1
    researcher --> uc2
    researcher --> uc3
    researcher --> uc4
    researcher --> uc5
    researcher --> uc7
    admin --> uc6
```

## 5. Reference benchmark

The product-completeness bar for ASM is **Tenable's Attack Surface Management product** — when scoping
new work or judging whether a feature is "done enough," compare against what a product at that tier
would offer, not just internal consistency.

## 6. Product scope

### 6.1 Attack Surface Management (ASM)

| Capability | Status |
|---|---|
| Multi-tenant workspace → organization → asset hierarchy | ✅ shipped |
| Subdomain/DNS/IP/port discovery (subfinder, amass, assetfinder, crt.sh, dnsx, naabu) | ✅ shipped |
| HTTP fingerprinting, web crawling, endpoint scoring (httpx, katana) | ✅ shipped |
| Vulnerability scanning (nuclei), named scan profiles | ✅ shipped |
| Correlation / dedup / asset-relationship graph | ✅ shipped |
| Weighted, decaying risk score with letter grade | ✅ shipped — see [DEVELOPMENT.md](./DEVELOPMENT.md#risk-scoring-formula) |
| CVSS + EPSS + CISA KEV + SSVC-informed exploit-likelihood boosting | ✅ shipped (4-stage risk-engine redesign) |
| End-of-life software detection | ✅ shipped |
| Screenshots | ✅ shipped |
| Enrichment | ✅ shipped, **keyless only** (ASN/RDAP/network baseline) — see [ARCHITECTURE.md's threat-intel note](./ARCHITECTURE.md#docs-vs-reality) |
| Notifications (email/Slack/Discord/Telegram/webhook) | ✅ shipped, on-demand triggers only |
| Scheduled/recurring daily-summary reports | ❌ dead code — `report.daily` has no consumer, see [ARCHITECTURE.md](./ARCHITECTURE.md#docs-vs-reality) |
| Continuous/passive monitoring without a manual scan trigger | ❌ not started — bigger architecture lift, explicitly deferred |
| PDF/CSV reports (executive/technical/compliance/custom) | ⚠️ partial — `executive` is real; `technical`/`compliance`/`custom` are currently aliases of the full finding list with no real framework-mapping built yet |

### 6.2 Bug Bounty

| Capability | Status |
|---|---|
| Program creation with explicit scope rules (fail-closed, explicit-deny-wins) | ✅ shipped |
| Recon → suggestion list, never auto-promoted to testable | ✅ shipped |
| Real-browser (Playwright) recon of SPA-only client-side routes | ✅ shipped |
| Bulk asset promotion (checkboxes + multi-select) | ✅ shipped |
| Full auto-chained pipeline (one button, recon→...→report) | ✅ shipped |
| 12 active-exploit modules (XSS/SQLi/SSRF/LFI/IDOR/CSRF/SSTI/NoSQL/mass-assignment/OAuth/BAC/upload+XXE) | ✅ shipped — see [PIPELINES.md](./PIPELINES.md#exploit-module-reference) |
| Two-identity IDOR / BAC confirmation | ✅ shipped, opt-in (needs a second, disposable test identity) |
| Stored-XSS confirmation | ✅ shipped, opt-in (creates real content on the target) |
| Subdomain takeover detection (subzy) | ✅ shipped |
| Step-by-step PoC generation in shareable HTML report | ✅ shipped |
| Critical/confirmed-finding notifications | ✅ shipped, reuses the ASM notification pipeline |
| Auto-scope-sync from HackerOne/Bugcrowd APIs | ❌ not built — scope is entered manually |
| Destructive/DoS testing | ❌ explicitly out of scope by default, not a gap |
| Data exfiltration / persistence beyond proof-of-concept | ❌ explicitly out of scope, not a gap |

## 7. Entity lifecycles

Where a status field drives real product behavior (what a user can or can't do next), the intended
lifecycle — these are the state machines a user actually experiences, distinct from the ERD in
[DATA_MODEL.md](./DATA_MODEL.md), which shows structure, not behavior over time.

### Scan status

```mermaid
stateDiagram-v2
    [*] --> pending
    pending --> queued
    queued --> running
    running --> completed
    running --> failed
    pending --> cancelled
    queued --> cancelled
    running --> cancelled
    completed --> [*]
    failed --> [*]
    cancelled --> [*]
```

`workers/scan_state.py` codifies exactly these two sets — `ACTIVE_STATUSES = {pending, queued, running}`,
`TERMINAL_STATUSES = {completed, failed, cancelled}`. A scan cannot be revived from a terminal state; the
user triggers a new scan instead.

### Bug Bounty program status

```mermaid
stateDiagram-v2
    [*] --> paused: created (default)
    paused --> active: Activate
    active --> paused: Pause
    active --> closed: Close
    paused --> closed: Close
    closed --> [*]
```

Only `active` allows any pipeline stage to actually run — every stage worker checks this independently
(see [PIPELINES.md](./PIPELINES.md)). Note this diagram describes the **supported product flow** (what
the frontend exposes: Activate/Pause buttons), not a strict database-enforced state machine — the update
endpoint validates `status` is one of the three valid *values*, not that the specific transition is
legal, so a direct API call could technically write `closed → active`. Don't rely on the API to reject
an unsupported transition; the frontend not offering the button is the actual guard today.

### Finding status (ASM)

```mermaid
stateDiagram-v2
    [*] --> open
    open --> accepted: risk-accept
    open --> false_positive
    open --> resolved
    accepted --> resolved
    false_positive --> open: reopen
    resolved --> open: reopen
    resolved --> [*]
```

### Bug Bounty finding status (`ExploitAttempt`)

```mermaid
stateDiagram-v2
    [*] --> confirmed: structural proof<br/>token execution, baseline diff, ...
    [*] --> inconclusive: needs human judgement
    [*] --> not_vulnerable
    [*] --> blocked: WAF or rate-limit interference
```

Deliberately **not** a mutable workflow like ASM's `Finding` — each row is a point-in-time result of one
test execution, not a ticket a human transitions through states. A human's judgement call on an
`inconclusive` result is captured downstream, in the `BountyReport` draft, not by mutating the attempt
itself.

## 8. Functional requirements

Numbered for reference; "the system" means the relevant combination of API + worker(s) unless a layer
is specified.

**Tenancy & Auth**
- FR-1: A user registering self-service **always** creates a new workspace (no join-existing-workspace
  flow exists today).
- FR-2: A workspace declares which product(s) it's entitled to (`enabled_products`) at registration;
  this is enforced server-side on every request to a product-gated router, not just hidden client-side.
- FR-3: Users have one of 4 roles (`owner/admin/analyst/viewer`) with a strict hierarchy; sensitive
  mutations require `admin` or `owner`.
- FR-4: Authentication supports both short-lived JWT (with refresh rotation) and long-lived API keys
  (scoped, hashed, revocable).
- FR-5: MFA (TOTP) is supported and enforceable per-user.

**ASM**
- FR-6: An organization's discovery seed data (domains, root domains, IP ranges, ASNs) drives
  subdomain/IP discovery without further manual input.
- FR-7: A scan's `modules` list gates every downstream worker stage — a worker must not do work outside
  its requested module list.
- FR-8: Findings are deduplicated via a stable fingerprint (SHA-256) so re-discovering the same issue
  across scans doesn't create duplicate rows.
- FR-9: A finding can be marked false-positive or risk-accepted, excluding it from score computation
  without deleting the record.
- FR-10: Risk score is computed per-organization, versioned (`score_version`), and historized (one row
  per computation, not upserted).

**Bug Bounty**
- FR-11: A `BountyAsset` (recon suggestion) is never automatically promoted to a `BountyTarget`
  (testable) — promotion is always an explicit human action (single or bulk).
- FR-12: Every URL the exploit stage touches must pass two independent checks at execution time:
  `is_target_in_scope` against current `scope_rules`, and ownership by an approved `BountyTarget`'s
  host. Neither check is trusted from an earlier pipeline stage.
- FR-13: IDOR confirmation never enumerates or extracts another identity's data — it stops at the first
  structural confirmation.
- FR-14: A confirmed finding (never a candidate/inconclusive one) can trigger a real-time notification
  through the existing ASM notification channels.
- FR-15: A program's pipeline can be run stage-by-stage (manual) or fully auto-chained (one trigger);
  both paths must respect the program's `active`/`paused`/`closed` status.

## 9. Non-functional requirements (summary — full detail in TRD)

See [TRD.md](./TRD.md) for the complete non-functional requirements (performance, scalability,
security, reliability, observability). Headline points:

- **Security is the primary non-functional requirement for Bug Bounty specifically** — the scope-gate
  model (FR-12) is treated as the single most safety-critical piece of code in the platform.
- Every pipeline stage must be independently horizontally scalable (`docker compose up -d --scale
  worker-X=N`), with no stage assuming a specific concurrency.
- No message is ever lost between "the API committed the decision" and "the queue received it"
  (transactional outbox — see [ARCHITECTURE.md](./ARCHITECTURE.md#request-flow-creating-an-asm-scan-outbox-pattern)).

## 10. Out of scope / non-goals (current)

- Continuous/passive monitoring without a manual scan trigger for ASM.
- Auto-scope-sync from bug bounty platform APIs.
- Any form of active exploitation beyond proof-of-concept (no data exfiltration, no persistence, no
  destructive/DoS testing) — a deliberate, standing product boundary, not a backlog item.
- Third-party paid threat-intelligence integration (Shodan/VirusTotal/AbuseIPDB/OTX/Censys) — a
  deliberate design decision (no dependency on paid/entitled APIs), revisit only with the project owner.
- Per-user product entitlement within a shared workspace (today it's workspace-wide).

## 11. Current priorities & roadmap

As of the most recent internal roadmap discussion:

1. **Core scanning/detection maturity stays the priority** over adjacent feature work — coverage,
   finding validity/triage correctness, exploit-intelligence accuracy (EPSS/KEV/SSVC), tool parameter
   tuning (rate limits, timeouts, concurrency, flags) over "is the tool wired at all."
2. **Deferred, explicitly not dropped**:
   - Platform self-security issues found during an earlier full-repo assessment (workspace-invite stub,
     email notification breakage, cross-tenant leak) — flagged as high priority but not yet actioned;
     worth resurfacing once core-feature work reaches a natural pause.
   - Dependency/library CVE remediation — deferred until features are stable.
3. **Frontend changes**: small display/readability fixes can proceed without asking; anything that
   amounts to a visual revamp needs a heads-up first (this document included — see the Bug Bounty
   dashboard redesign in `CHANGELOG.md`, 2026-07-21, for the pattern that was followed: mockup review
   before implementation).

## 12. Open questions

- Whether real-world finding *volume* from the exploit-intelligence stack (version-CVE correlation,
  EOL detection) needs tighter scoping/bounding on some deployments, or is accepted as-is — flagged
  during the risk-engine redesign, not yet resolved either way.
- Whether `technical`/`compliance`/`custom` report formats need real framework-mapping built out, or
  whether the `executive`-format-is-real / others-are-aliases split is acceptable long-term.
- Whether per-user (not just per-workspace) product entitlement is ever needed for larger teams sharing
  one workspace across both products.

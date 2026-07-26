# Documentation

Start with [`../README.md`](../README.md) for a quick start. This directory is the actual reference —
every file here is verified against the current code directly (models, routers, `docker-compose.yml`,
`workers/base_worker.py`'s queue map, etc.), not carried forward from older drafts. Where something here
corrects a previously-wrong claim, it says so explicitly rather than silently.

Structured around the [Diátaxis](https://diataxis.fr) framework: four kinds of documentation, kept
separate rather than mixed in one file, because a reader looking something up and a reader trying to
understand *why* need different things from the same page.

| Document | Mode | Read this for |
|---|---|---|
| [TUTORIAL.md](./TUTORIAL.md) | Tutorial | A guided, hands-on first run: stack up, register, create an org, run a scan, see a risk score |
| [HOWTO.md](./HOWTO.md) | How-to | Task guides: add a migration, add a worker queue, reverse-proxy a new internal service, run tests |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Reference | System context diagram, container/network topology, NGINX routing table, request-flow diagrams |
| [DATA_MODEL.md](./DATA_MODEL.md) | Reference | Full ERD (both schemas) + a complete field-by-field reference table for all 36 tables |
| [PIPELINES.md](./PIPELINES.md) | Reference | Queue topology table, ASM/Bug Bounty pipeline flowcharts, the scope-gate diagram, exploit-module reference table |
| [API_REFERENCE.md](./API_REFERENCE.md) | Reference | Every endpoint, every router, the auth model — plus the live interactive reference at `/api/docs` |
| [FRONTEND.md](./FRONTEND.md) | Reference | App Router structure, Zustand store shape, the Bug Bounty program-detail page's tab-by-tab patterns |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | Reference | Makefile command table, the risk-scoring formula's exact numbers, config wiring, known quirks |
| [EXPLANATION.md](./EXPLANATION.md) | Explanation | The reasoning behind the above: why two pipelines, the scope gate's safety property, theming/accessibility choices, self-hosted docs, what the self-security audit did and didn't find |

**Outside the four modes** (product/business planning documents, not user- or developer-facing system
documentation, so they don't fit the Diátaxis framework and aren't forced into it):

| Document | Read this for |
|---|---|
| [EXECUTIVE_SUMMARY.md](./EXECUTIVE_SUMMARY.md) | A half-page, non-technical summary of what this is and where it stands — for stakeholders who need neither the reference detail nor the reasoning |
| [PRD.md](./PRD.md) | Product vision, personas, use-case diagrams, entity-lifecycle state diagrams, functional requirements, current scope vs. non-goals, roadmap & priorities |
| [TRD.md](./TRD.md) | The non-functional requirements those PRD features must satisfy — security, reliability, performance, infra, testing, standing technical debt |

## Suggested reading order

**Stakeholder / non-technical?** EXECUTIVE_SUMMARY, stop there unless you want more.

**New to the product (PM, new hire)?** PRD → TRD — what it does and for whom, then what the system must
satisfy to deliver that.

**New to the codebase and want to run it (engineer)?** TUTORIAL first — get a working instance and see
the whole loop once, hands-on — then ARCHITECTURE → DATA_MODEL → PIPELINES → API_REFERENCE → FRONTEND →
DEVELOPMENT for the system shape, and EXPLANATION whenever something's structure raises a "why."

**Need to do one specific task?** HOWTO — it's organized by goal, not by file.

**Just need one fact?**
- "What is this product and who's it for?" → PRD
- "What does the database look like?" → DATA_MODEL
- "What happens when I click Run Full Pipeline?" → PIPELINES
- "What can this endpoint do / who can call it?" → API_REFERENCE
- "How do I add a migration / worker / env var?" → HOWTO
- "Why does the scope gate work this way? Why two pipelines?" → EXPLANATION
- "What security/performance/reliability bar does this have to hit?" → TRD

## Keeping this accurate

If you change something these documents describe (a queue, a table, an endpoint, a gate), update the
relevant doc in the same change — a wrong diagram is worse than no diagram, because it actively misleads
the next person who trusts it instead of the code. Past corrections (and why they mattered) are listed
in [EXPLANATION.md's "Docs vs. reality" section](./EXPLANATION.md#docs-vs-reality). When adding new
content, put it in the file matching its *mode*, not just its topic — a new endpoint's shape goes in
API_REFERENCE, the reasoning for why it works that way goes in EXPLANATION, and a step-by-step guide to
using it goes in HOWTO, even if all three end up linking to each other.

For anything not covered by these docs, `CHANGELOG.md` is the dated, per-change history and is generally
kept current; `graphify-out/` (if present) is a generated code-relationship graph queryable via
`graphify query "<question>"`.

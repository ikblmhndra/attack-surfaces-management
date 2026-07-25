# Documentation

Start with [`../README.md`](../README.md) for a quick start. This directory is the actual reference —
each file was written by reading the current code directly (models, routers, `docker-compose.yml`,
`workers/base_worker.py`'s queue map, etc.) on 2026-07-21, not carried forward from older drafts. Where
something here corrects a previously-wrong claim, it says so explicitly rather than silently.

| Document | Read this for |
|---|---|
| [PRD.md](./PRD.md) | Product vision, personas, use-case diagrams, entity-lifecycle state diagrams, functional requirements, current scope vs. non-goals, roadmap & priorities |
| [TRD.md](./TRD.md) | The non-functional requirements those PRD features must satisfy — security, reliability, performance, infra, testing, and standing technical debt |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System context diagram, container/network topology, NGINX routing, the outbox request-flow pattern, why ASM and Bug Bounty are two separate pipelines, known docs-vs-reality drift |
| [DATA_MODEL.md](./DATA_MODEL.md) | Full ERD (both schemas) + a complete field-by-field reference table for all 36 tables |
| [PIPELINES.md](./PIPELINES.md) | Queue topology table, the ASM scan pipeline flowchart, the Bug Bounty pipeline flowchart, the two-gate scope-safety model, the exploit-module reference table |
| [API_REFERENCE.md](./API_REFERENCE.md) | Every endpoint, every router, the auth model (JWT claims / RBAC / product entitlement), which routers are gated to which product — see also the live interactive reference at `/api/docs` |
| [FRONTEND.md](./FRONTEND.md) | App Router structure, the two-dashboard-shell split, Zustand store shape, the Bug Bounty program-detail page's tab-by-tab UI patterns |
| [DEVELOPMENT.md](./DEVELOPMENT.md) | Makefile commands, migration gotchas, the risk-scoring formula worked through step by step, the full incident-derived gotchas list |

## Suggested reading order

**New to the product (PM, stakeholder, new hire)?** PRD → TRD — what it does and for whom, then what
the system must satisfy to deliver that.

**New to the codebase (engineer)?** ARCHITECTURE → DATA_MODEL → PIPELINES → API_REFERENCE → FRONTEND →
DEVELOPMENT — roughly outside-in, system shape before implementation detail.

**Just need one thing?**
- "What is this product and who's it for?" → PRD
- "What does the database look like?" → DATA_MODEL
- "What happens when I click Run Full Pipeline?" → PIPELINES
- "What can this endpoint do / who can call it?" → API_REFERENCE
- "Why does this page look like that?" → FRONTEND
- "How do I run tests / migrations / add a worker?" → DEVELOPMENT
- "What security/performance/reliability bar does this have to hit?" → TRD

## Keeping this accurate

The previous version of `ARCHITECTURE.md` (and the root `README.md`) had drifted from the real code in
several concrete, misleading ways — see [ARCHITECTURE.md's "Docs vs. reality" section](./ARCHITECTURE.md#docs-vs-reality)
for the specifics. If you change something these documents describe (a queue, a table, an endpoint, a
gate), update the relevant doc in the same change — a wrong diagram is worse than no diagram, because it
actively misleads the next person who trusts it instead of the code. For anything not covered by these
docs, `CHANGELOG.md` is the dated, per-change history and is generally kept current; `graphify-out/` (if
present) is a generated code-relationship graph queryable via `graphify query "<question>"`.

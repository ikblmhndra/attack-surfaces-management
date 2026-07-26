# Executive Summary

**ASM Platform** is a self-hosted security platform covering two related but distinct needs from one
login: knowing what an organization exposes to the internet, and proving whether that exposure is
actually exploitable, safely and within explicit authorization.

## What it does

- **Attack Surface Management (ASM)** — continuously discovers and monitors an organization's
  internet-facing footprint (subdomains, IPs, ports, exposed services, TLS/DNS posture), scans it for
  known vulnerabilities, and reduces the results to a single weighted risk score (A–F grade) that a
  non-specialist stakeholder can track over time — instead of a raw dump of scanner output nobody has
  time to read.
- **Bug Bounty** — takes an authorized testing scope and runs it through an automated
  recon → probe → vulnerability scan → exploit confirmation → report pipeline, so a bug bounty
  researcher or internal red team gets confirmed, reproducible findings with proof-of-concept detail
  instead of hand-running the same sequence for every engagement — while a scope-enforcement mechanism
  makes it structurally impossible to test something out of bounds by accident.

Both share one account, one dashboard login, and one underlying platform, but run as two fully separate
product experiences — a security team can use either or both.

## Why self-hosted

Every component runs on infrastructure the organization already controls. No scan data, findings, or
target information ever leaves that infrastructure, and there's no per-seat SaaS pricing model — the
platform is a one-time deployment, not an ongoing per-analyst subscription.

## Where it stands today

Both products are functional end-to-end and in active use against real organizations and real bug
bounty programs, not prototypes. The completeness bar the team measures against is Tenable's Attack
Surface Management product — a recognized commercial benchmark, not an internally-invented standard.

Known, tracked gaps as of this writing: two platform self-security issues (a workspace invite feature
that doesn't yet send anything, and an email-notification path missing configuration) are confirmed and
scheduled once current feature work reaches a natural pause; scheduled/recurring daily-summary reports
are not yet wired up (on-demand reports are unaffected); and continuous scanning without a manual
trigger is a larger, explicitly deferred architecture item. None of these affect the core, actively-used
scanning and testing pipelines.

## For more detail

[docs/PRD.md](./PRD.md) has the full product requirements, target personas, and capability-by-capability
status; [docs/README.md](./README.md) indexes the complete documentation set (architecture, data model,
API reference, and more) for anyone who needs to go deeper.

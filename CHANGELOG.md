# Changelog

All notable changes to this project are documented below, sorted newest-first.

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

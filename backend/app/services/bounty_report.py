"""
ASM Platform — Bug Bounty pipeline: program summary classifier + HTML report.

Phase 4: turns a program's recon URLs + findings into (a) a "smart classifier"
summary (severity/module counts + priority buckets a researcher would triage
by) and (b) a standalone HTML report. Pure functions computed on demand from
already-persisted data -- no worker run, no schema change. See CHANGELOG.md.
"""
import html
import re
from collections import Counter
from typing import Any, Dict, List

from app.services.bounty_report_templates import build_report

# Priority-bucket patterns (from the reference framework's classifier).
_BUCKETS: Dict[str, re.Pattern] = {
    "idor_numeric": re.compile(r"[?&/](?:id|uid|pid|oid|user|account|order|no|num|invoice|ticket)[=/]\d+", re.I),
    "idor_uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
    "idor_api_object": re.compile(r"/api/v?\d+/[a-z]+/\d+", re.I),
    "bac_admin": re.compile(r"/(admin|dashboard|panel|moderator|manage|internal)(/|$|\?)", re.I),
    "bac_sensitive_action": re.compile(r"/(delete|remove|promote|impersonate|export|disable|approve|grant)(/|$|\?)", re.I),
    "bac_user_mgmt": re.compile(r"/(users?|accounts?|members?|roles?|permissions?)(/|$|\?)", re.I),
    "auth_oauth": re.compile(r"/(oauth|authorize|oidc|sso|login|signup|token|callback|password[-_]?reset)(/|$|\?)", re.I),
    "upload": re.compile(r"/(upload|import|attachment|file|media)(/|$|\?)", re.I),
    "payment": re.compile(r"/(payment|billing|invoice|checkout|charge|subscription|order)(/|$|\?)", re.I),
    "webhook": re.compile(r"/(webhook|callback|hook|notify)(/|$|\?)", re.I),
    "debug": re.compile(r"/(debug|dev|test|actuator|metrics|status|phpinfo|swagger|graphql|\.git|\.env)(/|$|\?)", re.I),
    "graphql": re.compile(r"/(graphql|graphiql)(/|$|\?)", re.I),
}

# Public alias -- exploit_worker.py reuses these same patterns to prioritize
# which discovered URLs get tested first when a run has more candidates than
# its MAX_URLS/MAX_URLS_PER_MODULE bounds allow.
PRIORITY_BUCKETS = _BUCKETS

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeat runs of the same finding (same module+technique+
    target) into one entry. Exploit can be re-run any number of times over a
    program's life and persists a new ExploitAttempt row every time, so the
    same confirmed vulnerability would otherwise show up once per re-run in
    any "top findings" list -- this only affects *display* lists, the raw
    counts (severity_counts/module_counts/totals) still reflect every run."""
    seen = set()
    out = []
    for f in findings:
        evidence = f.get("evidence") or {}
        target = evidence.get("target_url") or evidence.get("matched_at") or evidence.get("url") or ""
        key = (f.get("module"), f.get("technique"), target)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _rank_finding(f: Dict[str, Any]) -> tuple:
    sev = f.get("severity", "info")
    confirmed = 0 if f.get("status") == "confirmed" else 1
    return (confirmed, _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 99)


def classify_program(urls: List[str], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summary + priority buckets for a program.

    `urls`: distinct URL-ish strings (recon url assets + finding target URLs).
    `findings`: dicts with at least module/severity/status/technique/evidence.
    """
    urls = list(dict.fromkeys(u for u in urls if u))
    buckets: Dict[str, List[str]] = {name: [] for name in _BUCKETS}
    for url in urls:
        for name, pat in _BUCKETS.items():
            if pat.search(url):
                buckets[name].append(url)

    sev_counts = Counter(f.get("severity", "info") for f in findings)
    module_counts = Counter(f.get("module", "?") for f in findings)
    status_counts = Counter(f.get("status", "?") for f in findings)

    top = sorted(_dedup_findings(findings), key=_rank_finding)[:20]

    return {
        "totals": {
            "findings": len(findings),
            "confirmed": status_counts.get("confirmed", 0),
            "inconclusive": status_counts.get("inconclusive", 0),
            "urls_analyzed": len(urls),
        },
        "severity_counts": {s: sev_counts.get(s, 0) for s in _SEV_ORDER},
        "module_counts": dict(module_counts.most_common()),
        "priority_buckets": {name: {"count": len(v), "sample": v[:15]} for name, v in buckets.items() if v},
        "top_findings": [
            {
                "module": f.get("module"), "technique": f.get("technique"),
                "severity": f.get("severity"), "status": f.get("status"),
                "target_url": (f.get("evidence") or {}).get("target_url") or (f.get("evidence") or {}).get("url") or (f.get("evidence") or {}).get("matched_at"),
            }
            for f in top
        ],
    }


# ── HTML report ────────────────────────────────────────────────

_SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#6b7280"}

_FENCE_RE = re.compile(r"```(?:\w+)?\n(.*?)\n```", re.DOTALL)


def _steps_to_html(steps: str) -> str:
    """`_build_steps()` (app.services.bounty_report_templates) produces plain
    text with a small, fixed set of markdown-ish conventions -- numbered
    lines, ```-fenced code blocks, and `> ` blockquote notes. This renders
    exactly that subset, not general markdown."""
    e = html.escape
    # Pull out fenced blocks first (they may contain blank lines/indentation
    # that would otherwise confuse the line-by-line pass below).
    blocks: List[str] = []

    def _stash(m: "re.Match[str]") -> str:
        blocks.append(f'<pre class="poc-code"><code>{e(m.group(1))}</code></pre>')
        return f"\x00{len(blocks) - 1}\x00"

    text = _FENCE_RE.sub(_stash, steps)
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("\x00") and stripped.endswith("\x00"):
            out.append(blocks[int(stripped.strip("\x00"))])
        elif stripped.startswith(">"):
            out.append(f'<blockquote class="poc-note">{e(stripped.lstrip("> ").strip())}</blockquote>')
        else:
            out.append(f'<p class="poc-line">{e(stripped)}</p>')
    return "".join(out)


def render_html(program: Dict[str, Any], findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    """Standalone, self-contained HTML report for a program."""
    e = html.escape
    name = e(str(program.get("name", "Program")))
    sev = summary["severity_counts"]
    totals = summary["totals"]

    sev_bars = "".join(
        f'<div class="bar"><span class="lbl">{s.title()}</span>'
        f'<span class="track"><span class="fill" style="width:{(sev[s]/max(1,max(sev.values()) if any(sev.values()) else 1))*100:.0f}%;background:{_SEV_COLOR[s]}"></span></span>'
        f'<span class="n">{sev[s]}</span></div>'
        for s in _SEV_ORDER
    )

    def _rows(items):
        out = []
        for f in items:
            c = _SEV_COLOR.get(f.get("severity", "info"), "#6b7280")
            out.append(
                f'<tr><td><span class="pill" style="background:{c}22;color:{c};border-color:{c}55">{e(str(f.get("severity")))}</span></td>'
                f'<td>{e(str(f.get("module")))}</td><td>{e(str(f.get("technique")))}</td>'
                f'<td class="st st-{e(str(f.get("status")))}">{e(str(f.get("status")))}</td>'
                f'<td class="url">{e(str(f.get("target_url") or ""))}</td></tr>'
            )
        return "".join(out)

    bucket_rows = "".join(
        f'<tr><td>{e(name.replace("_", " ").title())}</td><td>{data["count"]}</td>'
        f'<td class="url">{e(", ".join(data["sample"][:5]))}</td></tr>'
        for name, data in summary.get("priority_buckets", {}).items()
    ) or '<tr><td colspan="3" class="muted">No priority-bucket matches.</td></tr>'

    # Same dedup + ranking as classify_program's top_findings, but kept on the
    # full finding dicts (with intact evidence) rather than the trimmed
    # summary version, since build_report() needs the real evidence to write
    # real steps-to-reproduce.
    poc_findings = sorted(_dedup_findings(findings), key=_rank_finding)[:20]
    program_name = str(program.get("name", "Program"))

    def _poc_sections(items: List[Dict[str, Any]]) -> str:
        out = []
        for f in items:
            evidence = f.get("evidence") or {}
            target_value = evidence.get("target_url") or evidence.get("matched_at") or ""
            draft = build_report(f, target_value, program_name)
            c = _SEV_COLOR.get(f.get("severity", "info"), "#6b7280")
            out.append(f"""<details class="poc">
  <summary>
    <span class="pill" style="background:{c}22;color:{c};border-color:{c}55">{e(str(f.get("severity")))}</span>
    <span class="poc-title">{e(draft["title"])}</span>
    <span class="st st-{e(str(f.get("status")))}">{e(str(f.get("status")))}</span>
  </summary>
  <div class="poc-body">
    <h4>Steps to Reproduce</h4>
    {_steps_to_html(draft["steps_to_reproduce"])}
    <h4>Impact</h4>
    <p class="poc-line">{e(draft["impact"])}</p>
    <h4>Remediation</h4>
    <p class="poc-line">{e(draft["remediation"])}</p>
  </div>
</details>""")
        return "".join(out) or '<p class="muted">No findings yet.</p>'

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Report — {name}</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:960px;margin:0 auto;padding:32px 20px;line-height:1.5;color:#1e293b;background:#fff}}
@media(prefers-color-scheme:dark){{body{{color:#e2e8f0;background:#0a0f1a}}table,th,td{{border-color:#1e293b!important}}.card{{background:#0f172a!important;border-color:#1e293b!important}}}}
h1{{font-size:1.6rem;margin:0 0 4px}} h2{{font-size:1.1rem;margin:28px 0 10px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}}
.muted{{color:#64748b}} .sub{{color:#64748b;margin:0 0 20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{flex:1;min-width:120px;border:1px solid #e2e8f0;border-radius:12px;padding:14px 16px}}
.card .v{{font-size:1.8rem;font-weight:700}} .card .k{{color:#64748b;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}}
.bar{{display:flex;align-items:center;gap:10px;margin:6px 0}} .bar .lbl{{width:80px;font-size:.85rem}} .bar .n{{width:32px;text-align:right;font-variant-numeric:tabular-nums}}
.track{{flex:1;height:10px;background:#e2e8f022;border-radius:6px;overflow:hidden}} .fill{{display:block;height:100%}}
table{{width:100%;border-collapse:collapse;font-size:.86rem}} th,td{{border:1px solid #e2e8f0;padding:7px 9px;text-align:left;vertical-align:top}}
th{{background:#f8fafc22;font-size:.75rem;text-transform:uppercase;letter-spacing:.03em;color:#64748b}}
.url{{font-family:ui-monospace,Menlo,monospace;font-size:.78rem;word-break:break-all;max-width:360px}}
.pill{{border:1px solid;border-radius:5px;padding:1px 6px;font-size:.72rem;font-weight:600}}
.st-confirmed{{color:#dc2626;font-weight:600}} .st-inconclusive{{color:#d97706}}
details.poc{{border:1px solid #e2e8f0;border-radius:10px;margin:10px 0;overflow:hidden}}
details.poc summary{{cursor:pointer;padding:10px 14px;display:flex;align-items:center;gap:10px;list-style:none;font-size:.88rem}}
details.poc summary::-webkit-details-marker{{display:none}}
details.poc summary::before{{content:"▸";color:#64748b;font-size:.75rem;transition:transform .15s}}
details.poc[open] summary::before{{transform:rotate(90deg)}}
.poc-title{{flex:1;font-weight:600}}
.poc-body{{padding:4px 16px 16px}}
.poc-body h4{{font-size:.78rem;text-transform:uppercase;letter-spacing:.03em;color:#64748b;margin:14px 0 6px}}
.poc-line{{margin:4px 0;font-size:.86rem}}
.poc-code{{background:#0f172a11;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;overflow-x:auto;font-family:ui-monospace,Menlo,monospace;font-size:.78rem;white-space:pre-wrap;word-break:break-word;margin:6px 0}}
@media(prefers-color-scheme:dark){{.poc-code{{background:#00000033}} details.poc{{border-color:#1e293b}}}}
.poc-note{{border-left:3px solid #94a3b8;margin:8px 0;padding:4px 10px;font-size:.82rem;color:#64748b}}
</style></head><body>
<h1>Bug Bounty Report</h1>
<p class="sub">{name} · {e(str(program.get("platform","")))} · generated by ASM Bounty pipeline</p>
<div class="cards">
  <div class="card"><div class="v">{totals["findings"]}</div><div class="k">Findings</div></div>
  <div class="card"><div class="v">{totals["confirmed"]}</div><div class="k">Confirmed</div></div>
  <div class="card"><div class="v">{totals["inconclusive"]}</div><div class="k">Candidates</div></div>
  <div class="card"><div class="v">{totals["urls_analyzed"]}</div><div class="k">URLs analyzed</div></div>
</div>
<h2>Severity distribution</h2>
{sev_bars}
<h2>Findings ({len(findings)})</h2>
<table><thead><tr><th>Severity</th><th>Module</th><th>Technique</th><th>Status</th><th>Target</th></tr></thead>
<tbody>{_rows(summary["top_findings"]) or '<tr><td colspan="5" class="muted">No findings yet.</td></tr>'}</tbody></table>
<h2>Proof of Concept</h2>
<p class="muted" style="margin:-4px 0 12px;font-size:.82rem">Click a finding to expand step-by-step reproduction instructions generated from what the pipeline actually observed.</p>
{_poc_sections(poc_findings)}
<h2>Priority targets to review</h2>
<table><thead><tr><th>Category</th><th>Count</th><th>Sample</th></tr></thead><tbody>{bucket_rows}</tbody></table>
<p class="muted" style="margin-top:28px;font-size:.8rem">Candidate (inconclusive) findings need manual confirmation — the pipeline surfaces them but does not assert impact it can't verify.</p>
</body></html>"""

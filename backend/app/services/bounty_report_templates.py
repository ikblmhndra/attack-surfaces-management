"""
ASM Platform — Bug Bounty pipeline: report templating (module 13).

Turns a confirmed ExploitAttempt into a submission-ready draft (title, summary,
steps-to-reproduce, impact, remediation) in Markdown. Pure functions, no I/O.
Lives in `app.services` (not `workers/`) because both the worker-side report
drafts (workers/bounty/report_worker.py) AND the backend-side shareable HTML
report (app/services/bounty_report.py) need it, and workers already import
backend directly (backend/app is mounted read-only into worker containers) --
the reverse import direction doesn't exist in this codebase, so shared logic
lives here. Impact/remediation text is deliberately generic per vulnerability
class: a starting point for the researcher, not a claim the platform verified
the real-world impact itself.
"""
from typing import Any, Dict

# Per-module framing, used when a finding's technique doesn't have its own
# more specific entry below. Kept intentionally conservative -- these
# describe the vulnerability class, not an assertion about this specific
# target's blast radius, which only the researcher can judge.
MODULE_META: Dict[str, Dict[str, str]] = {
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "impact": (
            "An attacker can execute arbitrary JavaScript in the victim's browser in the "
            "context of this origin -- enabling session/token theft, account actions on the "
            "victim's behalf, or phishing overlays. Confirm the exact impact against the "
            "affected user role before reporting."
        ),
        "remediation": (
            "Context-aware output encoding of user-controlled data, a strict Content-Security-"
            "Policy, and framework auto-escaping. Validate/normalise input server-side; never "
            "reflect raw request data into HTML/JS/attribute contexts."
        ),
    },
    "sqli": {
        "label": "SQL Injection",
        "impact": (
            "The parameter is injectable, allowing an attacker to alter the intended SQL query "
            "-- potentially reading or modifying data outside their authorisation. Scope the "
            "real impact carefully and avoid dumping data beyond what proves the issue."
        ),
        "remediation": (
            "Use parameterised queries / prepared statements everywhere; never concatenate "
            "user input into SQL. Apply least-privilege DB accounts and input validation as "
            "defence in depth."
        ),
    },
    "ssrf": {
        "label": "Server-Side Request Forgery (SSRF)",
        "impact": (
            "The server can be induced to make requests to attacker-chosen destinations -- "
            "potentially reaching internal services or cloud metadata endpoints. This finding "
            "is a candidate pending out-of-band confirmation."
        ),
        "remediation": (
            "Allowlist outbound destinations, resolve and validate URLs server-side, block "
            "requests to internal/link-local ranges, and disable unused URL schemes."
        ),
    },
    "lfi": {
        "label": "Local File Inclusion / Path Traversal",
        "impact": (
            "An attacker can read files outside the intended directory (confirmed against a "
            "known file signature). Depending on what is readable this can disclose source "
            "code, credentials, or configuration."
        ),
        "remediation": (
            "Never pass user input to filesystem APIs directly. Canonicalise and confine paths "
            "to an allowlisted base directory; reject traversal sequences and absolute paths."
        ),
    },
    "idor": {
        "label": "Insecure Direct Object Reference / Broken Access Control",
        "impact": (
            "An object-reference parameter was identified as a candidate for broken access "
            "control. Confirm manually with two authorised identities that one user can reach "
            "another's object -- the pipeline does not extract other users' data."
        ),
        "remediation": (
            "Enforce per-object authorisation server-side on every request; do not rely on "
            "unguessable IDs. Bind object access to the authenticated principal."
        ),
    },
    "csrf": {
        "label": "Cross-Site Request Forgery (CSRF)",
        "impact": (
            "A state-changing form without an anti-CSRF token was found. If the endpoint "
            "performs a real state change, an attacker can trick an authenticated victim into "
            "submitting it cross-site. Verify the endpoint actually changes state."
        ),
        "remediation": (
            "Add per-request anti-CSRF tokens to state-changing endpoints and/or require "
            "SameSite=Lax/Strict cookies. Re-authenticate for sensitive actions."
        ),
    },
    "ssti": {
        "label": "Server-Side Template Injection (SSTI)",
        "impact": (
            "User input is evaluated as a template expression server-side (confirmed: the "
            "evaluated result appeared, not the raw payload) -- depending on the template "
            "engine this can escalate to full remote code execution."
        ),
        "remediation": (
            "Never pass user-controlled data into a template-rendering call as template source. "
            "Treat all rendering input as data, use a logic-less/sandboxed template engine, and "
            "keep template engines patched."
        ),
    },
    "nosql": {
        "label": "NoSQL Injection",
        "impact": (
            "Mongo-style query operators in a parameter altered the query's behaviour -- "
            "potentially bypassing authentication/authorisation logic or exposing data outside "
            "the intended filter. Confirm manually; this is a candidate, not a proven bypass."
        ),
        "remediation": (
            "Enforce strict input types server-side (reject objects/operators where a scalar is "
            "expected), use an ODM's parameterised query builder, never pass raw client JSON "
            "into a query filter."
        ),
    },
    "jsonbody": {
        "label": "Unsafe JSON Body Handling",
        "impact": (
            "A crafted JSON body was accepted/echoed in a way that suggests the endpoint doesn't "
            "validate its shape server-side. Impact depends on the specific technique (see below)."
        ),
        "remediation": (
            "Validate request bodies against an explicit schema/allowlist; reject unknown or "
            "privileged fields server-side rather than trusting client-supplied shape."
        ),
    },
    "oauth": {
        "label": "OAuth / JWT Weakness",
        "impact": (
            "A weakness in token handling or the OAuth authorization flow was identified -- "
            "review the specific technique below for the exact issue and its real impact."
        ),
        "remediation": (
            "Follow OAuth2/OIDC best practice: always validate JWT signatures with an explicit "
            "algorithm allowlist, require `state` and PKCE on authorization requests, never accept "
            "tokens passed in URLs where they can leak via referrer/logs."
        ),
    },
    "bac": {
        "label": "Broken Access Control",
        "impact": (
            "An endpoint's authorisation enforcement appears inconsistent -- review the specific "
            "technique below for exactly what was observed."
        ),
        "remediation": (
            "Apply authorisation checks centrally (middleware/guard), consistently across every "
            "HTTP method and route variant, deny-by-default."
        ),
    },
    "nuclei": {
        "label": "Vulnerability / Misconfiguration (nuclei)",
        "impact": (
            "A nuclei template matched against this target. Review the template class and "
            "confirm real-world impact before reporting."
        ),
        "remediation": (
            "Follow the referenced template/advisory guidance; patch or reconfigure the "
            "affected component."
        ),
    },
}

# Technique-level overrides -- several modules bundle multiple, meaningfully
# different vulnerability classes under one module name (e.g. "jsonbody"
# covers prototype-pollution, mass-assignment, and nosql-body; "bac" covers
# both a missing-auth finding and an HTTP-method-bypass finding). Checked
# before MODULE_META so these get their own accurate label/impact/remediation
# instead of a generic module-level description. Exact technique match first,
# then a prefix table for techniques with a variable suffix.
TECHNIQUE_META: Dict[str, Dict[str, str]] = {
    "sqli-auth-bypass": {
        "label": "SQL Injection — Authentication Bypass",
        "impact": (
            "A crafted credential value bypasses the login query's intended logic entirely, "
            "authenticating as an arbitrary account (confirmed: a garbage-credential baseline "
            "failed, the injected payload succeeded) without knowing any valid password."
        ),
        "remediation": (
            "Use parameterised queries for the login query specifically -- this is the highest-"
            "value place in the whole app to get this right. Add rate-limiting/anomaly detection "
            "on login attempts and MFA as defence in depth."
        ),
    },
    "prototype-pollution": {
        "label": "Prototype Pollution",
        "impact": (
            "A `__proto__`/`constructor.prototype` JSON body was accepted/echoed without "
            "sanitisation. In Node.js apps this can corrupt shared object behaviour app-wide, "
            "sometimes escalating to authentication bypass, denial of service, or (via a gadget "
            "chain elsewhere in the app) remote code execution."
        ),
        "remediation": (
            "Freeze `Object.prototype`, use `Object.create(null)`/`Map` for user-controlled key-"
            "value data, and keep JSON-merging libraries (lodash and similar) patched against "
            "known prototype-pollution CVEs."
        ),
    },
    "mass-assignment": {
        "label": "Mass Assignment",
        "impact": (
            "Privileged fields (role/is_admin/etc.) in a client-supplied JSON body were accepted/"
            "echoed rather than rejected -- if the endpoint persists them, an attacker may be able "
            "to grant themselves elevated privileges on their own account."
        ),
        "remediation": (
            "Explicitly allowlist which fields a given endpoint/role may set server-side; never "
            "bind an entire request body directly onto a database model."
        ),
    },
    "nosql-body": {
        "label": "NoSQL Injection (JSON body)",
        "impact": (
            "Mongo-style query operators in a JSON body triggered an error/anomaly, suggesting "
            "the value flows into a query without type validation. Confirm manually -- this is a "
            "candidate, not a proven bypass."
        ),
        "remediation": (
            "Enforce strict input types server-side (reject objects/operators where a scalar is "
            "expected) before the value ever reaches a query builder."
        ),
    },
    "idor-cross-identity-confirmed": {
        "label": "Broken Object-Level Authorization (confirmed, two-identity)",
        "impact": (
            "Directly confirmed, not a candidate: a second, brand-new test identity with zero "
            "legitimate relationship to this resource received the same successful response as "
            "the primary identity -- the endpoint does not check resource ownership at all."
        ),
        "remediation": (
            "Enforce per-object authorisation server-side on every request: verify the "
            "authenticated principal actually owns (or is granted access to) the specific object "
            "id in the request, not just that they're logged in."
        ),
    },
    "bac-unauth-privileged": {
        "label": "Broken Access Control — Unauthenticated Access",
        "impact": (
            "A privileged-looking endpoint returned a full response with no Authorization header "
            "or session at all, where an authentication challenge was expected."
        ),
        "remediation": (
            "Require and enforce authentication middleware on all non-public routes; deny by "
            "default rather than allow by default."
        ),
    },
}
TECHNIQUE_PREFIX_META: Dict[str, Dict[str, str]] = {
    "method-switch": {
        "label": "Access Control Bypass via HTTP Method",
        "impact": (
            "Switching the HTTP method on the same URL (GET -> POST/PUT/DELETE/PATCH) produced a "
            "different, successful status where the baseline method didn't -- authorisation logic "
            "may only be applied to the expected method, not the route itself."
        ),
        "remediation": (
            "Apply the same authorisation checks regardless of HTTP method; explicitly allowlist "
            "which methods a route accepts rather than leaving unexpected ones enabled by default."
        ),
    },
}

SEVERITY_LABELS = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational",
}


def _resolve_meta(module: str, technique: str) -> Dict[str, str]:
    if technique in TECHNIQUE_META:
        return TECHNIQUE_META[technique]
    for prefix, meta in TECHNIQUE_PREFIX_META.items():
        if technique.startswith(prefix):
            return meta
    return MODULE_META.get(module, MODULE_META["nuclei"])


def _fenced(text: str, lang: str = "") -> str:
    text = str(text or "").strip()
    if not text:
        return ""
    return f"```{lang}\n{text}\n```"


def build_report(attempt: Dict[str, Any], target_value: str, program_name: str) -> Dict[str, str]:
    """Build a Markdown BountyReport draft from one ExploitAttempt dict.

    `attempt` keys used: module, technique, severity, status, evidence.
    Returns {title, summary, steps_to_reproduce, impact, remediation}.
    """
    module = str(attempt.get("module") or "nuclei")
    technique = str(attempt.get("technique") or module)
    meta = _resolve_meta(module, technique)
    severity = str(attempt.get("severity") or "info")
    evidence = attempt.get("evidence") or {}

    # Prefer the exact URL the module tested over the owning target's host, so
    # a finding on /file isn't reported as being on the host's /search target.
    display_target = evidence.get("target_url") or evidence.get("matched_at") or target_value

    title = f"{meta['label']} on {display_target}"
    param = evidence.get("param") or evidence.get("candidate_param")
    if param:
        title = f"{meta['label']} via `{param}` on {display_target}"

    summary = (
        f"**Program:** {program_name}  \n"
        f"**Target:** {display_target}  \n"
        f"**Severity:** {SEVERITY_LABELS.get(severity, severity)}  \n"
        f"**Class:** {meta['label']}  \n"
        f"**Detection:** {technique} ({attempt.get('status', 'confirmed')})"
    )

    steps = _build_steps(technique, evidence, target_value)
    return {
        "title": title[:500],
        "summary": summary,
        "steps_to_reproduce": steps,
        "impact": meta["impact"],
        "remediation": meta["remediation"],
    }


# Evidence keys already surfaced by name in one of the specific branches
# below -- excluded from the generic "additional evidence" dump at the end
# so nothing gets shown twice.
_HANDLED_EVIDENCE_KEYS = {
    "target_url", "poc_url", "payload", "param", "candidate_param", "matched_at", "form_action",
    "excerpt", "summary", "note", "poc_hint", "field", "baseline_status", "status_identity_a",
    "status_identity_b", "status", "method", "get_status", "resource", "id_value",
    "other_candidate_params", "expected",
}


def _build_steps(technique: str, evidence: Dict[str, Any], target_value: str) -> str:
    lines = []
    target_url = evidence.get("target_url") or target_value

    if technique == "sqli-auth-bypass":
        field = evidence.get("field", "email")
        payload = evidence.get("payload", "")
        lines.append("1. Send a baseline login request with garbage credentials to confirm it fails:")
        lines.append(_fenced(
            f'POST {target_url}\nContent-Type: application/json\n\n'
            f'{{"{field}": "nonexistent@example.com", "password": "wrong"}}'
        ))
        lines.append(f"   -> Expect a rejection (observed status: {evidence.get('baseline_status')}).")
        lines.append(f"2. Repeat the request with the SQL injection payload in the `{field}` field:")
        lines.append(_fenced(f'POST {target_url}\nContent-Type: application/json\n\n{{"{field}": "{payload}", "password": "x"}}'))
        lines.append("3. Observe a 200 response containing an authentication token/session -- "
                      "the injected value bypassed the login check entirely.")

    elif technique == "idor-cross-identity-confirmed":
        lines.append("1. Authenticate as the primary test identity and request:")
        lines.append(_fenced(f"GET {target_url}\nAuthorization: Bearer <identity-A-token>"))
        lines.append(f"   -> Observed status: {evidence.get('status_identity_a')}.")
        lines.append("2. Register and authenticate as a second, brand-new identity with no "
                      "relationship to this resource, then repeat the exact same request with its token:")
        lines.append(_fenced(f"GET {target_url}\nAuthorization: Bearer <identity-B-token>"))
        lines.append(f"   -> Observed status: {evidence.get('status_identity_b')} -- the same "
                      "successful response, despite identity B owning nothing.")
        lines.append("3. This confirms the endpoint does not check that the requesting identity "
                      "actually owns the resource.")

    elif technique == "bac-unauth-privileged":
        lines.append("1. Without any Authorization header or session cookie, request:")
        lines.append(_fenced(f"GET {target_url}"))
        lines.append(f"2. Observe a {evidence.get('status', 200)} response with real content, where "
                      "an authentication challenge (401/403/redirect) was expected.")

    elif technique.startswith("method-switch"):
        method = evidence.get("method", "POST")
        lines.append("1. Send a baseline GET to confirm the endpoint's normal behaviour:")
        lines.append(_fenced(f"GET {target_url}"))
        lines.append(f"   -> Observed status: {evidence.get('get_status')}.")
        lines.append(f"2. Repeat the request using {method} instead:")
        lines.append(_fenced(f"{method} {target_url}"))
        lines.append(f"   -> Observed status: {evidence.get('status')} -- an unexpected method was "
                      "accepted where the same authorisation logic may not have been applied.")

    elif evidence.get("poc_url"):
        lines.append("1. Send the following proof-of-concept request:")
        lines.append(_fenced(evidence["poc_url"]))
        if evidence.get("payload") and evidence.get("param"):
            lines.append(f"   (payload injected into the `{evidence['param']}` parameter: `{evidence['payload']}`)")

    elif evidence.get("payload") and (evidence.get("param") or evidence.get("candidate_param")):
        param = evidence.get("param") or evidence.get("candidate_param")
        location = f" against `{target_url}`" if target_url else ""
        lines.append(f"1. Inject the following payload into the `{param}` parameter{location}:")
        lines.append(_fenced(evidence["payload"]))
        if evidence.get("expected"):
            lines.append(f"2. Observe the evaluated result `{evidence['expected']}` in the response "
                          "(not the raw payload text) -- proof the value was executed, not just reflected.")

    elif evidence.get("resource") and evidence.get("id_value"):
        lines.append(f"1. Request `{target_url}` (a `{evidence['resource']}` resource referenced by "
                      f"numeric/UUID id `{evidence['id_value']}`).")
        lines.append("2. Attempt the same request while authenticated as a different account than the "
                      "one that owns this resource, and compare results.")

    elif evidence.get("candidate_param"):
        others = evidence.get("other_candidate_params") or []
        extra = f" (also seen: {', '.join(others)})" if others else ""
        lines.append(f"1. Note the object-reference-looking parameter `{evidence['candidate_param']}`"
                      f"{extra} on `{target_url}`.")
        lines.append("2. Attempt the same request while authenticated as a different account, varying "
                      "only that parameter's value, and compare results.")

    elif evidence.get("matched_at") or evidence.get("form_action"):
        matched = evidence.get("matched_at") or evidence.get("form_action")
        lines.append("1. Target the following location:")
        lines.append(_fenced(str(matched)))

    else:
        lines.append(f"1. Interact with `{target_url}`.")

    excerpt = evidence.get("excerpt") or evidence.get("summary")
    if excerpt:
        lines.append("\nResponse excerpt confirming the issue:")
        lines.append(_fenced(str(excerpt)[:1500]))

    # Nothing else hand-written above -- surface any other evidence fields
    # the pipeline actually recorded, so a finding never ends up with steps
    # this thin just because its technique doesn't have a bespoke branch yet.
    extra_fields = {
        k: v for k, v in evidence.items()
        if k not in _HANDLED_EVIDENCE_KEYS and v not in (None, "", [])
    }
    if extra_fields:
        lines.append("\nAdditional evidence recorded:")
        lines.append(_fenced("\n".join(f"{k}: {v}" for k, v in extra_fields.items())))

    note = evidence.get("note") or evidence.get("poc_hint")
    if note:
        lines.append(f"\n> {note}")

    return "\n".join(lines)


def render_markdown(report: Dict[str, Any]) -> str:
    """Render a stored BountyReport dict into a single Markdown document."""
    parts = [
        f"# {report.get('title', 'Untitled finding')}",
        "",
        "## Summary",
        str(report.get("summary") or ""),
        "",
        "## Steps to Reproduce",
        str(report.get("steps_to_reproduce") or ""),
        "",
        "## Impact",
        str(report.get("impact") or ""),
        "",
        "## Remediation",
        str(report.get("remediation") or ""),
    ]
    return "\n".join(parts).strip() + "\n"

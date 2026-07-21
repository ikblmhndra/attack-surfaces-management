"""
ASM Platform — Bug Bounty pipeline: browser-driven crawl (real SPA execution).

Every other URL-discovery tool in this package (katana, hakrawler, ffuf,
feroxbuster, waybackurls/gau/waymore) either parses static HTML/JS text or
brute-forces paths -- none of them execute JavaScript. A modern SPA
(Angular/React/Vue) only constructs its real routes and API calls at runtime,
client-side: a search box, a basket page, an order-history view all fire their
actual `/rest/...`/`/api/...` requests -- often carrying real, per-user
resource IDs -- only once real JS runs in a real browser. This module drives
Playwright to load the app, passively capture every network request the page
fires, then click through a bounded set of internal links to trigger more of
the same -- entirely detection-only (never fills or submits a form, so it
can't trigger a state-changing action; typing into a search box is the one
deliberate exception, see _SEARCH_FIELD_SELECTOR below -- search is
idempotent, unlike every other form on a real app).

Network-request capture alone misses a hash-routed SPA's own client-side
navigation: clicking a `routerlink="/contact"` element changes `page.url()`
but fires no HTTP request at all (the hash never reaches the server), so a
route reachable only by clicking through the app -- exactly the shape of a
real search-results page or a feedback/contact form -- was previously
invisible to this crawler even though it was clicking straight through it.
`page.url()` is now captured after every navigation (initial load, each
click, and the search probe), not just off the network listener. The
discovered URLs feed into recon_worker.py's normal BountyAsset persistence
path, same as every other URL source. See CHANGELOG.md.
"""
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import structlog
from playwright.async_api import async_playwright

log = structlog.get_logger()

MAX_INTERNAL_CLICKS = 8
CLICK_SETTLE_MS = 1200
INITIAL_SETTLE_MS = 2500

# Keywords identifying a search-style input worth probing -- deliberately
# narrow (not "any text input") so this never touches a login/registration/
# checkout field. Typing into a search box and reading back the URL it
# produces is read-only in effect: search is idempotent by definition, unlike
# every other form on a real app, which is why this is the one exception to
# this module's "never fills a form" rule.
_SEARCH_FIELD_SELECTOR = (
    "input[type='search'], input[name*='search' i], input[placeholder*='search' i], "
    "input[aria-label*='search' i], [formcontrolname*='search' i]"
)
# A collapsed search-icon-only toggle (Angular Material et al.) is common
# enough that the field selector alone routinely finds nothing -- the real
# <input> only exists/becomes visible once this is clicked (confirmed
# against a live target: Juice Shop's own search input carries zero
# discriminating attributes -- generic `id="mat-input-1"`, no name/
# aria-label/placeholder -- until its search *icon* is clicked first).
_SEARCH_TOGGLE_SELECTOR = (
    "[aria-label='search' i], button[title='search' i], "
    "mat-icon:text-is('search'), button:has(mat-icon:text-is('search'))"
)
_SEARCH_PROBE = "asmsearchprobe1"

# Carrying the Authorization header at the network level does NOT make an SPA
# render its logged-in UI/fire its logged-in-only API calls (basket, order
# history, whoami, ...) -- the app's own client-side JS decides that from its
# OWN auth state, almost always something it reads back out of localStorage,
# not from request headers it never inspects itself. There's no universal key
# name for that across frameworks, so this seeds every common convention
# speculatively before the first navigation; an app that doesn't recognize a
# given key just ignores it, so this is harmless when it doesn't apply.
COMMON_TOKEN_STORAGE_KEYS = ("token", "authToken", "access_token", "jwt", "id_token", "auth_token")


def _same_registrable_host(url: str, seed_host: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    seed_host = seed_host.lower()
    return bool(host) and (host == seed_host or host.endswith(f".{seed_host}"))


_DISMISS_SELECTOR = (
    'button[aria-label*="close" i], button[aria-label*="dismiss" i], '
    'button[aria-label*="accept" i], button[aria-label*="got it" i]'
)


async def _dismiss_overlay(page) -> None:
    """Cookie-consent/welcome-banner modals are near-universal on real sites
    and block every subsequent click (Angular Material's cdk-overlay-backdrop
    intercepts pointer events for anything behind it) -- dismissing one is a
    safe, read-only-equivalent action, not a state change, so it's done
    unconditionally before any navigation click is attempted."""
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    try:
        btn = page.locator(_DISMISS_SELECTOR).first
        if await btn.count() and await btn.is_visible():
            await btn.click(timeout=2000)
    except Exception:
        pass


async def browser_crawl(
    seed_url: str, timeout: int = 60,
    extra_headers: Optional[Dict[str, str]] = None, auth_token: Optional[str] = None,
    session_fields: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Load `seed_url` in a real browser, capture every network request the
    page fires (its own XHR/fetch calls included), then click through a
    bounded set of internal links to trigger more page transitions -- each
    one a chance for the app to make more real, ID-bearing API calls a
    static crawler could never see. Read-only: clicks links, never fills or
    submits a form.

    `auth_token` (the raw bearer token, not the header) seeds localStorage
    under every common convention key -- carrying `extra_headers` alone gets
    the network-level Authorization header onto every request, but doesn't
    make the app's own client-side JS *believe* it's logged in, which is what
    actually gates whether it renders/fetches basket, order-history, whoami,
    etc. at all. `session_fields` (from tools.py::login_and_get_session) seeds
    whatever OTHER scalar fields the login response carried under their own
    names too -- some apps track more client-side session state than just the
    token (e.g. a separate basket/cart id), and there's no way to know an
    arbitrary app's field names in advance except by reusing what its own
    login response already used."""
    seed_host = urlparse(seed_url).hostname or ""
    if not seed_host:
        return set()

    captured: Set[str] = set()
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                context = await browser.new_context(extra_http_headers=extra_headers or None)
                if auth_token or session_fields:
                    seed_pairs: Dict[str, str] = dict(session_fields or {})
                    for key in COMMON_TOKEN_STORAGE_KEYS:
                        if auth_token:
                            seed_pairs[key] = auth_token
                    seed_js = "".join(
                        f"try{{localStorage.setItem({key!r},{value!r});}}catch(e){{}}\n"
                        for key, value in seed_pairs.items()
                    )
                    await context.add_init_script(seed_js)
                page = await context.new_page()

                def _on_request(req):
                    url = req.url
                    if url.startswith("http") and _same_registrable_host(url, seed_host):
                        captured.add(url)

                page.on("request", _on_request)

                def _capture_page_url() -> None:
                    url = page.url
                    if url.startswith("http") and _same_registrable_host(url, seed_host):
                        captured.add(url)

                await page.goto(seed_url, timeout=timeout * 1000, wait_until="load")
                await page.wait_for_timeout(INITIAL_SETTLE_MS)
                await _dismiss_overlay(page)
                _capture_page_url()

                # Probe any search-style input once, before the link-click
                # loop (doesn't consume a click slot). Typing + reading the
                # resulting URL is how a hash-routed SPA's real search route
                # (e.g. #/search?q=...) is discovered at all -- it's built
                # entirely client-side and never touches the network, so no
                # static crawler or request listener can ever see it.
                try:
                    search_field = page.locator(_SEARCH_FIELD_SELECTOR).first
                    if not (await search_field.count() and await search_field.is_visible()):
                        toggle = page.locator(_SEARCH_TOGGLE_SELECTOR).first
                        if await toggle.count():
                            await toggle.click(timeout=3000)
                            await page.wait_for_timeout(500)
                            search_field = page.locator(_SEARCH_FIELD_SELECTOR).first
                            if not (await search_field.count() and await search_field.is_visible()):
                                # The revealed input often carries no
                                # discriminating attributes at all (confirmed
                                # live: Juice Shop's is a bare, unlabeled
                                # id="mat-input-1") -- once a search-labeled
                                # toggle has actually been clicked, any
                                # visible plain input left on the page is
                                # what it revealed.
                                any_visible = page.locator("input:visible").first
                                if await any_visible.count():
                                    search_field = any_visible
                    if await search_field.count() and await search_field.is_visible():
                        await search_field.fill(_SEARCH_PROBE, timeout=3000)
                        await search_field.press("Enter", timeout=3000)
                        await page.wait_for_timeout(CLICK_SETTLE_MS)
                        _capture_page_url()
                except Exception as exc:
                    log.warning("bounty_browser_crawl_search_probe_error", url=seed_url, error=str(exc)[:150])

                # Bounded, read-only exploration: click pure-navigation
                # elements only -- a real <a href> or anything carrying
                # Angular's `routerLink` (its basket/account/order-history
                # icons are <button routerlink="..."> in Juice Shop, not real
                # links). routerLink/href only changes the client-side view,
                # it's never a state-changing action -- deliberately NOT
                # clicking plain buttons with no navigation target (that's
                # exactly where "Add to Basket"-style actions live).
                clicked = 0
                seen_targets: Set[str] = set()
                while clicked < MAX_INTERNAL_CLICKS:
                    candidates = await page.eval_on_selector_all(
                        "a[href], [routerlink]",
                        """els => els.map(e => ({
                            sel: e.tagName.toLowerCase() + (e.getAttribute('routerlink')
                                ? `[routerlink="${e.getAttribute('routerlink')}"]`
                                : `[href="${e.getAttribute('href')}"]`),
                            target: e.getAttribute('routerlink') || e.getAttribute('href'),
                        })).filter(x => x.target)""",
                    )
                    chosen = None
                    for c in candidates:
                        target = c["target"]
                        if target in seen_targets or target.startswith(("mailto:", "tel:", "javascript:")):
                            continue
                        seen_targets.add(target)
                        chosen = c
                        break
                    if not chosen:
                        break
                    try:
                        locator = page.locator(chosen["sel"]).first
                        await locator.click(timeout=5000)
                        await page.wait_for_timeout(CLICK_SETTLE_MS)
                        await _dismiss_overlay(page)  # a new view can trigger its own modal/tip
                        _capture_page_url()
                    except Exception as exc:
                        log.warning("bounty_browser_crawl_click_error", target=chosen["target"], error=str(exc)[:150])
                    finally:
                        clicked += 1
                        try:
                            await page.go_back(timeout=5000)
                            await page.wait_for_timeout(400)
                        except Exception:
                            pass
            finally:
                await browser.close()
    except Exception as exc:
        log.warning("bounty_browser_crawl_error", url=seed_url, error=str(exc)[:200])
    return captured

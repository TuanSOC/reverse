"""Automated login → session-cookie capture for authenticated scans.

Given a login URL and credentials (for an authorized target), a headless browser
submits the login form and the resulting session cookies are captured and
returned as a target-scoped ``Cookie`` header string. The rest of the scan reuses
those cookies through the existing per-request, target-host-only injection.

The field-selection heuristic is a pure function so it can be unit-tested without
a browser; the password is never logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

# input hints that suggest the username/identifier field.
_USER_HINTS = ("user", "email", "login", "account", "phone", "mobile", "identifier", "uid")


@dataclass
class LoginFields:
    username_index: int | None
    password_index: int | None


def rank_login_fields(inputs: list[dict]) -> LoginFields:
    """Pick the username + password field indices from a list of input descriptors.

    Each descriptor: ``{"type","name","id","autocomplete","placeholder"}``. The
    password field is the first ``type=password``; the username field is the
    best-hinted text/email/tel input *before* it (falling back to the nearest
    one, then any text/email input).
    """
    def ftype(i: dict) -> str:
        return str(i.get("type") or "text").lower()

    pwd = next((idx for idx, i in enumerate(inputs) if ftype(i) == "password"), None)

    def hinted(i: dict) -> bool:
        blob = " ".join(str(i.get(k) or "") for k in
                        ("name", "id", "autocomplete", "placeholder")).lower()
        return any(h in blob for h in _USER_HINTS)

    def is_textlike(i: dict) -> bool:
        return ftype(i) in ("text", "email", "tel", "")

    candidates = range(pwd) if pwd is not None else range(len(inputs))
    textlike = [idx for idx in candidates if is_textlike(inputs[idx])]
    user = (
        next((idx for idx in textlike if hinted(inputs[idx])), None)  # best hint
        or (textlike[-1] if textlike else None)                        # nearest before pwd
    )
    if user is None:  # last resort: any textlike field anywhere
        user = next((idx for idx, i in enumerate(inputs) if is_textlike(i)), None)
    return LoginFields(user, pwd)


def login_succeeded(before_url: str, after_url: str, password_still_present: bool) -> bool:
    """Heuristic: logged in if the password field is gone or we left the login page."""
    if not password_still_present:
        return True
    if after_url and after_url.rstrip("/") != before_url.rstrip("/"):
        low = after_url.lower()
        return not any(w in low for w in ("login", "signin", "sign-in", "dang-nhap"))
    return False


def cookies_to_header(cookies: list[dict], host: str) -> str:
    """Serialize Playwright cookies whose domain matches ``host`` into 'k=v; …'."""
    host = (host or "").lower().lstrip(".")
    parts = []
    seen: set[str] = set()
    for c in cookies:
        dom = str(c.get("domain") or "").lower().lstrip(".")
        if not dom or not (host == dom or host.endswith("." + dom) or dom.endswith("." + host)):
            continue
        name = c.get("name")
        if name and name not in seen:
            seen.add(name)
            parts.append(f"{name}={c.get('value', '')}")
    return "; ".join(parts)


async def capture_session_cookies(cfg, target_host: str, log) -> str:
    """Log in via a headless browser and return a target-scoped Cookie header.

    Returns "" (and logs a warning) on any failure so the scan can continue
    unauthenticated rather than crash. The password is never logged.
    """
    from playwright.async_api import async_playwright

    auth = cfg.auth
    bcfg = cfg.browser
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    user_agent=cfg.http.user_agent,
                    ignore_https_errors=not cfg.http.verify_tls,
                )
                before = auth.login_url or ""
                try:
                    await page.goto(before, wait_until=bcfg.wait_until,
                                    timeout=bcfg.nav_timeout_ms)
                except Exception as nav:  # noqa: BLE001 - partial render still usable
                    log.info("login page nav wait timed out; proceeding", error=str(nav))
                await page.wait_for_timeout(bcfg.settle_ms)

                handles = await page.query_selector_all("input")
                descriptors = []
                for h in handles:
                    descriptors.append({
                        "type": await h.get_attribute("type"),
                        "name": await h.get_attribute("name"),
                        "id": await h.get_attribute("id"),
                        "autocomplete": await h.get_attribute("autocomplete"),
                        "placeholder": await h.get_attribute("placeholder"),
                    })
                fields = rank_login_fields(descriptors)

                # Fill username (explicit selector wins over the heuristic).
                if auth.username_selector:
                    await page.fill(auth.username_selector, auth.username or "")
                elif fields.username_index is not None:
                    await handles[fields.username_index].fill(auth.username or "")
                # Fill password.
                if auth.password_selector:
                    await page.fill(auth.password_selector, auth.password or "")
                elif fields.password_index is not None:
                    await handles[fields.password_index].fill(auth.password or "")
                else:
                    log.warning("auto-login: no password field found")
                    return ""

                await _submit(page, auth, handles, fields)
                await page.wait_for_timeout(bcfg.settle_ms)

                after = page.url
                pwd_present = bool(await page.query_selector("input[type=password]"))
                cookies = [dict(c) for c in await page.context.cookies()]
                ok = login_succeeded(before, after, pwd_present)
                header = cookies_to_header(cookies, target_host)
                if not ok or not header:
                    log.warning("auto-login likely failed", logged_in=ok,
                                cookies_captured=bool(header))
                    return header if ok else ""
                log.info("auto-login succeeded", cookies=header.count("=") )
                return header
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001 - never crash the scan on login problems
        log.warning("auto-login error", error=f"{type(exc).__name__}: {exc}")
        return ""


async def _submit(page, auth, handles, fields) -> None:
    """Click the submit control, or press Enter in the password field."""
    if auth.submit_selector:
        await page.click(auth.submit_selector)
        return
    for sel in ("button[type=submit]", "input[type=submit]",
                "button:has-text('Login')", "button:has-text('Sign in')",
                "button:has-text('Đăng nhập')"):
        el = await page.query_selector(sel)
        if el:
            await el.click()
            return
    if fields.password_index is not None:  # fallback: submit via Enter
        await handles[fields.password_index].press("Enter")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""

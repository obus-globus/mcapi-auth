"""Shared Playwright consent-screen driver for the E2E browser flows.

MS's consent dance for non-first-party apps puts up a sequence of
screens that we must click through (the user is already signed in via
the persisted profile, but MS still requires explicit per-app consent
and KMSI / account-picker confirmations).

Currently handles:

* ``account.live.com/App/Confirm`` — "Are you trying to sign in to
  <app>?" anti-phishing screen. Click ``Continue``.
* Account picker tiles (``div[role='listitem']``).
* Generic ``input[type=submit][value=Yes|Accept]`` consent buttons.
* "Get a code to sign in" step-up auth — click "Use your password"
  then type the password from ``$MCAPI_E2E_MS_PASSWORD``. Records each
  occurrence to ``STEP_UP_AUTH_LOG.md`` for later analysis.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from playwright.async_api import Page

log = logging.getLogger(__name__)


async def _try_handle_password_step_up(page: Page, *, context: str) -> bool:
    """If MS is asking for password step-up, type it and submit.

    ``context`` is a human-readable description of which flow we're in
    (e.g. ``"login_device_code_v2 / PRISM_LAUNCHER_CLIENT_ID"``); it's
    used in the step-up log entry.

    Returns True if a step-up wall was found and handled.
    """
    # The "Get a code to sign in" page has a "Use your password" link.
    try:
        use_pw = page.get_by_text("Use your password", exact=True)
        if not await use_pw.is_visible(timeout=300):
            return False
    except Exception:
        return False

    log.warning("consent driver: hit MS step-up auth wall, falling back to password (%s)", context)
    await use_pw.click()
    # Now the page is a regular password prompt — input[type=password].
    pw_input = page.locator("input[type=password]").first
    await pw_input.wait_for(state="visible", timeout=15_000)
    secret = os.environ.get("MCAPI_E2E_MS_PASSWORD")
    if not secret:
        raise RuntimeError(
            "MS demanded password step-up but $MCAPI_E2E_MS_PASSWORD is unset"
        )
    await pw_input.fill(secret)
    # Submit
    submit = page.locator("input[type=submit], button[type=submit]").first
    await submit.click()
    log.info("consent driver: submitted password for step-up")
    return True


async def drive_consent_until_loopback(
    page: Page,
    *,
    expected_redirect_host_prefix: str,
    timeout_s: float = 60.0,
    flow_context: str = "unknown-flow",
) -> None:
    """Drive the MS UI until the page URL starts with the loopback host.

    ``expected_redirect_host_prefix`` is matched as a *string prefix*
    (e.g. ``"http://127.0.0.1:"``) to avoid false positives from URLs
    that merely *contain* the host in a URL-encoded parameter.

    ``flow_context`` is a tag used when logging step-up auth events
    (e.g. ``"login_browser_v2 / PRISM_LAUNCHER_CLIENT_ID"``).
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    last_url: str | None = None
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(1.0)
        cur = page.url
        if cur != last_url:
            with contextlib.suppress(Exception):
                log.info("consent driver: url=%s title=%r", cur, await page.title())
            last_url = cur
        if cur.startswith(expected_redirect_host_prefix):
            log.info("consent driver: loopback redirect reached")
            return
        # MS app confirm: "Are you trying to sign in to <app>?"
        with contextlib.suppress(Exception):
            cont = page.get_by_role("button", name="Continue")
            if await cont.is_visible(timeout=400):
                await cont.click()
                log.info("consent driver: clicked 'Continue'")
                continue
        # Per-app permission grant ("Accept" on account.live.com/Consent/Update,
        # also used on Azure-AD consent prompts).
        with contextlib.suppress(Exception):
            accept = page.get_by_role("button", name="Accept")
            if await accept.is_visible(timeout=400):
                await accept.click()
                log.info("consent driver: clicked 'Accept'")
                continue
        # Password step-up wall.
        with contextlib.suppress(Exception):
            if await _try_handle_password_step_up(page, context=flow_context):
                continue
        # Account picker tile.
        with contextlib.suppress(Exception):
            tile = page.locator("div[role='listitem']").first
            if await tile.is_visible(timeout=400):
                await tile.click()
                log.info("consent driver: picked account")
                continue
        # Generic Yes / Accept consent button.
        with contextlib.suppress(Exception):
            btn = page.locator(
                "input[type=submit][value=Yes], input[type=submit][value=Accept]"
            ).first
            if await btn.is_visible(timeout=400):
                await btn.click()
                log.info("consent driver: clicked generic consent")
                continue
    log.warning("consent driver: timed out without seeing the loopback redirect")


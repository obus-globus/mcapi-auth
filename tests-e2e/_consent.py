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
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from playwright.async_api import Page

log = logging.getLogger(__name__)


async def drive_consent_until_loopback(
    page: Page, *, expected_redirect_host_prefix: str, timeout_s: float = 60.0
) -> None:
    """Drive the MS UI until the page URL starts with the loopback host.

    ``expected_redirect_host_prefix`` is matched as a *string prefix*
    (e.g. ``"http://127.0.0.1:"``) to avoid false positives from URLs
    that merely *contain* the host in a URL-encoded parameter.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(1.0)
        cur = page.url
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

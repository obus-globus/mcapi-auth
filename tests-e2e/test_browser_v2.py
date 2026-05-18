"""E2E: v2 PKCE + loopback browser flow.

Plan:

1. Call ``login_browser_v2`` with an ``open_browser`` callback that
   navigates a *Playwright* page (loaded with our persisted MS session)
   to the consent URL.
2. MS sees the existing session → either auto-completes, or shows a
   consent prompt we click through.
3. MS redirects to ``http://127.0.0.1:<port>/callback?code=...``.
4. The library's loopback listener picks that up, completes PKCE, and
   returns a fully populated ``MinecraftSession``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest
from playwright.async_api import BrowserContext, Page

from mcapi_auth import login_browser_v2

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def _drive_consent(page: Page) -> None:
    """Click through any consent / account-picker that MS may show."""
    with contextlib.suppress(Exception):
        await page.locator("div[role='listitem']").first.click(timeout=4000)
    with contextlib.suppress(Exception):
        button = page.locator(
            "input[type=submit][value=Yes], "
            "input[type=submit][value=Continue], "
            "input[type=submit][value=Accept], "
            "button[type=submit]:has-text('Yes'), "
            "button[type=submit]:has-text('Continue')"
        ).first
        await button.click(timeout=4000)


async def test_login_browser_v2(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()
    consent_done = asyncio.Event()

    nav_task: asyncio.Task[None] | None = None

    async def open_browser(url: str) -> None:
        log.info("Navigating Playwright page to %s", url)

        async def go() -> None:
            try:
                # The page will redirect to 127.0.0.1:<port>/callback — that
                # connection will fail from inside Playwright (the listener
                # closes the socket immediately) which is fine; the
                # library-side listener already received the code.
                await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                await _drive_consent(page)
            except Exception as e:
                log.info("Playwright nav ended (expected on 127.0.0.1 redirect): %s", e)
            finally:
                consent_done.set()

        nonlocal nav_task
        nav_task = asyncio.create_task(go())

    session = await login_browser_v2(open_browser=open_browser)

    assert session.access_token
    assert session.uuid
    assert session.username
    assert session.refresh_token
    # Wait for the Playwright side to finish cleanly so the fixture
    # teardown doesn't race with an in-flight nav.
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(consent_done.wait(), timeout=10)
    if nav_task is not None:
        with contextlib.suppress(Exception):
            await nav_task

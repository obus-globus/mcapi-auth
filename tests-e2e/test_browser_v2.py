"""E2E: v2 PKCE + loopback browser flow.

Plan:

1. Call ``login_browser_v2`` with an ``open_browser`` callback that
   navigates a Playwright page (loaded with our persisted MS session)
   to the consent URL.
2. MS shows its "Are you trying to sign in to <app>?" anti-phishing
   screen; the shared consent driver in :mod:`_consent` clicks Continue.
3. MS redirects to ``http://127.0.0.1:<port>/`` (Prism Launcher's
   registered loopback redirect, which ``login_browser_v2`` now
   resolves automatically from the client_id).
4. The library's loopback listener picks that up, completes PKCE, and
   returns a fully populated ``MinecraftSession``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from urllib.parse import urlparse

import pytest
from _consent import drive_consent_until_loopback
from playwright.async_api import BrowserContext

from mcapi_auth import login_browser_v2

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def test_login_browser_v2(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()
    nav_task: asyncio.Task[None] | None = None

    async def open_browser(url: str) -> None:
        parsed = urlparse(url)
        # The library encodes the loopback redirect into ?redirect_uri=…
        # We need its host:port to know when MS has redirected back.
        # In practice the Prism client_id always redirects to 127.0.0.1:<picked-port>/.
        loopback_prefix = "http://127.0.0.1:"

        async def go() -> None:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                await drive_consent_until_loopback(
                    page, expected_redirect_host_prefix=loopback_prefix
                )
            except Exception as e:
                log.info("Playwright nav ended (expected on 127.0.0.1 redirect): %s", e)

        nonlocal nav_task
        nav_task = asyncio.create_task(go())
        _ = parsed  # silence unused-var linter

    session = await login_browser_v2(open_browser=open_browser)

    assert session.access_token
    assert session.uuid
    assert session.username
    assert session.refresh_token

    if nav_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(nav_task, timeout=5)

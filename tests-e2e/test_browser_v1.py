"""E2E: v1 / Live-Connect OOB browser flow (official MC launcher client_id).

The v1 browser flow uses the Live-Connect ``oauth20_desktop.srf`` OOB
redirect (the client_id ``00000000402b5328`` only registers that
single redirect URI). After sign-in MS redirects to
``login.live.com/oauth20_desktop.srf?code=…`` — we read the URL out of
the Playwright page and feed it back to the library via the
``prompt_for_code`` callback.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from pathlib import Path

import pytest
from playwright.async_api import BrowserContext

from mcapi_auth import login_browser_v1

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e

_OOB_REDIRECT_PREFIX = "https://login.live.com/oauth20_desktop.srf"


async def test_login_browser_v1(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()

    code_url_future: asyncio.Future[str] = asyncio.get_event_loop().create_future()

    async def open_browser(url: str) -> None:
        async def go() -> None:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                await drive_consent_until_loopback(
                    page,
                    expected_redirect_host_prefix=_OOB_REDIRECT_PREFIX,
                    timeout_s=60.0,
                    flow_context="login_browser_v1 / MINECRAFT_LAUNCHER_V1_CLIENT_ID",
                )
                if not code_url_future.done():
                    code_url_future.set_result(page.url)
            except Exception as e:
                if not code_url_future.done():
                    code_url_future.set_exception(e)

        _nav_task = asyncio.create_task(go())
        _ = _nav_task

    async def prompt_for_code(_url: str) -> str:
        # The library hands us the consent URL it just opened; we
        # already kicked off the Playwright nav in ``open_browser``,
        # so we just wait for it to land on the OOB redirect and
        # return the resulting URL (which contains ``?code=…``).
        return await asyncio.wait_for(code_url_future, timeout=90)

    session = await login_browser_v1(
        open_browser=open_browser,
        prompt_for_code=prompt_for_code,
    )

    assert session.access_token
    assert session.uuid
    assert session.username
    assert session.refresh_token

    _ = contextlib  # keep import for symmetry with other tests

"""E2E: v2 device-code flow.

The library reports a :class:`DeviceCodePrompt` (``verification_uri`` +
``user_code``); we use Playwright (with the persisted MS session) to
visit the URL, type the code, click through the consent screens, and
let the library's polling loop pick up the resulting token.

⚠ Microsoft applies extra step-up authentication to the device-code
flow even when the persisted profile already has a valid session
(MS classifies "code entered on another device" as higher risk).
The shared consent driver in :mod:`_consent` falls back to the
``MCAPI_E2E_MS_PASSWORD`` env var if it sees the "Get a code to sign
in" wall. Each such occurrence is meant to be recorded in
``MS_PROMPT_LOG.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from pathlib import Path

import pytest
from playwright.async_api import BrowserContext, Page

from mcapi_auth import login_device_code_v2
from mcapi_auth.auth.msa import DeviceCodePrompt

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def _drive_device_code(page: Page, prompt: DeviceCodePrompt) -> None:
    log.info("device-code: visiting %s with code=%s", prompt.verification_uri, prompt.user_code)
    await page.goto(prompt.verification_uri, wait_until="domcontentloaded", timeout=30_000)

    # Type the user_code into <input name="otc" /> ("one-time code").
    code_input = page.locator("input[name='otc'], #otc").first
    await code_input.wait_for(state="visible", timeout=15_000)
    await code_input.fill(prompt.user_code)

    # Click "Next".
    await page.locator("input[type=submit], button[type=submit]").first.click()
    log.info("device-code: submitted user_code, driving consent screens")

    # Drive consent: account picker → step-up (password) → app confirm
    # → terminal "You're signed in" screen. There's no loopback redirect
    # for device-code, so use a sentinel that never matches and rely on
    # the timeout. The library's poll loop is what actually completes
    # the flow.
    await drive_consent_until_loopback(
        page,
        expected_redirect_host_prefix="zzz://never",
        timeout_s=60.0,
        flow_context="login_device_code_v2 / PRISM_LAUNCHER_CLIENT_ID",
    )


async def test_login_device_code_v2(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()
    drive_task: asyncio.Task[None] | None = None

    async def on_device_code(prompt: DeviceCodePrompt) -> None:
        nonlocal drive_task
        drive_task = asyncio.create_task(_drive_device_code(page, prompt))

    session = await login_device_code_v2(on_device_code=on_device_code)

    assert session.access_token
    assert session.uuid
    assert session.username
    assert session.refresh_token

    if drive_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(drive_task, timeout=5)

"""E2E: v1 / Live-Connect device-code flow (official MC launcher client_id).

Identical UX to v2 device-code (Microsoft routes the user through the
same ``microsoft.com/link`` page either way), but uses the legacy
Live-Connect endpoints with ``MINECRAFT_LAUNCHER_V1_CLIENT_ID``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from pathlib import Path

import pytest
from playwright.async_api import BrowserContext, Page

from mcapi_auth import login_device_code_v1
from mcapi_auth.auth.msa import DeviceCodePrompt

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def _drive_device_code(page: Page, prompt: DeviceCodePrompt) -> None:
    log.info("device-code: visiting %s with code=%s", prompt.verification_uri, prompt.user_code)
    await page.goto(prompt.verification_uri, wait_until="domcontentloaded", timeout=30_000)
    await page.locator("input[name='otc'], #otc").first.fill(prompt.user_code)
    await page.locator("input[type=submit], button[type=submit]").first.click()
    await drive_consent_until_loopback(
        page,
        expected_redirect_host_prefix="zzz://never",
        timeout_s=60.0,
        flow_context="login_device_code_v1 / MINECRAFT_LAUNCHER_V1_CLIENT_ID",
    )


async def test_login_device_code_v1(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()
    drive_task: asyncio.Task[None] | None = None

    async def on_device_code(prompt: DeviceCodePrompt) -> None:
        nonlocal drive_task
        drive_task = asyncio.create_task(_drive_device_code(page, prompt))

    session = await login_device_code_v1(on_device_code=on_device_code)

    assert session.access_token
    assert session.uuid
    assert session.username
    assert session.refresh_token

    if drive_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(drive_task, timeout=5)

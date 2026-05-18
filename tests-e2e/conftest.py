"""Shared fixtures for the E2E suite.

Every test loads the same persisted Microsoft session from
``tests-e2e/storage_state.json``. If that file doesn't exist (e.g. you
haven't run ``bootstrap_login.py`` yet), the whole module is skipped.

The ``browser_context`` fixture is scoped per-test to keep tests
hermetic: an interactive flow that rotates cookies during its run
doesn't leak that change into the next test.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from playwright.async_api import Browser, BrowserContext, async_playwright

STATE_PATH = Path(__file__).parent / "storage_state.json"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    skip_marker = pytest.mark.skip(reason="storage_state.json missing — run bootstrap_login.py")
    if not STATE_PATH.exists():
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip_marker)


@pytest_asyncio.fixture(scope="session")
async def playwright_browser() -> AsyncIterator[Browser]:
    headless_env = os.environ.get("MCAPI_E2E_HEADLESS", "1")
    headless = headless_env != "0"
    channel = os.environ.get("MCAPI_E2E_BROWSER_CHANNEL") or None
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless, channel=channel)
        try:
            yield browser
        finally:
            await browser.close()


@pytest_asyncio.fixture
async def browser_context(playwright_browser: Browser) -> AsyncIterator[BrowserContext]:
    ctx = await playwright_browser.new_context(
        storage_state=str(STATE_PATH) if STATE_PATH.exists() else None,
        viewport={"width": 1400, "height": 800},
    )
    try:
        yield ctx
    finally:
        await ctx.close()

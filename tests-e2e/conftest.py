"""Shared fixtures for the E2E suite.

We use a **persistent browser context** rather than a fresh
``new_context()`` with imported storage state, because Microsoft's
login flow plants pieces of state outside the OAuth cookies that
``storage_state.json`` captures (device-bound tokens in IndexedDB,
service-worker caches, …). Re-using the whole Chromium profile means
the bootstrap "log in once" actually sticks for as long as MS keeps
the session alive.

The profile lives at ``tests-e2e/.user-data/`` (gitignored). Run
``bootstrap_login.py`` once to populate it; every test re-opens the
same directory.

If the profile directory doesn't exist (e.g. you haven't bootstrapped
yet), the whole module is skipped.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from playwright.async_api import BrowserContext, async_playwright

# Make sibling helpers (e.g. ``_consent``) importable without making
# ``tests-e2e`` a real Python package (the hyphen forbids that).
sys.path.insert(0, str(Path(__file__).parent))

USER_DATA_DIR = Path(__file__).parent / ".user-data"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    skip_marker = pytest.mark.skip(
        reason="tests-e2e/.user-data missing — run bootstrap_login.py first"
    )
    if not USER_DATA_DIR.is_dir() or not any(USER_DATA_DIR.iterdir()):
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip_marker)


@pytest_asyncio.fixture
async def browser_context() -> AsyncIterator[BrowserContext]:
    """Per-test persistent Chromium context.

    Scoped per-test rather than per-session because flows that rotate
    cookies during the run shouldn't leak that change into the next
    test. Closing the context flushes the profile back to disk.
    """
    headless_env = os.environ.get("MCAPI_E2E_HEADLESS", "1")
    headless = headless_env != "0"
    channel = os.environ.get("MCAPI_E2E_BROWSER_CHANNEL") or None
    async with async_playwright() as p:
        ctx = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=headless,
            channel=channel,
            viewport={"width": 1400, "height": 800},
        )
        try:
            yield ctx
        finally:
            await ctx.close()

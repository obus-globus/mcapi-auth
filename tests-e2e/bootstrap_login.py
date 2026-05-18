"""One-time interactive login bootstrapper.

Opens a headed Chromium with a **persistent profile** at
``tests-e2e/.user-data/``. Sign in with the Microsoft account that
owns the Minecraft license, then close the browser window. The
profile (cookies + IndexedDB + service worker caches) lives on disk
and is re-used by every test in ``tests-e2e/``.

Re-run only when the saved session has fully expired (MS rotates
cookies/tokens on ~30-90 day intervals).

Run with::

    uv run --active python tests-e2e/bootstrap_login.py

Honours:
- ``$MCAPI_E2E_HEADLESS=1`` to run headless (rarely useful for the
  interactive bootstrap itself, but supported for parity with tests).
- ``$MCAPI_E2E_BROWSER_CHANNEL=chrome|msedge`` to use a system
  browser channel instead of Playwright's bundled Chromium.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path

from playwright.async_api import async_playwright

USER_DATA_DIR = Path(__file__).parent / ".user-data"


async def main() -> None:
    headless = os.environ.get("MCAPI_E2E_HEADLESS") == "1"
    channel = os.environ.get("MCAPI_E2E_BROWSER_CHANNEL") or None

    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        ctx = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=headless,
            channel=channel,
            viewport={"width": 1400, "height": 800},
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        await page.goto("https://login.live.com/", wait_until="domcontentloaded")
        print("=" * 70)
        print("Sign in with the Microsoft account that owns the Minecraft license.")
        print("Tip: open https://account.microsoft.com/ in the same window to verify")
        print("the session is fully active (your name should appear in the top-right).")
        print()
        print("When done, just close the browser window — the profile saves automatically.")
        print("=" * 70)
        # Wait for the user to close the last page / window.
        closed = asyncio.Event()
        ctx.on("close", lambda _ctx: closed.set())
        page.on("close", lambda _p: closed.set())
        try:
            await asyncio.wait_for(closed.wait(), timeout=3600)
        except TimeoutError:
            print("Timed out after 1h with no close; saving anyway.")
        # closing the context flushes the profile to disk
        with contextlib.suppress(Exception):
            await ctx.close()
        print(f"Saved persistent profile to {USER_DATA_DIR}")


if __name__ == "__main__":
    asyncio.run(main())

"""One-time interactive login bootstrapper.

Opens a headed Chromium pointed at https://login.live.com/. Sign in
with the Microsoft account that owns the Minecraft license under test,
then press Enter in the terminal. Your browser context (cookies +
localStorage) is saved to ``tests-e2e/storage_state.json``.

Re-run whenever the saved session expires (MS rotates web cookies on
~30-90 day intervals).

Run with::

    uv run --active python tests-e2e/bootstrap_login.py

The script honours ``$MCAPI_E2E_HEADLESS=1`` for environments where you
can attach to the Xvfb display via VNC and don't want the script to
spawn another window manager. Set ``$MCAPI_E2E_BROWSER_CHANNEL`` to
``chrome`` or ``msedge`` to use the system browser instead of
Playwright's bundled Chromium.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from playwright.async_api import async_playwright

STATE_PATH = Path(__file__).parent / "storage_state.json"


async def main() -> None:
    headless = os.environ.get("MCAPI_E2E_HEADLESS") == "1"
    channel = os.environ.get("MCAPI_E2E_BROWSER_CHANNEL") or None

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless, channel=channel)
        ctx = await browser.new_context(viewport={"width": 1400, "height": 800})
        page = await ctx.new_page()
        await page.goto("https://login.live.com/", wait_until="domcontentloaded")
        print("=" * 70)
        print("Sign in with the Microsoft account that owns the Minecraft license.")
        print("When you're fully signed in (see your name in the top-right of")
        print("account.microsoft.com), press Enter here to save the session.")
        print("=" * 70)
        await asyncio.get_event_loop().run_in_executor(None, input, "Press Enter to save... ")
        await ctx.storage_state(path=str(STATE_PATH))
        print(f"Saved storage state to {STATE_PATH}")
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())

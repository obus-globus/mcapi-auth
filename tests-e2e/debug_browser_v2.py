"""Debug-mode browser_v2 flow. Takes screenshots at every step.

Run with::

    env DISPLAY=:99 MCAPI_E2E_HEADLESS=0 \\
        uv run --active python tests-e2e/debug_browser_v2.py

Saves screenshots to /tmp/mcapi-e2e-step-*.png. The Chromium window
should also be visible on Xvfb :99 (open it via the VNC URL).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path

from playwright.async_api import async_playwright

from mcapi_auth import login_browser_v2

USER_DATA_DIR = Path(__file__).parent / ".user-data"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


async def main() -> None:
    headless = os.environ.get("MCAPI_E2E_HEADLESS", "0") == "1"
    async with async_playwright() as p:
        ctx = await p.chromium.launch_persistent_context(
            user_data_dir=str(USER_DATA_DIR),
            headless=headless,
            viewport={"width": 1400, "height": 800},
            args=["--window-size=1500,850", "--window-position=20,20"],
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        async def open_browser(url: str) -> None:
            log.info("OPEN_BROWSER called with: %s", url)

            async def go() -> None:
                try:
                    log.info("step 1: navigating to consent URL")
                    await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                    await page.screenshot(path="/tmp/mcapi-e2e-step-1-loaded.png")
                    log.info("step 1: title=%s url=%s", await page.title(), page.url)

                    # Wait for either redirect to 127.0.0.1 (auto-consent worked)
                    # or a consent / account-picker to render.
                    for i in range(30):
                        await asyncio.sleep(1)
                        cur = page.url
                        log.info("  wait[%d]: url=%s", i, cur[:120])
                        # Real redirect to loopback (not just URL-encoded in a param)
                        if cur.startswith("http://127.0.0.1") or cur.startswith("http://localhost"):
                            log.info("  -> reached loopback redirect")
                            break
                        # "Are you trying to sign in to <app>?" anti-phishing screen
                        # at account.live.com/App/Confirm — has a 'Continue' <button>.
                        with contextlib.suppress(Exception):
                            cont = page.get_by_role("button", name="Continue")
                            if await cont.is_visible(timeout=500):
                                await page.screenshot(path=f"/tmp/mcapi-e2e-step-2-confirm-{i}.png")
                                await cont.click()
                                log.info("  -> clicked 'Continue' on app confirm screen")
                                continue
                        # Account picker (KMSI / "stay signed in" / picker)
                        with contextlib.suppress(Exception):
                            tile = page.locator("div[role='listitem']").first
                            if await tile.is_visible(timeout=500):
                                await page.screenshot(path=f"/tmp/mcapi-e2e-step-2-picker-{i}.png")
                                await tile.click()
                                log.info("  -> clicked account tile")
                                continue
                        # Generic Yes / Accept input
                        with contextlib.suppress(Exception):
                            btn = page.locator(
                                "input[type=submit][value=Yes], input[type=submit][value=Accept]"
                            ).first
                            if await btn.is_visible(timeout=500):
                                await btn.click()
                                log.info("  -> clicked generic consent button")
                                continue
                    await page.screenshot(path="/tmp/mcapi-e2e-step-3-final.png")
                except Exception as e:
                    log.exception("nav failed: %s", e)

            asyncio.create_task(go())  # noqa: RUF006

        try:
            session = await asyncio.wait_for(
                login_browser_v2(open_browser=open_browser), timeout=120
            )
            log.info("SUCCESS: username=%s uuid=%s", session.username, session.uuid)
            log.info("  access_token=%s...", session.access_token[:40])
        except Exception as e:
            log.exception("login_browser_v2 failed: %s", e)
            await page.screenshot(path="/tmp/mcapi-e2e-step-X-failure.png")

        await ctx.close()


if __name__ == "__main__":
    asyncio.run(main())

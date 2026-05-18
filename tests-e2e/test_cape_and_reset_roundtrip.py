"""Exercise the mutating cape + reset_skin endpoints against the live account.

Sequence (deliberately reversible):

1. Snapshot the current `OwnProfile` (active skin + active cape, if any).
2. Pick any cape the account owns and `change_cape` it to ACTIVE.
3. `disable_cape` — clear active cape.
4. `reset_skin` — drop back to the default Steve/Alex.
5. Restoration: re-upload the original skin PNG (saved by
   ``test_skin_roundtrip``) so the account ends close to how we found it.
6. If a cape was originally ACTIVE, re-enable it via `change_cape`.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

from mcapi_auth import login_browser_v2
from mcapi_auth.api import account

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)
SNAPSHOT_DIR = Path(__file__).parent / ".skin-snapshots"


async def _do_login(browser_context: BrowserContext):
    page = await browser_context.new_page()
    try:

        async def open_browser(url: str) -> None:
            async def go() -> None:
                with suppress(Exception):
                    await page.goto(url)
                with suppress(Exception):
                    await drive_consent_until_loopback(
                        page,
                        expected_redirect_host_prefix="127.0.0.1",
                        timeout_s=60.0,
                        flow_context="cape_reset_roundtrip / login_browser_v2",
                    )

            _t = asyncio.create_task(go())
            _ = _t

        return await login_browser_v2(open_browser=open_browser)
    finally:
        with suppress(Exception):
            await page.close()


def _summarize(profile: account.OwnProfile) -> str:
    skins = ", ".join(f"{s.id}/{s.state}" for s in profile.skins) or "<none>"
    capes = ", ".join(f"{c.alias or c.id}/{c.state}" for c in profile.capes) or "<none>"
    return f"skins=[{skins}] capes=[{capes}]"


@pytest.mark.asyncio
async def test_cape_and_reset_roundtrip(browser_context: BrowserContext) -> None:
    session = await _do_login(browser_context)

    snapshot = await account.get_own_profile(session)
    logger.info("snapshot: %s", _summarize(snapshot))

    owned_capes = list(snapshot.capes)
    assert owned_capes, "this test needs at least one owned cape on the account"
    original_active_cape = next((c for c in owned_capes if c.state == "ACTIVE"), None)
    target_cape = original_active_cape or owned_capes[0]
    other_cape = next((c for c in owned_capes if c.id != target_cape.id), None)
    flip_to = other_cape or target_cape  # if only one cape, flip to itself (still a no-op API call)

    # 1) change_cape
    logger.info("change_cape -> %s (%s)", flip_to.alias, flip_to.id)
    after_change = await account.change_cape(session, flip_to.id)
    new_active = next((c for c in after_change.capes if c.state == "ACTIVE"), None)
    assert new_active is not None and new_active.id == flip_to.id, (
        f"expected cape {flip_to.id} active after change_cape, got {_summarize(after_change)}"
    )
    logger.info("after change_cape: %s", _summarize(after_change))

    # 2) disable_cape
    logger.info("disable_cape")
    after_disable = await account.disable_cape(session)
    still_active = [c for c in after_disable.capes if c.state == "ACTIVE"]
    assert not still_active, f"expected no active cape after disable_cape, got {still_active}"
    logger.info("after disable_cape: %s", _summarize(after_disable))

    # 3) reset_skin
    logger.info("reset_skin")
    after_reset = await account.reset_skin(session)
    # After reset, Mojang treats the account as having no custom skin; the API
    # may either return an empty `skins` tuple or a default entry — accept both.
    custom_skins_left = [s for s in after_reset.skins if s.state == "ACTIVE"]
    logger.info(
        "after reset_skin: %s (active skins remaining: %d)",
        _summarize(after_reset),
        len(custom_skins_left),
    )

    # 4) Restoration: re-upload the saved original skin if we have it.
    original_skin = next((s for s in snapshot.skins if s.state == "ACTIVE"), None)
    if original_skin is not None:
        saved = SNAPSHOT_DIR / f"before-{original_skin.id}.png"
        if saved.exists():
            png_bytes = saved.read_bytes()
        else:
            logger.info(
                "no local snapshot for %s, downloading from %s",
                original_skin.id,
                original_skin.url,
            )
            async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as c:
                r = await c.get(original_skin.url)
                r.raise_for_status()
                png_bytes = r.content
        logger.info("restoring skin (%d bytes, variant=%s)", len(png_bytes), original_skin.variant)
        restored = await account.change_skin_from_file(
            session,
            png_bytes,
            variant=account.SkinVariant(original_skin.variant),
        )
        logger.info("after restore_skin: %s", _summarize(restored))
    else:
        logger.info("snapshot had no active skin; leaving Steve/Alex as-is")

    # 5) If a cape was originally ACTIVE, restore it.
    if original_active_cape is not None:
        logger.info("restoring cape -> %s (%s)", original_active_cape.alias, original_active_cape.id)
        restored = await account.change_cape(session, original_active_cape.id)
        logger.info("after restore_cape: %s", _summarize(restored))
    else:
        logger.info("no cape was originally active; leaving disabled")

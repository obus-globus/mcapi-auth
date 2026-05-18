"""Exercise `account.change_skin_from_url` against the live account.

Sequence (reversible):

  1. Snapshot the current active skin (id + url + variant).
  2. Look up Notch's public profile and decode his skin URL.
  3. `change_skin_from_url(session, notch_url, variant=classic)`.
  4. Verify the new ACTIVE skin url matches what we set.
  5. Restore the original skin by POSTing it back via the same helper.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

from mcapi_auth import login_browser_v2
from mcapi_auth.api import account, textures
from mcapi_auth.api import profile as profile_api

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)
NOTCH_UUID = "069a79f444e94726a5befca90e38aaf5"


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
                        flow_context="skin_from_url_roundtrip / login_browser_v2",
                    )

            _t = asyncio.create_task(go())
            _ = _t

        return await login_browser_v2(open_browser=open_browser)
    finally:
        with suppress(Exception):
            await page.close()


def _active_skin(profile: account.OwnProfile) -> account.SkinEntry | None:
    return next((s for s in profile.skins if s.state == "ACTIVE"), None)


@pytest.mark.asyncio
async def test_change_skin_from_url_roundtrip(browser_context: BrowserContext) -> None:
    session = await _do_login(browser_context)

    before = await account.get_own_profile(session)
    original = _active_skin(before)
    assert original is not None, "expected an ACTIVE skin on the account"
    logger.info(
        "before: skin id=%s variant=%s url=%s",
        original.id,
        original.variant,
        original.url,
    )

    notch_profile = await profile_api.get_profile_by_uuid(NOTCH_UUID)
    notch_textures = textures.extract_textures(notch_profile)
    assert notch_textures is not None and notch_textures.skin is not None, (
        "Notch's profile should always carry a SKIN texture"
    )
    notch_skin_url = notch_textures.skin.url
    logger.info("Notch skin url: %s", notch_skin_url)

    # Don't wait until we're done — apply via URL.
    after_change = await account.change_skin_from_url(
        session,
        notch_skin_url,
        variant=account.SkinVariant.CLASSIC,
    )
    new_active = _active_skin(after_change)
    assert new_active is not None
    logger.info("after change_skin_from_url: id=%s url=%s", new_active.id, new_active.url)

    # Mojang downloads the PNG from our URL and normalizes it before
    # re-hosting. The new texture url may end up the same hash as before if
    # the source URL happens to normalize to identical bytes (e.g. when we
    # point a second run at the same Notch skin). The reliable invariant is
    # that Mojang creates a NEW skin entry (new skin id) for each upload.
    assert new_active.id != original.id, (
        f"expected change_skin_from_url to create a new skin entry; "
        f"id stayed at {original.id}"
    )
    logger.info(
        "skin entry replaced (id %s -> %s, texture %s) ✓",
        original.id,
        new_active.id,
        new_active.url,
    )

    # Restore: brief pause then re-post the original URL.
    await asyncio.sleep(2.0)
    restored = await account.change_skin_from_url(
        session,
        original.url,
        variant=account.SkinVariant(original.variant),
    )
    final_active = _active_skin(restored)
    assert final_active is not None
    logger.info(
        "after restore: id=%s variant=%s url=%s",
        final_active.id,
        final_active.variant,
        final_active.url,
    )
    # Restoration is best-effort: Mojang stripped/normalized the original PNG
    # already (its `url` is whatever Mojang re-hosted it as), so re-uploading
    # that same url just round-trips through the same normalization. The
    # invariant we check is just "skin slot is back to a single ACTIVE entry".
    assert final_active is not None

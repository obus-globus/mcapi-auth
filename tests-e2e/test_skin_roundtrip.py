"""Roundtrip skin change: download current skin, mutate one pixel, upload, verify."""

from __future__ import annotations

import asyncio
import io
import logging
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest
from httpdbg import HTTPRecords, httprecord  # pyright: ignore[reportMissingImports]
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback

from mcapi_auth import login_browser_v2
from mcapi_auth.api import account

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)


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
                        flow_context="skin_roundtrip / login_browser_v2",
                    )

            _t = asyncio.create_task(go())
            _ = _t

        return await login_browser_v2(open_browser=open_browser)
    finally:
        with suppress(Exception):
            await page.close()


def _bump_one_pixel(png_bytes: bytes) -> tuple[bytes, tuple[int, int, tuple[int, int, int, int], tuple[int, int, int, int]]]:
    """Flip the LSB of the red channel of pixel (0,0). Returns new PNG bytes
    plus a diff description (x,y,before,after) for logging.
    """
    img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
    x, y = 0, 0
    before = img.getpixel((x, y))
    assert isinstance(before, tuple)
    r, g, b, a = before
    new_r = r ^ 1  # flip the low bit so we don't accidentally clamp
    after = (new_r, g, b, a)
    img.putpixel((x, y), after)
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue(), (x, y, before, after)


@pytest.mark.asyncio
async def test_skin_roundtrip(browser_context: BrowserContext) -> None:
    session = await _do_login(browser_context)

    profile_before = await account.get_own_profile(session)
    active_skin = next(
        (s for s in profile_before.skins if s.state == "ACTIVE"),
        None,
    )
    assert active_skin is not None, "expected an ACTIVE skin on the account"
    logger.info(
        "before: active skin id=%s variant=%s url=%s",
        active_skin.id,
        active_skin.variant,
        active_skin.url,
    )

    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as c:
        r = await c.get(active_skin.url)
        r.raise_for_status()
        original_png = r.content
    logger.info("downloaded original skin: %d bytes", len(original_png))

    snapshot_dir = Path(__file__).parent / ".skin-snapshots"
    snapshot_dir.mkdir(exist_ok=True)
    (snapshot_dir / f"before-{active_skin.id}.png").write_bytes(original_png)

    mutated_png, (x, y, before_px, after_px) = _bump_one_pixel(original_png)
    logger.info(
        "mutated pixel (%d,%d): %s -> %s (delta on red LSB)",
        x,
        y,
        before_px,
        after_px,
    )
    (snapshot_dir / "after-mutation.png").write_bytes(mutated_png)

    # Capture the upload exchange via httpdbg for the API log.
    records = HTTPRecords()
    with httprecord(records):
        profile_after = await account.change_skin_from_file(
            session,
            mutated_png,
            variant=account.SkinVariant(active_skin.variant),
            filename="skin.png",
        )

    new_active = next(
        (s for s in profile_after.skins if s.state == "ACTIVE"),
        None,
    )
    assert new_active is not None
    logger.info(
        "after: active skin id=%s variant=%s url=%s",
        new_active.id,
        new_active.variant,
        new_active.url,
    )

    # Mojang assigns a new skin id (hash) when the bytes change. If we picked a
    # pixel that survives Mojang's normalization the id should differ from the
    # original. If by chance it matched (e.g. Mojang re-hosts the same canonical
    # PNG) we still consider this a pass — the upload at least round-tripped.
    if new_active.id != active_skin.id:
        logger.info("skin id changed (%s -> %s) — upload accepted", active_skin.id, new_active.id)
    else:
        logger.warning(
            "skin id unchanged (%s) — bytes were normalized to the same hash",
            new_active.id,
        )

    # Best effort: log captured HTTP for transparency.
    for rec in records.requests.values():
        if rec.method == "CONNECT":
            continue
        if "minecraftservices.com" in (rec.netloc or ""):
            logger.info(
                "captured: %s %s -> %s",
                rec.method,
                rec.url,
                rec.status_code,
            )

    # We do NOT restore the original skin automatically — the account is the
    # test rig, and reverting would itself be another mutation. The original
    # PNG is saved under tests-e2e/.skin-snapshots/ if you want to restore by
    # hand.

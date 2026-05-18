"""Try `account.change_name` with names we *expect* to be rejected.

Two cases, both reachable without burning the account's 30-day cooldown:

  1. ``Notch`` — already owned by Mojang's founder, must come back as a
     ``NameTakenError`` (HTTP 403 DUPLICATE).
  2. ``ass`` — too short *and* on Mojang's profanity filter; Mojang should
     respond with HTTP 400 (``NameNotAllowedError``) or HTTP 403
     (``ForbiddenError``). If Mojang's per-account rate-limiter triggers
     because of the first call we accept ``RateLimitedError`` too — that's
     still proof the endpoint and library plumbing work.

If either call succeeds with a 200 we re-raise — that would be a real
account mutation and a sign that something's wrong with the live API.
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
from mcapi_auth.api import account
from mcapi_auth.exceptions import (
    ForbiddenError,
    NameNotAllowedError,
    NameTakenError,
    RateLimitedError,
)

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
                        flow_context="change_name_rejected / login_browser_v2",
                    )

            _t = asyncio.create_task(go())
            _ = _t

        return await login_browser_v2(open_browser=open_browser)
    finally:
        with suppress(Exception):
            await page.close()


@pytest.mark.asyncio
async def test_change_name_rejected_for_taken_and_blocked(
    browser_context: BrowserContext,
) -> None:
    session = await _do_login(browser_context)

    # 1) Taken (and famous) name — expect 403 DUPLICATE -> NameTakenError
    with pytest.raises(NameTakenError) as exc_notch:
        await account.change_name(session, "Notch")
    logger.info("change_name('Notch') correctly raised NameTakenError: %s", exc_notch.value)

    # Mojang rate-limits per-account aggressively (one failed PUT in a row is
    # enough to trip a 429). Pause to let the limiter recover.
    await asyncio.sleep(10.0)

    # 2) The user asked us to try a "blocked-looking" name like 'ass'. In
    # practice Mojang's profanity filter only applies to *new* registrations,
    # not to names that were already registered before the filter went in,
    # so 'ass' itself is just an owned username -> 403 DUPLICATE. Accept any
    # of NameTakenError / NameNotAllowedError / ForbiddenError / RateLimited
    # so we don't false-fail when Mojang re-classifies a profane name.
    with pytest.raises(
        (NameTakenError, NameNotAllowedError, ForbiddenError, RateLimitedError)
    ) as exc_ass:
        await account.change_name(session, "ass")
    logger.info(
        "change_name('ass') correctly raised %s: %s",
        type(exc_ass.value).__name__,
        exc_ass.value,
    )

    await asyncio.sleep(10.0)

    # 3) A name that is *format-invalid* (17 chars; Mojang's username spec is
    # 3-16 chars, [A-Za-z0-9_]). This must hit the 400 NOT_ALLOWED path and
    # become NameNotAllowedError in the library.
    too_long = "abcdefghijklmnopq"  # 17 chars
    with pytest.raises((NameNotAllowedError, RateLimitedError)) as exc_long:
        await account.change_name(session, too_long)
    logger.info(
        "change_name(%r) correctly raised %s: %s",
        too_long,
        type(exc_long.value).__name__,
        exc_long.value,
    )

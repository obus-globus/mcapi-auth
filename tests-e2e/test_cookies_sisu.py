"""E2E: cookie-based SISU (Xbox SSO) flow.

The library's :func:`login_with_cookies_sisu` hits
``sisu.xboxlive.com/connect/XboxLive/`` with the user's cookies and
returns a :class:`SISUTokens` bag — XBL/XSTS tokens directly, no
MS access/refresh token. Used as a fallback when MSA-v1 cookies are
rejected (FIDO-only accounts).
"""

from __future__ import annotations

import logging

import pytest
from playwright.async_api import BrowserContext

from mcapi_auth import (
    SISUTokens,
    extract_sisu_token,
    login_with_cookies_sisu,
)

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def test_login_with_cookies_sisu(browser_context: BrowserContext) -> None:
    cookies = await browser_context.cookies()
    # SISU lives under sisu.xboxlive.com but bootstraps off .live.com
    # session cookies (the same MSPAuth/RPSSecAuth as MSA-v1). Send
    # both so MS can complete the login → SISU SSO without prompting.
    pieces: list[str] = [
        f"{c.get('name', '')}={c.get('value', '')}"
        for c in cookies
        if str(c.get("domain", "")).endswith((".live.com", ".xboxlive.com"))
    ]
    header = "; ".join(pieces)
    assert header, "no .live.com / .xboxlive.com cookies — bootstrap login first"
    log.info("sisu: %d cookies", len(pieces))

    sisu: SISUTokens = await login_with_cookies_sisu(header)
    xbl = extract_sisu_token(sisu, "http://xboxlive.com")
    assert xbl.token
    assert xbl.userhash
    log.info("sisu: got XBL token (userhash=%s)", xbl.userhash)

"""E2E: cookie-based MSA-v2 + loopback flow (PrismLauncher client_id).

Like ``test_cookies_msa_v1`` but uses the Azure-AD consumers endpoints
and a structured cookie list instead of a header string. Useful when
the Live-Connect / MBI_SSL endpoint refuses the account.
"""

from __future__ import annotations

import logging

import pytest
from playwright.async_api import BrowserContext

from mcapi_auth import BrowserCookie, login_with_cookies_msa_v2_loopback
from mcapi_auth.auth.app_config import MsaApplicationConfig
from mcapi_auth.auth.chain import AuthChain

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def test_login_with_cookies_msa_v2_loopback(browser_context: BrowserContext) -> None:
    raw = await browser_context.cookies()
    cookies: list[BrowserCookie] = [
        BrowserCookie(
            name=str(c.get("name", "")),
            value=str(c.get("value", "")),
            domain=str(c.get("domain", "")),
            path=str(c.get("path", "/")),
        )
        for c in raw
        if str(c.get("domain", "")).endswith(".live.com")
        or str(c.get("domain", "")) == "login.live.com"
    ]
    assert cookies, "no .live.com cookies in persisted profile — bootstrap login first"
    log.info("v2-cookies: %d .live.com cookies", len(cookies))

    msa = await login_with_cookies_msa_v2_loopback(cookies)
    assert msa.access_token
    assert msa.refresh_token

    chain = AuthChain(app=MsaApplicationConfig.v2(), msa=msa)
    session = await chain.to_session()
    assert session.uuid
    assert session.username
    log.info("v2-cookies: chained to MC profile uuid=%s user=%s", session.uuid, session.username)

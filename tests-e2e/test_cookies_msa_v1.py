"""E2E: cookie-based MSA-v1 (Live-Connect MBI_SSL) flow.

Pull ``.live.com`` cookies out of the persisted Playwright profile,
serialize them as a ``Cookie:`` header, and hand them to
:func:`login_with_cookies_msa_v1`. Then chain the resulting
:class:`MSATokens` through XBL/XSTS/Mojang via :class:`AuthChain` to
prove end-to-end usability.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest
from playwright.async_api import BrowserContext

from mcapi_auth import login_with_cookies_msa_v1
from mcapi_auth.auth.app_config import MsaApplicationConfig
from mcapi_auth.auth.chain import AuthChain

sys.path.insert(0, str(Path(__file__).parent))

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


def _cookies_to_header(cookies: list, *, domain_suffix: str) -> str:
    """Render Playwright cookies whose domain ends with ``domain_suffix`` as a Cookie header."""
    pieces: list[str] = []
    for c in cookies:
        domain = str(c.get("domain", ""))
        if not (domain == domain_suffix or domain.endswith(domain_suffix)):
            continue
        pieces.append(f"{c.get('name', '')}={c.get('value', '')}")
    return "; ".join(pieces)


async def test_login_with_cookies_msa_v1(browser_context: BrowserContext) -> None:
    cookies = await browser_context.cookies()
    header = _cookies_to_header(cookies, domain_suffix=".live.com")
    assert header, "no .live.com cookies in persisted profile — bootstrap login first"
    log.info("v1-cookies: %d .live.com cookies, header is %d bytes", header.count("="), len(header))

    msa = await login_with_cookies_msa_v1(header)
    assert msa.access_token
    assert msa.refresh_token

    # Drive through XBL → XSTS → MC profile to prove the MSA token is usable.
    chain = AuthChain(app=MsaApplicationConfig.v1_launcher(), msa=msa)
    session = await chain.to_session()
    assert session.uuid
    assert session.username
    log.info("v1-cookies: chained to MC profile uuid=%s user=%s", session.uuid, session.username)

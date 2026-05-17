"""Bulk-auth via browser cookies — try MSA-v1 first, fall back to SISU.
You'll need to extract Microsoft login cookies (``MSPAuth``, ``MSPProf``,
``RPSSecAuth``, …) from a browser session that is signed into the target
account. Selenium / nodriver / playwright with a real profile all work;
the library doesn't ship a browser driver because the choice of automation
tool is yours.

.. warning::
   These flows let you impersonate an account using its session cookies.
   Only use them on accounts you own or have explicit permission to
   automate. They are bulk-auth primitives, not a way around 2FA.
"""


import asyncio
import os

from mcapi_auth import (
    BrowserCookie,
    CookieAuthError,
    SISUTokens,
    extract_sisu_token,
    login_with_cookies_msa_v1,
    login_with_cookies_sisu,
)


async def main() -> None:
    cookie_header = os.environ["MS_COOKIE_HEADER"]  # "MSPAuth=...; MSPProf=...; ..."

    try:
        tokens = await login_with_cookies_msa_v1(cookie_header)
    except CookieAuthError as e:
        print(f"MSA-v1 flow failed ({e}); falling back to SISU")
        sisu: SISUTokens = await login_with_cookies_sisu(cookie_header)
        xbl = extract_sisu_token(sisu, "http://xboxlive.com")
        print(f"SISU XBL token: {xbl.token[:24]}… userhash={xbl.userhash}")
        return

    print(f"MSA access token (truncated): {tokens.access_token[:24]}…")
    print(f"MSA refresh token (truncated): {tokens.refresh_token[:24]}…")


async def prism_example() -> None:
    """Prism-Launcher Azure-AD flow — takes a structured cookie list."""
    from mcapi_auth import login_with_cookies_prism

    cookies = [
        BrowserCookie(name="MSPAuth", value="...", domain=".live.com"),
        BrowserCookie(name="MSPProf", value="...", domain=".live.com"),
    ]
    tokens = await login_with_cookies_prism(cookies)
    print(f"Prism access token (truncated): {tokens.access_token[:24]}…")


if __name__ == "__main__":
    asyncio.run(main())

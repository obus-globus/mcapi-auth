"""E2E: Realms listing + sessionserver/join smoke.

Combines two API calls that build on a fresh ``MinecraftSession``:

* ``fetch_realms_worlds`` — lists worlds the account owns / has joined.
  Should always succeed (even for accounts with no realms, it returns
  an empty list, not an error).
* ``join_server`` — drives the sessionserver/join Mojang endpoint with
  a synthetic ``server_id`` hash. Mojang returns 204 if the access
  token is valid; we don't care about the server existing.

Also round-trips the chain via ``AuthChain.dump_json`` /
``AuthChain.load_json`` to validate the persistence path.
"""

from __future__ import annotations

import logging
import secrets

import pytest
from playwright.async_api import BrowserContext

from mcapi_auth import login_browser_v2
from mcapi_auth.api.realms import fetch_realms_worlds
from mcapi_auth.auth.chain import AuthChain
from mcapi_auth.auth.session_server import join_server

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e


async def test_realms_and_join_smoke(browser_context: BrowserContext) -> None:
    import asyncio
    import contextlib
    import sys
    from pathlib import Path
    from urllib.parse import urlparse

    sys.path.insert(0, str(Path(__file__).parent))
    from _consent import drive_consent_until_loopback

    page = await browser_context.new_page()
    nav_task: asyncio.Task[None] | None = None

    async def open_browser(url: str) -> None:
        nonlocal nav_task

        async def go() -> None:
            with contextlib.suppress(Exception):
                await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                await drive_consent_until_loopback(
                    page,
                    expected_redirect_host_prefix="http://127.0.0.1:",
                    flow_context="realms_smoke / login_browser_v2",
                )

        nav_task = asyncio.create_task(go())
        _ = urlparse  # silence linter

    session = await login_browser_v2(open_browser=open_browser)
    if nav_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(nav_task, timeout=5)

    # --- Realms ---
    worlds = await fetch_realms_worlds(session)
    assert isinstance(worlds, list)
    log.info("realms: %d worlds for %s", len(worlds), session.username)

    # --- sessionserver/join ---
    # Random 20-byte hex string as serverId — Mojang doesn't actually
    # care about validity, only that the access_token + uuid are good.
    server_id = secrets.token_hex(20)
    await join_server(
        access_token=session.access_token,
        uuid=session.uuid,
        server_id=server_id,
    )
    log.info("join_server: 204 for server_id=%s…", server_id[:10])

    # --- AuthChain dump/load round-trip ---
    chain = AuthChain.from_session(session)
    blob = chain.dump_json()
    assert "access_token" in blob
    rehydrated = AuthChain.load_json(blob, app=chain.app)
    assert (await rehydrated.get_profile()).uuid == session.uuid
    log.info("chain: dump/load round-trip OK (%d bytes)", len(blob))

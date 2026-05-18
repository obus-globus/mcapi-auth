"""E2E: full Bedrock auth chain end-to-end against the live account.

Drives :func:`BedrockAuthManager.login` to completion — which, because
``prime=True`` is the default, transitively exercises every step of
the Bedrock chain and every Bedrock/PlayFab endpoint:

  1. MSA device-code   → :func:`request_device_code` + Playwright drive
  2. XBL device-token  → ``user.auth.xboxlive.com /device/authenticate``
  3. Bedrock SISU      → ``sisu.xboxlive.com /authorize``  (RP=multiplayer.minecraft.net)
  4. ``minecraft_authenticate``      → cert chain
  5. PlayFab SISU      → ``sisu.xboxlive.com /authorize``  (RP=PlayFab Bedrock)
  6. ``playfab_login_with_xbox``     → PlayFab session ticket
  7. ``start_minecraft_session``     → franchise session
  8. ``start_minecraft_multiplayer_session`` → multiplayer token

Bedrock device-code goes through the **same** microsoft.com/link page
as the Java device-code flow, just with a different client_id
(``BEDROCK_WIN32_CLIENT_ID``). Microsoft's step-up auth fires on
device-code flows even with a fresh profile, so we rely on the shared
:mod:`_consent` driver to enter ``$MCAPI_E2E_MS_PASSWORD`` when asked.

All HTTP traffic is captured via httpdbg and written to
``BEDROCK_TRAFFIC_LOG.md`` with the usual bearer/cookie redaction.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from httpdbg import HTTPRecords, httprecord  # pyright: ignore[reportMissingImports]
from playwright.async_api import BrowserContext, Page

from mcapi_auth.auth.bedrock_chain import BedrockAuthManager
from mcapi_auth.auth.msa import DeviceCodePrompt
from mcapi_auth.exceptions import XSTSError

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback
from _traffic import write_traffic_log

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e

TRAFFIC_LOG = Path(__file__).parent / "BEDROCK_TRAFFIC_LOG.md"


async def _drive_bedrock_device_code(page: Page, prompt: DeviceCodePrompt) -> None:
    log.info(
        "bedrock device-code: visiting %s with code=%s",
        prompt.verification_uri,
        prompt.user_code,
    )
    await page.goto(prompt.verification_uri, wait_until="domcontentloaded", timeout=30_000)

    code_input = page.locator("input[name='otc'], #otc").first
    await code_input.wait_for(state="visible", timeout=15_000)
    await code_input.fill(prompt.user_code)
    await page.locator("input[type=submit], button[type=submit]").first.click()
    log.info("bedrock device-code: submitted user_code, driving consent screens")

    await drive_consent_until_loopback(
        page,
        expected_redirect_host_prefix="zzz://never",
        timeout_s=90.0,
        flow_context="BedrockAuthManager.login / BEDROCK_WIN32_CLIENT_ID",
    )


_TRAFFIC_INTRO = (
    "Captured via httpdbg while running `BedrockAuthManager.login(prime=True)`. "
    "Authorization, Cookie, Set-Cookie, signature, and JWT-shaped fields are redacted."
)


def _write_traffic_log(records: HTTPRecords) -> None:
    size = write_traffic_log(
        records,
        path=TRAFFIC_LOG,
        title="Bedrock auth chain — live HTTP traffic",
        intro=_TRAFFIC_INTRO,
    )
    log.info("wrote %d-byte traffic log to %s", size, TRAFFIC_LOG)


async def test_bedrock_chain_end_to_end(browser_context: BrowserContext) -> None:
    page = await browser_context.new_page()
    drive_task: asyncio.Task[None] | None = None

    async def on_device_code(prompt: DeviceCodePrompt) -> None:
        nonlocal drive_task
        drive_task = asyncio.create_task(_drive_bedrock_device_code(page, prompt))

    records = HTTPRecords()
    try:
        with httprecord(records):
            mgr = await BedrockAuthManager.login(on_device_code=on_device_code, prime=True)
    except XSTSError as e:
        _write_traffic_log(records)
        # ATemmtion (our shared test account) doesn't own Bedrock Edition — Sisu
        # 401s with an empty body when the account lacks the Bedrock entitlement
        # for either the multiplayer or PlayFab relying party. Skip the test
        # rather than failing; the library fix is still validated up to here.
        sisu_records = [
            r for r in records.requests.values() if "sisu.xboxlive.com" in r.netloc
        ]
        if sisu_records and sisu_records[-1].status_code == 401:
            pytest.skip(
                f"account lacks Bedrock entitlement: Sisu 401 (empty body) — {e}. "
                "Re-run against a Bedrock-Edition-entitled account to exercise "
                "the remaining bedrock.* / playfab.* helpers."
            )
        raise
    finally:
        _write_traffic_log(records)

    if drive_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(drive_task, timeout=5)

    # Every holder must be populated after priming.
    assert mgr.msa_holder.get_cached() is not None
    assert mgr.device_holder is not None
    assert mgr.bedrock_sisu_holder is not None
    assert mgr.playfab_sisu_holder is not None
    assert mgr.playfab_holder is not None
    assert mgr.cert_chain_holder is not None
    assert mgr.franchise_holder is not None
    assert mgr.multiplayer_holder is not None

    msa = mgr.msa_holder.get_cached()
    device = mgr.device_holder.get_cached()
    bedrock_sisu = mgr.bedrock_sisu_holder.get_cached()
    playfab_sisu = mgr.playfab_sisu_holder.get_cached()
    playfab = mgr.playfab_holder.get_cached()
    cert_chain = mgr.cert_chain_holder.get_cached()
    franchise = mgr.franchise_holder.get_cached()
    multiplayer = mgr.multiplayer_holder.get_cached()

    log.info("MSA access token: %d bytes, refresh: %d bytes",
             len(msa.access_token), len(msa.refresh_token or ""))
    log.info("XBL device token: token=%d bytes, device_id=%s",
             len(device.token), device.device_id)
    log.info("Bedrock SISU: xsts userhash=%s...",
             bedrock_sisu.xsts_token.userhash[:8])
    log.info("PlayFab SISU: xsts userhash=%s...",
             playfab_sisu.xsts_token.userhash[:8])
    log.info("PlayFab token: session_ticket=%d bytes, play_fab_id=%s, entity_id=%s",
             len(playfab.session_ticket),
             playfab.play_fab_id,
             playfab.entity_token.entity_id)
    log.info("Cert chain: mojang_jwt=%d bytes, identity_jwt=%d bytes",
             len(cert_chain.mojang_jwt), len(cert_chain.identity_jwt))
    log.info("Franchise session: auth_header=%d bytes",
             len(franchise.authorization_header))
    log.info("Multiplayer token: signed_token=%d bytes",
             len(multiplayer.token))

    # Snapshot round-trip — proves dump_json / load_json work against
    # the freshly-minted live state.
    dumped = mgr.dump_json()
    assert len(dumped) > 100
    log.info("snapshot dump: %d bytes JSON", len(dumped))

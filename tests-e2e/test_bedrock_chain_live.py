"""Live Bedrock chain E2E for a Bedrock-entitled account.

This test loads a previously-primed BedrockAuthManager snapshot from
``MCAPI_E2E_BEDROCK_STATE`` (defaults to ``~/.config/mcapi-auth-e2e/
bedrock_chain_state.json``) and exercises the chain segments that
:func:`BedrockAuthManager.get_multiplayer_token` would otherwise skip:

  * :meth:`get_certificate_chain` — drives
    ``api.minecraftservices.com/player/cert``-style cert minting via
    ``minecraft_authenticate`` (sets ``cert_chain_holder``).
  * :meth:`get_bedrock_sisu`      — drives Bedrock-RP SISU
    (``sisu.xboxlive.com /authorize`` with RP=multiplayer.minecraft.net,
    sets ``bedrock_sisu_holder``).
  * :meth:`get_multiplayer_token` — re-exercises the franchise +
    multiplayer endpoints to confirm refresh still works.

After the run we persist the (possibly-rotated) state back to the
snapshot file so the next run picks up where we left off.

The snapshot is created out-of-band by
``/tmp/bedrock_browser_login.py`` (interactive browser flow); see the
notes in that script. We deliberately *don't* drive a browser here —
keep this test fast and headless-friendly.

Run with:

    MCAPI_E2E_BEDROCK=1 uv run --active pytest \
        tests-e2e/test_bedrock_chain_live.py -v -s --log-cli-level=INFO
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest
from httpdbg import HTTPRecords, httprecord  # pyright: ignore[reportMissingImports]

from mcapi_auth.auth.bedrock_chain import BedrockAuthManager

sys.path.insert(0, str(Path(__file__).parent))
from _traffic import write_traffic_log

log = logging.getLogger(__name__)

pytestmark = pytest.mark.e2e

DEFAULT_STATE_PATH = Path.home() / ".config" / "mcapi-auth-e2e" / "bedrock_chain_state.json"
TRAFFIC_LOG = Path(__file__).parent / "BEDROCK_LIVE_TRAFFIC_LOG.md"

_TRAFFIC_INTRO = (
    "Captured via httpdbg while running `BedrockAuthManager.load_json(...)` "
    "and exercising `get_certificate_chain`, `get_bedrock_sisu`, and "
    "`get_multiplayer_token`. Bearer tokens / session tickets / cert keys "
    "have been redacted; structural diffs only.\n"
)


def _snapshot_path() -> Path:
    return Path(os.environ.get("MCAPI_E2E_BEDROCK_STATE", str(DEFAULT_STATE_PATH)))


@pytest.mark.skipif(
    os.environ.get("MCAPI_E2E_BEDROCK") != "1",
    reason="Bedrock live E2E gated on MCAPI_E2E_BEDROCK=1 (needs entitled account snapshot)",
)
@pytest.mark.skipif(
    not _snapshot_path().exists(),
    reason="Bedrock chain snapshot missing; bootstrap via /tmp/bedrock_browser_login.py first",
)
async def test_bedrock_chain_live() -> None:
    path = _snapshot_path()
    log.info("loading Bedrock chain snapshot from %s", path)
    raw = path.read_bytes()

    records = HTTPRecords()
    with httprecord(records):
        mgr = BedrockAuthManager.load_json(raw)

        log.info("exercising get_certificate_chain() …")
        cert = await mgr.get_certificate_chain()
        assert cert.mojang_jwt
        assert cert.identity_jwt
        assert mgr.cert_chain_holder is not None

        log.info("exercising get_bedrock_sisu() …")
        sisu = await mgr.get_bedrock_sisu()
        assert sisu.xsts_token.token
        assert mgr.bedrock_sisu_holder is not None

        log.info("exercising get_multiplayer_token() …")
        mp = await mgr.get_multiplayer_token()
        assert mp.token
        assert mgr.multiplayer_holder is not None

    write_traffic_log(
        records=records,
        path=TRAFFIC_LOG,
        title="Bedrock Chain Live Traffic Log",
        intro=_TRAFFIC_INTRO,
    )
    log.info("wrote traffic log to %s", TRAFFIC_LOG)

    log.info("persisting refreshed snapshot back to %s", path)
    path.write_text(mgr.dump_json(indent=2))

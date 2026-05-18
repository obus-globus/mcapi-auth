"""Tests for mcapi_auth.auth.inspect (chain introspection helpers)."""

from __future__ import annotations

import base64
import json

import respx
from whenever import Instant

from mcapi_auth import (
    AuthChain,
    MinecraftSession,
    chain_state_summary,
    describe_chain,
    describe_minecraft_token,
    redact_token,
)


def test_redact_token_none() -> None:
    assert redact_token(None) == "<none>"
    assert redact_token("") == "<none>"


def test_redact_token_short_returns_verbatim() -> None:
    assert redact_token("short", keep=8) == "short"
    assert redact_token("exactly8", keep=8) == "exactly8"


def test_redact_token_long_truncates_and_includes_length() -> None:
    long = "a" * 200
    out = redact_token(long, keep=8)
    assert out.startswith("aaaaaaaa")
    assert "200 chars" in out
    assert long not in out


def _make_session() -> MinecraftSession:
    return MinecraftSession(
        access_token="mc-tok-secret",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc-secret",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )


@respx.mock
async def test_chain_state_summary_full_session() -> None:
    chain = AuthChain.from_session(_make_session())
    rows = chain_state_summary(chain)
    names = [r.name for r in rows]
    assert names == ["msa", "xbl", "xsts", "minecraft", "profile"]
    msa = rows[0]
    assert msa.present is True
    assert msa.expired is False
    assert msa.token_preview is not None
    assert "msa-acc-" in msa.token_preview
    # XBL/XSTS not yet acquired from a bare session bridge
    assert rows[1].present is False
    assert rows[2].present is False
    # MC token IS in the session
    mc = rows[3]
    assert mc.present is True
    assert mc.token_preview is not None
    assert "mc-tok-" in mc.token_preview
    # Profile present
    profile = rows[4]
    assert profile.present is True
    assert profile.token_preview is not None
    assert "Notch" in profile.token_preview


@respx.mock
async def test_describe_chain_contains_marks_and_header() -> None:
    chain = AuthChain.from_session(_make_session())
    out = describe_chain(chain)
    assert "AuthChain" in out
    assert "client_id=" in out
    assert "msa" in out
    assert "minecraft" in out
    # never leaks raw tokens
    assert "mc-tok-secret" not in out
    assert "msa-acc-secret" not in out


def test_stage_summary_to_dict() -> None:
    chain = AuthChain.from_session(_make_session())
    rows = chain_state_summary(chain)
    d = rows[0].to_dict()
    assert d["name"] == "msa"
    assert d["present"] is True
    assert d["expired"] is False
    assert "expires_at" in d


def _b64u(payload: dict[str, object]) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_describe_minecraft_token_formats_claims() -> None:
    header = _b64u({"alg": "HS256", "typ": "JWT"})
    payload = _b64u(
        {
            "pfd": [
                {
                    "type": "mc",
                    "name": "Notch",
                    "id": "069a79f444e94726a5befca90e38aaf5",
                }
            ],
            "nbf": 1_700_000_000,
            "exp": 1_700_086_400,
        }
    )
    sig = _b64u({"sig": "fake"})
    token = f"{header}.{payload}.{sig}"
    out = describe_minecraft_token(token)
    assert "Minecraft access token" in out
    assert "Notch" in out
    assert "069a79f444e94726a5befca90e38aaf5" in out
    assert "issued at" in out
    assert "expires at" in out

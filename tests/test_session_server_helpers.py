"""Tests for the join_server convenience overload + compute_server_id_hash."""

from __future__ import annotations

import hashlib
import json

import pytest
import respx
from whenever import Instant

from mcapi_auth._constants import SESSIONSERVER_JOIN_URL
from mcapi_auth.auth.session import MinecraftSession
from mcapi_auth.auth.session_server import (
    compute_server_id_hash,
    join_server,
    join_server_with_session,
)


def _make_session() -> MinecraftSession:
    return MinecraftSession(
        access_token="mc-tok",
        refresh_token="ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-tok",
        msa_access_token_expires_at=Instant.from_timestamp(1_700_000_000),
        minecraft_access_token_expires_at=Instant.from_timestamp(1_700_086_400),
    )


@respx.mock
async def test_join_server_session_overload() -> None:
    """Positional MinecraftSession sends the session's access_token + uuid."""
    route = respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=204)
    await join_server(_make_session(), server_id="abc")
    assert route.called
    sent = json.loads(route.calls.last.request.content)
    assert sent == {
        "accessToken": "mc-tok",
        "selectedProfile": "069a79f444e94726a5befca90e38aaf5",
        "serverId": "abc",
    }


async def test_join_server_rejects_both_forms() -> None:
    with pytest.raises(TypeError, match="not both"):
        await join_server(
            _make_session(),
            access_token="other",  # type: ignore[call-overload]
            uuid="u" * 32,
            server_id="s",
        )


async def test_join_server_rejects_neither_form() -> None:
    with pytest.raises(TypeError, match="provide either"):
        await join_server(server_id="s")  # type: ignore[call-overload]


def test_compute_server_id_hash_notch_vectors() -> None:
    """The three canonical test vectors from the Mojang protocol wiki."""
    assert compute_server_id_hash("Notch", b"", b"") == "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
    assert compute_server_id_hash("jeb_", b"", b"") == "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1"
    assert compute_server_id_hash("simon", b"", b"") == "88e16a1019277b15d58faf0541e11910eb756f6"


def test_compute_server_id_hash_uses_sha1_chain() -> None:
    server_id = "x" * 20
    shared = b"\x01" * 16
    der = b"\xde\xad\xbe\xef" * 32
    out = compute_server_id_hash(server_id, shared, der)
    # Round-trip: redo the hash and verify our signed-hex matches
    raw = hashlib.sha1(server_id.encode("ascii") + shared + der, usedforsecurity=False).digest()
    n = int.from_bytes(raw, byteorder="big", signed=True)
    expected = ("-" + format(-n, "x")) if n < 0 else format(n, "x")
    assert out == expected


@respx.mock
async def test_join_server_with_session_posts_hash() -> None:
    route = respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=204)
    session = _make_session()
    await join_server_with_session(
        session,
        server_id_str="Notch",
        shared_secret=b"",
        public_key_der=b"",
    )
    sent = json.loads(route.calls.last.request.content)
    assert sent["serverId"] == "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
    assert sent["accessToken"] == "mc-tok"

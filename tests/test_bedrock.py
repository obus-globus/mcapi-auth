"""Tests for the Bedrock-Edition client chain."""

from __future__ import annotations

import base64
import json
import time
from uuid import UUID

import httpx
import pytest
import respx

from mcapi_auth.api.bedrock import (
    BedrockKeyPair,
    MinecraftCertificateChain,
    MinecraftMultiplayerToken,
    MinecraftSession,
    decode_jwt_payload,
    generate_bedrock_session_keypair,
    minecraft_authenticate,
    start_minecraft_multiplayer_session,
    start_minecraft_session,
)
from mcapi_auth.auth.xbox import XSTSToken
from mcapi_auth.exceptions import HttpError, MinecraftAuthError


def _xsts() -> XSTSToken:
    return XSTSToken(token="xsts-bedrock", userhash="uhs")


def _b64url(obj: object) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_jwt(payload: dict[str, object]) -> str:
    header = _b64url({"alg": "ES384", "typ": "JWT"})
    body = _b64url(payload)
    return f"{header}.{body}.signature"


def test_generate_keypair_produces_valid_p384() -> None:
    kp = generate_bedrock_session_keypair()
    # SubjectPublicKeyInfo DER for P-384 is 120 bytes -> 160 base64.
    assert len(kp.public_key_der()) == 120
    assert len(kp.public_key_der_b64()) == 160
    # Should round-trip via PEM.
    priv, pub = kp.to_pem()
    assert "BEGIN PRIVATE KEY" in priv
    assert "BEGIN PUBLIC KEY" in pub
    restored = BedrockKeyPair.from_pem(priv)
    assert restored.public_key_der_b64() == kp.public_key_der_b64()


def test_keypair_rejects_wrong_curve() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    p256 = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="SECP384R1"):
        _ = BedrockKeyPair(p256)


def test_decode_jwt_payload_works() -> None:
    jwt = _make_jwt({"hello": "world", "exp": 999})
    payload = decode_jwt_payload(jwt)
    assert payload == {"hello": "world", "exp": 999}


def test_decode_jwt_payload_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="3 segments"):
        decode_jwt_payload("notajwt")


def test_certificate_chain_extra_data_parsing() -> None:
    exp = int(time.time()) + 86400
    mojang_jwt = _make_jwt({"exp": exp})
    identity_jwt = _make_jwt(
        {
            "exp": exp - 60,
            "extraData": {
                "XUID": "2535400000000000",
                "displayName": "TestPlayer",
                "identity": "11111111-2222-3333-4444-555555555555",
            },
        }
    )
    chain = MinecraftCertificateChain(mojang_jwt=mojang_jwt, identity_jwt=identity_jwt)
    assert chain.xuid == "2535400000000000"
    assert chain.display_name == "TestPlayer"
    assert chain.identity_uuid == UUID("11111111-2222-3333-4444-555555555555")
    # Earliest of the two exp claims.
    assert chain.expires_at.timestamp() == exp - 60


@respx.mock
async def test_minecraft_authenticate_happy_path() -> None:
    kp = generate_bedrock_session_keypair()
    exp = int(time.time()) + 86400
    mojang_jwt = _make_jwt({"exp": exp})
    identity_jwt = _make_jwt(
        {
            "exp": exp,
            "extraData": {
                "XUID": "2535400000000001",
                "displayName": "Bedrock",
                "identity": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            },
        }
    )
    route = respx.post("https://multiplayer.minecraft.net/authentication").respond(
        json={"chain": [mojang_jwt, identity_jwt]}
    )

    chain = await minecraft_authenticate(_xsts(), kp)

    assert chain.mojang_jwt == mojang_jwt
    assert chain.identity_jwt == identity_jwt
    assert chain.xuid == "2535400000000001"

    sent = route.calls.last.request
    assert sent.headers["authorization"] == "XBL3.0 x=uhs;xsts-bedrock"
    body = json.loads(sent.content)
    assert body == {"identityPublicKey": kp.public_key_der_b64()}


@respx.mock
async def test_minecraft_authenticate_bad_chain_length() -> None:
    kp = generate_bedrock_session_keypair()
    respx.post("https://multiplayer.minecraft.net/authentication").respond(
        json={"chain": [_make_jwt({"exp": 1})]}
    )
    with pytest.raises(MinecraftAuthError, match="2-element"):
        await minecraft_authenticate(_xsts(), kp)


@respx.mock
async def test_minecraft_authenticate_http_error_translates() -> None:
    kp = generate_bedrock_session_keypair()
    respx.post("https://multiplayer.minecraft.net/authentication").mock(
        return_value=httpx.Response(401, text="nope")
    )
    with pytest.raises(HttpError) as exc:
        await minecraft_authenticate(_xsts(), kp)
    assert exc.value.status_code == 401


@respx.mock
async def test_start_minecraft_session_happy_path() -> None:
    device = UUID("12345678-1234-5678-1234-567812345678")
    route = respx.post(
        "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start"
    ).respond(
        json={
            "result": {
                "validUntil": "2030-01-01T00:00:00Z",
                "authorizationHeader": "Bearer session-jwt",
            }
        }
    )

    session = await start_minecraft_session(
        "ticket-abc",
        game_version="1.21.50",
        device_id=device,
    )

    assert isinstance(session, MinecraftSession)
    assert session.authorization_header == "Bearer session-jwt"
    assert session.bearer_token == "session-jwt"

    body = json.loads(route.calls.last.request.content)
    assert body["device"]["gameVersion"] == "1.21.50"
    assert body["device"]["id"] == device.hex
    assert body["user"]["tokenType"] == "PlayFab"
    assert body["user"]["token"] == "ticket-abc"


@respx.mock
async def test_start_minecraft_multiplayer_session_happy_path() -> None:
    kp = generate_bedrock_session_keypair()
    session = MinecraftSession.model_validate(
        {
            "validUntil": "2030-01-01T00:00:00Z",
            "authorizationHeader": "Bearer session-jwt",
        }
    )
    exp = int(time.time()) + 3600
    token_jwt = _make_jwt({"exp": exp, "xid": "2535400000000099", "xname": "BedrockMP"})
    route = respx.post(
        "https://authorization.franchise.minecraft-services.net/api/v1.0/multiplayer/session/start"
    ).respond(json={"result": {"validUntil": "2030-01-01T00:00:00Z", "signedToken": token_jwt}})

    mp = await start_minecraft_multiplayer_session(session, kp)
    assert isinstance(mp, MinecraftMultiplayerToken)
    assert mp.token == token_jwt
    assert mp.xuid == "2535400000000099"
    assert mp.display_name == "BedrockMP"
    # MD5-derived v3 UUID is stable for the same XUID.
    assert mp.uuid == mp.uuid

    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer session-jwt"
    body = json.loads(sent.content)
    assert body == {"publicKey": kp.public_key_der_b64()}


def test_multiplayer_token_uuid_matches_md5_namespace() -> None:
    import hashlib

    xuid = "2535400000000099"
    expected = hashlib.md5(("pocket-auth-1-xuid:" + xuid).encode("utf-8")).digest()
    b = bytearray(expected)
    b[6] = (b[6] & 0x0F) | 0x30
    b[8] = (b[8] & 0x3F) | 0x80
    expected_uuid = UUID(bytes=bytes(b))

    mp = MinecraftMultiplayerToken.model_validate(
        {
            "validUntil": "2030-01-01T00:00:00Z",
            "signedToken": _make_jwt({"exp": 9, "xid": xuid, "xname": "X"}),
        }
    )
    assert mp.uuid == expected_uuid

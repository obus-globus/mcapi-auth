"""Tests for player chat-signing certificates."""

import base64

import respx
from whenever import Instant

from mcapi_auth import (
    MinecraftKeyPair,
    MinecraftPlayerCertificates,
    MinecraftSession,
    fetch_player_certificates,
)
from mcapi_auth.api.player_certificates import PLAYER_CERTIFICATES_URL

# Two trivially-small valid base64 PEM bodies (not real RSA keys; we
# only test the wire parsing + base64 decoding).
_PUB_PEM = "-----BEGIN RSA PUBLIC KEY-----\nQUJDREVG\n-----END RSA PUBLIC KEY-----"
_PRIV_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMTIzNDU2\n-----END RSA PRIVATE KEY-----"


def _wire_response() -> dict[str, object]:
    return {
        "keyPair": {"publicKey": _PUB_PEM, "privateKey": _PRIV_PEM},
        "publicKeySignatureV2": base64.b64encode(b"signature-v2").decode(),
        "publicKeySignature": base64.b64encode(b"signature-legacy").decode(),
        "expiresAt": "2030-01-01T00:00:00Z",
        "refreshedAfter": "2029-01-01T00:00:00Z",
    }


def _session() -> MinecraftSession:
    return MinecraftSession(
        access_token="mc-tok",
        refresh_token="ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=3600),
    )


@respx.mock
async def test_fetch_player_certificates_parses_payload() -> None:
    respx.post(PLAYER_CERTIFICATES_URL).respond(json=_wire_response())
    certs = await fetch_player_certificates(_session())
    assert isinstance(certs, MinecraftPlayerCertificates)
    assert isinstance(certs.key_pair, MinecraftKeyPair)
    assert certs.key_pair.public_key.startswith("-----BEGIN RSA PUBLIC KEY")
    assert certs.public_key_signature_v2_bytes == b"signature-v2"
    legacy = certs.legacy_public_key_signature_bytes
    assert legacy == b"signature-legacy"


@respx.mock
async def test_key_pair_der_decoding() -> None:
    respx.post(PLAYER_CERTIFICATES_URL).respond(json=_wire_response())
    certs = await fetch_player_certificates("just-a-token")
    assert certs.key_pair.public_key_der() == b"ABCDEF"
    assert certs.key_pair.private_key_der() == b"123456"


@respx.mock
async def test_missing_legacy_signature_is_optional() -> None:
    wire = _wire_response()
    del wire["publicKeySignature"]
    respx.post(PLAYER_CERTIFICATES_URL).respond(json=wire)
    certs = await fetch_player_certificates(_session())
    assert certs.legacy_public_key_signature is None
    assert certs.legacy_public_key_signature_bytes is None


@respx.mock
async def test_unauthorized_raises_typed_error() -> None:
    from mcapi_auth import UnauthorizedError

    respx.post(PLAYER_CERTIFICATES_URL).respond(status_code=401, text="invalid token")
    import pytest

    with pytest.raises(UnauthorizedError):
        await fetch_player_certificates(_session())

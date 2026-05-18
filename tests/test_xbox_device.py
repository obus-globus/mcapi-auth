"""Tests for the Sisu / XBL-device-token flow."""

from __future__ import annotations

import base64
import json
import struct
from uuid import UUID

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from whenever import Instant

from mcapi_auth.auth.xbox_device import (
    XBL_AUTH_RELYING_PARTY,
    XBL_XSTS_BEDROCK_RELYING_PARTY,
    XblDeviceKeyPair,
    authenticate_xbl_device,
    sisu_authorize,
)
from mcapi_auth.exceptions import XboxAuthError, XSTSError


def test_generate_keypair_proof_key_shape() -> None:
    kp = XblDeviceKeyPair.generate()
    proof = kp.proof_key()
    assert proof["kty"] == "EC"
    assert proof["alg"] == "ES256"
    assert proof["crv"] == "P-256"
    assert proof["use"] == "sig"
    # base64url, no padding, 32 bytes -> 43 chars.
    for coord in ("x", "y"):
        assert len(proof[coord]) == 43
        # Decode-then-encode round-trip should be lossless.
        raw = base64.urlsafe_b64decode(proof[coord] + "==")
        assert len(raw) == 32


def test_keypair_pem_roundtrip() -> None:
    kp = XblDeviceKeyPair.generate()
    pem = kp.private_key_pem()
    assert "BEGIN PRIVATE KEY" in pem
    restored = XblDeviceKeyPair.from_pem(pem)
    assert restored.proof_key() == kp.proof_key()


def test_keypair_rejects_wrong_curve() -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="SECP256R1"):
        XblDeviceKeyPair(p384)


def test_signature_header_byte_layout() -> None:
    """Decode a signature header and verify it against the keypair."""
    kp = XblDeviceKeyPair.generate()
    timestamp = Instant.from_timestamp(1_700_000_000)  # fixed value for stability

    header_b64 = kp.signature_header(
        method="POST",
        path_and_query="/device/authenticate",
        body=b'{"hello":"world"}',
        timestamp=timestamp,
    )
    header = base64.b64decode(header_b64)
    assert len(header) == 4 + 8 + 64  # policy + windows_ts + raw r||s
    policy_version = struct.unpack(">I", header[:4])[0]
    windows_ts = struct.unpack(">Q", header[4:12])[0]
    raw_sig = header[12:]
    assert policy_version == 1

    # Windows timestamp = (unix_seconds + 11644473600) * 1e7 (100ns units).
    expected_ts = (1_700_000_000 + 11_644_473_600) * 10_000_000
    assert windows_ts == expected_ts

    # Verify the signature against the keypair's public half.
    sign_body = (
        struct.pack(">I", 1)
        + b"\x00"
        + struct.pack(">Q", windows_ts)
        + b"\x00"
        + b"POST"
        + b"\x00"
        + b"/device/authenticate"
        + b"\x00"
        + b""  # no Authorization header
        + b"\x00"
        + b'{"hello":"world"}'
        + b"\x00"
    )
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils

    der = utils.encode_dss_signature(r, s)
    # If this verifies, the signature is structurally correct.
    kp._private_key.public_key().verify(der, sign_body, ec.ECDSA(hashes.SHA256()))
    # Sanity: decode_dss_signature returns the same (r, s).
    assert decode_dss_signature(der) == (r, s)


@respx.mock
async def test_authenticate_xbl_device_happy_path() -> None:
    kp = XblDeviceKeyPair.generate()
    device_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    route = respx.post("https://device.auth.xboxlive.com/device/authenticate").respond(
        json={
            "Token": "device-jwt",
            "NotAfter": "2030-01-01T00:00:00Z",
            "DisplayClaims": {"xdi": {"did": "device-id-echoed"}},
        }
    )

    token = await authenticate_xbl_device(kp, device_id=device_id)

    assert token.token == "device-jwt"
    assert token.device_id == "device-id-echoed"

    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body["RelyingParty"] == XBL_AUTH_RELYING_PARTY
    assert body["Properties"]["DeviceType"] == "Win32"
    assert body["Properties"]["Id"] == "{" + str(device_id) + "}"
    assert body["Properties"]["AuthMethod"] == "ProofOfPossession"
    assert body["Properties"]["ProofKey"]["crv"] == "P-256"
    assert "Signature" in sent.headers
    assert sent.headers["x-xbl-contract-version"] == "1"


@respx.mock
async def test_authenticate_xbl_device_http_error() -> None:
    kp = XblDeviceKeyPair.generate()
    respx.post("https://device.auth.xboxlive.com/device/authenticate").mock(
        return_value=httpx.Response(500, text="server angry")
    )
    with pytest.raises(XboxAuthError, match="status=500"):
        await authenticate_xbl_device(kp, device_id=UUID(int=0))


@respx.mock
async def test_sisu_authorize_happy_path() -> None:
    kp = XblDeviceKeyPair.generate()
    device_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    # Mock device-auth so we get a real XblDeviceToken to pass into sisu.
    respx.post("https://device.auth.xboxlive.com/device/authenticate").respond(
        json={
            "Token": "device-jwt",
            "NotAfter": "2030-01-01T00:00:00Z",
            "DisplayClaims": {"xdi": {"did": "device-id"}},
        }
    )
    device_token = await authenticate_xbl_device(kp, device_id=device_id)

    sisu_route = respx.post("https://sisu.xboxlive.com/authorize").respond(
        json={
            "UserToken": {
                "Token": "user-jwt",
                "NotAfter": "2030-01-01T00:00:00Z",
                "DisplayClaims": {"xui": [{"uhs": "userhash-abc"}]},
            },
            "TitleToken": {
                "Token": "title-jwt",
                "NotAfter": "2030-01-01T00:00:00Z",
                "DisplayClaims": {"xti": {"tid": "title-123"}},
            },
            "AuthorizationToken": {
                "Token": "xsts-jwt",
                "NotAfter": "2030-01-01T00:00:00Z",
                "DisplayClaims": {"xui": [{"uhs": "userhash-abc"}]},
            },
        }
    )

    sisu = await sisu_authorize(
        "msa-access-token",
        device_token,
        kp,
        client_id="00000000-0000-0000-0000-000000000abc",
        relying_party=XBL_XSTS_BEDROCK_RELYING_PARTY,
    )

    assert sisu.user_token.token == "user-jwt"
    assert sisu.user_token.userhash == "userhash-abc"
    assert sisu.title_token.token == "title-jwt"
    assert sisu.title_token.title_id == "title-123"
    assert sisu.xsts_token.token == "xsts-jwt"
    assert sisu.xsts_token.userhash == "userhash-abc"

    sent = sisu_route.calls.last.request
    body = json.loads(sent.content)
    assert body["AccessToken"] == "t=msa-access-token"
    assert body["DeviceToken"] == "device-jwt"
    assert body["AppId"] == "00000000-0000-0000-0000-000000000abc"
    assert body["Sandbox"] == "RETAIL"
    assert body["UseModernGamertag"] is True
    assert body["RelyingParty"] == XBL_XSTS_BEDROCK_RELYING_PARTY
    assert body["ProofKey"]["crv"] == "P-256"
    assert "Signature" in sent.headers


@respx.mock
async def test_sisu_authorize_translates_xerr() -> None:
    kp = XblDeviceKeyPair.generate()
    respx.post("https://sisu.xboxlive.com/authorize").respond(
        status_code=401,
        json={"XErr": 2148916233, "Identity": "0", "Message": "", "Redirect": ""},
    )
    device_token = type(
        "FakeDeviceToken",
        (),
        {"token": "device-jwt"},
    )()
    with pytest.raises(XSTSError):
        await sisu_authorize(
            "msa",
            device_token,  # type: ignore[arg-type]
            kp,
            client_id="title-id",
            relying_party=XBL_XSTS_BEDROCK_RELYING_PARTY,
        )

"""Tests for the Minecraft access-token JWT decoder."""

import base64
import json
from typing import Any

import pytest

from mcapi_auth.auth.token import (
    MinecraftTokenDecodeError,
    decode_minecraft_access_token,
)


def _make_jwt(payload: dict[str, Any]) -> str:
    """Build a JWS-shaped string with the given payload (no real signature)."""

    def _segment(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = _segment({"alg": "HS256", "typ": "JWT"})
    body = _segment(payload)
    return f"{header}.{body}.signature-placeholder"


def test_decode_extracts_exp_and_nbf() -> None:
    from whenever import Instant

    token = _make_jwt({"exp": 1_800_000_000, "nbf": 1_700_000_000})
    info = decode_minecraft_access_token(token)
    assert info.expires_at == Instant.from_timestamp(1_800_000_000.0)
    assert info.issued_at == Instant.from_timestamp(1_700_000_000.0)


def test_decode_extracts_pfd_profile() -> None:
    token = _make_jwt(
        {
            "exp": 1_800_000_000,
            "pfd": [
                {"type": "xbox", "id": "xbox-id"},
                {"type": "mc", "name": "Notch", "id": "069a79f4-44e9-4726-a5be-fca90e38aaf5"},
            ],
        }
    )
    info = decode_minecraft_access_token(token)
    assert info.username == "Notch"
    assert info.uuid == "069a79f444e94726a5befca90e38aaf5"


def test_decode_falls_back_to_profiles_mc() -> None:
    token = _make_jwt({"profiles": {"mc": "069a79f4-44e9-4726-a5be-fca90e38aaf5"}})
    info = decode_minecraft_access_token(token)
    assert info.username is None
    assert info.uuid == "069a79f444e94726a5befca90e38aaf5"


def test_decode_returns_none_for_missing_claims() -> None:
    token = _make_jwt({})
    info = decode_minecraft_access_token(token)
    assert info.expires_at is None
    assert info.username is None
    assert info.uuid is None
    assert info.raw_claims == {}


def test_decode_rejects_empty_string() -> None:
    with pytest.raises(MinecraftTokenDecodeError, match="non-empty"):
        _ = decode_minecraft_access_token("")


def test_decode_rejects_wrong_segment_count() -> None:
    with pytest.raises(MinecraftTokenDecodeError, match="three"):
        _ = decode_minecraft_access_token("a.b")


def test_decode_rejects_bad_base64() -> None:
    # A non-ASCII char in the payload segment can't be base64-decoded.
    with pytest.raises(MinecraftTokenDecodeError, match="base64url"):
        _ = decode_minecraft_access_token("h.ñ.s")


def test_decode_rejects_bad_json() -> None:
    bad_payload = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    with pytest.raises(MinecraftTokenDecodeError, match="JSON"):
        _ = decode_minecraft_access_token(f"h.{bad_payload}.s")


def test_decode_rejects_non_object_payload() -> None:
    array_payload = base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode()
    with pytest.raises(MinecraftTokenDecodeError, match="expected object"):
        _ = decode_minecraft_access_token(f"h.{array_payload}.s")


def test_decode_ignores_non_mc_pfd_entries() -> None:
    token = _make_jwt({"pfd": [{"type": "xbox", "name": "x", "id": "x"}]})
    info = decode_minecraft_access_token(token)
    assert info.username is None
    assert info.uuid is None

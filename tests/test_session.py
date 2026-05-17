"""Tests for the MinecraftSession dataclass."""

import pytest
from pydantic import ValidationError
from whenever import Instant

from mcapi_auth.auth import MinecraftSession


def _make(**overrides: object) -> MinecraftSession:
    defaults: dict[str, object] = dict(
        access_token="mc-access",
        refresh_token="ms-refresh",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-access",
        msa_access_token_expires_at=Instant.from_timestamp(2_000_000_000.0),
        minecraft_access_token_expires_at=Instant.from_timestamp(2_000_000_000.0),
    )
    defaults.update(overrides)
    return MinecraftSession(**defaults)  # type: ignore[arg-type]


def test_uuid_dashed_inserts_dashes_for_32_char_input() -> None:
    s = _make()
    assert s.uuid_dashed == "069a79f4-44e9-4726-a5be-fca90e38aaf5"


def test_uuid_dashed_passes_through_already_dashed() -> None:
    s = _make(uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5")
    assert s.uuid_dashed == "069a79f4-44e9-4726-a5be-fca90e38aaf5"


def test_uuid_dashed_returns_input_for_unexpected_length() -> None:
    s = _make(uuid="weird")
    assert s.uuid_dashed == "weird"


def test_minecraft_token_seconds_remaining_is_signed() -> None:
    s = _make(minecraft_access_token_expires_at=Instant.from_timestamp(100.0))
    assert s.minecraft_token_seconds_remaining(now=Instant.from_timestamp(80.0)) == 20.0
    assert s.minecraft_token_seconds_remaining(now=Instant.from_timestamp(120.0)) == -20.0


def test_minecraft_token_expired_respects_leeway() -> None:
    s = _make(minecraft_access_token_expires_at=Instant.from_timestamp(100.0))
    assert not s.minecraft_token_expired(now=Instant.from_timestamp(80.0), leeway=10.0)
    assert s.minecraft_token_expired(now=Instant.from_timestamp(80.0), leeway=25.0)
    assert s.minecraft_token_expired(now=Instant.from_timestamp(200.0))


def test_session_is_frozen() -> None:
    s = _make()
    with pytest.raises(ValidationError):
        s.username = "Jeb_"  # type: ignore[misc]

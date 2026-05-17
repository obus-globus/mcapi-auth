"""Test MinecraftSession dump/load round-trip."""

from whenever import Instant

from mcapi_auth.auth.session import MinecraftSession


def test_dump_load_round_trip() -> None:
    s = MinecraftSession(
        access_token="mc-tok",
        refresh_token="ref-tok",
        uuid="069a79f4448e4a07b1a32e3a0e1d1234",
        username="player",
        msa_access_token="msa-tok",
        msa_access_token_expires_at=Instant.from_timestamp(1_700_000_000),
        minecraft_access_token_expires_at=Instant.from_timestamp(1_700_086_400),
    )
    blob = s.dump()
    assert isinstance(blob, str)
    assert "mc-tok" in blob
    rt = MinecraftSession.load(blob)
    assert rt.access_token == s.access_token
    assert rt.refresh_token == s.refresh_token
    assert rt.uuid == s.uuid
    assert rt.username == s.username
    assert rt.msa_access_token == s.msa_access_token
    assert rt.msa_access_token_expires_at == s.msa_access_token_expires_at
    assert rt.minecraft_access_token_expires_at == s.minecraft_access_token_expires_at

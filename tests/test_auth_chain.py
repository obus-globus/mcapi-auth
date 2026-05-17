"""Tests for :class:`mcapi_auth.AuthChain`."""

import respx
from whenever import Instant

from mcapi_auth import (
    AuthChain,
    MinecraftSession,
    MsaApplicationConfig,
)
from mcapi_auth._constants import (
    MC_LOGIN_WITH_XBOX_URL,
    MC_PROFILE_URL,
    MSA_TOKEN_URL,
    XBL_AUTH_URL,
    XSTS_AUTH_URL,
)


def _wire_full_chain(
    *,
    msa_access: str = "msa-acc",
    msa_refresh: str = "msa-ref",
    msa_expires_in: int = 3600,
    mc_access: str = "mc-tok",
    mc_expires_in: int = 86400,
    uuid: str = "069a79f444e94726a5befca90e38aaf5",
    username: str = "Notch",
) -> None:
    respx.post(MSA_TOKEN_URL).respond(
        json={
            "access_token": msa_access,
            "refresh_token": msa_refresh,
            "expires_in": msa_expires_in,
        }
    )
    respx.post(XBL_AUTH_URL).respond(
        json={"Token": "xbl-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(XSTS_AUTH_URL).respond(
        json={"Token": "xsts-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(
        json={"access_token": mc_access, "expires_in": mc_expires_in}
    )
    respx.get(MC_PROFILE_URL).respond(json={"id": uuid, "name": username})


@respx.mock
async def test_from_session_round_trip() -> None:
    session = MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )
    chain = AuthChain.from_session(session)
    assert (await chain.get_msa_tokens()).access_token == "msa-acc"
    mc = await chain.get_minecraft_token()
    assert mc.access_token == "mc-tok"
    profile = await chain.get_profile()
    assert profile.username == "Notch"


@respx.mock
async def test_dump_and_load_json_round_trip() -> None:
    _wire_full_chain()
    session = MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )
    chain = AuthChain.from_session(session)
    # Drive the chain so XBL+XSTS are populated.
    await chain.get_minecraft_token()
    blob = chain.dump_json()

    restored = AuthChain.load_json(blob, app=MsaApplicationConfig.v2())
    # Cached values should be intact — get_minecraft_token must NOT call
    # the network because nothing's expired.
    assert restored.minecraft_holder is not None
    assert restored.minecraft_holder.get_cached().access_token == "mc-tok"


@respx.mock
async def test_msa_rotation_invalidates_downstream() -> None:
    _wire_full_chain()
    session = MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=-10),  # expired
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )
    chain = AuthChain.from_session(session)
    # Force the MSA to refresh.
    new_msa = await chain.get_msa_tokens()
    assert new_msa.access_token == "msa-acc"  # what the mock returns
    # XBL must NOT be cached anymore.
    assert chain.xbl_holder is None


@respx.mock
async def test_chain_listener_fires_on_each_stage() -> None:
    _wire_full_chain()
    session = MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=-10),  # mc expired
    )
    chain = AuthChain.from_session(session)
    rotations: list[str] = []
    chain.on_change(lambda stage, _old, _new: rotations.append(stage))
    await chain.get_minecraft_token()
    # mc was expired so it rotates; xbl + xsts get built fresh
    assert "minecraft" in rotations
    assert "xbl" in rotations
    assert "xsts" in rotations


@respx.mock
async def test_to_session_returns_flat_snapshot() -> None:
    _wire_full_chain()
    session = MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )
    chain = AuthChain.from_session(session)
    flat = await chain.to_session()
    assert flat.uuid == session.uuid
    assert flat.username == session.username
    assert flat.refresh_token == "msa-ref"

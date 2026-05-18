"""Tests for the Realms API surface."""

import httpx
import pytest
import respx
from whenever import Instant

from mcapi_auth import (
    MinecraftSession,
    RealmsTosError,
    accept_realms_tos,
    fetch_realms_join_info,
    fetch_realms_worlds,
    is_realms_available,
    is_realms_tos_agreed,
)
from mcapi_auth.api.realms import REALMS_BASE


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
async def test_fetch_realms_worlds() -> None:
    respx.get(f"{REALMS_BASE}/worlds").respond(
        json={
            "servers": [
                {
                    "id": 12345,
                    "name": "MyRealm",
                    "owner": "Notch",
                    "expired": False,
                    "minigameId": None,
                    "activeSlot": 1,
                }
            ]
        }
    )
    worlds = await fetch_realms_worlds(_session())
    assert len(worlds) == 1
    assert worlds[0].world_id == 12345
    assert worlds[0].name == "MyRealm"
    assert worlds[0].active_slot == 1


@respx.mock
async def test_fetch_realms_join_info() -> None:
    respx.get(f"{REALMS_BASE}/worlds/v1/42/join/pc").respond(
        json={"address": "realm.minecraft.net:25565"}
    )
    info = await fetch_realms_join_info(_session(), 42)
    assert info.address == "realm.minecraft.net:25565"
    assert info.host == "realm.minecraft.net"
    assert info.port == 25565


@respx.mock
async def test_tos_not_accepted_surfaces_typed_error() -> None:
    respx.get(f"{REALMS_BASE}/worlds").respond(
        status_code=401, text="terms-of-service-not-accepted"
    )
    with pytest.raises(RealmsTosError):
        await fetch_realms_worlds(_session())


@respx.mock
async def test_is_realms_available_returns_bool() -> None:
    respx.get(f"{REALMS_BASE}/mco/available").respond(text="true")
    assert await is_realms_available(_session()) is True
    respx.get(f"{REALMS_BASE}/mco/available").respond(text="false")
    assert await is_realms_available(_session()) is False


@respx.mock
async def test_is_realms_tos_agreed_returns_false_when_unagreed() -> None:
    respx.get(f"{REALMS_BASE}/mco/available").respond(
        status_code=401, text='{"errorCode":"terms-of-service-not-accepted"}'
    )
    assert await is_realms_tos_agreed(_session()) is False


@respx.mock
async def test_is_realms_tos_agreed_returns_true_when_endpoint_succeeds() -> None:
    respx.get(f"{REALMS_BASE}/mco/available").respond(text="true")
    assert await is_realms_tos_agreed(_session()) is True


@respx.mock
async def test_accept_realms_tos() -> None:
    route = respx.post(f"{REALMS_BASE}/mco/tos/agreed").respond(status_code=204)
    await accept_realms_tos(_session())
    assert route.called


@respx.mock
async def test_realms_cookie_header_format() -> None:
    captured: dict[str, str] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers.get("cookie", "")
        return httpx.Response(200, json={"servers": []})

    respx.get(f"{REALMS_BASE}/worlds").mock(side_effect=_capture)
    await fetch_realms_worlds(_session())
    cookie = captured["cookie"]
    assert "sid=token:mc-tok:069a79f444e94726a5befca90e38aaf5" in cookie
    assert "user=Notch" in cookie
    assert "version=" in cookie


async def test_realms_requires_identity_for_raw_token() -> None:
    with pytest.raises(TypeError, match="uuid \\+ username"):
        await fetch_realms_worlds("just-a-token")  # type: ignore[arg-type]

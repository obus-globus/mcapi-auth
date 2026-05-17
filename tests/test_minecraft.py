"""Tests for Mojang exchange + profile fetch."""

import pytest
import respx

from mcapi_auth._constants import MC_LOGIN_WITH_XBOX_URL, MC_PROFILE_URL
from mcapi_auth.auth.minecraft import fetch_profile, login_with_xbox
from mcapi_auth.exceptions import MinecraftAuthError, MinecraftProfileNotFoundError


@respx.mock
async def test_login_with_xbox_happy_path() -> None:
    route = respx.post(MC_LOGIN_WITH_XBOX_URL).respond(
        json={"access_token": "mc-tok", "expires_in": 86400}
    )
    token = await login_with_xbox("uhs", "xsts-tok")
    assert token.access_token == "mc-tok"
    # Verify the identityToken header was constructed correctly.
    assert route.called
    request = route.calls.last.request
    body = request.content.decode()
    assert "XBL3.0 x=uhs;xsts-tok" in body


@respx.mock
async def test_login_with_xbox_raises_on_5xx() -> None:
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(status_code=502, text="bad gateway")
    with pytest.raises(MinecraftAuthError, match="status=502"):
        _ = await login_with_xbox("uhs", "xsts")


@respx.mock
async def test_login_with_xbox_raises_on_missing_fields() -> None:
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(json={"expires_in": 60})
    with pytest.raises(MinecraftAuthError, match="access_token"):
        _ = await login_with_xbox("uhs", "xsts")


@respx.mock
async def test_fetch_profile_happy_path() -> None:
    respx.get(MC_PROFILE_URL).respond(
        json={"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"}
    )
    profile = await fetch_profile("mc-tok")
    assert profile.uuid == "069a79f444e94726a5befca90e38aaf5"
    assert profile.username == "Notch"


@respx.mock
async def test_fetch_profile_404_means_not_owned() -> None:
    respx.get(MC_PROFILE_URL).respond(status_code=404, text="")
    with pytest.raises(MinecraftProfileNotFoundError):
        _ = await fetch_profile("mc-tok")


@respx.mock
async def test_fetch_profile_other_errors_raise_generic() -> None:
    respx.get(MC_PROFILE_URL).respond(status_code=500, text="boom")
    with pytest.raises(MinecraftAuthError, match="status=500"):
        _ = await fetch_profile("mc-tok")


@respx.mock
async def test_fetch_profile_sends_bearer_header() -> None:
    route = respx.get(MC_PROFILE_URL).respond(json={"id": "abc", "name": "n"})
    _ = await fetch_profile("the-token")
    assert route.calls.last.request.headers["Authorization"] == "Bearer the-token"

"""Tests for the sessionserver ``joinServer`` call."""

import json

import pytest
import respx

from mcapi_auth._constants import SESSIONSERVER_JOIN_URL
from mcapi_auth.auth.session_server import JoinServerError, join_server


@respx.mock
async def test_join_server_success() -> None:
    route = respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=204)
    await join_server(
        access_token="mc-tok",
        uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
        server_id="abcdef0123",
    )
    assert route.called
    sent = json.loads(route.calls.last.request.content)
    assert sent == {
        "accessToken": "mc-tok",
        "selectedProfile": "069a79f444e94726a5befca90e38aaf5",
        "serverId": "abcdef0123",
    }


@respx.mock
async def test_join_server_accepts_undashed_uuid() -> None:
    route = respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=204)
    await join_server(
        access_token="t",
        uuid="069a79f444e94726a5befca90e38aaf5",
        server_id="s",
    )
    sent = json.loads(route.calls.last.request.content)
    assert sent["selectedProfile"] == "069a79f444e94726a5befca90e38aaf5"


@respx.mock
async def test_join_server_raises_on_403() -> None:
    respx.post(SESSIONSERVER_JOIN_URL).respond(
        status_code=403, json={"error": "ForbiddenOperationException"}
    )
    with pytest.raises(JoinServerError) as info:
        await join_server(access_token="bad", uuid="u" * 32, server_id="s")
    assert info.value.status_code == 403
    assert "ForbiddenOperationException" in info.value.body


@respx.mock
async def test_join_server_raises_on_503() -> None:
    respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=503, text="down")
    with pytest.raises(JoinServerError) as info:
        await join_server(access_token="t", uuid="u" * 32, server_id="s")
    assert info.value.status_code == 503
    assert info.value.body == "down"


@pytest.mark.parametrize("status", [400, 429, 500, 502])
@respx.mock
async def test_join_server_raises_on_misc_status_codes(status: int) -> None:
    respx.post(SESSIONSERVER_JOIN_URL).respond(status_code=status, text="nope")
    with pytest.raises(JoinServerError) as info:
        await join_server(access_token="t", uuid="u" * 32, server_id="s")
    assert info.value.status_code == status

"""Tests for PlayFab login (Bedrock telemetry)."""

import pytest
import respx
from httpx import Response

from mcapi_auth import (
    BEDROCK_PLAYFAB_TITLE_ID,
    EDU_PLAYFAB_TITLE_ID,
    PlayFabEntityToken,
    PlayFabError,
    PlayFabToken,
    playfab_get_entity_token,
    playfab_login_with_xbox,
)
from mcapi_auth.auth.xbox import XSTSToken


def _xsts() -> XSTSToken:
    return XSTSToken(token="xsts-token", userhash="uhs")


def _login_payload() -> dict[str, object]:
    return {
        "code": 200,
        "status": "OK",
        "data": {
            "SessionTicket": "session-ticket-abc",
            "PlayFabId": "PF1234",
            "EntityToken": {
                "EntityToken": "entity-jwt",
                "TokenExpiration": "2030-01-01T00:00:00Z",
                "Entity": {"Id": "EID1234", "Type": "title_player_account"},
            },
        },
    }


@respx.mock
async def test_login_with_xbox_parses_full_response() -> None:
    url = "https://20ca2.playfabapi.com/Client/LoginWithXbox"
    route = respx.post(url).respond(json=_login_payload())

    token = await playfab_login_with_xbox(_xsts())

    assert isinstance(token, PlayFabToken)
    assert token.play_fab_id == "PF1234"
    assert token.session_ticket == "session-ticket-abc"
    assert token.entity_token.token == "entity-jwt"
    assert token.entity_token.entity_id == "EID1234"
    assert token.entity_token.entity_type == "title_player_account"
    # Expiry delegated.
    assert token.expires_at == token.entity_token.expires_at

    # Request body sanity check.
    assert route.called
    sent = route.calls.last.request
    import json as _json

    body = _json.loads(sent.content)
    assert body["TitleId"] == "20CA2"
    assert body["CreateAccount"] is True
    assert body["XboxToken"] == "XBL3.0 x=uhs;xsts-token"
    assert body["InfoRequestParameters"]["GetPlayerProfile"] is True


@respx.mock
async def test_login_with_xbox_edu_title() -> None:
    url = "https://6955f.playfabapi.com/Client/LoginWithXbox"
    respx.post(url).respond(json=_login_payload())

    token = await playfab_login_with_xbox(_xsts(), title_id=EDU_PLAYFAB_TITLE_ID)
    assert token.play_fab_id == "PF1234"


@respx.mock
async def test_login_with_xbox_playfab_error() -> None:
    url = "https://20ca2.playfabapi.com/Client/LoginWithXbox"
    respx.post(url).mock(
        return_value=Response(
            400,
            json={
                "code": 400,
                "status": "BadRequest",
                "error": "InvalidXboxToken",
                "errorCode": 1234,
                "errorMessage": "Xbox token rejected.",
            },
        )
    )

    with pytest.raises(PlayFabError) as exc:
        await playfab_login_with_xbox(_xsts())
    assert exc.value.status_code == 400
    assert exc.value.error == "InvalidXboxToken"
    assert exc.value.error_message == "Xbox token rejected."
    assert exc.value.error_code == 1234


@respx.mock
async def test_get_entity_token_refreshes() -> None:
    old = PlayFabEntityToken.model_validate(
        {
            "EntityToken": "old-entity-jwt",
            "TokenExpiration": "2025-01-01T00:00:00Z",
            "entity_id": "EID1234",
            "entity_type": "title_player_account",
        }
    )
    url = "https://20ca2.playfabapi.com/Authentication/GetEntityToken"
    route = respx.post(url).respond(
        json={
            "code": 200,
            "data": {
                "EntityToken": "new-entity-jwt",
                "TokenExpiration": "2030-06-01T00:00:00Z",
                "Entity": {"Id": "EID1234", "Type": "title_player_account"},
            },
        }
    )

    refreshed = await playfab_get_entity_token(old)
    assert isinstance(refreshed, PlayFabEntityToken)
    assert refreshed.token == "new-entity-jwt"
    assert refreshed.entity_id == "EID1234"
    assert refreshed.entity_type == "title_player_account"

    # Old token sent as header.
    sent = route.calls.last.request
    assert sent.headers["X-EntityToken"] == "old-entity-jwt"
    import json as _json

    body = _json.loads(sent.content)
    assert body["Entity"] == {"Id": "EID1234", "Type": "title_player_account"}


@respx.mock
async def test_get_entity_token_override_entity() -> None:
    old = PlayFabEntityToken.model_validate(
        {
            "EntityToken": "old-jwt",
            "TokenExpiration": "2025-01-01T00:00:00Z",
            "entity_id": "EID-A",
            "entity_type": "title_player_account",
        }
    )
    url = "https://20ca2.playfabapi.com/Authentication/GetEntityToken"
    route = respx.post(url).respond(
        json={
            "code": 200,
            "data": {
                "EntityToken": "new-jwt",
                "TokenExpiration": "2030-06-01T00:00:00Z",
                "Entity": {"Id": "EID-B", "Type": "master_player_account"},
            },
        }
    )

    refreshed = await playfab_get_entity_token(
        old, entity_id="EID-B", entity_type="master_player_account"
    )
    assert refreshed.entity_id == "EID-B"
    assert refreshed.entity_type == "master_player_account"
    import json as _json

    body = _json.loads(route.calls.last.request.content)
    assert body["Entity"] == {"Id": "EID-B", "Type": "master_player_account"}


def test_constants_exposed() -> None:
    assert BEDROCK_PLAYFAB_TITLE_ID == "20CA2"
    assert EDU_PLAYFAB_TITLE_ID == "6955F"

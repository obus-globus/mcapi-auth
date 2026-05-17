"""Unit tests for the small Prism-flow parsing helpers.

The full Prism login is exercised end-to-end through the integration
flows; these tests pin down the behaviour of the building-block helpers
directly so that refactors don't silently break a corner.
"""

import httpx
import pytest
import respx

from mcapi_auth._constants import LIVE_CONNECT_AUTHORIZE_URL
from mcapi_auth.auth.cookies import (
    _build_tile_params,
    _extract_server_data,
    _handle_prism_html_flow,
    _is_signed_in,
    _pick_session_id,
    _session_id_of,
)


class TestExtractServerData:
    def test_parses_inline_blob(self) -> None:
        html = '<script>var ServerData = {"a": 1, "b": [2, 3]};</script>'
        assert _extract_server_data(html) == {"a": 1, "b": [2, 3]}

    def test_returns_none_when_blob_missing(self) -> None:
        assert _extract_server_data("<html>no server data here</html>") is None

    def test_returns_none_on_malformed_json(self) -> None:
        html = "<script>var ServerData = {not json};</script>"
        assert _extract_server_data(html) is None

    def test_returns_none_when_blob_is_not_object(self) -> None:
        # Regex requires `{...}` so this can't actually fire in practice,
        # but the defensive branch should still hold.
        html = '<script>var ServerData = {"x":1};</script>'
        assert isinstance(_extract_server_data(html), dict)


class TestSessionIdOf:
    def test_returns_id_for_dict_with_string_id(self) -> None:
        assert _session_id_of({"id": "abc", "isSignedIn": True}) == "abc"

    def test_returns_none_for_non_dict(self) -> None:
        assert _session_id_of("not a dict") is None
        assert _session_id_of(None) is None

    def test_returns_none_when_id_missing(self) -> None:
        assert _session_id_of({"isSignedIn": True}) is None

    def test_returns_none_when_id_empty(self) -> None:
        assert _session_id_of({"id": ""}) is None

    def test_returns_none_when_id_not_a_string(self) -> None:
        assert _session_id_of({"id": 123}) is None


class TestIsSignedIn:
    def test_true_when_flag_set(self) -> None:
        assert _is_signed_in({"isSignedIn": True}) is True

    def test_false_when_flag_unset(self) -> None:
        assert _is_signed_in({"isSignedIn": False}) is False
        assert _is_signed_in({}) is False

    def test_false_for_non_dict(self) -> None:
        assert _is_signed_in("nope") is False


class TestPickSessionId:
    def test_prefers_signed_in_session(self) -> None:
        sd = {
            "arrSessions": [
                {"id": "anon", "isSignedIn": False},
                {"id": "signed", "isSignedIn": True},
            ]
        }
        assert _pick_session_id(sd) == "signed"

    def test_falls_back_to_first_when_none_signed_in(self) -> None:
        sd = {
            "arrSessions": [
                {"id": "first", "isSignedIn": False},
                {"id": "second", "isSignedIn": False},
            ]
        }
        assert _pick_session_id(sd) == "first"

    def test_returns_none_when_empty(self) -> None:
        assert _pick_session_id({"arrSessions": []}) is None

    def test_returns_none_when_missing(self) -> None:
        assert _pick_session_id({}) is None

    def test_returns_none_when_not_a_list(self) -> None:
        assert _pick_session_id({"arrSessions": "huh"}) is None

    def test_signed_in_without_id_falls_through_to_first(self) -> None:
        # Fallback is always sessions[0], regardless of whether earlier
        # signed-in entries lacked a usable id.
        sd = {
            "arrSessions": [
                {"id": "first", "isSignedIn": False},
                {"isSignedIn": True},
            ]
        }
        assert _pick_session_id(sd) == "first"


class TestBuildTileParams:
    def _html(self, *, ctx: str = "AAA1", opid: str = "BBB2", extras: str = "") -> str:
        return f"contextid={ctx}&opid={opid}{extras}"

    def test_minimal_required_params(self) -> None:
        params = _build_tile_params(self._html(), session_id="sid", client_id="cid")
        assert params == {
            "client_id": "cid",
            "contextid": "AAA1",
            "opid": "BBB2",
            "sessionid": "sid",
            "mkt": "EN-US",
            "lc": "1033",
        }

    def test_includes_bk_and_uaid_when_present(self) -> None:
        html = self._html(extras="&bk=1700000000&uaid=deadbeef")
        params = _build_tile_params(html, session_id="sid", client_id="cid")
        assert params is not None
        assert params["bk"] == "1700000000"
        assert params["uaid"] == "deadbeef"

    def test_returns_none_without_contextid(self) -> None:
        assert _build_tile_params("opid=BBB2", session_id="s", client_id="c") is None

    def test_returns_none_without_opid(self) -> None:
        assert _build_tile_params("contextid=AAA1", session_id="s", client_id="c") is None


_VALID_PRISM_HTML = (
    '<script>var ServerData = '
    '{"arrSessions":[{"id":"sess-1","isSignedIn":true}]};</script>'
    "contextid=AAA1&opid=BBB2&bk=1700000000&uaid=cafe"
)


class TestHandlePrismHtmlFlow:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_code_from_302_redirect(self) -> None:
        respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
            return_value=httpx.Response(
                302, headers={"location": "https://login.live.com/oauth20_desktop.srf?code=M.R3_BAY.abc"}
            )
        )
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client,
                html=_VALID_PRISM_HTML,
                referer="https://login.live.com/",
                client_id="000000004C12AE6F",
                user_agent="ua",
            )
        assert code == "M.R3_BAY.abc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_when_redirect_has_no_code(self) -> None:
        respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
            return_value=httpx.Response(302, headers={"location": "https://example.invalid/"})
        )
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client,
                html=_VALID_PRISM_HTML,
                referer="https://login.live.com/",
                client_id="000000004C12AE6F",
                user_agent="ua",
            )
        assert code is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_unknown_interstitial(self) -> None:
        respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
            return_value=httpx.Response(200, text="<html>no form here</html>")
        )
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client,
                html=_VALID_PRISM_HTML,
                referer="https://login.live.com/",
                client_id="000000004C12AE6F",
                user_agent="ua",
            )
        assert code is None

    @pytest.mark.asyncio
    async def test_returns_none_without_server_data(self) -> None:
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client,
                html="<html>no server data</html>",
                referer="r",
                client_id="cid",
                user_agent="ua",
            )
        assert code is None

    @pytest.mark.asyncio
    async def test_returns_none_without_session(self) -> None:
        html = '<script>var ServerData = {"arrSessions": []};</script>'
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client, html=html, referer="r", client_id="cid", user_agent="ua"
            )
        assert code is None

    @pytest.mark.asyncio
    async def test_returns_none_without_tile_params(self) -> None:
        html = '<script>var ServerData = {"arrSessions":[{"id":"s","isSignedIn":true}]};</script>'
        async with httpx.AsyncClient() as client:
            code = await _handle_prism_html_flow(
                client, html=html, referer="r", client_id="cid", user_agent="ua"
            )
        assert code is None

"""Tests for ``mcapi_auth.auth.cookies``."""

import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from mcapi_auth._constants import (
    BEDROCK_ANDROID_CLIENT_ID,
    BEDROCK_IOS_CLIENT_ID,
    BEDROCK_NINTENDO_CLIENT_ID,
    BEDROCK_PLAYSTATION_CLIENT_ID,
    BEDROCK_WIN32_CLIENT_ID,
    LIQUIDLAUNCHER_CLIENT_ID,
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_TOKEN_URL,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    PRISM_LAUNCHER_CLIENT_ID,
    SISU_CONNECT_URL,
    SISU_DEFAULT_RU,
    SISU_DEFAULT_TID,
    XBOX_APP_IOS_CLIENT_ID,
    XBOX_GAMEPASS_IOS_CLIENT_ID,
    is_v1_client_id,
)
from mcapi_auth.auth import (
    BrowserCookie,
    ConsentRequiredError,
    CookieAuthError,
    FidoRequiredError,
    SISUTokens,
    StaleCookiesError,
    cookies_to_header,
    extract_sisu_token,
    login_with_cookies_msa_v1,
    login_with_cookies_msa_v2_loopback,
    login_with_cookies_sisu,
)
from mcapi_auth.auth.cookies import _build_cookie_jar, _classify_cookie_failure

# ---- cookies_to_header / _build_cookie_jar ---------------------------------


def test_cookies_to_header_from_dataclass() -> None:
    header = cookies_to_header(
        [
            BrowserCookie(name="MSPAuth", value="abc"),
            BrowserCookie(name="MSPProf", value="xyz"),
        ]
    )
    assert header == "MSPAuth=abc; MSPProf=xyz"


def test_cookies_to_header_from_dict() -> None:
    header = cookies_to_header([{"name": "A", "value": "1"}, {"name": "B", "value": "2"}])
    assert header == "A=1; B=2"


def test_cookies_to_header_missing_name_raises() -> None:
    with pytest.raises(CookieAuthError):
        cookies_to_header([{"value": "1"}])


def test_build_cookie_jar_strips_leading_dot() -> None:
    jar = _build_cookie_jar(
        [BrowserCookie(name="MSPAuth", value="v", domain=".live.com", path="/")]
    )
    cookies_for_live = list(jar.jar)
    assert any(
        c.domain.endswith("live.com") and not c.domain.startswith(".") for c in cookies_for_live
    )


# ---- login_with_cookies_msa_v1 ---------------------------------------------


@respx.mock
async def test_login_with_cookies_msa_v1_happy_path() -> None:
    respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://login.live.com/oauth20_desktop.srf?code=THE_CODE"},
        )
    )
    respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "msa-access",
                "refresh_token": "msa-refresh",
                "expires_in": 3600,
                "token_type": "bearer",
            },
        )
    )
    tokens = await login_with_cookies_msa_v1("MSPAuth=foo")
    assert tokens.access_token == "msa-access"
    assert tokens.refresh_token == "msa-refresh"


@respx.mock
async def test_login_with_cookies_msa_v1_non_302_raises() -> None:
    respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(200, text="<html>FIDO challenge</html>")
    )
    with pytest.raises(CookieAuthError, match="did not 302"):
        await login_with_cookies_msa_v1("MSPAuth=foo")


@respx.mock
async def test_login_with_cookies_msa_v1_missing_code_raises() -> None:
    respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://login.live.com/oauth20_desktop.srf?error=denied"},
        )
    )
    with pytest.raises(CookieAuthError, match="no auth code"):
        await login_with_cookies_msa_v1("MSPAuth=foo")


@respx.mock
async def test_login_with_cookies_msa_v1_accepts_http_client() -> None:
    respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://login.live.com/oauth20_desktop.srf?code=C2"},
        )
    )
    respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 60,
                "token_type": "bearer",
            },
        )
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        tokens = await login_with_cookies_msa_v1("MSPAuth=foo", http_client=client)
    assert tokens.access_token == "a"


# ---- login_with_cookies_sisu -----------------------------------------------


def _sisu_payload() -> str:
    data = [
        {
            "Item1": "http://xboxlive.com",
            "Item2": {
                "Token": "xbl-token",
                "DisplayClaims": {"xui": [{"uhs": "uhs-123"}]},
            },
        },
        {
            "Item1": "rp://api.minecraftservices.com/",
            "Item2": {
                "Token": "mc-xsts",
                "DisplayClaims": {"xui": [{"uhs": "uhs-123"}]},
            },
        },
    ]
    return base64.b64encode(json.dumps(data).encode("utf-8")).decode("ascii").rstrip("=")


@respx.mock
async def test_login_with_cookies_sisu_happy_path() -> None:
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/login.srf?wa=wsignin"}
        )
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://sisu.xboxlive.com/connect/callback?code=ABC"},
        )
    )
    respx.get(re.compile(r"^https://sisu\.xboxlive\.com/connect/callback")).mock(
        return_value=httpx.Response(
            302,
            headers={
                "location": (
                    "https://www.minecraft.net/msaprofile/msa-profile#accessToken="
                    + _sisu_payload()
                )
            },
        )
    )
    sisu = await login_with_cookies_sisu("MSPAuth=foo")
    assert isinstance(sisu, SISUTokens)
    xbl = extract_sisu_token(sisu, "http://xboxlive.com")
    assert xbl.token == "xbl-token"
    assert xbl.userhash == "uhs-123"
    mc = extract_sisu_token(sisu, "rp://api.minecraftservices.com/")
    assert mc.token == "mc-xsts"


def test_extract_sisu_token_unknown_rp_raises() -> None:
    sisu = SISUTokens(tokens_by_relying_party={})
    with pytest.raises(CookieAuthError):
        extract_sisu_token(sisu, "http://nope")


@respx.mock
async def test_login_with_cookies_sisu_missing_fragment_raises() -> None:
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(302, headers={"location": "https://login.live.com/login.srf"})
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://sisu.xboxlive.com/connect/callback?code=ABC"},
        )
    )
    respx.get(re.compile(r"^https://sisu\.xboxlive\.com/connect/callback")).mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://www.minecraft.net/msaprofile/msa-profile#error=denied"},
        )
    )
    with pytest.raises(CookieAuthError, match="accessToken"):
        await login_with_cookies_sisu("MSPAuth=foo")


# ---- login_with_cookies_msa_v2_loopback (direct-302 happy path only) ------------------


@respx.mock
async def test_login_with_cookies_msa_v2_loopback_direct_302_happy_path() -> None:
    respx.get(re.compile(r"^https://login\.microsoftonline\.com/consumers/")).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/login.srf?something"}
        )
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "http://localhost:5000/auth?code=PRISMCODE&state=x"},
        )
    )
    respx.post(
        re.compile(r"^https://login\.microsoftonline\.com/consumers/oauth2/v2\.0/token")
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "prism-access",
                "refresh_token": "prism-refresh",
                "expires_in": 3600,
                "token_type": "bearer",
            },
        )
    )
    tokens = await login_with_cookies_msa_v2_loopback(
        [BrowserCookie(name="MSPAuth", value="foo", domain=".live.com")]
    )
    assert tokens.access_token == "prism-access"
    assert tokens.refresh_token == "prism-refresh"


# ---- client_id matrix ------------------------------------------------------
#
# Verifies that each known v1 / v2 client_id is threaded into the
# underlying OAuth ``client_id=`` parameter verbatim, both on the
# authorize call and on the token-exchange POST. Catches regressions
# where the helper might (e.g.) lower-case a hex id, drop dashes, or
# substitute its default.


V1_CLIENT_IDS = pytest.mark.parametrize(
    "client_id",
    [
        MINECRAFT_LAUNCHER_V1_CLIENT_ID,
        BEDROCK_WIN32_CLIENT_ID,
        BEDROCK_ANDROID_CLIENT_ID,
        BEDROCK_IOS_CLIENT_ID,
        BEDROCK_NINTENDO_CLIENT_ID,
        BEDROCK_PLAYSTATION_CLIENT_ID,
        XBOX_APP_IOS_CLIENT_ID,
        XBOX_GAMEPASS_IOS_CLIENT_ID,
    ],
)

V2_CLIENT_IDS = pytest.mark.parametrize(
    "client_id",
    [
        PRISM_LAUNCHER_CLIENT_ID,
        LIQUIDLAUNCHER_CLIENT_ID,
    ],
)


def _query_client_id(url: str) -> str | None:
    qs = parse_qs(urlsplit(url).query)
    values = qs.get("client_id", [])
    return values[0] if values else None


@V1_CLIENT_IDS
@respx.mock
async def test_login_with_cookies_msa_v1_client_id_matrix(client_id: str) -> None:
    """Every v1 client_id is threaded into authorize + token requests verbatim."""
    assert is_v1_client_id(client_id), "test inputs must all be v1-shaped"

    authorize_route = respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://login.live.com/oauth20_desktop.srf?code=MATRIX"},
        )
    )
    token_route = respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 60,
                "token_type": "bearer",
            },
        )
    )

    tokens = await login_with_cookies_msa_v1("MSPAuth=foo", client_id=client_id)
    assert tokens.access_token == "a"

    # Authorize call: client_id must appear in the URL query, verbatim.
    sent_authorize = authorize_route.calls.last.request
    assert _query_client_id(str(sent_authorize.url)) == client_id

    # Token call: form-encoded body must carry the same client_id.
    body = token_route.calls.last.request.content.decode()
    posted = parse_qs(body)
    assert posted["client_id"] == [client_id]
    assert posted["grant_type"] == ["authorization_code"]
    assert posted["code"] == ["MATRIX"]


@V2_CLIENT_IDS
@respx.mock
async def test_login_with_cookies_msa_v2_loopback_client_id_matrix(client_id: str) -> None:
    """Every v2 loopback-registered client_id is threaded through the v2-loopback flow."""
    assert not is_v1_client_id(client_id), "test inputs must all be v2-shaped"

    authorize_route = respx.get(
        re.compile(r"^https://login\.microsoftonline\.com/consumers/")
    ).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/login.srf?stuff"}
        )
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "http://localhost:5000/auth?code=MATRIXV2&state=x"},
        )
    )
    token_route = respx.post(
        re.compile(r"^https://login\.microsoftonline\.com/consumers/oauth2/v2\.0/token")
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 60,
                "token_type": "bearer",
            },
        )
    )

    tokens = await login_with_cookies_msa_v2_loopback(
        [BrowserCookie(name="MSPAuth", value="foo", domain=".live.com")],
        client_id=client_id,
    )
    assert tokens.access_token == "a"

    sent_authorize = authorize_route.calls.last.request
    assert _query_client_id(str(sent_authorize.url)) == client_id

    body = token_route.calls.last.request.content.decode()
    posted = parse_qs(body)
    assert posted["client_id"] == [client_id]
    assert posted["grant_type"] == ["authorization_code"]
    assert posted["code"] == ["MATRIXV2"]


@respx.mock
async def test_msa_v1_default_client_id_is_minecraft_launcher() -> None:
    """When no client_id is supplied, the default is the Minecraft launcher v1 id."""
    authorize_route = respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/oauth20_desktop.srf?code=D"}
        )
    )
    respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 60,
                "token_type": "bearer",
            },
        )
    )

    await login_with_cookies_msa_v1("MSPAuth=foo")

    assert (
        _query_client_id(str(authorize_route.calls.last.request.url))
        == MINECRAFT_LAUNCHER_V1_CLIENT_ID
    )


@respx.mock
async def test_prism_default_client_id_is_prism_launcher() -> None:
    """When no client_id is supplied, the default is PrismLauncher's."""
    authorize_route = respx.get(
        re.compile(r"^https://login\.microsoftonline\.com/consumers/")
    ).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/login.srf?stuff"}
        )
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "http://localhost:5000/auth?code=DPRISM&state=x"},
        )
    )
    respx.post(
        re.compile(r"^https://login\.microsoftonline\.com/consumers/oauth2/v2\.0/token")
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 60,
                "token_type": "bearer",
            },
        )
    )

    await login_with_cookies_msa_v2_loopback(
        [BrowserCookie(name="MSPAuth", value="foo", domain=".live.com")]
    )

    assert _query_client_id(str(authorize_route.calls.last.request.url)) == PRISM_LAUNCHER_CLIENT_ID


# ---- SISU + MSA exchange ---------------------------------------------------


@respx.mock
async def test_login_with_cookies_sisu_with_msa_exchange() -> None:
    """When also_exchange_msa=True, SISUTokens.msa is populated from oauth20_token.srf."""
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://login.live.com/login.srf?wa=wsignin"}
        )
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://sisu.xboxlive.com/connect/callback?code=SISU-CODE-42"},
        )
    )
    respx.get(re.compile(r"^https://sisu\.xboxlive\.com/connect/callback")).mock(
        return_value=httpx.Response(
            302,
            headers={
                "location": (
                    "https://www.minecraft.net/msaprofile/msa-profile#accessToken="
                    + _sisu_payload()
                )
            },
        )
    )
    token_route = respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "msa-access-token",
                "refresh_token": "msa-refresh-token",
                "expires_in": 86400,
                "token_type": "bearer",
                "user_id": "u-1",
            },
        )
    )

    sisu = await login_with_cookies_sisu("MSPAuth=foo", also_exchange_msa=True)

    assert sisu.msa is not None
    assert sisu.msa.access_token == "msa-access-token"
    assert sisu.msa.refresh_token == "msa-refresh-token"
    # XBL still extracted normally.
    assert extract_sisu_token(sisu, "http://xboxlive.com").token == "xbl-token"
    # The token-exchange request carried the SISU code + sisu tid + return url.
    sent = token_route.calls.last.request
    sent_body = parse_qs(sent.content.decode())
    assert sent_body["code"] == ["SISU-CODE-42"]
    assert sent_body["grant_type"] == ["authorization_code"]
    # default client_id = SISU tid
    assert sent_body["client_id"] == [SISU_DEFAULT_TID]
    assert sent_body["redirect_uri"] == [SISU_DEFAULT_RU]


@respx.mock
async def test_login_with_cookies_sisu_msa_exchange_failure_raises() -> None:
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(302, headers={"location": "https://login.live.com/login.srf"})
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://sisu.xboxlive.com/connect/callback?code=ABC"},
        )
    )
    respx.get(re.compile(r"^https://sisu\.xboxlive\.com/connect/callback")).mock(
        return_value=httpx.Response(
            302,
            headers={
                "location": (
                    "https://www.minecraft.net/msaprofile/msa-profile#accessToken="
                    + _sisu_payload()
                )
            },
        )
    )
    respx.post(LIVE_CONNECT_TOKEN_URL).mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )

    with pytest.raises(CookieAuthError, match="SISU MSA token exchange failed"):
        await login_with_cookies_sisu("MSPAuth=foo", also_exchange_msa=True)


@respx.mock
async def test_login_with_cookies_sisu_default_no_msa() -> None:
    """Without the flag, msa stays None and oauth20_token.srf is never hit."""
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(302, headers={"location": "https://login.live.com/login.srf"})
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            302,
            headers={"location": "https://sisu.xboxlive.com/connect/callback?code=ABC"},
        )
    )
    respx.get(re.compile(r"^https://sisu\.xboxlive\.com/connect/callback")).mock(
        return_value=httpx.Response(
            302,
            headers={
                "location": (
                    "https://www.minecraft.net/msaprofile/msa-profile#accessToken="
                    + _sisu_payload()
                )
            },
        )
    )
    token_route = respx.post(LIVE_CONNECT_TOKEN_URL).mock(return_value=httpx.Response(200, json={}))

    sisu = await login_with_cookies_sisu("MSPAuth=foo")
    assert sisu.msa is None
    assert token_route.call_count == 0


# ---- CookieAuthError subclass dispatch -------------------------------------


def test_classify_picks_fido_on_passkey_body() -> None:
    cls = _classify_cookie_failure(
        status_code=200,
        body="<html>Sign in with a passkey</html>",
        location=None,
    )
    assert cls is FidoRequiredError


def test_classify_picks_consent_on_consent_marker() -> None:
    cls = _classify_cookie_failure(
        status_code=200,
        body="Permissions requested by Minecraft",
        location=None,
    )
    assert cls is ConsentRequiredError


def test_classify_picks_stale_on_login_form() -> None:
    cls = _classify_cookie_failure(
        status_code=200,
        body='<input id="i0116" name="loginfmt"/>',
        location=None,
    )
    assert cls is StaleCookiesError


def test_classify_falls_back_to_base() -> None:
    cls = _classify_cookie_failure(status_code=500, body="oops", location=None)
    assert cls is CookieAuthError


def test_error_subclasses_still_match_base() -> None:
    err = FidoRequiredError("nope", status_code=200, body_preview="passkey here")
    assert isinstance(err, CookieAuthError)
    assert err.status_code == 200
    assert err.body_preview == "passkey here"


@respx.mock
async def test_v1_flow_raises_fido_required_on_passkey_page() -> None:
    respx.get(LIVE_CONNECT_AUTHORIZE_URL).mock(
        return_value=httpx.Response(
            200,
            text="<html>Use your passkey to sign in</html>",
        )
    )
    with pytest.raises(FidoRequiredError):
        await login_with_cookies_msa_v1("MSPAuth=foo", client_id=LIQUIDLAUNCHER_CLIENT_ID)


@respx.mock
async def test_sisu_raises_stale_cookies_on_login_form() -> None:
    respx.get(re.compile(rf"^{re.escape(SISU_CONNECT_URL)}")).mock(
        return_value=httpx.Response(302, headers={"location": "https://login.live.com/login.srf"})
    )
    respx.get("https://login.live.com/login.srf").mock(
        return_value=httpx.Response(
            200,
            text='<input id="i0116" name="loginfmt"/>',
        )
    )
    with pytest.raises(StaleCookiesError):
        await login_with_cookies_sisu("MSPAuth=foo")


# ---- ServerData-based classification ---------------------------------------


def test_classify_serverdata_signed_in_false_is_stale() -> None:
    html = """<html><script>
    ServerData = {"fIsSignedIn": false, "arrSessions": null};
    </script>passkey support enabled</html>"""
    # body contains "passkey" but ServerData says not signed in — stale wins.
    assert _classify_cookie_failure(status_code=200, body=html, location=None) is StaleCookiesError


def test_classify_serverdata_empty_sessions_is_stale() -> None:
    html = '<script>ServerData = {"arrSessions": [], "fIsSignedIn": true};</script>'
    assert _classify_cookie_failure(status_code=200, body=html, location=None) is StaleCookiesError


def test_classify_serverdata_signed_in_with_fido_marker_is_fido() -> None:
    html = """<script>
    ServerData = {"fIsSignedIn": true, "arrSessions": [{"name": "user@example.com"}]};
    </script>
    <p>Use your passkey to continue</p>"""
    # ServerData says signed in -> fall through to marker ladder -> FIDO.
    assert _classify_cookie_failure(status_code=200, body=html, location=None) is FidoRequiredError


def test_classify_serverdata_malformed_falls_back() -> None:
    html = "<script>ServerData = {not valid json};</script><p>passkey</p>"
    assert _classify_cookie_failure(status_code=200, body=html, location=None) is FidoRequiredError

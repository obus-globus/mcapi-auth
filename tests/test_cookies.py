"""Tests for ``mcapi_auth.auth.cookies``."""

import base64
import json
import re

import httpx
import pytest
import respx

from mcapi_auth._constants import (
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_TOKEN_URL,
    SISU_CONNECT_URL,
)
from mcapi_auth.auth import (
    BrowserCookie,
    CookieAuthError,
    SISUTokens,
    cookies_to_header,
    extract_sisu_token,
    login_with_cookies_msa_v1,
    login_with_cookies_prism,
    login_with_cookies_sisu,
)
from mcapi_auth.auth.cookies import _build_cookie_jar

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


# ---- login_with_cookies_prism (direct-302 happy path only) ------------------


@respx.mock
async def test_login_with_cookies_prism_direct_302_happy_path() -> None:
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
    tokens = await login_with_cookies_prism(
        [BrowserCookie(name="MSPAuth", value="foo", domain=".live.com")]
    )
    assert tokens.access_token == "prism-access"
    assert tokens.refresh_token == "prism-refresh"

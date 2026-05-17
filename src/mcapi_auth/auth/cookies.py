"""Cookie-based MSA auth flows (browser-session impersonation).

The three flows in this module trade *Microsoft session cookies*
(usually obtained out-of-band by automating a real browser sign-in,
e.g. via :mod:`nodriver` / Selenium / Playwright) for launcher-style
tokens, *without* the user having to consent again. They exist
because the regular device-code and authorization-code flows demand
human interaction at each sign-in — which doesn't scale for bulk
account management (alt-checking, mass-token-refresh tooling, etc.).

Three options ship, in order of preference:

1. :func:`login_with_cookies_msa_v1` — the legacy Live-Connect
   public-client flow used by the official Minecraft Launcher.
   Returns full :class:`~mcapi_auth.auth.msa.MSATokens` (access + refresh +
   expiry). Preferred whenever it works.
2. :func:`login_with_cookies_prism` — Azure-AD consumers flow using
   PrismLauncher's client_id. More involved (Microsoft sometimes
   serves an interstitial consent page that has to be auto-clicked)
   but works when the v1 flow is blocked by FIDO / passkey
   enforcement.
3. :func:`login_with_cookies_sisu` — Xbox SISU SSO. Returns *only*
   XBL/XSTS tokens (no MS access/refresh token). Use as a last-resort
   fallback; you'll need to re-run SISU each time the XBL token
   expires.

All three accept a ``cookie_header`` (a literal ``Cookie:`` header
string of the user's ``login.live.com`` cookies) **or** a
``cookies`` list of ``{name, domain, path, value}`` dicts (the
format ``nodriver`` / Selenium produces). Pass whichever you have;
the helpers convert.

.. warning::
   These flows are protocol-faithful impersonation of the Microsoft
   Launcher's auth dance. Only run them against Microsoft accounts
   you legitimately control — abusing them against third parties is
   credential theft.
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import logging
import re
from collections.abc import AsyncGenerator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .._constants import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_USER_AGENT,
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    LIVE_CONNECT_SCOPE_MBI_SSL,
    LIVE_CONNECT_TOKEN_URL,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    PRISM_LAUNCHER_CLIENT_ID,
    PRISM_LAUNCHER_REDIRECT_URI,
    SISU_CONNECT_URL,
    SISU_DEFAULT_COBRAND_ID,
    SISU_DEFAULT_RU,
    SISU_DEFAULT_TID,
)
from .._http import parse_json_object_auth
from ..exceptions import MCAuthError, MSAFlowError
from .auth_code import create_pkce_challenge
from .msa import MSATokens, _parse_token_response  # pyright: ignore[reportPrivateUsage]
from .xbox import XboxLiveToken

__all__ = [
    "BrowserCookie",
    "CookieAuthError",
    "SISUTokens",
    "cookies_to_header",
    "extract_sisu_token",
    "login_with_cookies_msa_v1",
    "login_with_cookies_prism",
    "login_with_cookies_sisu",
]

logger = logging.getLogger(__name__)


def _parse_qs(query: str) -> dict[str, list[str]]:
    """``urllib.parse.parse_qs`` with explicit typing for basedpyright strict."""
    return parse_qs(query)


def _query_of(url: str) -> str:
    """Return ``urlparse(url).query`` as a plain ``str`` for basedpyright."""
    return str(urlparse(url).query)


def _fragment_of(url: str) -> str:
    return str(urlparse(url).fragment)


@asynccontextmanager
async def _acquire_for_cookies(
    client: httpx.AsyncClient | None, *, timeout: float  # NOSONAR public API kwarg; do not change signature
) -> AsyncGenerator[httpx.AsyncClient]:
    """Acquire an httpx client for cookie flows.

    Callers can pass their own client (e.g. configured with a proxy);
    individual requests inside the flow pass ``follow_redirects=False``
    explicitly so we don't depend on the caller's client setting.
    """
    if client is not None:
        yield client
        return
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as owned:
        yield owned


class CookieAuthError(MSAFlowError):
    """A cookie-based auth flow couldn't complete (FIDO / passkey block, etc.)."""


@dataclass(frozen=True, slots=True)
class BrowserCookie:
    """A single browser cookie in the shape that ``nodriver`` / Selenium emit.

    Pass a list of these (or plain ``dict``s with the same keys) to the
    cookie-login functions.
    """

    name: str
    value: str
    domain: str = ""
    path: str = "/"


@dataclass(frozen=True, slots=True)
class SISUTokens:
    """All XBL/XSTS tokens minted by a single SISU run.

    Keyed by the *relying party* the token is bound to. Useful when one
    SISU run mints both an Xbox Live token (``"http://auth.xboxlive.com"``)
    and an XSTS token (``"rp://api.minecraftservices.com/"``).
    """

    tokens_by_relying_party: dict[str, XboxLiveToken]

    def get(self, relying_party: str) -> XboxLiveToken | None:
        """Return the token for ``relying_party`` if SISU minted one."""
        return self.tokens_by_relying_party.get(relying_party)


def cookies_to_header(
    cookies: Iterable[BrowserCookie | Mapping[str, Any]],
) -> str:
    """Flatten a list of cookie dicts/objects into a single ``Cookie:`` header value.

    Each entry must carry ``name`` and ``value``; ``domain`` / ``path``
    are ignored here — the caller decides which cookies to include.
    """
    parts: list[str] = []
    for entry in cookies:
        if isinstance(entry, BrowserCookie):
            name, value = entry.name, entry.value
        else:
            entry_typed: Mapping[str, Any] = entry
            name_obj = entry_typed.get("name")
            value_obj = entry_typed.get("value")
            if not isinstance(name_obj, str) or not isinstance(value_obj, str):
                raise CookieAuthError(
                    "cookie entry is missing string name/value "
                    f"(name={type(name_obj).__name__}, value={type(value_obj).__name__})"
                )
            name, value = name_obj, value_obj
        parts.append(f"{name}={value}")
    return "; ".join(parts)


def _build_cookie_jar(  # NOSONAR linear protocol stages; splitting hurts readability
    cookies: Iterable[BrowserCookie | Mapping[str, Any]],
) -> httpx.Cookies:
    """Build a real :class:`httpx.Cookies` jar from browser cookie dicts.

    Used when we need redirects honored within a single ``AsyncClient``
    invocation (e.g. the Prism flow's interstitial chain). For
    single-shot requests, ``cookies_to_header`` + a literal ``Cookie:``
    header is simpler.
    """
    jar = httpx.Cookies()
    for entry in cookies:
        if isinstance(entry, BrowserCookie):
            name, value, domain, path = entry.name, entry.value, entry.domain, entry.path
        else:
            entry_typed: Mapping[str, Any] = entry
            name_obj = entry_typed.get("name")
            value_obj = entry_typed.get("value")
            if not isinstance(name_obj, str) or not isinstance(value_obj, str):
                raise CookieAuthError(
                    "cookie entry is missing string name/value "
                    f"(name={type(name_obj).__name__}, value={type(value_obj).__name__})"
                )
            domain_obj = entry_typed.get("domain", "")
            path_obj = entry_typed.get("path", "/")
            name = name_obj
            value = value_obj
            domain = domain_obj if isinstance(domain_obj, str) else ""
            path = path_obj if isinstance(path_obj, str) else "/"
        if domain.startswith("."):
            domain = domain[1:]
        jar.set(name, value, domain=domain, path=path or "/")
    return jar


# -- Flow 1: Live-Connect (MSA v1) public-client -----------------------------


async def login_with_cookies_msa_v1(
    cookie_header: str,
    *,
    client_id: str = MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    redirect_uri: str = LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = DEFAULT_HTTP_TIMEOUT,  # NOSONAR public API kwarg; do not change signature
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Drive the Live-Connect "Java public client" flow using session cookies.

    1. Hit ``oauth20_authorize.srf`` with PKCE + ``MBI_SSL`` scope and
       the user's cookies.
    2. If Microsoft 302s back with a ``code=`` parameter, exchange it
       for tokens. If not, the account is FIDO/passkey-enforced and
       this flow can't complete — raise :class:`CookieAuthError`.

    Returns :class:`MSATokens` carrying the access + refresh tokens.

    Pass ``http_client`` (e.g. ``httpx.AsyncClient(proxy="socks5://...")``)
    to route the flow through a proxy or share a connection pool. The
    ``timeout`` argument is only used when constructing the default
    client; a caller-supplied client keeps its own timeout.
    """
    pkce = create_pkce_challenge()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": LIVE_CONNECT_SCOPE_MBI_SSL,
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
    }
    authorize_url = f"{LIVE_CONNECT_AUTHORIZE_URL}?{urlencode(params)}"

    async with _acquire_for_cookies(http_client, timeout=timeout) as client:
        resp = await client.get(
            authorize_url,
            headers={"Cookie": cookie_header, "User-Agent": user_agent},
            follow_redirects=False,
        )
        if resp.status_code != 302:
            raise CookieAuthError(
                "Live-Connect /oauth20_authorize.srf did not 302 — "
                "the account is likely FIDO-enforced or the cookies are stale "
                f"(status={resp.status_code})"
            )
        location = resp.headers.get("location", "")
        if "code=" not in location:  # NOSONAR intentional: inlined for readability
            raise CookieAuthError(f"Live-Connect 302 had no auth code: location={location!r}")
        code_values = _parse_qs(_query_of(location)).get("code", [])
        if not code_values or not code_values[0]:
            raise CookieAuthError(f"empty 'code' in redirect: location={location!r}")
        code = code_values[0]

        token_resp = await client.post(
            LIVE_CONNECT_TOKEN_URL,
            data={
                "client_id": client_id,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": pkce.verifier,
            },
            headers={
                "Content-Type": _FORM_URLENCODED,
                "User-Agent": user_agent,
            },
            follow_redirects=False,
        )
    if token_resp.status_code != 200:
        raise CookieAuthError(
            f"Live-Connect token exchange failed: status={token_resp.status_code} "
            f"body={token_resp.text!r}"
        )
    return _parse_token_response(token_resp)


# -- Flow 2: SISU (Xbox Sign-In/Sign-Up) -------------------------------------


async def login_with_cookies_sisu(
    cookie_header: str,
    *,
    cobrand_id: str = SISU_DEFAULT_COBRAND_ID,
    tid: str = SISU_DEFAULT_TID,
    return_url: str = SISU_DEFAULT_RU,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = DEFAULT_HTTP_TIMEOUT,  # NOSONAR public API kwarg; do not change signature
    http_client: httpx.AsyncClient | None = None,
) -> SISUTokens:
    """SISU (Xbox SSO) flow — returns XBL/XSTS tokens directly.

    Use as a fallback when :func:`login_with_cookies_msa_v1` returns
    :class:`CookieAuthError` (typically because FIDO is enforced on the
    account). The output does **not** carry an MS access/refresh token,
    so you can't refresh — you'll need to re-run SISU on token expiry.

    Pass ``http_client`` to route through a proxy or share a pool.
    """
    sisu_url = f"{SISU_CONNECT_URL}?state=login&cobrandId={cobrand_id}&tid={tid}&ru={return_url}"
    async with _acquire_for_cookies(http_client, timeout=timeout) as client:
        resp = await client.get(
            sisu_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code != 302:
            raise CookieAuthError(f"SISU /connect did not 302: status={resp.status_code}")
        login_url = resp.headers["location"]

        resp = await client.get(
            login_url,
            headers={"Cookie": cookie_header, "User-Agent": user_agent},
            follow_redirects=False,
        )
        if resp.status_code != 302:
            raise CookieAuthError(
                f"SISU login.live.com did not 302 — cookies likely stale "
                f"or FIDO-enforced (status={resp.status_code})"
            )
        callback_url = resp.headers["location"]
        if "code=" not in callback_url:
            raise CookieAuthError(f"SISU callback missing 'code=': {callback_url!r}")

        resp = await client.get(
            callback_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code != 302:
            raise CookieAuthError(f"SISU callback did not 302: status={resp.status_code}")

        final_url = resp.headers.get("location", "")

    fragment = _fragment_of(final_url)
    frag_params = _parse_qs(fragment)
    token_b64_list = frag_params.get("accessToken", [])
    if not token_b64_list or not token_b64_list[0]:
        raise CookieAuthError(f"SISU final redirect missing 'accessToken' fragment: {final_url!r}")
    token_b64 = token_b64_list[0]
    try:
        decoded = base64.b64decode(token_b64 + "==").decode("utf-8")
        parsed_obj: object = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:  # NOSONAR intentional: documents distinct error sources
        raise CookieAuthError(f"SISU 'accessToken' fragment is not valid b64+JSON: {e}") from e
    if not isinstance(parsed_obj, list):
        raise CookieAuthError(f"SISU returned non-array payload: {type(parsed_obj).__name__}")
    return _parse_sisu_array(cast(list[object], parsed_obj))


def extract_sisu_token(sisu: SISUTokens, relying_party: str) -> XboxLiveToken:
    """Return the SISU token for ``relying_party`` or raise :class:`CookieAuthError`."""
    token = sisu.get(relying_party)
    if token is None:
        raise CookieAuthError(f"SISU response had no token for relying party {relying_party!r}")
    return token


def _parse_sisu_array(entries: list[object]) -> SISUTokens:  # NOSONAR linear protocol stages; splitting hurts readability
    out: dict[str, XboxLiveToken] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_typed = cast(dict[str, Any], entry)
        rp = entry_typed.get("Item1")
        item2 = entry_typed.get("Item2")
        if not isinstance(rp, str) or not isinstance(item2, dict):
            continue
        item2_typed = cast(dict[str, Any], item2)
        token = item2_typed.get("Token")
        display = item2_typed.get("DisplayClaims")
        if not isinstance(token, str) or not isinstance(display, dict):
            continue
        display_typed = cast(dict[str, Any], display)
        xui = display_typed.get("xui")
        if not isinstance(xui, list) or not xui:
            continue
        xui_first = cast(list[object], xui)[0]
        if not isinstance(xui_first, dict):
            continue
        uhs = cast(dict[str, Any], xui_first).get("uhs")
        if not isinstance(uhs, str) or not uhs:
            continue
        out[rp] = XboxLiveToken(token=token, userhash=uhs)
    if not out:
        raise CookieAuthError("SISU response contained no usable tokens")
    return SISUTokens(tokens_by_relying_party=out)


# -- Flow 3: Prism Launcher (Azure-AD consumers) -----------------------------


async def login_with_cookies_prism(
    cookies: Iterable[BrowserCookie | Mapping[str, Any]],
    *,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    redirect_uri: str = PRISM_LAUNCHER_REDIRECT_URI,
    scope: str = "XboxLive.SignIn XboxLive.offline_access",
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = DEFAULT_HTTP_TIMEOUT,  # NOSONAR public API kwarg; do not change signature
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Prism-Launcher-style Azure-AD consumers flow using session cookies.

    Microsoft sometimes serves an interstitial (consent / "Stay signed
    in?" / cancel) page during this flow; we auto-handle the common
    shapes. Returns :class:`MSATokens` carrying access + refresh tokens.

    Raises :class:`CookieAuthError` if Microsoft never gives us a ``code``
    parameter — the cookies are stale or the account requires
    interactive consent we couldn't auto-click.

    Pass ``http_client`` to route through a proxy or share a pool. Note
    that this flow mutates the client's cookie jar (adding the provided
    browser cookies plus anything Microsoft sets along the way); pass a
    dedicated client if that matters.
    """
    pkce = create_pkce_challenge()
    jar = _build_cookie_jar(cookies)

    async with _acquire_for_cookies(http_client, timeout=timeout) as client:
        client.cookies.update(jar)
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "code_challenge": pkce.challenge,
            "code_challenge_method": pkce.method,
            "prompt": "select_account",
        }
        authorize_url = (
            f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?{urlencode(params)}"
        )

        resp = await client.get(
            authorize_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code != 302:
            raise CookieAuthError(f"Azure-AD authorize did not 302: status={resp.status_code}")
        live_url = resp.headers.get("location", "")
        if "login.live.com" not in live_url:
            raise CookieAuthError(
                f"Azure-AD authorize did not redirect to login.live.com: {live_url!r}"
            )

        resp = await client.get(
            live_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code == 302:
            code = _code_from_redirect(resp.headers.get("location", ""))
            if code:
                return await _exchange_prism_code(
                    client,
                    code=code,
                    pkce_verifier=pkce.verifier,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    user_agent=user_agent,
                )
            raise CookieAuthError(
                "login.live.com 302'd without a code parameter "
                f"(location={resp.headers.get('location', '')!r})"
            )
        if resp.status_code != 200:
            raise CookieAuthError(f"login.live.com returned unexpected status {resp.status_code}")

        # 200 OK with an HTML body — Microsoft is asking us to follow
        # the "tile click" / consent dance. Parse the embedded
        # ``ServerData`` JSON and proceed.
        code = await _handle_prism_html_flow(
            client,
            html=resp.text,
            referer=live_url,
            client_id=client_id,
            user_agent=user_agent,
        )
        if code is None:
            raise CookieAuthError(
                "Prism HTML flow finished without an auth code — Microsoft "
                "likely served an interstitial we don't handle. Try the "
                "Live-Connect or SISU flow instead."
            )
        return await _exchange_prism_code(
            client,
            code=code,
            pkce_verifier=pkce.verifier,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_agent=user_agent,
        )


def _code_from_redirect(location: str) -> str | None:
    if "code=" not in location:
        return None
    values = _parse_qs(_query_of(location)).get("code", [])
    return values[0] if values and values[0] else None


_FORM_URLENCODED = "application/x-www-form-urlencoded"


_SERVER_DATA_RE = re.compile(r"var ServerData\s*=\s*({.*?});\s*</script>", re.DOTALL)  # NOSONAR reluctant needed: matched JSON has nested } chars
_CONSENT_SERVER_DATA_RE = re.compile(r"ServerData\s*=\s*(\{.+?\});", re.DOTALL)  # NOSONAR reluctant needed: matched JSON has nested } chars
_FORM_ACTION_RE = re.compile(r'action="([^"]+)"')
_FORM_INPUT_RE = re.compile(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"')
_CTX_RE = re.compile(r"contextid[=:]([A-F0-9]+)", re.IGNORECASE)
_OPID_RE = re.compile(r"opid[=:]([A-F0-9]+)", re.IGNORECASE)
_BK_RE = re.compile(r"bk[=:](\d+)")
_UAID_RE = re.compile(r"uaid[=:]([a-f0-9]+)", re.IGNORECASE)


async def _handle_prism_html_flow(  # NOSONAR linear protocol stages; splitting hurts readability
    client: httpx.AsyncClient,
    *,
    html: str,
    referer: str,
    client_id: str,
    user_agent: str,
) -> str | None:
    """Walk the "ServerData → tile-click → interstitial" page chain.

    Faithful port of the bulk-auth tool's interstitial logic. Returns
    the auth code on success, or ``None`` if Microsoft showed us a
    page we don't know how to advance.
    """
    sd_match = _SERVER_DATA_RE.search(html)
    if not sd_match:
        return None
    try:
        parsed_sd: object = json.loads(sd_match.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed_sd, dict):
        return None
    server_data = cast(dict[str, Any], parsed_sd)

    sessions_raw = server_data.get("arrSessions")
    if not isinstance(sessions_raw, list) or not sessions_raw:
        return None
    sessions = cast(list[object], sessions_raw)
    session_id: str | None = None
    for s in sessions:
        if isinstance(s, dict):
            s_typed = cast(dict[str, Any], s)
            if s_typed.get("isSignedIn"):
                candidate = s_typed.get("id")
                if isinstance(candidate, str) and candidate:
                    session_id = candidate
                    break
    if session_id is None:
        first = sessions[0]
        if isinstance(first, dict):
            candidate = cast(dict[str, Any], first).get("id")
            if isinstance(candidate, str):
                session_id = candidate
    if not session_id:
        return None

    ctx_match = _CTX_RE.search(html)
    opid_match = _OPID_RE.search(html)
    if not ctx_match or not opid_match:
        return None
    bk_match = _BK_RE.search(html)
    uaid_match = _UAID_RE.search(html)

    tile_params = {
        "client_id": client_id,
        "contextid": ctx_match.group(1),
        "opid": opid_match.group(1),
        "sessionid": session_id,
        "mkt": "EN-US",
        "lc": "1033",
    }
    if bk_match:
        tile_params["bk"] = bk_match.group(1)
    if uaid_match:
        tile_params["uaid"] = uaid_match.group(1)

    tile_url = f"{LIVE_CONNECT_AUTHORIZE_URL}?{urlencode(tile_params)}"
    resp = await client.get(
        tile_url, headers={"User-Agent": user_agent, "Referer": referer}, follow_redirects=False
    )

    if resp.status_code == 302:
        code = _code_from_redirect(resp.headers.get("location", ""))
        if code:
            return code

    if resp.status_code == 200:
        return await _handle_prism_interstitial(client, page_html=resp.text, user_agent=user_agent)
    return None


async def _handle_prism_interstitial(  # NOSONAR linear protocol stages; splitting hurts readability
    client: httpx.AsyncClient,
    *,
    page_html: str,
    user_agent: str,
) -> str | None:
    """Auto-advance "ar/cancel" / "Consent/Update" interstitial pages."""
    action_match = _FORM_ACTION_RE.search(page_html)
    if not action_match:
        return None
    action_url = html_mod.unescape(action_match.group(1))
    inputs = _FORM_INPUT_RE.findall(page_html)
    form_data: dict[str, str] = dict(inputs)

    if "ar/cancel" in action_url:
        parsed_action = urlparse(action_url)
        action_params = _parse_qs(parsed_action.query)
        ru_list = action_params.get("ru", [])
        if not ru_list or not ru_list[0]:
            return None
        ru = ru_list[0]
        _ = await client.post(
            action_url,
            data=form_data,
            headers={
                "User-Agent": user_agent,
                "Content-Type": _FORM_URLENCODED,
            },
            follow_redirects=False,
        )
        resp = await client.get(ru, headers={"User-Agent": user_agent}, follow_redirects=False)
        if resp.status_code in (301, 302, 303, 307):
            code = _code_from_redirect(resp.headers.get("location", ""))
            if code:
                return code
        if resp.status_code != 200:
            return None
        return await _handle_prism_interstitial(client, page_html=resp.text, user_agent=user_agent)

    if "Consent/Update" not in action_url:
        return None

    resp = await client.post(
        action_url,
        data=form_data,
        headers={
            "User-Agent": user_agent,
            "Content-Type": _FORM_URLENCODED,
        },
        follow_redirects=False,
    )
    if resp.status_code != 200:
        return None
    consent_page_url = str(resp.url)
    sd_match = _CONSENT_SERVER_DATA_RE.search(resp.text)
    if not sd_match:
        return None
    try:
        decoder = json.JSONDecoder()
        sd_obj, _idx = decoder.raw_decode(sd_match.group(1))
    except (json.JSONDecodeError, ValueError):  # NOSONAR intentional: documents distinct error sources
        return None
    if not isinstance(sd_obj, dict):
        return None
    sd = cast(dict[str, Any], sd_obj)
    consent_form: dict[str, str] = {
        "ucaction": "Yes",
        "client_id": _safe_str(sd.get("sClientId")),
        "scope": _safe_str(sd.get("sRawInputScopes")),
        "cscope": _safe_str(sd.get("sRawInputGrantedScopes")),
        "canary": _safe_str(sd.get("sCanary")),
    }
    resp = await client.post(
        consent_page_url,
        data=consent_form,
        headers={
            "User-Agent": user_agent,
            "Content-Type": _FORM_URLENCODED,
            "Referer": consent_page_url,
        },
        follow_redirects=False,
    )
    for _ in range(10):
        if resp.status_code not in (301, 302, 303, 307):
            break
        location = resp.headers.get("location", "")
        code = _code_from_redirect(location)
        if code:
            return code
        if location.startswith("/") and not location.startswith("//"):
            parsed = urlparse(str(resp.url))
            location = f"{parsed.scheme}://{parsed.netloc}{location}"
        resp = await client.get(
            location, headers={"User-Agent": user_agent}, follow_redirects=False
        )
    return None


def _safe_str(value: object) -> str:
    return value if isinstance(value, str) else ""


async def _exchange_prism_code(
    client: httpx.AsyncClient,
    *,
    code: str,
    pkce_verifier: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    user_agent: str,
) -> MSATokens:
    resp = await client.post(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "code_verifier": pkce_verifier,
            "scope": scope,
        },
        headers={
            "Content-Type": _FORM_URLENCODED,
            "User-Agent": user_agent,
        },
        follow_redirects=False,
    )
    if resp.status_code == 200:
        return _parse_token_response(resp)
    try:
        data = parse_json_object_auth(resp)
    except MCAuthError:
        data = {"raw": resp.text}
    raise CookieAuthError(f"Prism token exchange failed: status={resp.status_code} body={data!r}")

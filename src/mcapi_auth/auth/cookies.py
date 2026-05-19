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
2. :func:`login_with_cookies_msa_v2_loopback` — Azure-AD consumers
   flow using a v2 client_id with a loopback redirect URI (the
   approach pioneered by PrismLauncher; defaults to its client_id
   but works for any v2 app with a loopback URL registered, e.g.
   LiquidLauncher). More involved (Microsoft sometimes serves an
   interstitial consent page that has to be auto-clicked) but
   works when the v1 flow is blocked by FIDO / passkey enforcement.
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

import base64
import html as html_mod
import json
import logging
import re
from collections.abc import AsyncGenerator, Iterable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final, cast
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
from ..exceptions import McAuthError, MSAFlowError
from .auth_code import create_pkce_challenge
from .msa import MSATokens, _parse_token_response  # pyright: ignore[reportPrivateUsage]
from .xbox import XboxLiveToken

__all__ = [
    "BrowserCookie",
    "ConsentRequiredError",
    "CookieAuthError",
    "FidoRequiredError",
    "SISUTokens",
    "StaleCookiesError",
    "cookies_to_header",
    "extract_sisu_token",
    "login_with_cookies_msa_v1",
    "login_with_cookies_msa_v2_loopback",
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
    client: httpx.AsyncClient | None,
) -> AsyncGenerator[httpx.AsyncClient]:
    """Acquire an httpx client for cookie flows.

    Callers can pass their own client (e.g. configured with a proxy);
    individual requests inside the flow pass ``follow_redirects=False``
    explicitly so we don't depend on the caller's client setting.
    """
    if client is not None:
        yield client
        return
    async with httpx.AsyncClient(follow_redirects=False, timeout=DEFAULT_HTTP_TIMEOUT) as owned:
        yield owned


class CookieAuthError(MSAFlowError):
    """A cookie-based auth flow couldn't complete (FIDO / passkey block, etc.).

    Concrete subclasses signal *why* it failed so callers can pick the
    right recovery path:

    * :class:`StaleCookiesError` — cookies are expired / not signed in.
      The recovery is to re-run the browser cookie capture step.
    * :class:`FidoRequiredError` — the account is FIDO / passkey-locked.
      The Live-Connect v1 flow can't proceed; fall back to
      :func:`login_with_cookies_sisu`.
    * :class:`ConsentRequiredError` — Microsoft served an MFA / app
      consent interstitial we don't auto-click. Manual sign-in required.

    Generic / unknown failures still raise the base :class:`CookieAuthError`.

    Attributes carry forensics that help the caller decide what to do:

    Attributes:
        status_code: HTTP status of the response that gave up.
        body_preview: First ~512 chars of the body (PII-redacted by
            convention; we trim aggressively).
        location: The ``Location:`` header if any.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body_preview: str | None = None,
        location: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code: int | None = status_code
        self.body_preview: str | None = body_preview
        self.location: str | None = location


class StaleCookiesError(CookieAuthError):
    """The browser cookies are expired or refer to a signed-out session.

    Recovery: re-run the browser cookie capture step (the user has to
    sign in again in the headless browser).
    """


class FidoRequiredError(CookieAuthError):
    """The Microsoft account is FIDO / passkey-locked.

    The Live-Connect v1 cookie flow can't bypass FIDO. Recovery: call
    :func:`login_with_cookies_sisu` instead — SISU is one of the few
    paths Microsoft still allows for FIDO-only accounts.
    """


class ConsentRequiredError(CookieAuthError):
    """Microsoft served an MFA / app-consent interstitial we don't auto-click.

    Typical for accounts with conditional-access policies or first-time
    consent for the launcher client. Recovery: have the user sign in
    interactively once to grant consent, then retry.
    """


_FIDO_BODY_MARKERS: Final = (
    "passkey",
    "windowshello",
    "windows hello",
    "fido2",
    "/fido/",
    "fidoauth",
    "security key",
    "biometric",
)
_STALE_BODY_MARKERS: Final = (
    "your account or password is incorrect",
    "we couldn't find an account",
    "couldn't sign you in",
    "couldn&#39;t sign you in",
    "session has expired",
    "sign in to your account",
    'id="i0116"',  # the login form's email field
)
_CONSENT_BODY_MARKERS: Final = (
    "/consent/",
    "permissions requested",
    "let this app access your info",
    "needs your permission",
    "verify your identity",
    "we need to verify",
)


def _truncate(text: str | None, *, max_chars: int = 512) -> str | None:
    if text is None:
        return None
    return text if len(text) <= max_chars else text[:max_chars] + "…"


# NOSONAR S5857 reluctant qty needed; nested-object JSON can't use [^}] safely.
# fmt: off
_SERVERDATA_RE: Final = re.compile(r"ServerData\s*=\s*(\{.+?\})\s*;", re.DOTALL)  # NOSONAR
# fmt: on


def _parse_serverdata(body: str | None) -> dict[str, object] | None:
    """Extract the ``ServerData = {...};`` blob that Microsoft inlines.

    Returns the parsed object (typed as ``dict[str, object]`` for the
    callers' convenience) or ``None`` if the blob isn't present or isn't
    valid JSON. ``ServerData`` is plain JSON in practice even though the
    surrounding context is JavaScript.
    """
    if not body:
        return None
    match = _SERVERDATA_RE.search(body)
    if match is None:
        return None
    try:
        parsed: object = json.loads(match.group(1))
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return cast(dict[str, object], parsed)


def _classify_cookie_failure(
    *,
    status_code: int | None,
    body: str | None,
    location: str | None,
) -> type[CookieAuthError]:
    """Pick the most specific :class:`CookieAuthError` subclass for a failure.

    Detection prefers Microsoft's inlined ``ServerData = {...};`` JS blob
    when present (it's the canonical signed-in/session state) and falls
    back to body-marker scanning when it isn't. Marker order is
    FIDO → Consent → Stale so that a page mentioning "passkey" is treated
    as FIDO regardless of whether the login form is also rendered.
    """
    server_data = _parse_serverdata(body)
    if server_data is not None:
        # Canonical signed-in state. Microsoft uses ``fIsSignedIn`` and
        # ``arrSessions`` to track active sessions; either being empty
        # means the cookies are dead.
        signed_in = server_data.get("fIsSignedIn")
        sessions = server_data.get("arrSessions")
        if (
            signed_in is False
            or sessions is None
            or (isinstance(sessions, list) and len(cast(list[object], sessions)) == 0)
        ):
            return StaleCookiesError
    lc_body = (body or "").lower()
    lc_loc = (location or "").lower()
    haystack = lc_body + " " + lc_loc
    if any(marker in haystack for marker in _FIDO_BODY_MARKERS):
        return FidoRequiredError
    if any(marker in haystack for marker in _CONSENT_BODY_MARKERS):
        return ConsentRequiredError
    if any(marker in haystack for marker in _STALE_BODY_MARKERS):
        return StaleCookiesError
    # ``ServerData`` being absent + 200 OK on a Live-Connect URL still
    # usually means we got the sign-in page (older flows / non-Azure
    # endpoints don't inline ServerData). Keep the loose login-page
    # fallback for that case.
    if status_code == 200 and "login" in lc_loc + lc_body[:200]:
        return StaleCookiesError
    return CookieAuthError


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

    When :func:`login_with_cookies_sisu` is called with
    ``also_exchange_msa=True`` the ``msa`` field carries the MSA
    access/refresh tokens minted from the same SISU OAuth code — useful
    for FIDO-locked accounts that need an MS refresh token without going
    through the Live-Connect cookie flow (which FIDO blocks).
    """

    tokens_by_relying_party: dict[str, XboxLiveToken]
    msa: MSATokens | None = None

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
    invocation (e.g. the v2-loopback flow's interstitial chain). For
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
    to route the flow through a proxy or share a connection pool. When
    a caller-supplied client is given it keeps its own timeout; otherwise
    a default :data:`DEFAULT_HTTP_TIMEOUT` is applied. Wrap the call in
    ``async with asyncio.timeout(N):`` for an overall deadline.
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

    async with _acquire_for_cookies(http_client) as client:
        resp = await client.get(
            authorize_url,
            headers={"Cookie": cookie_header, "User-Agent": user_agent},
            follow_redirects=False,
        )
        if resp.status_code != 302:
            err_cls = _classify_cookie_failure(
                status_code=resp.status_code,
                body=resp.text,
                location=resp.headers.get("location"),
            )
            raise err_cls(
                "Live-Connect /oauth20_authorize.srf did not 302 — "
                "the account is likely FIDO-enforced or the cookies are stale "
                f"(status={resp.status_code})",
                status_code=resp.status_code,
                body_preview=_truncate(resp.text),
                location=resp.headers.get("location"),
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
    also_exchange_msa: bool = False,
    msa_client_id: str | None = None,
    msa_redirect_uri: str | None = None,
    msa_scope: str = LIVE_CONNECT_SCOPE_MBI_SSL,
    http_client: httpx.AsyncClient | None = None,
) -> SISUTokens:
    """SISU (Xbox SSO) flow — returns XBL/XSTS tokens directly.

    Use as a fallback when :func:`login_with_cookies_msa_v1` returns
    :class:`CookieAuthError` (typically because FIDO is enforced on the
    account).

    Args:
        cookie_header: Pre-flattened ``Cookie:`` header value for
            ``login.live.com``.
        cobrand_id: SISU co-brand ID (defaults to the Minecraft launcher's).
        tid: SISU tenant / Live-Connect client_id. The default is the
            Minecraft launcher's ``896928775``.
        return_url: SISU ``ru=`` query parameter.
        user_agent: User-Agent header sent on every hop.
        also_exchange_msa: If ``True``, also POST the ``code=`` from the
            SISU callback to ``oauth20_token.srf`` to mint an MSA
            access/refresh-token pair. The resulting tokens are attached
            to ``SISUTokens.msa``. Defaults to ``False`` for back-compat.
            This is useful for FIDO-locked accounts that can only reach
            Minecraft through SISU and would otherwise have to re-capture
            cookies on every XBL expiry.
        msa_client_id: Override the ``client_id`` used in the MSA token
            exchange. Defaults to ``tid`` (the SISU tenant). The
            ``code=`` returned by SISU is bound to this client.
        msa_redirect_uri: Override the ``redirect_uri`` used in the MSA
            token exchange. Defaults to :data:`SISU_DEFAULT_RU` (the
            same URL SISU 302'd us back to).
        msa_scope: OAuth scope to request in the MSA exchange. Defaults
            to ``service::user.auth.xboxlive.com::MBI_SSL`` (what SISU
            itself uses).
        http_client: Optional :class:`httpx.AsyncClient` to reuse.

    Raises:
        StaleCookiesError: ``login.live.com`` declined the cookies.
        FidoRequiredError: The account is FIDO/passkey-locked and even
            SISU can't bypass it.
        ConsentRequiredError: Microsoft served an interstitial.
        CookieAuthError: Any other SISU-flow failure.
    """
    sisu_url = f"{SISU_CONNECT_URL}?state=login&cobrandId={cobrand_id}&tid={tid}&ru={return_url}"
    async with _acquire_for_cookies(http_client) as client:
        resp = await client.get(
            sisu_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code != 302:
            err_cls = _classify_cookie_failure(
                status_code=resp.status_code,
                body=resp.text,
                location=resp.headers.get("location"),
            )
            raise err_cls(
                f"SISU /connect did not 302: status={resp.status_code}",
                status_code=resp.status_code,
                body_preview=_truncate(resp.text),
                location=resp.headers.get("location"),
            )
        login_url = resp.headers["location"]

        resp = await client.get(
            login_url,
            headers={"Cookie": cookie_header, "User-Agent": user_agent},
            follow_redirects=False,
        )
        if resp.status_code != 302:
            err_cls = _classify_cookie_failure(
                status_code=resp.status_code,
                body=resp.text,
                location=resp.headers.get("location"),
            )
            raise err_cls(
                f"SISU login.live.com did not 302 — cookies likely stale "
                f"or FIDO-enforced (status={resp.status_code})",
                status_code=resp.status_code,
                body_preview=_truncate(resp.text),
                location=resp.headers.get("location"),
            )
        callback_url = resp.headers["location"]
        if "code=" not in callback_url:
            raise CookieAuthError(f"SISU callback missing 'code=': {callback_url!r}")
        sisu_code_values = _parse_qs(_query_of(callback_url)).get("code", [])
        sisu_code = sisu_code_values[0] if sisu_code_values and sisu_code_values[0] else None

        resp = await client.get(
            callback_url, headers={"User-Agent": user_agent}, follow_redirects=False
        )
        if resp.status_code != 302:
            raise CookieAuthError(f"SISU callback did not 302: status={resp.status_code}")

        final_url = resp.headers.get("location", "")

        # Optional: exchange the SISU code for MSA tokens before exiting
        # the AsyncClient ctx so we share the connection pool.
        msa_tokens: MSATokens | None = None
        if also_exchange_msa:
            if sisu_code is None:
                raise CookieAuthError(
                    "also_exchange_msa=True but SISU callback URL had no usable 'code='"
                )
            msa_tokens = await _exchange_sisu_code_for_msa(
                client,
                code=sisu_code,
                client_id=msa_client_id or tid,
                redirect_uri=msa_redirect_uri or return_url,
                scope=msa_scope,
                user_agent=user_agent,
            )

    parsed_sisu = _parse_sisu_final_url(final_url)
    if msa_tokens is not None:
        return SISUTokens(
            tokens_by_relying_party=parsed_sisu.tokens_by_relying_party, msa=msa_tokens
        )
    return parsed_sisu


def _parse_sisu_final_url(final_url: str) -> SISUTokens:
    """Parse the ``accessToken=`` fragment of the SISU return URL.

    Extracted from :func:`login_with_cookies_sisu` to keep that
    function's cognitive complexity within Sonar's S3776 budget.
    """
    fragment = _fragment_of(final_url)
    frag_params = _parse_qs(fragment)
    token_b64_list = frag_params.get("accessToken", [])
    if not token_b64_list or not token_b64_list[0]:
        raise CookieAuthError(f"SISU final redirect missing 'accessToken' fragment: {final_url!r}")
    token_b64 = token_b64_list[0]
    try:
        decoded = base64.b64decode(token_b64 + "==").decode("utf-8")
        parsed_obj: object = json.loads(decoded)
    except ValueError as e:  # UnicodeDecodeError + json.JSONDecodeError both subclass ValueError
        raise CookieAuthError(f"SISU 'accessToken' fragment is not valid b64+JSON: {e}") from e
    if not isinstance(parsed_obj, list):
        raise CookieAuthError(f"SISU returned non-array payload: {type(parsed_obj).__name__}")
    return _parse_sisu_array(cast(list[object], parsed_obj))


async def _exchange_sisu_code_for_msa(
    client: httpx.AsyncClient,
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    user_agent: str,
) -> MSATokens:
    """POST the SISU OAuth code to ``oauth20_token.srf`` for MSA tokens.

    SISU's first hop is a normal Live-Connect OAuth ``response_type=code``
    handshake under the hood, so the code Microsoft 302s back to the
    callback is exchangeable at the same token endpoint the v1 cookie
    flow uses. The trick is matching the ``client_id`` / ``redirect_uri``
    pair the SISU authorize request used — by default those are the SISU
    ``tid`` and ``return_url``, but callers may override.
    """
    resp = await client.post(
        LIVE_CONNECT_TOKEN_URL,
        data={
            "client_id": client_id,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "scope": scope,
        },
        headers={
            "Content-Type": _FORM_URLENCODED,
            "User-Agent": user_agent,
        },
        follow_redirects=False,
    )
    if resp.status_code != 200:
        raise CookieAuthError(
            f"SISU MSA token exchange failed: status={resp.status_code} body={resp.text!r}",
            status_code=resp.status_code,
            body_preview=_truncate(resp.text),
        )
    return _parse_token_response(resp)


def extract_sisu_token(sisu: SISUTokens, relying_party: str) -> XboxLiveToken:
    """Return the SISU token for ``relying_party`` or raise :class:`CookieAuthError`."""
    token = sisu.get(relying_party)
    if token is None:
        raise CookieAuthError(f"SISU response had no token for relying party {relying_party!r}")
    return token


def _parse_sisu_entry(entry: object) -> tuple[str, XboxLiveToken] | None:
    """Extract one (relying_party, token) pair from a single SISU array entry, or None if invalid."""
    if not isinstance(entry, dict):
        return None
    entry_typed = cast(dict[str, Any], entry)
    rp = entry_typed.get("Item1")
    item2 = entry_typed.get("Item2")
    if not isinstance(rp, str) or not isinstance(item2, dict):
        return None
    item2_typed = cast(dict[str, Any], item2)
    token = item2_typed.get("Token")
    display = item2_typed.get("DisplayClaims")
    if not isinstance(token, str) or not isinstance(display, dict):
        return None
    display_typed = cast(dict[str, Any], display)
    xui = display_typed.get("xui")
    if not isinstance(xui, list) or not xui:
        return None
    xui_first = cast(list[object], xui)[0]
    if not isinstance(xui_first, dict):
        return None
    uhs = cast(dict[str, Any], xui_first).get("uhs")
    if not isinstance(uhs, str) or not uhs:
        return None
    return rp, XboxLiveToken(token=token, userhash=uhs)


def _parse_sisu_array(entries: list[object]) -> SISUTokens:
    out: dict[str, XboxLiveToken] = {}
    for entry in entries:
        parsed = _parse_sisu_entry(entry)
        if parsed is not None:
            rp, tok = parsed
            out[rp] = tok
    if not out:
        raise CookieAuthError("SISU response contained no usable tokens")
    return SISUTokens(tokens_by_relying_party=out)


# -- Flow 3: MSA v2 + loopback redirect (Azure-AD consumers) -----------------


async def login_with_cookies_msa_v2_loopback(
    cookies: Iterable[BrowserCookie | Mapping[str, Any]],
    *,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    redirect_uri: str = PRISM_LAUNCHER_REDIRECT_URI,
    scope: str = "XboxLive.SignIn XboxLive.offline_access",
    user_agent: str = DEFAULT_USER_AGENT,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """MSA-v2 + loopback-redirect flow on Azure-AD consumers endpoints.

    Pioneered by PrismLauncher, but works for any v2 client_id that has
    a loopback (``http://127.0.0.1:*``) redirect URI registered — e.g.
    LiquidLauncher. Defaults to PrismLauncher's client_id + redirect.

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

    async with _acquire_for_cookies(http_client) as client:
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
                return await _exchange_v2_loopback_code(
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
            err_cls = _classify_cookie_failure(
                status_code=resp.status_code,
                body=resp.text,
                location=resp.headers.get("location"),
            )
            raise err_cls(
                f"login.live.com returned unexpected status {resp.status_code}",
                status_code=resp.status_code,
                body_preview=_truncate(resp.text),
                location=resp.headers.get("location"),
            )

        # 200 OK with an HTML body — Microsoft is asking us to follow
        # the "tile click" / consent dance. Parse the embedded
        # ``ServerData`` JSON and proceed.
        code = await _handle_v2_loopback_html_flow(
            client,
            html=resp.text,
            referer=live_url,
            client_id=client_id,
            user_agent=user_agent,
        )
        if code is None:
            err_cls = _classify_cookie_failure(status_code=200, body=resp.text, location=None)
            if err_cls is CookieAuthError:
                err_cls = ConsentRequiredError
            raise err_cls(
                "v2-loopback HTML flow finished without an auth code — "
                "Microsoft likely served an interstitial we don't handle. "
                "Try the Live-Connect or SISU flow instead.",
                status_code=200,
                body_preview=_truncate(resp.text),
            )
        return await _exchange_v2_loopback_code(
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


_SERVER_DATA_RE = re.compile(
    r"var ServerData\s*=\s*({.*?});\s*</script>",  # NOSONAR reluctant intentional (ServerData JSON contains '}' chars)
    re.DOTALL,
)
_CONSENT_SERVER_DATA_RE = re.compile(
    r"ServerData\s*=\s*(\{.+?\});",  # NOSONAR reluctant intentional (matched JSON has nested '}' chars)
    re.DOTALL,
)
_FORM_ACTION_RE = re.compile(r'action="([^"]+)"')
_FORM_INPUT_RE = re.compile(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"')
_CTX_RE = re.compile(r"contextid[=:]([A-F0-9]+)", re.IGNORECASE)
_OPID_RE = re.compile(r"opid[=:]([A-F0-9]+)", re.IGNORECASE)
_BK_RE = re.compile(r"bk[=:](\d+)")
_UAID_RE = re.compile(r"uaid[=:]([a-f0-9]+)", re.IGNORECASE)


def _extract_server_data(html: str) -> dict[str, Any] | None:
    """Parse the ``var ServerData = {...};`` blob into a dict, or return None."""
    sd_match = _SERVER_DATA_RE.search(html)
    if not sd_match:
        return None
    try:
        parsed_sd: object = json.loads(sd_match.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed_sd, dict):
        return None
    return cast(dict[str, Any], parsed_sd)


def _session_id_of(entry: object) -> str | None:
    if not isinstance(entry, dict):
        return None
    candidate = cast(dict[str, Any], entry).get("id")
    return candidate if isinstance(candidate, str) and candidate else None


def _is_signed_in(entry: object) -> bool:
    return isinstance(entry, dict) and bool(cast(dict[str, Any], entry).get("isSignedIn"))


def _pick_session_id(server_data: dict[str, Any]) -> str | None:
    """Prefer a signed-in session; fall back to the first session."""
    sessions_raw = server_data.get("arrSessions")
    if not isinstance(sessions_raw, list) or not sessions_raw:
        return None
    sessions = cast(list[object], sessions_raw)
    for s in sessions:
        if _is_signed_in(s) and (sid := _session_id_of(s)) is not None:
            return sid
    return _session_id_of(sessions[0])


def _build_tile_params(html: str, *, session_id: str, client_id: str) -> dict[str, str] | None:
    """Pull contextid / opid / bk / uaid from the page and assemble the tile URL params."""
    ctx_match = _CTX_RE.search(html)
    opid_match = _OPID_RE.search(html)
    if not ctx_match or not opid_match:
        return None
    params: dict[str, str] = {
        "client_id": client_id,
        "contextid": ctx_match.group(1),
        "opid": opid_match.group(1),
        "sessionid": session_id,
        "mkt": "EN-US",
        "lc": "1033",
    }
    bk_match = _BK_RE.search(html)
    if bk_match:
        params["bk"] = bk_match.group(1)
    uaid_match = _UAID_RE.search(html)
    if uaid_match:
        params["uaid"] = uaid_match.group(1)
    return params


async def _handle_v2_loopback_html_flow(
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
    server_data = _extract_server_data(html)
    if server_data is None:
        return None
    session_id = _pick_session_id(server_data)
    if session_id is None:
        return None
    tile_params = _build_tile_params(html, session_id=session_id, client_id=client_id)
    if tile_params is None:
        return None

    tile_url = f"{LIVE_CONNECT_AUTHORIZE_URL}?{urlencode(tile_params)}"
    resp = await client.get(
        tile_url, headers={"User-Agent": user_agent, "Referer": referer}, follow_redirects=False
    )

    if resp.status_code == 302:
        code = _code_from_redirect(resp.headers.get("location", ""))
        if code:
            return code

    if resp.status_code == 200:
        return await _handle_v2_loopback_interstitial(
            client, page_html=resp.text, user_agent=user_agent
        )
    return None


async def _handle_v2_loopback_interstitial(  # NOSONAR linear protocol stages; splitting hurts readability
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
        return await _handle_v2_loopback_interstitial(
            client, page_html=resp.text, user_agent=user_agent
        )

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
    except ValueError:  # json.JSONDecodeError subclasses ValueError
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


async def _exchange_v2_loopback_code(
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
    except McAuthError:
        data = {"raw": resp.text}
    raise CookieAuthError(f"MSA v2 token exchange failed: status={resp.status_code} body={data!r}")

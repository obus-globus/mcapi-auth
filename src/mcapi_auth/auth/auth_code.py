"""Authorization-Code with PKCE flow (alternative to device-code).
For desktop apps that can spin up a localhost HTTP listener for the
redirect, the auth-code flow is friendlier than device-code: the user
sees a normal browser sign-in instead of having to type a code.

This module provides:

* The protocol pieces — :func:`create_pkce_challenge`,
  :func:`build_authorize_url`, :func:`exchange_authorization_code` — for
  callers that want to host the redirect listener themselves.
* A high-level convenience wrapper, :func:`acquire_msa_via_browser`,
  that handles the listener, browser open, state CSRF, and code
  exchange end-to-end using only the stdlib.

Typical usage::

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    msa = await acquire_msa_via_browser()
    # msa.access_token / msa.refresh_token are now valid.

For the *full* MS → Xbox → Mojang chain returning a
``MinecraftSession``, see :func:`mcapi_auth.login_via_browser`.
"""

import asyncio
import base64
import contextlib
import hashlib
import inspect
import logging
import secrets
import webbrowser
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .._constants import (
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    LIVE_CONNECT_SCOPE_MBI_SSL,
    LIVE_CONNECT_TOKEN_URL,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    MSA_AUTHORIZE_URL,
    MSA_SCOPE,
    MSA_TOKEN_URL,
    PRISM_LAUNCHER_CLIENT_ID,
)
from .._http import acquire_client, parse_json_object_auth
from ..exceptions import MSAFlowError
from .msa import MSATokens, _parse_token_response  # pyright: ignore[reportPrivateUsage]

__all__ = [
    "PKCEChallenge",
    "acquire_msa_via_browser",
    "acquire_msa_via_browser_v1",
    "build_authorize_url",
    "create_pkce_challenge",
    "exchange_authorization_code",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PKCEChallenge:
    """A generated PKCE verifier/challenge pair.

    Hold onto :attr:`verifier` — you'll need it for the token-exchange
    call. Send :attr:`challenge` (with :attr:`method`) to the authorize
    endpoint.
    """

    verifier: str
    challenge: str
    method: str = "S256"


def create_pkce_challenge() -> PKCEChallenge:
    """Generate a fresh PKCE verifier/challenge using SHA-256.

    The verifier is 43 characters of base64url-encoded entropy (32 bytes
    pre-encoding) — the recommended length from RFC 7636.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PKCEChallenge(verifier=verifier, challenge=challenge, method="S256")


def build_authorize_url(
    *,
    redirect_uri: str,
    pkce: PKCEChallenge | None = None,
    state: str | None = None,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    scope: str = MSA_SCOPE,
    prompt: str | None = None,
    authorize_url: str = MSA_AUTHORIZE_URL,
) -> str:
    """Build the MSA ``/authorize`` URL the user must visit.

    ``state`` is strongly recommended — generate a random string, store
    it, and reject the callback if it doesn't match. ``prompt`` may be
    ``"select_account"`` to force the account picker.

    ``pkce`` may be omitted for legacy Live-Connect v1 endpoints which
    do not support PKCE. ``authorize_url`` defaults to the v2 endpoint
    and may be overridden (e.g. to :data:`LIVE_CONNECT_AUTHORIZE_URL`).
    """
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
    }
    if pkce is not None:
        params["code_challenge"] = pkce.challenge
        params["code_challenge_method"] = pkce.method
    if state is not None:
        params["state"] = state
    if prompt is not None:
        params["prompt"] = prompt
    return f"{authorize_url}?{urlencode(params)}"


async def exchange_authorization_code(
    *,
    redirect_uri: str,
    code: str,
    pkce_verifier: str | None = None,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    token_url: str = MSA_TOKEN_URL,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Exchange an authorization ``code`` for MSA access + refresh tokens.

    ``pkce_verifier`` may be ``None`` for the legacy Live-Connect v1
    flow. ``token_url`` defaults to the v2 endpoint; set it to
    :data:`LIVE_CONNECT_TOKEN_URL` for the v1 flow.

    Raises :class:`MSAFlowError` on a non-200 response from the token
    endpoint.
    """
    data: dict[str, str] = {
        "client_id": client_id,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    if pkce_verifier is not None:
        data["code_verifier"] = pkce_verifier
    async with acquire_client(http_client) as c:
        response = await c.post(token_url, data=data)
    if response.status_code == 200:
        return _parse_token_response(response)
    parsed = parse_json_object_auth(response)
    raise MSAFlowError(
        "authorization-code exchange failed: "
        f"status={response.status_code} error={parsed.get('error', 'unknown')!r}"
    )


# -- Convenience: full browser-driven flow --------------------------------

_DEFAULT_SUCCESS_HTML = (
    "<!doctype html><html><head><meta charset=utf-8>"
    "<title>Signed in</title></head>"
    "<body style='font-family:system-ui;text-align:center;padding:3em'>"
    "<h1>Signed in</h1>"
    "<p>You can close this tab and return to the application.</p>"
    "</body></html>"
)


async def acquire_msa_via_browser(  # NOSONAR linear protocol stages; splitting hurts readability
    *,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    bind_host: str = "127.0.0.1",
    bind_port: int = 0,
    redirect_path: str = "/callback",
    prompt: str | None = None,
    scope: str = MSA_SCOPE,
    open_browser: Callable[[str], None | Awaitable[None]] | None = None,
    success_html: str = _DEFAULT_SUCCESS_HTML,
    http_client: httpx.AsyncClient | None = None,
    authorize_url: str = MSA_AUTHORIZE_URL,
    token_url: str = MSA_TOKEN_URL,
    use_pkce: bool = True,
) -> MSATokens:
    """Run the authorization-code flow end-to-end via a browser.

    Spins up a stdlib-only asyncio TCP listener on
    ``bind_host:bind_port`` (port ``0`` picks a free one), opens the
    user's browser to the MSA authorize URL, waits for the redirect
    callback, validates the CSRF ``state``, and exchanges the resulting
    ``code`` for :class:`MSATokens`.

    By default this targets the modern v2 ``/consumers/oauth2/v2.0/*``
    endpoints with PKCE. Pass ``authorize_url=LIVE_CONNECT_AUTHORIZE_URL``,
    ``token_url=LIVE_CONNECT_TOKEN_URL``, ``use_pkce=False``, and the
    appropriate Live-Connect scope + client_id to drive the v1
    ``login.live.com/oauth20_*.srf`` flow instead — or just call
    :func:`acquire_msa_via_browser_v1`.

    This function does not impose its own deadline — wrap the call in
    ``async with asyncio.timeout(N):`` if you need a bounded wait
    (callers typically want ~300s for the browser flow). On timeout a
    plain :class:`TimeoutError` propagates out.

    The redirect URI sent to Microsoft is
    ``http://{bind_host}:{actual_port}{redirect_path}`` — register that
    pattern in your Azure-AD app, or use the public Minecraft Launcher
    client_id which accepts any ``http://localhost:*`` redirect.

    Pass ``open_browser=lambda url: print(url)`` (or any callable) to
    suppress the automatic browser open and just hand the URL to the
    caller's UI.
    """
    pkce = create_pkce_challenge() if use_pkce else None
    state = secrets.token_urlsafe(24)
    loop = asyncio.get_running_loop()
    received: asyncio.Future[dict[str, str]] = loop.create_future()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            if len(request_line) > 8192:
                writer.write(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return
            header_bytes = 0
            while True:
                line = await reader.readline()
                header_bytes += len(line)
                if header_bytes > 32768:
                    writer.write(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    return
                if line in (b"\r\n", b""):
                    break
            try:
                _method, full_path, _version = request_line.decode("latin-1").split(" ", 2)
            except ValueError:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            parsed = urlparse(full_path)
            if parsed.path != redirect_path:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            # Only treat a request as the real callback if it carries the
            # OAuth-defined ``code`` or ``error`` parameter — otherwise a
            # browser prefetch / favicon / preview request to the same
            # path can race the user's real redirect.
            is_oauth_callback = "code" in params or "error" in params
            body = success_html.encode("utf-8")
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            if is_oauth_callback and not received.done():
                received.set_result(params)
        except asyncio.CancelledError, ConnectionError:
            raise
        except Exception as e:
            if not received.done():
                received.set_exception(e)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    try:
        server = await asyncio.start_server(handle, host=bind_host, port=bind_port)
    except OSError as e:
        raise MSAFlowError(
            f"failed to bind local listener on {bind_host}:{bind_port} for "
            f"the OAuth redirect ({e}). Pass a different bind_port=, or use "
            f"bind_port=0 to let the OS pick a free port."
        ) from e
    sockets = server.sockets or ()
    if not sockets:
        server.close()
        await server.wait_closed()
        raise MSAFlowError("failed to bind local listener for auth-code redirect")
    actual_port = int(sockets[0].getsockname()[1])
    redirect_uri = f"http://{bind_host}:{actual_port}{redirect_path}"
    url = build_authorize_url(
        redirect_uri=redirect_uri,
        pkce=pkce,
        state=state,
        client_id=client_id,
        scope=scope,
        prompt=prompt,
        authorize_url=authorize_url,
    )

    opener = open_browser if open_browser is not None else webbrowser.open
    try:
        result = opener(url)
        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.warning("failed to open browser for auth-code flow; visit manually: %s", url)

    try:
        params = await received
    finally:
        server.close()
        await server.wait_closed()

    if "error" in params:
        raise MSAFlowError(
            f"authorize endpoint returned error={params['error']!r} "
            f"description={params.get('error_description', '')!r}"
        )
    if params.get("state") != state:
        raise MSAFlowError(
            "OAuth redirect 'state' did not match — possible CSRF, refusing to continue"
        )
    code = params.get("code")
    if not code:
        raise MSAFlowError(f"OAuth redirect did not include 'code': params={params!r}")
    return await exchange_authorization_code(
        redirect_uri=redirect_uri,
        code=code,
        pkce_verifier=pkce.verifier if pkce else None,
        client_id=client_id,
        token_url=token_url,
        http_client=http_client,
    )


async def acquire_msa_via_browser_v1(
    *,
    client_id: str = MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    scope: str = LIVE_CONNECT_SCOPE_MBI_SSL,
    redirect_uri: str = LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    open_browser: Callable[[str], None | Awaitable[None]] | None = None,
    prompt_for_code: Callable[[str], str | Awaitable[str]] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Run the **legacy Live-Connect v1** auth-code flow via a browser.

    Unlike the v2 ``acquire_msa_via_browser`` this does **not** spin up
    a localhost HTTP listener — the ``00000000402b5328`` client_id is
    registered against the OOB desktop redirect
    (``https://login.live.com/oauth20_desktop.srf``) only, and
    Microsoft will reject any other ``redirect_uri`` with::

        invalid_request: The provided value for the input parameter
        'redirect_uri' is not valid.

    Instead, after the user completes sign-in the browser lands on a
    page whose URL contains ``?code=...&state=...``. The user copies
    that URL (or just the ``code=`` value) and pastes it back into the
    CLI. PKCE is not used.

    Args:
        client_id: MSA client_id (default ``00000000402b5328``).
        scope: OAuth scope (default ``service::user.auth.xboxlive.com::MBI_SSL``).
        redirect_uri: OOB redirect URI. Defaults to the desktop URI;
            you can override if you have another registered redirect.
        open_browser: Optional callback invoked with the authorize URL
            before falling back to :func:`webbrowser.open`.
        prompt_for_code: Async/sync callable taking a help message and
            returning either the bare authorization code or the full
            redirected URL. Defaults to a blocking ``input()`` on a
            thread.
        http_client: Optional shared :class:`httpx.AsyncClient`.

    Returns:
        The exchanged :class:`MSATokens`.

    Raises:
        MSAFlowError: if the redirect page reports an error, the
            ``state`` doesn't match, or the token exchange fails.
    """
    state = secrets.token_urlsafe(24)
    authorize_url = build_authorize_url(
        redirect_uri=redirect_uri,
        pkce=None,
        state=state,
        client_id=client_id,
        scope=scope,
        authorize_url=LIVE_CONNECT_AUTHORIZE_URL,
    )

    if open_browser is not None:
        result = open_browser(authorize_url)
        if isinstance(result, Awaitable):
            await result
    else:
        with contextlib.suppress(Exception):
            webbrowser.open(authorize_url)

    if prompt_for_code is None:

        async def _default_prompt(msg: str) -> str:
            return await asyncio.to_thread(input, msg)

        prompt_for_code = _default_prompt

    help_msg = (
        "After signing in, your browser will land on a page whose URL\n"
        "starts with " + redirect_uri + "?code=... — paste that URL\n"
        "(or just the code= value) here: "
    )
    raw = prompt_for_code(help_msg)
    if isinstance(raw, Awaitable):
        raw = await raw
    code, returned_state = _parse_oob_response(raw.strip())
    if returned_state is not None and returned_state != state:
        raise MSAFlowError(f"OAuth state mismatch: expected {state!r}, got {returned_state!r}")

    return await exchange_authorization_code(
        redirect_uri=redirect_uri,
        code=code,
        pkce_verifier=None,
        client_id=client_id,
        token_url=LIVE_CONNECT_TOKEN_URL,
        http_client=http_client,
    )


def _parse_oob_response(pasted: str) -> tuple[str, str | None]:
    """Parse a pasted OOB-redirect URL or bare code.

    Accepts:

    * A bare authorization code (any string without ``?``, ``=``, or
      ``&``) — returned with ``state=None``.
    * A full URL like ``https://login.live.com/oauth20_desktop.srf?code=...&state=...``.
    * A bare query string like ``code=...&state=...``.
    * An ``error=...&error_description=...`` URL / query, which raises
      :class:`MSAFlowError`.

    Returns ``(code, state_or_none)``.
    """
    from urllib.parse import parse_qs, urlparse

    if "=" not in pasted and "?" not in pasted and "&" not in pasted:
        return pasted, None

    query = urlparse(pasted).query or pasted.split("?", 1)[1] if "?" in pasted else pasted
    parsed = parse_qs(query, keep_blank_values=False)

    if "error" in parsed:
        err = parsed["error"][0]
        desc = parsed.get("error_description", [""])[0]
        raise MSAFlowError(f"authorize endpoint returned error: {err}: {desc}")

    if "code" not in parsed:
        raise MSAFlowError(
            "could not find 'code' in pasted response — make sure you "
            "copied the full redirected URL after signing in"
        )
    code = parsed["code"][0]
    state = parsed["state"][0] if "state" in parsed else None
    return code, state

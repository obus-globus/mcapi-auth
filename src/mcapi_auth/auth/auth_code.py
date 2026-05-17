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

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
import secrets
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .._constants import (
    MINECRAFT_LAUNCHER_CLIENT_ID,
    MSA_AUTHORIZE_URL,
    MSA_SCOPE,
    MSA_TOKEN_URL,
)
from .._http import acquire_client, parse_json_object_auth
from ..exceptions import MSAFlowError
from .msa import MSATokens, _parse_token_response  # pyright: ignore[reportPrivateUsage]

__all__ = [
    "PKCEChallenge",
    "acquire_msa_via_browser",
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
    pkce: PKCEChallenge,
    state: str | None = None,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    scope: str = MSA_SCOPE,
    prompt: str | None = None,
) -> str:
    """Build the MSA ``/authorize`` URL the user must visit.

    ``state`` is strongly recommended — generate a random string, store
    it, and reject the callback if it doesn't match. ``prompt`` may be
    ``"select_account"`` to force the account picker.
    """
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
    }
    if state is not None:
        params["state"] = state
    if prompt is not None:
        params["prompt"] = prompt
    return f"{MSA_AUTHORIZE_URL}?{urlencode(params)}"


async def exchange_authorization_code(
    *,
    redirect_uri: str,
    code: str,
    pkce_verifier: str,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Exchange an authorization ``code`` for MSA access + refresh tokens.

    Raises :class:`MSAFlowError` on a non-200 response from the token
    endpoint.
    """
    async with acquire_client(http_client) as c:
        response = await c.post(
            MSA_TOKEN_URL,
            data={
                "client_id": client_id,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code_verifier": pkce_verifier,
            },
        )
    if response.status_code == 200:
        return _parse_token_response(response)
    data = parse_json_object_auth(response)
    raise MSAFlowError(
        "authorization-code exchange failed: "
        f"status={response.status_code} error={data.get('error', 'unknown')!r}"
    )


# -- Convenience: full browser-driven flow --------------------------------

_DEFAULT_SUCCESS_HTML = (
    b"<!doctype html><html><head><meta charset=utf-8>"
    b"<title>Signed in</title></head>"
    b"<body style='font-family:system-ui;text-align:center;padding:3em'>"
    b"<h1>Signed in</h1>"
    b"<p>You can close this tab and return to the application.</p>"
    b"</body></html>"
)


class _CallbackTimeoutError(MSAFlowError):
    """Browser-driven auth-code flow timed out waiting for the redirect."""


async def acquire_msa_via_browser(
    *,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    bind_host: str = "127.0.0.1",
    bind_port: int = 0,
    redirect_path: str = "/callback",
    timeout: float = 300.0,
    prompt: str | None = None,
    scope: str = MSA_SCOPE,
    open_browser: Callable[[str], object] | None = None,
    success_html: bytes = _DEFAULT_SUCCESS_HTML,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Run the authorization-code + PKCE flow end-to-end via a browser.

    Spins up a stdlib-only asyncio TCP listener on
    ``bind_host:bind_port`` (port ``0`` picks a free one), opens the
    user's browser to the MSA authorize URL, waits for the redirect
    callback (up to ``timeout`` seconds), validates the CSRF ``state``,
    and exchanges the resulting ``code`` for :class:`MSATokens`.

    The redirect URI sent to Microsoft is
    ``http://{bind_host}:{actual_port}{redirect_path}`` — register that
    pattern in your Azure-AD app, or use the public Minecraft Launcher
    client_id which accepts any ``http://localhost:*`` redirect.

    Pass ``open_browser=lambda url: print(url)`` (or any callable) to
    suppress the automatic browser open and just hand the URL to the
    caller's UI.
    """
    pkce = create_pkce_challenge()
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
            body = success_html
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
            if is_oauth_callback and not received.done():
                received.set_result(params)
        except (asyncio.CancelledError, ConnectionError):
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
    )

    opener = open_browser if open_browser is not None else webbrowser.open
    try:
        opener(url)
    except Exception:
        logger.warning("failed to open browser for auth-code flow; visit manually: %s", url)

    try:
        try:
            async with asyncio.timeout(timeout):
                params = await received
        except TimeoutError as e:
            raise _CallbackTimeoutError(
                f"timed out after {timeout}s waiting for the OAuth redirect"
            ) from e
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
        pkce_verifier=pkce.verifier,
        client_id=client_id,
        http_client=http_client,
    )

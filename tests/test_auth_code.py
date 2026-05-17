"""Tests for the authorization-code + PKCE flow."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
import respx

from mcapi_auth._constants import MSA_AUTHORIZE_URL, MSA_TOKEN_URL
from mcapi_auth.auth.auth_code import (
    build_authorize_url,
    create_pkce_challenge,
    exchange_authorization_code,
)
from mcapi_auth.exceptions import MSAFlowError


def test_pkce_challenge_is_s256_of_verifier() -> None:
    pkce = create_pkce_challenge()
    assert pkce.method == "S256"
    # Verifier is base64url(32 bytes) → 43 chars, no padding.
    assert len(pkce.verifier) == 43
    assert "=" not in pkce.verifier
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pkce.verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert pkce.challenge == expected


def test_pkce_challenges_are_unique() -> None:
    seen = {create_pkce_challenge().verifier for _ in range(20)}
    assert len(seen) == 20


def test_build_authorize_url_has_required_params() -> None:
    pkce = create_pkce_challenge()
    url = build_authorize_url(
        redirect_uri="http://localhost:8765/callback",
        pkce=pkce,
        state="csrf-token",
        prompt="select_account",
    )
    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == MSA_AUTHORIZE_URL
    q = parse_qs(parsed.query)
    assert q["response_type"] == ["code"]
    assert q["redirect_uri"] == ["http://localhost:8765/callback"]
    assert q["code_challenge"] == [pkce.challenge]
    assert q["code_challenge_method"] == ["S256"]
    assert q["state"] == ["csrf-token"]
    assert q["prompt"] == ["select_account"]
    assert q["scope"] == ["XboxLive.signin offline_access"]


def test_build_authorize_url_omits_optional_params() -> None:
    pkce = create_pkce_challenge()
    url = build_authorize_url(redirect_uri="http://localhost/cb", pkce=pkce)
    q = parse_qs(urlparse(url).query)
    assert "state" not in q
    assert "prompt" not in q


@respx.mock
async def test_exchange_authorization_code_happy_path() -> None:
    route = respx.post(MSA_TOKEN_URL).respond(
        json={"access_token": "acc", "refresh_token": "ref", "expires_in": 3600}
    )
    tokens = await exchange_authorization_code(
        redirect_uri="http://localhost/cb",
        code="auth-code",
        pkce_verifier="verifier-string",
    )
    assert tokens.access_token == "acc"
    assert tokens.refresh_token == "ref"
    body = route.calls.last.request.content.decode()
    assert "grant_type=authorization_code" in body
    assert "code=auth-code" in body
    assert "code_verifier=verifier-string" in body


@respx.mock
async def test_exchange_authorization_code_raises_on_error() -> None:
    respx.post(MSA_TOKEN_URL).respond(
        status_code=400, json={"error": "invalid_grant", "error_description": "code expired"}
    )
    with pytest.raises(MSAFlowError, match="status=400"):
        _ = await exchange_authorization_code(
            redirect_uri="http://localhost/cb",
            code="stale",
            pkce_verifier="v",
        )


# -- Tests for the convenience browser-driven wrapper ---------------------


@respx.mock
async def test_acquire_msa_via_browser_end_to_end() -> None:
    import asyncio
    import re

    import httpx as _httpx

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    # Let the localhost callback through respx; only the token endpoint is mocked.
    respx.route(url__regex=re.compile(r"^http://127\.0\.0\.1:\d+/")).pass_through()
    token_route = respx.post(MSA_TOKEN_URL).respond(
        json={"access_token": "acc", "refresh_token": "ref", "expires_in": 3600}
    )

    captured_url: list[str] = []

    def fake_browser(url: str) -> None:
        captured_url.append(url)
        # Simulate the browser hitting the redirect with code + state.
        parsed = parse_qs(urlparse(url).query)
        redirect_uri = parsed["redirect_uri"][0]
        state = parsed["state"][0]

        async def _hit() -> None:
            # Give the server a moment to start accepting.
            await asyncio.sleep(0.05)
            async with _httpx.AsyncClient(timeout=5.0) as c:
                _ = await c.get(f"{redirect_uri}?code=test-code&state={state}")

        # Schedule the simulated callback without blocking the caller.
        _ = asyncio.ensure_future(_hit())  # noqa: RUF006  - lifetime ends with the loop

    tokens = await acquire_msa_via_browser(
        bind_host="127.0.0.1",
        bind_port=0,
        timeout=5.0,
        open_browser=fake_browser,
    )
    assert tokens.access_token == "acc"
    assert tokens.refresh_token == "ref"
    assert token_route.called
    # The authorize URL we generated should have been handed to the
    # "browser" exactly once and contain a localhost redirect URI.
    assert len(captured_url) == 1
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A" in captured_url[0]


async def test_acquire_msa_via_browser_rejects_mismatched_state() -> None:
    import asyncio

    import httpx as _httpx

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    def fake_browser(url: str) -> None:
        redirect_uri = parse_qs(urlparse(url).query)["redirect_uri"][0]

        async def _hit() -> None:
            await asyncio.sleep(0.05)
            async with _httpx.AsyncClient(timeout=5.0) as c:
                _ = await c.get(f"{redirect_uri}?code=c&state=wrong-state")

        _ = asyncio.ensure_future(_hit())  # noqa: RUF006

    with pytest.raises(MSAFlowError, match="state"):
        _ = await acquire_msa_via_browser(
            bind_host="127.0.0.1", bind_port=0, timeout=5.0, open_browser=fake_browser
        )


async def test_acquire_msa_via_browser_surfaces_authorize_error() -> None:
    import asyncio

    import httpx as _httpx

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    def fake_browser(url: str) -> None:
        redirect_uri = parse_qs(urlparse(url).query)["redirect_uri"][0]

        async def _hit() -> None:
            await asyncio.sleep(0.05)
            async with _httpx.AsyncClient(timeout=5.0) as c:
                _ = await c.get(
                    f"{redirect_uri}?error=access_denied&error_description=user+cancelled"
                )

        _ = asyncio.ensure_future(_hit())  # noqa: RUF006

    with pytest.raises(MSAFlowError, match="access_denied"):
        _ = await acquire_msa_via_browser(
            bind_host="127.0.0.1", bind_port=0, timeout=5.0, open_browser=fake_browser
        )


async def test_acquire_msa_via_browser_times_out() -> None:
    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    # No-op opener — nothing will ever hit the callback path.
    def noop(url: str) -> None:
        _ = url

    with pytest.raises(MSAFlowError, match="timed out"):
        _ = await acquire_msa_via_browser(
            bind_host="127.0.0.1", bind_port=0, timeout=0.3, open_browser=noop
        )


async def test_acquire_msa_via_browser_friendly_error_on_port_in_use() -> None:
    """If bind_port is already taken, surface a clear MSAFlowError, not raw OSError."""
    import asyncio
    import socket

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    # Reserve a port by binding a dummy server to it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        busy_port = s.getsockname()[1]

        async def serve() -> None:
            srv = await asyncio.start_server(
                lambda r, w: asyncio.sleep(60), host="127.0.0.1", port=busy_port
            )
            try:
                await asyncio.sleep(0.2)
            finally:
                srv.close()
                await srv.wait_closed()

        # Close the synchronous socket so asyncio can bind in `serve()`.

    async def runner() -> None:
        srv = await asyncio.start_server(lambda r, w: asyncio.sleep(60), host="127.0.0.1", port=0)
        held_port = srv.sockets[0].getsockname()[1]
        try:
            with pytest.raises(MSAFlowError, match="bind"):
                _ = await acquire_msa_via_browser(
                    bind_host="127.0.0.1",
                    bind_port=held_port,
                    timeout=0.5,
                    open_browser=lambda _u: None,
                )
        finally:
            srv.close()
            await srv.wait_closed()

    await runner()


async def test_acquire_msa_via_browser_ignores_non_oauth_requests() -> None:
    """Prefetch / preview / favicon requests must not satisfy the callback."""
    import asyncio

    import httpx as _httpx

    from mcapi_auth.auth.auth_code import acquire_msa_via_browser

    def fake_browser(url: str) -> None:
        redirect_uri = parse_qs(urlparse(url).query)["redirect_uri"][0]
        state = parse_qs(urlparse(url).query)["state"][0]

        async def _hit() -> None:
            await asyncio.sleep(0.05)
            async with _httpx.AsyncClient(timeout=5.0) as c:
                # A "prefetch" with no code or error should be ignored.
                _ = await c.get(f"{redirect_uri}?utm_source=preview")
                # And a malformed-callback / wrong path should 404.
                _ = await c.get(f"{redirect_uri.replace('/callback', '/favicon.ico')}")
                # Only this real one should satisfy the listener.
                _ = await c.get(f"{redirect_uri}?code=real&state={state}")

        _ = asyncio.ensure_future(_hit())  # noqa: RUF006

    import re

    import respx as _respx

    with _respx.mock() as router:
        router.route(url__regex=re.compile(r"^http://127\.0\.0\.1:\d+/")).pass_through()
        router.post(MSA_TOKEN_URL).respond(
            json={"access_token": "ok", "refresh_token": "r", "expires_in": 3600}
        )
        tokens = await acquire_msa_via_browser(
            bind_host="127.0.0.1", bind_port=0, timeout=5.0, open_browser=fake_browser
        )
    assert tokens.access_token == "ok"

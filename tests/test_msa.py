"""Tests for the MSA device-code + refresh-token flow.
Uses respx to mock httpx at the transport layer.
"""

import inspect

import httpx
import pytest
import respx

from mcapi_auth._constants import MSA_DEVICE_CODE_URL, MSA_TOKEN_URL
from mcapi_auth.auth.msa import (
    exchange_refresh_token,
    poll_for_device_code_token,
    request_device_code,
)
from mcapi_auth.exceptions import (
    AuthorizationDeclinedError,
    DeviceCodeExpiredError,
    MSAFlowError,
)


@respx.mock
async def test_request_device_code_parses_response() -> None:
    respx.post(MSA_DEVICE_CODE_URL).respond(
        json={
            "user_code": "ABCD-1234",
            "device_code": "dev-code-xyz",
            "verification_uri": "https://microsoft.com/link",
            "expires_in": 900,
            "interval": 5,
            "message": "Go to https://microsoft.com/link and enter ABCD-1234",
        }
    )
    prompt, pending = await request_device_code()
    assert prompt.user_code == "ABCD-1234"
    assert prompt.verification_uri == "https://microsoft.com/link"
    assert prompt.expires_in == 900
    assert pending.device_code == "dev-code-xyz"


@respx.mock
async def test_request_device_code_raises_on_http_error() -> None:
    respx.post(MSA_DEVICE_CODE_URL).respond(status_code=500, text="oops")
    with pytest.raises(MSAFlowError, match="status=500"):
        _ = await request_device_code()


@respx.mock
async def test_request_device_code_raises_on_malformed_body() -> None:
    respx.post(MSA_DEVICE_CODE_URL).respond(json={"only_partial": "yes"})
    with pytest.raises(MSAFlowError, match="malformed"):
        _ = await request_device_code()


@respx.mock
async def test_poll_succeeds_after_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    # Make asyncio.sleep instant so the test doesn't pause for the poll interval.
    async def fast_sleep(_secs: float) -> None:
        return None

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", fast_sleep)

    respx.post(MSA_TOKEN_URL).mock(
        side_effect=[
            httpx.Response(400, json={"error": "authorization_pending"}),
            httpx.Response(400, json={"error": "authorization_pending"}),
            httpx.Response(
                200,
                json={
                    "access_token": "msa-access",
                    "refresh_token": "msa-refresh",
                    "expires_in": 3600,
                },
            ),
        ]
    )

    pending, _ = _make_pending()
    tokens = await poll_for_device_code_token(pending)
    assert tokens.access_token == "msa-access"
    assert tokens.refresh_token == "msa-refresh"


@respx.mock
async def test_poll_slow_down_bumps_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    async def record_sleep(secs: float) -> None:
        sleeps.append(secs)

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", record_sleep)

    respx.post(MSA_TOKEN_URL).mock(
        side_effect=[
            httpx.Response(400, json={"error": "slow_down"}),
            httpx.Response(
                200,
                json={
                    "access_token": "a",
                    "refresh_token": "r",
                    "expires_in": 60,
                },
            ),
        ]
    )

    pending, _ = _make_pending(interval=5)
    _ = await poll_for_device_code_token(pending)
    assert sleeps == [5.0, 10.0]  # second poll waits 5 + 5


@respx.mock
async def test_poll_authorization_declined_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast_sleep(_secs: float) -> None:
        return None

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", fast_sleep)
    respx.post(MSA_TOKEN_URL).respond(status_code=400, json={"error": "authorization_declined"})
    pending, _ = _make_pending()
    with pytest.raises(AuthorizationDeclinedError):
        _ = await poll_for_device_code_token(pending)


@respx.mock
async def test_poll_expired_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fast_sleep(_secs: float) -> None:
        return None

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", fast_sleep)
    respx.post(MSA_TOKEN_URL).respond(status_code=400, json={"error": "expired_token"})
    pending, _ = _make_pending()
    with pytest.raises(DeviceCodeExpiredError):
        _ = await poll_for_device_code_token(pending)


async def test_poll_raises_when_deadline_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Construct a pending that is already expired.
    pending, _ = _make_pending(expires_in=-1)

    # Stub sleep so we don't wait for the initial poll interval.
    async def fast_sleep(_secs: float) -> None:
        return None

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", fast_sleep)
    with pytest.raises(DeviceCodeExpiredError):
        _ = await poll_for_device_code_token(pending)


@respx.mock
async def test_exchange_refresh_token_happy_path() -> None:
    respx.post(MSA_TOKEN_URL).respond(
        json={
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_in": 3600,
        }
    )
    tokens = await exchange_refresh_token("old-refresh")
    assert tokens.access_token == "new-access"
    assert tokens.refresh_token == "new-refresh"


@respx.mock
async def test_exchange_refresh_token_failure_raises() -> None:
    respx.post(MSA_TOKEN_URL).respond(status_code=400, json={"error": "invalid_grant"})
    with pytest.raises(MSAFlowError, match="invalid_grant"):
        _ = await exchange_refresh_token("bogus")


# --- helpers ---------------------------------------------------------------


def _make_pending(*, interval: int = 1, expires_in: int = 300):
    """Return (pending, now) for tests that need a fresh ``_PendingDeviceCode``."""
    from whenever import Instant

    from mcapi_auth.auth.msa import _PendingDeviceCode

    now = Instant.now()
    pending = _PendingDeviceCode(
        device_code="dc-test", interval=interval, expires_at=now.add(seconds=expires_in)
    )
    return pending, now


def test_module_imports_cleanly() -> None:
    # Sanity-check that public re-exports are wired up.
    from mcapi_auth import auth as mcauth

    assert mcauth.login is not None
    assert inspect.iscoroutinefunction(mcauth.login)

"""Stages 1-2: Microsoft device-code flow and refresh-token rotation."""

from __future__ import annotations

import asyncio
import logging

import httpx
from whenever import Instant

from .._constants import (
    MIN_DEVICE_CODE_POLL_INTERVAL,
    MINECRAFT_LAUNCHER_CLIENT_ID,
    MSA_DEVICE_CODE_URL,
    MSA_SCOPE,
    MSA_TOKEN_URL,
)
from .._http import acquire_client, parse_json_object_auth
from .._models import InstantField, McModel
from ..exceptions import (
    AuthorizationDeclinedError,
    DeviceCodeExpiredError,
    MSAFlowError,
)

__all__ = [
    "DeviceCodePrompt",
    "MSATokens",
    "exchange_refresh_token",
    "poll_for_device_code_token",
    "request_device_code",
]

logger = logging.getLogger(__name__)


class DeviceCodePrompt(McModel):
    """Information shown to the user during the device-code flow.

    Pass a callback of ``(prompt: DeviceCodePrompt) -> None`` to
    :func:`mcapi_auth.login` to control how the user is informed of the URL +
    code they must visit.
    """

    user_code: str
    verification_uri: str
    message: str
    expires_in: int
    interval: int


class MSATokens(McModel):
    """Microsoft access + refresh tokens, plus expiry."""

    access_token: str
    refresh_token: str
    expires_at: InstantField


class _PendingDeviceCode(McModel):
    """The opaque ``device_code`` plus its poll parameters."""

    device_code: str
    interval: int
    expires_at: InstantField


async def request_device_code(
    *,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    http_client: httpx.AsyncClient | None = None,
) -> tuple[DeviceCodePrompt, _PendingDeviceCode]:
    """Kick off the device-code flow.

    Returns the prompt to display to the user *and* an opaque
    ``_PendingDeviceCode`` to be passed to :func:`poll_for_device_code_token`.
    """
    async with acquire_client(http_client) as c:
        response = await c.post(
            MSA_DEVICE_CODE_URL,
            data={"client_id": client_id, "scope": MSA_SCOPE},
        )
    if response.status_code != 200:
        raise MSAFlowError(f"device-code request failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    try:
        prompt = DeviceCodePrompt(
            user_code=str(data["user_code"]),
            verification_uri=str(data["verification_uri"]),
            message=str(data.get("message") or ""),
            expires_in=int(data["expires_in"]),
            interval=int(data.get("interval") or 5),
        )
        pending = _PendingDeviceCode(
            device_code=str(data["device_code"]),
            interval=prompt.interval,
            expires_at=Instant.now().add(seconds=float(prompt.expires_in)),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise MSAFlowError(
            f"device-code response is malformed: {e}: keys={sorted(data.keys())}"
        ) from e
    return prompt, pending


async def poll_for_device_code_token(
    pending: _PendingDeviceCode,
    *,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Poll Microsoft's token endpoint until the user authorizes or it expires.

    The poll cadence honors the server's ``interval`` claim, clamped to
    :data:`MIN_DEVICE_CODE_POLL_INTERVAL`. The server may bump us with
    ``slow_down`` errors, in which case we add 5 seconds permanently
    (per the OAuth spec).
    """
    interval = max(float(pending.interval), MIN_DEVICE_CODE_POLL_INTERVAL)

    async with acquire_client(http_client) as c:
        while True:
            await asyncio.sleep(interval)
            if Instant.now() >= pending.expires_at:
                raise DeviceCodeExpiredError("device-code flow expired before user completed it")
            response = await c.post(
                MSA_TOKEN_URL,
                data={
                    "client_id": client_id,
                    "device_code": pending.device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
            if response.status_code == 200:
                return _parse_token_response(response)
            data = parse_json_object_auth(response)
            error = str(data.get("error") or "")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5.0
                continue
            if error == "expired_token":
                raise DeviceCodeExpiredError("device-code flow expired before user completed it")
            if error in {"authorization_declined", "access_denied"}:
                raise AuthorizationDeclinedError("user declined the device-code authorization")
            raise MSAFlowError(f"device-code token poll failed: error={error!r}")


async def exchange_refresh_token(
    refresh_token: str,
    *,
    client_id: str = MINECRAFT_LAUNCHER_CLIENT_ID,
    http_client: httpx.AsyncClient | None = None,
) -> MSATokens:
    """Swap a refresh token for a fresh access + refresh pair.

    Raises :class:`MSAFlowError` if the refresh token is rejected — the
    caller should fall back to :func:`request_device_code` after clearing
    persisted state.
    """
    async with acquire_client(http_client) as c:
        response = await c.post(
            MSA_TOKEN_URL,
            data={
                "client_id": client_id,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
                "scope": MSA_SCOPE,
            },
        )
    if response.status_code == 200:
        return _parse_token_response(response)
    data = parse_json_object_auth(response)
    raise MSAFlowError(
        "refresh-token exchange failed: "
        f"status={response.status_code} error={data.get('error', 'unknown')!r}"
    )


def _parse_token_response(response: httpx.Response) -> MSATokens:
    data = parse_json_object_auth(response)
    try:
        access = str(data["access_token"])
        refresh = str(data["refresh_token"])
        expires_in = int(data["expires_in"])
    except (KeyError, TypeError, ValueError) as e:
        # Never echo `data` — it contains the access_token + refresh_token.
        raise MSAFlowError(
            f"MSA token response is malformed: {e}: keys={sorted(data.keys())}"
        ) from e
    if not access or not refresh:
        raise MSAFlowError(
            f"MSA token response is missing token fields: keys={sorted(data.keys())}"
        )
    return MSATokens(
        access_token=access,
        refresh_token=refresh,
        expires_at=Instant.now().add(seconds=float(expires_in)),
    )

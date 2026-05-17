"""Stage 5: Mojang exchange and profile fetch."""

import logging
from typing import ClassVar

import httpx
from pydantic import ValidationError
from whenever import Instant

from .._constants import MC_LOGIN_WITH_XBOX_URL, MC_PROFILE_URL
from .._http import acquire_client, parse_json_object_auth
from .._models import InstantField, McModel
from ..exceptions import MinecraftAuthError, MinecraftProfileNotFoundError

__all__ = ["MinecraftProfile", "MinecraftToken", "fetch_profile", "login_with_xbox"]

logger = logging.getLogger(__name__)


class MinecraftToken(McModel):
    """The Minecraft access token returned by ``login_with_xbox``."""

    access_token: str
    expires_at: InstantField


class MinecraftProfile(McModel):
    """A Minecraft profile (UUID + current username)."""

    __field_aliases__: ClassVar[dict[str, str]] = {"id": "uuid", "name": "username"}

    uuid: str
    username: str


async def login_with_xbox(
    userhash: str,
    xsts_token: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftToken:
    """Exchange ``(userhash, xsts_token)`` for a Minecraft access token."""
    identity_token = f"XBL3.0 x={userhash};{xsts_token}"
    async with acquire_client(http_client) as c:
        response = await c.post(
            MC_LOGIN_WITH_XBOX_URL,
            json={"identityToken": identity_token},
            headers={"Accept": "application/json"},
        )
    if response.status_code != 200:
        raise MinecraftAuthError(f"login_with_xbox failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    access_raw = data.get("access_token")
    expires_in_raw = data.get("expires_in")
    if not isinstance(access_raw, str) or not access_raw:
        raise MinecraftAuthError(
            f"login_with_xbox response missing 'access_token': keys={sorted(data.keys())}"
        )
    if not isinstance(expires_in_raw, int | float):
        raise MinecraftAuthError(
            f"login_with_xbox response missing numeric 'expires_in': keys={sorted(data.keys())}"
        )
    return MinecraftToken(
        access_token=access_raw,
        expires_at=Instant.now().add(seconds=float(expires_in_raw)),
    )


async def fetch_profile(
    access_token: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftProfile:
    """Fetch ``/minecraft/profile`` for the given access token.

    Raises :class:`MinecraftProfileNotFoundError` on HTTP 404 — that's the
    server's way of saying "this account doesn't own Minecraft".
    """
    async with acquire_client(http_client) as c:
        response = await c.get(
            MC_PROFILE_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
    if response.status_code == 404:
        raise MinecraftProfileNotFoundError(
            "the authenticated Microsoft account does not own Minecraft"
        )
    if response.status_code != 200:
        raise MinecraftAuthError(f"profile fetch failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    try:
        return MinecraftProfile.model_validate(data)
    except ValidationError as e:
        raise MinecraftAuthError(
            f"profile response missing required fields: keys={sorted(data.keys())}"
        ) from e

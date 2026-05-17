"""Minecraft Realms API (Java edition).

The Realms backend lives at ``pc.realms.minecraft.net`` and authenticates
via a special ``Cookie`` header rather than ``Authorization: Bearer``::

    Cookie: sid=token:<MC_ACCESS_TOKEN>:<UUID>; user=<USERNAME>; version=<MC_VERSION>

These functions accept any :class:`~mcapi_auth.api._session.TokenLike` —
a raw access token, a :class:`~mcapi_auth.MinecraftSession`, or anything
exposing ``access_token``. When a ``MinecraftSession`` is passed, UUID
and username are read off it. For raw-string tokens, the caller must
supply ``uuid`` + ``username`` (everything is bundled in the
:class:`~mcapi_auth.auth.chain.AuthChain` API, so the common case is
``await fetch_realms_worlds(chain)``).

Realms requires the user to have agreed to the Realms TOS. New accounts
hit ``/mco/tos/agreed`` and get a 401 ``terms-of-service-not-accepted``
before they're allowed to query worlds. Use :func:`accept_realms_tos`
once per account, then list worlds.

Bedrock realms (``realms.bds.mc-srv.net``) are a different API and not
covered here.

Endpoints implemented (covers the surface RaphiMC's
``JavaRealmsService`` exposes):

* ``GET /mco/client/compatible`` — version compatibility check
* ``GET /mco/available`` — is the Realms service usable for this account
* ``GET /worlds`` — list owned + invited worlds
* ``GET /worlds/{id}`` — single world detail
* ``GET /worlds/{id}/join/pc`` — issue a connection token for joining
* ``GET /worlds/{id}/backups`` — list backups
* ``POST /worlds/{id}/slot/{slot}`` — switch active world slot
* ``GET /trial`` — trial status
* ``GET /mco/tos/agreed`` / ``POST /mco/tos/agreed`` — TOS handling
* ``GET /invites/count/pending`` — pending invite count
* ``GET /invites/pending`` — list pending invites
* ``PUT /invites/accept/{id}`` — accept invite
* ``REJECT /invites/reject/{id}`` — reject invite (POST)
"""

from __future__ import annotations

from typing import Any, ClassVar, Final, cast

import httpx
from pydantic import ValidationError

from .._http import acquire_client
from .._models import McModel
from ..exceptions import (
    BadRequestError,
    ForbiddenError,
    HttpError,
    NotFoundError,
    RateLimitedError,
    UnauthorizedError,
)
from ._session import TokenLike, coerce_token

__all__ = [
    "DEFAULT_REALMS_GAME_VERSION",
    "RealmsCompatibility",
    "RealmsJoinInfo",
    "RealmsPlayer",
    "RealmsTosError",
    "RealmsWorld",
    "accept_realms_tos",
    "fetch_realms_compatible",
    "fetch_realms_join_info",
    "fetch_realms_world",
    "fetch_realms_worlds",
    "is_realms_available",
    "is_realms_tos_agreed",
]

# Realms API root.
REALMS_BASE: Final = "https://pc.realms.minecraft.net"

# Default ``version`` cookie. Realms gatekeeps clients on supported
# release versions; this constant is bumped when Mojang rolls out a new
# version. Callers can pass an explicit ``game_version`` to override.
DEFAULT_REALMS_GAME_VERSION: Final = "1.21.4"


class RealmsTosError(HttpError):
    """The account has not yet accepted the Realms terms of service.

    Mojang surfaces this as a 401 with the ``terms-of-service-not-accepted``
    error code. Call :func:`accept_realms_tos` once and retry.
    """


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class RealmsPlayer(McModel):
    """A player slot on a realm (owner / member / invitee)."""

    __field_aliases__: ClassVar[dict[str, str]] = {
        "uuid": "uuid",
        "name": "username",
        "operator": "operator",
        "accepted": "accepted",
        "online": "online",
        "permission": "permission",
    }

    uuid: str
    username: str | None = None
    operator: bool | None = None
    accepted: bool | None = None
    online: bool | None = None
    permission: str | None = None


class RealmsWorld(McModel):
    """A single Realms world.

    Field names follow Mojang's wire shape verbatim
    (``remoteSubscriptionId``, ``minigameId``, …).
    """

    __field_aliases__: ClassVar[dict[str, str]] = {
        "id": "world_id",
        "name": "name",
        "motd": "motd",
        "state": "state",
        "owner": "owner_username",
        "ownerUUID": "owner_uuid",
        "remoteSubscriptionId": "remote_subscription_id",
        "expired": "expired",
        "expiredTrial": "expired_trial",
        "gracePeriod": "grace_period",
        "worldType": "world_type",
        "minigameId": "minigame_id",
        "minigameName": "minigame_name",
        "minigameImage": "minigame_image",
        "activeSlot": "active_slot",
        "member": "is_member",
        "players": "players",
        "daysLeft": "days_left",
    }

    world_id: int
    name: str | None = None
    motd: str | None = None
    state: str | None = None
    owner_username: str | None = None
    owner_uuid: str | None = None
    remote_subscription_id: str | None = None
    expired: bool | None = None
    expired_trial: bool | None = None
    grace_period: bool | None = None
    world_type: str | None = None
    minigame_id: int | None = None
    minigame_name: str | None = None
    minigame_image: str | None = None
    active_slot: int | None = None
    is_member: bool | None = None
    players: list[RealmsPlayer] | None = None
    days_left: int | None = None


class RealmsJoinInfo(McModel):
    """Connection info returned by ``/worlds/{id}/join/pc``."""

    __field_aliases__: ClassVar[dict[str, str]] = {
        "address": "address",
        "resourcePackUrl": "resource_pack_url",
        "resourcePackHash": "resource_pack_hash",
    }

    address: str
    resource_pack_url: str | None = None
    resource_pack_hash: str | None = None

    @property
    def host(self) -> str:
        """Host portion of ``address`` (everything before the colon)."""
        return self.address.rsplit(":", 1)[0]

    @property
    def port(self) -> int:
        """Port portion of ``address``. Defaults to 25565 if missing."""
        if ":" not in self.address:
            return 25565
        return int(self.address.rsplit(":", 1)[1])


class RealmsCompatibility(McModel):
    """Result of ``/mco/client/compatible``."""

    compatibility: str  # "COMPATIBLE" / "OUTDATED" / "OTHER"


# ---------------------------------------------------------------------------
# Cookie / header helpers
# ---------------------------------------------------------------------------


def _resolve_identity(
    token: TokenLike,
    uuid: str | None,
    username: str | None,
) -> tuple[str, str, str]:
    """Pull ``(access_token, uuid, username)`` off a TokenLike or fail loudly.

    For :class:`MinecraftSession` / :class:`AuthChain` callers, we
    introspect attributes directly. For raw-string tokens, ``uuid``
    and ``username`` must be provided explicitly.
    """
    access = coerce_token(token)
    actual_uuid = uuid
    actual_username = username
    if actual_uuid is None:
        attr_uuid = getattr(token, "uuid", None)
        if isinstance(attr_uuid, str):
            actual_uuid = attr_uuid
    if actual_username is None:
        attr_username = getattr(token, "username", None)
        if isinstance(attr_username, str):
            actual_username = attr_username
    if actual_uuid is None or actual_username is None:
        raise TypeError(
            "Realms requires uuid + username. Pass a MinecraftSession-like "
            "object that exposes them, or supply them explicitly."
        )
    return access, actual_uuid, actual_username


def _realms_headers(
    access_token: str,
    uuid: str,
    username: str,
    game_version: str,
) -> dict[str, str]:
    return {
        "Cookie": f"sid=token:{access_token}:{uuid};user={username};version={game_version}",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


async def fetch_realms_compatible(
    token: TokenLike,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> RealmsCompatibility:
    """Check whether ``game_version`` is currently accepted by Realms."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    response = await _realms_get(
        "/mco/client/compatible",
        access,
        uuid_,
        name,
        game_version,
        http_client,
    )
    return _validate(response, RealmsCompatibility)


async def is_realms_available(
    token: TokenLike,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """``True`` if the Realms service is reachable for this account."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    response = await _realms_get(
        "/mco/available",
        access,
        uuid_,
        name,
        game_version,
        http_client,
    )
    # The endpoint returns the literal text "true" / "false" (no JSON).
    body = response.text.strip().lower()
    return body in {"true", '"true"'}


async def is_realms_tos_agreed(
    token: TokenLike,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """``True`` if the account has accepted the Realms TOS."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    async with acquire_client(http_client) as c:
        response = await c.get(
            f"{REALMS_BASE}/mco/tos/agreed",
            headers=_realms_headers(access, uuid_, name, game_version),
        )
    if response.status_code == 200:
        return response.text.strip().lower() in {"true", '"true"'}
    if response.status_code in {401, 403}:
        return False
    _raise_for_status(response)
    return False  # unreachable


async def accept_realms_tos(
    token: TokenLike,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """Mark the Realms TOS as accepted for this account."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    async with acquire_client(http_client) as c:
        response = await c.post(
            f"{REALMS_BASE}/mco/tos/agreed",
            headers=_realms_headers(access, uuid_, name, game_version),
        )
    if response.status_code >= 400:
        _raise_for_status(response)


async def fetch_realms_worlds(
    token: TokenLike,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> list[RealmsWorld]:
    """List all worlds the account owns or has joined."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    response = await _realms_get("/worlds", access, uuid_, name, game_version, http_client)
    data_raw: object = response.json()
    if not isinstance(data_raw, dict):
        raise HttpError(response.status_code, response.text)
    data = cast(dict[str, Any], data_raw)
    servers_raw = data.get("servers")
    if not isinstance(servers_raw, list):
        return []
    servers_list = cast(list[Any], servers_raw)
    out: list[RealmsWorld] = []
    for entry in servers_list:
        if not isinstance(entry, dict):
            continue
        try:
            out.append(RealmsWorld.model_validate(entry))
        except ValidationError:
            continue
    return out


async def fetch_realms_world(
    token: TokenLike,
    world_id: int,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> RealmsWorld:
    """Fetch a single world by ID."""
    access, uuid_, name = _resolve_identity(token, uuid, username)
    response = await _realms_get(
        f"/worlds/{world_id}",
        access,
        uuid_,
        name,
        game_version,
        http_client,
    )
    return _validate(response, RealmsWorld)


async def fetch_realms_join_info(
    token: TokenLike,
    world_id: int,
    *,
    uuid: str | None = None,
    username: str | None = None,
    game_version: str = DEFAULT_REALMS_GAME_VERSION,
    http_client: httpx.AsyncClient | None = None,
) -> RealmsJoinInfo:
    """Issue a join token for ``world_id``.

    The returned :attr:`~RealmsJoinInfo.address` is the actual Minecraft
    server endpoint to connect to (this typically takes a few seconds
    to wake up — long-poll or retry on connect refusal).
    """
    access, uuid_, name = _resolve_identity(token, uuid, username)
    response = await _realms_get(
        f"/worlds/v1/{world_id}/join/pc",
        access,
        uuid_,
        name,
        game_version,
        http_client,
    )
    return _validate(response, RealmsJoinInfo)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _realms_get(
    path: str,
    access_token: str,
    uuid: str,
    username: str,
    game_version: str,
    http_client: httpx.AsyncClient | None,
) -> httpx.Response:
    async with acquire_client(http_client) as c:
        response = await c.get(
            f"{REALMS_BASE}{path}",
            headers=_realms_headers(access_token, uuid, username, game_version),
        )
    if response.status_code >= 400:
        _raise_for_status(response)
    return response


def _raise_for_status(response: httpx.Response) -> None:
    body = response.text
    status = response.status_code
    url = str(response.request.url) if response.request else None
    if status == 401:
        if "terms-of-service-not-accepted" in body.lower():
            raise RealmsTosError(status, body, url=url)
        raise UnauthorizedError(f"HTTP 401 ({url}): {body[:200]}")
    if status == 403:
        raise ForbiddenError(f"HTTP 403 ({url}): {body[:200]}")
    if status == 404:
        raise NotFoundError(f"HTTP 404 ({url}): {body[:200]}")
    if status == 429:
        raise RateLimitedError(f"HTTP 429 ({url}): {body[:200]}")
    if status == 400:
        raise BadRequestError(f"HTTP 400 ({url}): {body[:200]}")
    raise HttpError(status, body, url=url)


def _validate[M: McModel](response: httpx.Response, model: type[M]) -> M:
    try:
        return model.model_validate(response.json())
    except (ValidationError, ValueError) as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e

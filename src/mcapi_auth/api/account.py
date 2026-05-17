"""Authenticated profile / skin / cape / name endpoints.
Every function in this module takes a ``token: TokenLike`` — either a raw
Minecraft access-token string or a :class:`mcapi_auth.MinecraftSession` (anything
exposing an ``access_token`` attribute).

Responses are wrapped in :class:`OwnProfile` / :class:`NameAvailability` /
:class:`NameChangeEligibility` Pydantic models. The Mojang ``error`` JSON is
mapped to :mod:`mcapi_auth.exceptions` subclasses by status code, so callers
can ``except NameTakenError`` rather than parsing strings.
"""

from enum import StrEnum
from typing import Any, ClassVar, Literal

import httpx
from pydantic import field_validator

from .._constants import (
    PROFILE_CAPES_ACTIVE_URL,
    PROFILE_NAME_BASE_URL,
    PROFILE_NAMECHANGE_URL,
    PROFILE_SKINS_ACTIVE_URL,
    PROFILE_SKINS_URL,
    PROFILE_URL,
)
from .._http import acquire_client, bearer_headers, validate_response
from .._models import InstantField, McModel
from ..exceptions import (
    BadRequestError,
    ForbiddenError,
    HttpError,
    NameNotAllowedError,
    NameTakenError,
    NotFoundError,
    RateLimitedError,
    UnauthorizedError,
)
from ._session import TokenLike, coerce_token


class SkinVariant(StrEnum):
    """Skin model variant accepted by skin-change endpoints."""

    CLASSIC = "classic"
    SLIM = "slim"


class SkinEntry(McModel):
    id: str
    state: str
    url: str
    variant: SkinVariant = SkinVariant.CLASSIC
    alias: str | None = None

    @field_validator("variant", mode="before")
    @classmethod
    def _coerce_variant(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v

    @property
    def is_active(self) -> bool:
        return self.state.upper() == "ACTIVE"


class CapeEntry(McModel):
    id: str
    state: str
    url: str
    alias: str | None = None

    @property
    def is_active(self) -> bool:
        return self.state.upper() == "ACTIVE"


class OwnProfile(McModel):
    """Authenticated profile view — includes inactive skins/capes too."""

    __field_aliases__: ClassVar[dict[str, str]] = {"id": "uuid"}

    uuid: str
    name: str
    skins: tuple[SkinEntry, ...] = ()
    capes: tuple[CapeEntry, ...] = ()

    @property
    def active_skin(self) -> SkinEntry | None:
        return next((s for s in self.skins if s.is_active), None)

    @property
    def active_cape(self) -> CapeEntry | None:
        return next((c for c in self.capes if c.is_active), None)


class NameAvailability(StrEnum):
    """Result of the authed name-availability endpoint."""

    AVAILABLE = "AVAILABLE"
    DUPLICATE = "DUPLICATE"
    NOT_ALLOWED = "NOT_ALLOWED"


class _NameAvailabilityBody(McModel):
    status: str


class NameChangeEligibility(McModel):
    """Cooldown / eligibility info for the authed account."""

    __field_aliases__: ClassVar[dict[str, str]] = {
        "nameChangeAllowed": "name_change_allowed",
        "createdAt": "created_at",
        "changedAt": "changed_at",
    }

    name_change_allowed: bool
    created_at: InstantField
    changed_at: InstantField | None = None


def _raise_for_authed_status(r: httpx.Response) -> None:
    """Map a non-2xx response on an authed endpoint to a typed exception."""
    if r.status_code == 401:
        raise UnauthorizedError("access token is invalid, missing, or expired")
    if r.status_code == 403:
        raise ForbiddenError(r.text)
    if r.status_code == 404:
        raise NotFoundError(r.text)
    if r.status_code == 429:
        retry: float | None = None
        ra = r.headers.get("Retry-After")
        if ra is not None:
            try:
                retry = float(ra)
            except ValueError:
                retry = None
        raise RateLimitedError(
            retry_after=retry,
            rate_limit_result=r.headers.get("X-Minecraft-Rate-Limit-Result"),
        )
    if r.status_code >= 400:
        raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def get_own_profile(
    token: TokenLike,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """GET ``/minecraft/profile`` — your skins, capes, name, UUID.

    Includes inactive skins and capes (useful for cape switching).
    """
    headers = bearer_headers(coerce_token(token))
    async with acquire_client(http_client) as client:
        r = await client.get(PROFILE_URL, headers=headers)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def check_name_availability(
    token: TokenLike,
    name: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> NameAvailability:
    """GET ``/minecraft/profile/name/<name>/available`` — accurate, authed check."""
    headers = bearer_headers(coerce_token(token))
    url = f"{PROFILE_NAME_BASE_URL}/{name}/available"
    async with acquire_client(http_client) as client:
        r = await client.get(url, headers=headers)
    if r.status_code == 200:
        body = validate_response(r, _NameAvailabilityBody)
        try:
            return NameAvailability(body.status.upper())
        except ValueError as e:
            raise HttpError(r.status_code, r.text, url=str(r.request.url)) from e
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def get_name_change_eligibility(
    token: TokenLike,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> NameChangeEligibility:
    """GET ``/minecraft/profile/namechange`` — cooldown + account creation date."""
    headers = bearer_headers(coerce_token(token))
    async with acquire_client(http_client) as client:
        r = await client.get(PROFILE_NAMECHANGE_URL, headers=headers)
    if r.status_code == 200:
        return validate_response(r, NameChangeEligibility)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def change_name(
    token: TokenLike,
    new_name: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """PUT ``/minecraft/profile/name/<new_name>`` — rename the authed account.

    Rate-limited by Mojang to ~3 changes per account per IP, with a 30-day
    cooldown between successful changes (call
    :func:`get_name_change_eligibility` to check upfront).

    Raises:
        NameTakenError: HTTP 403 — name is taken or on cooldown.
        NameNotAllowedError: HTTP 400 — invalid name shape / filter hit.
        ForbiddenError: HTTP 403 with a non-DUPLICATE status (e.g. security
            questions not answered).
        NotFoundError: HTTP 404 — account doesn't own Minecraft.
    """
    headers = bearer_headers(coerce_token(token))
    url = f"{PROFILE_NAME_BASE_URL}/{new_name}"
    async with acquire_client(http_client) as client:
        r = await client.put(url, headers=headers)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    if r.status_code == 400:
        raise NameNotAllowedError(r.text)
    if r.status_code == 403:
        # Body normally carries details.status — promote DUPLICATE to NameTakenError.
        body_lower = r.text.lower()
        if '"duplicate"' in body_lower or "duplicate" in body_lower:
            raise NameTakenError(r.text)
        raise ForbiddenError(r.text)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def change_skin_from_url(
    token: TokenLike,
    skin_url: str,
    *,
    variant: SkinVariant = SkinVariant.CLASSIC,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """POST ``/minecraft/profile/skins`` (JSON body) — load skin from a URL."""
    headers = bearer_headers(coerce_token(token))
    headers["Content-Type"] = "application/json"
    body = {"url": skin_url, "variant": variant.value}
    async with acquire_client(http_client) as client:
        r = await client.post(PROFILE_SKINS_URL, headers=headers, json=body)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    if r.status_code == 400:
        raise BadRequestError(r.text)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def change_skin_from_file(
    token: TokenLike,
    skin_png: bytes | bytearray | memoryview,
    *,
    variant: SkinVariant = SkinVariant.CLASSIC,
    filename: str = "skin.png",
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """POST ``/minecraft/profile/skins`` (multipart) — upload skin PNG bytes.

    Pass the raw PNG bytes. If you have a file on disk, read it yourself
    (e.g. ``Path("skin.png").read_bytes()``) — we don't accept synchronous
    file handles because their ``.read()`` would block the event loop.
    """
    headers = bearer_headers(coerce_token(token))
    png_bytes = bytes(skin_png)
    files = {"file": (filename, png_bytes, "image/png")}
    data: dict[str, str] = {"variant": variant.value}
    async with acquire_client(http_client) as client:
        r = await client.post(PROFILE_SKINS_URL, headers=headers, files=files, data=data)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    if r.status_code == 400:
        raise BadRequestError(r.text)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def reset_skin(
    token: TokenLike,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """DELETE ``/minecraft/profile/skins/active`` — drop back to Steve/Alex."""
    headers = bearer_headers(coerce_token(token))
    async with acquire_client(http_client) as client:
        r = await client.delete(PROFILE_SKINS_ACTIVE_URL, headers=headers)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def change_cape(
    token: TokenLike,
    cape_id: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """PUT ``/minecraft/profile/capes/active`` — enable a cape you own."""
    headers = bearer_headers(coerce_token(token))
    headers["Content-Type"] = "application/json"
    async with acquire_client(http_client) as client:
        r = await client.put(PROFILE_CAPES_ACTIVE_URL, headers=headers, json={"capeId": cape_id})
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    if r.status_code == 400:
        raise BadRequestError(f"account does not own cape {cape_id!r} or request invalid")
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def disable_cape(
    token: TokenLike,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OwnProfile:
    """DELETE ``/minecraft/profile/capes/active`` — hide any active cape."""
    headers = bearer_headers(coerce_token(token))
    async with acquire_client(http_client) as client:
        r = await client.delete(PROFILE_CAPES_ACTIVE_URL, headers=headers)
    if r.status_code == 200:
        return validate_response(r, OwnProfile)
    _raise_for_authed_status(r)
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


# Convenience alias matching the spec phrasing the Mojang docs use.
VariantStr = Literal["classic", "slim"]

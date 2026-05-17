"""Public profile / UUID lookup endpoints (no authentication required).
All three functions here hit ``api.mojang.com`` / ``sessionserver.mojang.com``.
The endpoints are rate-limited (Mojang's documented number is ~600 req per
10 min per IP for the GET name→UUID path; bulk POSTs share a similar bucket).
A 429 response surfaces as :class:`mcapi_auth.RateLimitedError`.
"""


from typing import Any, ClassVar, cast

import httpx
from pydantic import ValidationError

from .._constants import (
    BULK_USERNAME_LOOKUP_MAX,
    BULK_USERNAME_TO_UUID_URL,
    USERNAME_TO_UUID_URL,
    UUID_TO_PROFILE_URL,
)
from .._http import acquire_client, validate_response
from .._models import McModel
from ..exceptions import (
    BadRequestError,
    HttpError,
    NotFoundError,
    RateLimitedError,
    TooManyNamesError,
)


def _normalize_uuid(value: str) -> str:
    """Strip dashes from a UUID; the public endpoints accept undashed only."""
    return value.replace("-", "").lower()


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class NameLookupResult(McModel):
    """Minimal name↔UUID result returned by the public lookup endpoints.

    ``uuid`` is the undashed (32-char) form as Mojang serves it.
    """

    __field_aliases__: ClassVar[dict[str, str]] = {"id": "uuid"}

    name: str
    uuid: str


class ProfileProperty(McModel):
    """A single property attached to a session-server profile.

    For the well-known ``textures`` property, ``value`` is the raw base64
    string — call :func:`mcapi_auth.api.textures.decode_texture_property` on it (or
    use :attr:`PublicProfile.textures_property`) to get a structured view.
    """

    name: str
    value: str
    signature: str | None = None


class PublicProfile(McModel):
    """A profile blob from ``sessionserver.mojang.com``."""

    __field_aliases__: ClassVar[dict[str, str]] = {"id": "uuid"}

    uuid: str
    name: str
    properties: tuple[ProfileProperty, ...] = ()
    legacy: bool = False

    @property
    def textures_property(self) -> ProfileProperty | None:
        for p in self.properties:
            if p.name == "textures":
                return p
        return None


async def get_uuid_by_name(
    name: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> NameLookupResult:
    """Resolve a Minecraft username to its UUID.

    Raises:
        NotFoundError: No account currently owns this username.
        BadRequestError: The supplied string isn't a valid name shape.
        RateLimitedError: Hit the 429 cooldown.
    """
    url = f"{USERNAME_TO_UUID_URL}/{name}"
    async with acquire_client(http_client) as client:
        r = await client.get(url)
    if r.status_code == 200:
        return validate_response(r, NameLookupResult)
    if r.status_code in (204, 404):
        raise NotFoundError(f"no account currently owns username {name!r}")
    if r.status_code == 400:
        raise BadRequestError(f"invalid username {name!r}: {r.text}")
    if r.status_code == 429:
        raise RateLimitedError(retry_after=_retry_after(r))
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def get_uuids_by_names(
    names: list[str],
    *,
    http_client: httpx.AsyncClient | None = None,
) -> list[NameLookupResult]:
    """Bulk-resolve up to 10 usernames in a single POST.

    The server returns only the names that resolved — invalid / unknown
    names are silently dropped, so callers should compare lengths if they
    care about per-name presence.

    Raises:
        TooManyNamesError: More than 10 names were passed.
        BadRequestError: A name in the batch was malformed enough that
            the server rejected the whole request.
        RateLimitedError: HTTP 429.
    """
    if len(names) > BULK_USERNAME_LOOKUP_MAX:
        raise TooManyNamesError(
            f"bulk lookup accepts at most {BULK_USERNAME_LOOKUP_MAX} names, got {len(names)}"
        )
    if not names:
        return []
    async with acquire_client(http_client) as client:
        r = await client.post(
            BULK_USERNAME_TO_UUID_URL,
            json=names,
            headers={"Content-Type": "application/json"},
        )
    if r.status_code == 200:
        body: Any = r.json()
        if not isinstance(body, list):
            raise HttpError(r.status_code, r.text, url=str(r.request.url))
        results: list[NameLookupResult] = []
        for entry in cast("list[Any]", body):
            try:
                results.append(NameLookupResult.model_validate(entry))
            except ValidationError:
                # Mojang occasionally returns junk entries in bulk responses;
                # drop them silently rather than failing the whole batch.
                continue
        return results
    if r.status_code == 400:
        raise BadRequestError(f"bulk lookup rejected: {r.text}")
    if r.status_code == 429:
        raise RateLimitedError(retry_after=_retry_after(r))
    raise HttpError(r.status_code, r.text, url=str(r.request.url))


async def get_profile_by_uuid(
    uuid: str,
    *,
    signed: bool = False,
    http_client: httpx.AsyncClient | None = None,
) -> PublicProfile:
    """Fetch the public profile (name, properties, optional signature) by UUID.

    Pass ``signed=True`` to request Yggdrasil-signed texture properties
    (``?unsigned=false``). Without it the property is still present but
    has no ``signature`` field.

    Raises:
        NotFoundError: HTTP 204 / 404 — no such profile.
        BadRequestError: The UUID string is malformed.
        RateLimitedError: HTTP 429.
    """
    undashed = _normalize_uuid(uuid)
    url = f"{UUID_TO_PROFILE_URL}/{undashed}"
    params: dict[str, str] = {"unsigned": "false"} if signed else {}
    async with acquire_client(http_client) as client:
        r = await client.get(url, params=params)
    if r.status_code == 200:
        return validate_response(r, PublicProfile)
    if r.status_code in (204, 404):
        raise NotFoundError(f"no profile found for UUID {uuid!r}")
    if r.status_code == 400:
        raise BadRequestError(f"invalid UUID {uuid!r}")
    if r.status_code == 429:
        raise RateLimitedError(retry_after=_retry_after(r))
    raise HttpError(r.status_code, r.text, url=str(r.request.url))

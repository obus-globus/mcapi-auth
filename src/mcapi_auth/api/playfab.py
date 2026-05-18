"""PlayFab login (Bedrock Edition telemetry / title-service).

Minecraft Bedrock authenticates against `PlayFab
<https://playfab.com/>`_ in addition to Xbox Live, using the XSTS
token as an OAuth-style credential. This module exposes the two
endpoints needed for full Bedrock parity:

* ``POST {title}.playfabapi.com/Client/LoginWithXbox`` —
  exchange an XSTS token for a :class:`PlayFabToken` (entity token +
  PlayFab account id + session ticket).
* ``POST {title}.playfabapi.com/Authentication/GetEntityToken`` —
  refresh just the :class:`PlayFabEntityToken` for an existing PlayFab
  identity.

The default title is the public Bedrock title (``20CA2``); pass
``title_id=EDU_PLAYFAB_TITLE_ID`` for Minecraft: Education Edition.

PlayFab errors come back as 4xx/5xx with a JSON body containing
``error`` + ``errorMessage`` — they're surfaced as
:class:`PlayFabError`.

This module does **not** generate the Bedrock signing key-pair or
build the full ``mcChain``; that's a separate concern (see the
deferred Bedrock-Edition work).
"""

from __future__ import annotations

from typing import Any, Final, cast

import httpx
from pydantic import Field, ValidationError
from whenever import Instant

from .._http import acquire_client
from .._models import InstantField, McModel
from ..auth.xbox import XSTSToken
from ..exceptions import HttpError, MinecraftAuthError

__all__ = [
    "BEDROCK_PLAYFAB_TITLE_ID",
    "EDU_PLAYFAB_TITLE_ID",
    "PlayFabEntityToken",
    "PlayFabError",
    "PlayFabToken",
    "playfab_get_entity_token",
    "playfab_login_with_xbox",
]

BEDROCK_PLAYFAB_TITLE_ID: Final = "20CA2"
"""PlayFab title id for retail Minecraft: Bedrock Edition.

Source: ``https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/1.x.x``.
"""

EDU_PLAYFAB_TITLE_ID: Final = "6955F"
"""PlayFab title id for Minecraft: Education Edition."""


def _playfab_base(title_id: str) -> str:
    return f"https://{title_id.lower()}.playfabapi.com"


class PlayFabError(MinecraftAuthError):
    """A PlayFab API call returned a structured error response.

    Args:
        status_code: HTTP status code returned by PlayFab.
        error: Short error name (``"InvalidParams"``, ``"AccountBanned"`` …).
        error_message: Human-readable error message.
        error_code: PlayFab's numeric error code, if present.
    """

    def __init__(
        self,
        status_code: int,
        error: str,
        error_message: str,
        *,
        error_code: int | None = None,
    ) -> None:
        super().__init__(f"PlayFab {status_code} {error}: {error_message}")
        self.status_code: int = status_code
        self.error: str = error
        self.error_message: str = error_message
        self.error_code: int | None = error_code


class PlayFabEntityToken(McModel):
    """An ``X-EntityToken`` plus the PlayFab entity it identifies.

    Refresh via :func:`playfab_get_entity_token`.
    """

    __field_aliases__ = {  # noqa: RUF012
        "EntityToken": "token",
        "TokenExpiration": "expires_at",
    }

    token: str
    entity_id: str = Field(default="")
    entity_type: str = Field(default="")
    expires_at: InstantField

    @classmethod
    def from_api_payload(cls, data: dict[str, Any]) -> PlayFabEntityToken:
        """Construct from a PlayFab API payload (``Entity`` nested).

        The ``Entity`` sub-object is flattened to ``entity_id`` /
        ``entity_type`` for the standard field-alias machinery.
        """
        flat = dict(data)
        entity = data.get("Entity")
        if isinstance(entity, dict):
            entity_typed = cast(dict[str, Any], entity)
            if "Id" in entity_typed:
                flat["entity_id"] = entity_typed["Id"]
            if "Type" in entity_typed:
                flat["entity_type"] = entity_typed["Type"]
        return cls.model_validate(flat)


class PlayFabToken(McModel):
    """Result of :func:`playfab_login_with_xbox`.

    Holds the PlayFab :class:`PlayFabEntityToken` plus the immutable
    account-identifying ``play_fab_id`` and a ``session_ticket`` used
    by the Bedrock title service for telemetry / matchmaking.

    The token's :attr:`expires_at` is forwarded from the entity token —
    that's the value to refresh against.
    """

    entity_token: PlayFabEntityToken
    play_fab_id: str
    session_ticket: str

    @property
    def expires_at(self) -> Instant:
        """Convenience: delegates to ``entity_token.expires_at``."""
        return self.entity_token.expires_at


def _xsts_authorization_header(xsts: XSTSToken) -> str:
    return f"XBL3.0 x={xsts.userhash};{xsts.token}"


def _raise_for_playfab_error(response: httpx.Response) -> None:
    """If ``response`` is a PlayFab error, raise :class:`PlayFabError`.

    Falls back to :class:`HttpError` for non-JSON bodies / unexpected
    shapes.
    """
    if response.is_success:
        return
    try:
        payload = response.json()
    except ValueError:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from None
    if isinstance(payload, dict):
        payload_typed = cast(dict[str, Any], payload)
        error = payload_typed.get("error")
        message = payload_typed.get("errorMessage")
        code = payload_typed.get("errorCode")
        if isinstance(error, str) and isinstance(message, str):
            raise PlayFabError(
                response.status_code,
                error,
                message,
                error_code=code if isinstance(code, int) else None,
            )
    raise HttpError(
        response.status_code,
        response.text,
        url=str(response.request.url) if response.request else None,
    )


async def playfab_login_with_xbox(
    xsts: XSTSToken,
    *,
    title_id: str = BEDROCK_PLAYFAB_TITLE_ID,
    http_client: httpx.AsyncClient | None = None,
) -> PlayFabToken:
    """Exchange an XSTS token for a :class:`PlayFabToken`.

    Args:
        xsts: An :class:`XSTSToken` obtained earlier in the chain.
            (Note: the XSTS exchange for PlayFab requires a different
            ``RelyingParty`` than the Java Minecraft login flow —
            ``http://playfab.xboxlive.com/`` rather than
            ``rp://api.minecraftservices.com/``. The current
            :func:`~mcapi_auth.authenticate_xsts` returns a token for
            the Minecraft RP. Callers who need a PlayFab-scoped XSTS
            should re-run XSTS authentication with the appropriate
            relying party; that's left to the caller for now since
            most consumers want their own retry/cache strategy.)
        title_id: PlayFab title id. Defaults to retail Bedrock
            (``"20CA2"``). Use :data:`EDU_PLAYFAB_TITLE_ID` for the
            Education edition.
        http_client: Optional shared :class:`httpx.AsyncClient`.

    Returns:
        A :class:`PlayFabToken` with entity token + account id +
        session ticket.

    Raises:
        PlayFabError: PlayFab returned a structured error.
        HttpError: Non-PlayFab-shaped failure.
    """
    body: dict[str, Any] = {
        "CreateAccount": True,
        "InfoRequestParameters": {
            "GetPlayerProfile": True,
            "GetUserAccountInfo": True,
        },
        "TitleId": title_id.upper(),
        "XboxToken": _xsts_authorization_header(xsts),
    }
    async with acquire_client(http_client) as client:
        response = await client.post(
            f"{_playfab_base(title_id)}/Client/LoginWithXbox",
            json=body,
        )
    _raise_for_playfab_error(response)
    try:
        envelope = response.json()
    except ValueError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    data = cast(dict[str, Any], envelope).get("data") if isinstance(envelope, dict) else None
    if not isinstance(data, dict):
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        )
    data_typed = cast(dict[str, Any], data)
    entity_json = data_typed.get("EntityToken")
    play_fab_id = data_typed.get("PlayFabId")
    session_ticket = data_typed.get("SessionTicket")
    if (
        not isinstance(entity_json, dict)
        or not isinstance(play_fab_id, str)
        or not isinstance(session_ticket, str)
    ):
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        )
    try:
        entity_token = PlayFabEntityToken.from_api_payload(cast(dict[str, Any], entity_json))
    except ValidationError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    return PlayFabToken(
        entity_token=entity_token,
        play_fab_id=play_fab_id,
        session_ticket=session_ticket,
    )


async def playfab_get_entity_token(
    entity_token: PlayFabEntityToken,
    *,
    title_id: str = BEDROCK_PLAYFAB_TITLE_ID,
    entity_id: str | None = None,
    entity_type: str | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> PlayFabEntityToken:
    """Refresh a :class:`PlayFabEntityToken`.

    The existing ``token`` is sent as the ``X-EntityToken`` header,
    PlayFab returns a new ``EntityToken`` for the same entity. If the
    existing token has already expired, this call will 401 — the
    caller must restart from :func:`playfab_login_with_xbox`.

    Args:
        entity_token: The current entity token. ``entity_id`` and
            ``entity_type`` default to its values.
        title_id: PlayFab title id (default: retail Bedrock).
        entity_id: Override the entity id sent in the body.
        entity_type: Override the entity type sent in the body.
        http_client: Optional shared :class:`httpx.AsyncClient`.

    Returns:
        A fresh :class:`PlayFabEntityToken` (same entity, new token
        + expiry).
    """
    eid = entity_id if entity_id is not None else entity_token.entity_id
    etype = entity_type if entity_type is not None else entity_token.entity_type
    body: dict[str, Any] = {"Entity": {"Id": eid, "Type": etype}}
    headers = {"X-EntityToken": entity_token.token}
    async with acquire_client(http_client) as client:
        response = await client.post(
            f"{_playfab_base(title_id)}/Authentication/GetEntityToken",
            json=body,
            headers=headers,
        )
    _raise_for_playfab_error(response)
    try:
        envelope = response.json()
    except ValueError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    data = cast(dict[str, Any], envelope).get("data") if isinstance(envelope, dict) else None
    if not isinstance(data, dict):
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        )
    try:
        return PlayFabEntityToken.from_api_payload(cast(dict[str, Any], data))
    except ValidationError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e

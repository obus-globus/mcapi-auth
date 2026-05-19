"""Stages 3-4: Xbox Live and Xbox STS authentication."""

import logging
from typing import Any, ClassVar

import httpx
from pydantic import ValidationError, model_validator

from .._constants import XBL_AUTH_URL, XSTS_AUTH_URL, XSTS_RELYING_PARTY
from .._http import acquire_client, parse_json_object_auth
from .._models import McModel
from ..exceptions import McAuthError, XboxAuthError, xerr_to_exception

__all__ = ["XSTSToken", "XboxLiveToken", "authenticate_xbl", "authenticate_xsts"]

logger = logging.getLogger(__name__)


class _XboxTokenBase(McModel):
    """Shared validator for Xbox Live / XSTS token responses."""

    __field_aliases__: ClassVar[dict[str, str]] = {"Token": "token"}

    token: str
    userhash: str

    @model_validator(mode="before")
    @classmethod
    def _extract_userhash(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        src: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        if "userhash" in src:
            return src
        display = src.get("DisplayClaims")
        if isinstance(display, dict):
            display_typed: dict[str, Any] = display  # type: ignore[assignment]
            xui = display_typed.get("xui")
            if isinstance(xui, list) and xui:
                xui_list: list[object] = xui  # type: ignore[assignment]
                first = xui_list[0]
                if isinstance(first, dict):
                    first_typed: dict[str, Any] = first  # type: ignore[assignment]
                    uhs = first_typed.get("uhs")
                    if isinstance(uhs, str):
                        src["userhash"] = uhs
        return src


class XboxLiveToken(_XboxTokenBase):
    """Result of stage 3 — Xbox Live ``Token`` plus the user-hash claim."""


class XSTSToken(_XboxTokenBase):
    """Result of stage 4 — XSTS ``Token`` plus the user-hash claim.

    ``userhash`` will equal the value from :class:`XboxLiveToken`, but
    we re-extract it from the XSTS response in case XSTS ever swaps the
    user under a service account.
    """


async def authenticate_xbl(
    msa_access_token: str,
    *,
    use_d_prefix: bool = True,
    http_client: httpx.AsyncClient | None = None,
) -> XboxLiveToken:
    """Exchange a Microsoft access token for an Xbox Live token.

    The right ``use_d_prefix`` value depends on **which OAuth endpoint
    minted** ``msa_access_token``:

    * **v2 / Azure-AD ``consumers`` endpoint** (modern flows — Xbox app,
      Xbox-Gamepass, PrismLauncher, Liquid Launcher, the
      ``MsaApplicationConfig.v2_consumers`` factory): tokens start with
      ``eyJ…`` (JWT-shaped) and **must** be wrapped as ``d={token}``.
      Pass ``use_d_prefix=True`` (the default).

    * **v1 / Live-Connect endpoint** (legacy Minecraft Launcher client
      ``00000000402b5328`` with scope
      ``service::user.auth.xboxlive.com::MBI_SSL``, Bedrock device
      clients, the ``MsaApplicationConfig.v1_launcher`` factory):
      tokens are opaque ``EwD…`` RPS tickets and **must NOT** be
      wrapped — XBL returns ``401 Unauthorized`` if you prefix them
      with ``d=``. Pass ``use_d_prefix=False``.

    If you're driving the auth chain through :class:`AuthChain`, this
    is handled for you — ``MsaApplicationConfig.xbl_use_d_prefix`` is
    set correctly by the ``v1_launcher`` / ``v2_consumers`` factories
    and the chain forwards it on every refresh. The standalone
    ``authenticate_xbl`` is mostly useful for ad-hoc / testing code
    that owns its own token plumbing — those callers need to choose
    the right prefix mode themselves.

    Args:
        msa_access_token: The MS access token to exchange.
        use_d_prefix: Whether to wrap the token as ``d={token}`` in the
            ``RpsTicket`` payload. See above for which endpoint needs
            which.
        http_client: Optional :class:`httpx.AsyncClient` to reuse.
    """
    rps_ticket = f"d={msa_access_token}" if use_d_prefix else msa_access_token
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": rps_ticket,
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
    }
    async with acquire_client(http_client) as c:
        response = await c.post(
            XBL_AUTH_URL,
            json=payload,
            headers={
                "Accept": "application/json",
                "x-xbl-contract-version": "1",
            },
        )
    if response.status_code != 200:
        raise XboxAuthError(f"XBL authenticate failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    try:
        return XboxLiveToken.model_validate(data)
    except ValidationError as e:
        raise XboxAuthError(
            f"XBL response missing required fields: keys={sorted(data.keys())}"
        ) from e


async def authenticate_xsts(
    xbl_token: str,
    *,
    relying_party: str = XSTS_RELYING_PARTY,
    http_client: httpx.AsyncClient | None = None,
) -> XSTSToken:
    """Exchange an XBL token for an XSTS token for Minecraft Services.

    Raises a typed XErr exception on 401 — see
    :func:`mcapi_auth.exceptions.xerr_to_exception` for the mapping.
    """
    payload = {
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
        "RelyingParty": relying_party,
        "TokenType": "JWT",
    }
    async with acquire_client(http_client) as c:
        response = await c.post(
            XSTS_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json"},
        )
    if response.status_code == 401:
        try:
            data = parse_json_object_auth(response)
        except McAuthError:
            raise xerr_to_exception(None, body_excerpt=response.text) from None
        xerr_raw = data.get("XErr")
        xerr: int | None = xerr_raw if isinstance(xerr_raw, int) else None
        if xerr is None:
            raise xerr_to_exception(None, body_excerpt=response.text)
        raise xerr_to_exception(xerr)
    if response.status_code != 200:
        raise XboxAuthError(f"XSTS authorize failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    try:
        return XSTSToken.model_validate(data)
    except ValidationError as e:
        raise XboxAuthError(
            f"XSTS response missing required fields: keys={sorted(data.keys())}"
        ) from e

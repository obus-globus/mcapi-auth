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

    Set ``use_d_prefix=True`` (the default) for tokens minted by the
    Minecraft Launcher / MSA "consumers" OAuth flows — XBL expects the
    RPS ticket prefixed with ``d=`` for those. Set it to ``False`` when
    using non-public Azure-AD client_ids (e.g. PrismLauncher's own
    client) which mint tokens that XBL accepts raw.
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
            raise xerr_to_exception(None) from None
        xerr_raw = data.get("XErr")
        xerr: int | None = xerr_raw if isinstance(xerr_raw, int) else None
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

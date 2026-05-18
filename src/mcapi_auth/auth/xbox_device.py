"""Sisu / Xbox Live device-token authentication flow.

The "Sisu" Xbox Live flow exchanges a Microsoft access token *plus* a
client-controlled device key for **three** Xbox Live tokens in one
round-trip: a UserToken, a TitleToken, and a fully-formed XSTSToken
scoped to the relying party you asked for. The Java reference (RaphiMC)
uses it for the Bedrock client chain (XSTS RP
``https://multiplayer.minecraft.net/``) and the PlayFab leg (XSTS RP
``https://b980a380.minecraft.playfabapi.com/``) — both of which the
plain Java ``user.auth.xboxlive.com`` + ``xsts.auth.xboxlive.com`` chain
either can't reach (Bedrock requires a TitleToken) or returns less
usable data for.

The flow is two HTTP calls:

1. ``POST https://device.auth.xboxlive.com/device/authenticate`` with a
   ProofKey (the public half of an ES256 / P-256 device keypair) plus a
   custom Xbox ``Signature`` header signed with the private half. Returns
   an :class:`XblDeviceToken` (valid for ~24h).
2. ``POST https://sisu.xboxlive.com/authorize`` with the MSA access
   token, the DeviceToken, the same ProofKey, and another signed header.
   Returns :class:`XblSisuTokens` containing UserToken + TitleToken +
   XSTSToken.

The device keypair should be persisted across launches; the Xbox
back-end remembers it as a stable device identity. Re-generating it
every run looks like a new device on every login.

This module requires the optional ``[bedrock]`` extra (for the
``cryptography`` package).
"""

from __future__ import annotations

import base64
import io
import json
import logging
import struct
from typing import Any, ClassVar
from uuid import UUID

import httpx
from pydantic import ValidationError, model_validator
from whenever import Instant

from .._http import acquire_client, parse_json_object_auth
from .._models import McModel
from ..exceptions import McAuthError, XboxAuthError, xerr_to_exception

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
except ImportError as exc:  # pragma: no cover - import-time guard
    raise ImportError(
        "mcapi_auth.auth.xbox_device requires the 'cryptography' package. "
        "Install it via the optional extra: pip install mcapi-auth[bedrock]"
    ) from exc

__all__ = [
    "XBL_AUTH_RELYING_PARTY",
    "XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY",
    "XBL_XSTS_BEDROCK_REALMS_RELYING_PARTY",
    "XBL_XSTS_BEDROCK_RELYING_PARTY",
    "XblDeviceKeyPair",
    "XblDeviceToken",
    "XblSisuTokens",
    "XblTitleToken",
    "XblUserToken",
    "XblXstsToken",
    "authenticate_xbl_device",
    "sisu_authorize",
]

logger = logging.getLogger(__name__)

XBL_DEVICE_AUTH_URL = "https://device.auth.xboxlive.com/device/authenticate"
XBL_SISU_AUTHORIZE_URL = "https://sisu.xboxlive.com/authorize"

XBL_AUTH_RELYING_PARTY = "http://auth.xboxlive.com"
XBL_XSTS_BEDROCK_RELYING_PARTY = "https://multiplayer.minecraft.net/"
XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY = "https://b980a380.minecraft.playfabapi.com/"
XBL_XSTS_BEDROCK_REALMS_RELYING_PARTY = "https://pocket.realms.minecraft.net/"

# 100ns intervals between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix epoch).
_WINDOWS_EPOCH_OFFSET_100NS = 11_644_473_600 * 10_000_000


# ---------------------------------------------------------------------
# Device keypair + Xbox signature helpers
# ---------------------------------------------------------------------


class XblDeviceKeyPair:
    """ES256 / NIST P-256 device keypair used for the Sisu flow.

    Wraps :class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    on the P-256 curve. The public half is exposed as a JWK ``ProofKey``
    object; the private half signs the Xbox-style ``Signature`` header
    that ``device.auth.xboxlive.com`` and ``sisu.xboxlive.com`` require.
    """

    __slots__ = ("_private_key",)

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError(
                "XblDeviceKeyPair requires a SECP256R1 (NIST P-256) key; "
                f"got {type(private_key.curve).__name__}"
            )
        self._private_key = private_key

    @classmethod
    def generate(cls) -> XblDeviceKeyPair:
        """Generate a fresh ES256 device keypair."""
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: str | bytes) -> XblDeviceKeyPair:
        """Load a previously-persisted keypair from a PKCS#8 PEM blob."""
        data = pem.encode("utf-8") if isinstance(pem, str) else pem
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("PEM did not contain an EC private key")
        return cls(key)

    def private_key_pem(self) -> str:
        """Return the keypair as an unencrypted PKCS#8 PEM string."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def proof_key(self) -> dict[str, str]:
        """Return the Xbox-format ``ProofKey`` JWK for this keypair.

        Matches RaphiMC's ``SignedXblPostRequest#getProofKey``: a JSON
        object with ``kty=EC``, ``alg=ES256``, ``crv=P-256``, ``use=sig``,
        and base64url(x|y) coordinates padded to 32 bytes.
        """
        public = self._private_key.public_key()
        numbers = public.public_numbers()
        x = _coord_to_b64url(numbers.x)
        y = _coord_to_b64url(numbers.y)
        return {
            "kty": "EC",
            "alg": "ES256",
            "crv": "P-256",
            "use": "sig",
            "x": x,
            "y": y,
        }

    def _sign_p1363(self, data: bytes) -> bytes:
        """Sign ``data`` with ECDSA-SHA256, returning raw r||s (64 bytes)."""
        der = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def signature_header(
        self,
        *,
        method: str,
        path_and_query: str,
        body: bytes,
        authorization: str | None = None,
        timestamp: Instant | None = None,
    ) -> str:
        """Build the ``Signature`` header value for an Xbox-signed POST.

        Replicates the byte layout from RaphiMC's
        ``SignedXblPostRequest#appendSignatureHeader``: a custom packet
        of (policy version, NUL, Windows timestamp, NUL, HTTP method,
        NUL, URL path+query, NUL, Authorization header or empty, NUL,
        body, NUL), signed with ECDSA-SHA256 in P1363 format (raw r||s).
        The header itself is u32(policy)|u64(windows_ts)|signature,
        base64-encoded.
        """
        ts_instant = timestamp if timestamp is not None else Instant.now()
        windows_ts = ts_instant.timestamp() * 10_000_000 + _WINDOWS_EPOCH_OFFSET_100NS

        body_to_sign = io.BytesIO()
        body_to_sign.write(struct.pack(">I", 1))  # policy version
        body_to_sign.write(b"\x00")
        body_to_sign.write(struct.pack(">Q", windows_ts))
        body_to_sign.write(b"\x00")
        body_to_sign.write(method.encode("utf-8"))
        body_to_sign.write(b"\x00")
        body_to_sign.write(path_and_query.encode("utf-8"))
        body_to_sign.write(b"\x00")
        if authorization is not None:
            body_to_sign.write(authorization.encode("utf-8"))
        body_to_sign.write(b"\x00")
        body_to_sign.write(body)
        body_to_sign.write(b"\x00")

        signature = self._sign_p1363(body_to_sign.getvalue())

        header = struct.pack(">I", 1) + struct.pack(">Q", windows_ts) + signature
        return base64.b64encode(header).decode("ascii")


def _coord_to_b64url(coord: int) -> str:
    """Encode an EC coordinate as base64url with the P-256 32-byte width."""
    raw = coord.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------


class _XblTokenBase(McModel):
    """Shared validator that lifts the Xbox ``NotAfter`` / ``Token`` claims."""

    __field_aliases__: ClassVar[dict[str, str]] = {
        "Token": "token",
        "NotAfter": "expires_at",
    }

    token: str
    expires_at: Instant


class XblDeviceToken(_XblTokenBase):
    """An Xbox Live device token + the device id Xbox echoed back."""

    device_id: str

    @model_validator(mode="before")
    @classmethod
    def _extract_device_id(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        src: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        if "device_id" in src:
            return src
        display = src.get("DisplayClaims")
        if isinstance(display, dict):
            display_typed: dict[str, Any] = display  # type: ignore[assignment]
            xdi = display_typed.get("xdi")
            if isinstance(xdi, dict):
                xdi_typed: dict[str, Any] = xdi  # type: ignore[assignment]
                did = xdi_typed.get("did")
                if isinstance(did, str):
                    src["device_id"] = did
        return src


class XblUserToken(_XblTokenBase):
    """A Sisu UserToken — same shape as a classic Xbox Live user token."""

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


class XblTitleToken(_XblTokenBase):
    """A Sisu TitleToken (bound to an MSA application/title)."""

    title_id: str

    @model_validator(mode="before")
    @classmethod
    def _extract_title_id(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        src: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        if "title_id" in src:
            return src
        display = src.get("DisplayClaims")
        if isinstance(display, dict):
            display_typed: dict[str, Any] = display  # type: ignore[assignment]
            xti = display_typed.get("xti")
            if isinstance(xti, dict):
                xti_typed: dict[str, Any] = xti  # type: ignore[assignment]
                tid = xti_typed.get("tid")
                if isinstance(tid, str):
                    src["title_id"] = tid
        return src


class XblXstsToken(_XblTokenBase):
    """The XSTS half of a Sisu response — same shape as :class:`mcapi_auth.XSTSToken`."""

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


class XblSisuTokens(McModel):
    """The three tokens Sisu returns in one round-trip."""

    user_token: XblUserToken
    title_token: XblTitleToken
    xsts_token: XblXstsToken

    __field_aliases__: ClassVar[dict[str, str]] = {
        "UserToken": "user_token",
        "TitleToken": "title_token",
        "AuthorizationToken": "xsts_token",
    }


# ---------------------------------------------------------------------
# HTTP requests
# ---------------------------------------------------------------------


async def authenticate_xbl_device(
    keypair: XblDeviceKeyPair,
    *,
    device_type: str = "Win32",
    device_id: UUID,
    http_client: httpx.AsyncClient | None = None,
) -> XblDeviceToken:
    """Authenticate the device keypair against ``device.auth.xboxlive.com``.

    The returned :class:`XblDeviceToken` is valid for ~24 hours and is
    fed into :func:`sisu_authorize`. Callers should persist both the
    keypair and the ``device_id`` UUID across launches — Xbox treats
    that pair as a stable device identity.

    ``device_type`` is the Xbox device class string; common values are
    ``"Win32"`` (Windows desktop), ``"iOS"``, ``"Android"``, and
    ``"Nintendo"``.
    """
    properties = {
        "DeviceType": device_type,
        "Id": "{" + str(device_id) + "}",
        "AuthMethod": "ProofOfPossession",
        "ProofKey": keypair.proof_key(),
    }
    body = {
        "Properties": properties,
        "RelyingParty": XBL_AUTH_RELYING_PARTY,
        "TokenType": "JWT",
    }
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")

    signature = keypair.signature_header(
        method="POST",
        path_and_query="/device/authenticate",
        body=body_bytes,
    )

    async with acquire_client(http_client) as c:
        response = await c.post(
            XBL_DEVICE_AUTH_URL,
            content=body_bytes,
            headers={
                "Content-Type": "application/json",
                "Signature": signature,
                "x-xbl-contract-version": "1",
            },
        )
    if response.status_code != 200:
        raise XboxAuthError(
            f"device authenticate failed: status={response.status_code} "
            f"body={response.text[:200]!r}"
        )

    data = parse_json_object_auth(response)
    try:
        return XblDeviceToken.model_validate(data)
    except ValidationError as e:
        raise XboxAuthError(
            f"device authenticate response missing fields: keys={sorted(data.keys())}"
        ) from e


async def sisu_authorize(
    msa_access_token: str,
    device_token: XblDeviceToken,
    keypair: XblDeviceKeyPair,
    *,
    client_id: str,
    relying_party: str,
    http_client: httpx.AsyncClient | None = None,
) -> XblSisuTokens:
    """Exchange MSA token + DeviceToken for UserToken + TitleToken + XSTS.

    ``client_id`` must be a Microsoft *title* client id — Sisu rejects
    non-title client ids with HTTP 400. The Minecraft launcher / Bedrock
    title ids in :mod:`mcapi_auth._constants` are all suitable.

    ``relying_party`` controls the audience of the returned XSTS token.
    Common values:

    - :data:`XBL_XSTS_BEDROCK_RELYING_PARTY` (Bedrock multiplayer)
    - :data:`XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY` (Bedrock PlayFab leg)
    - :data:`XBL_XSTS_BEDROCK_REALMS_RELYING_PARTY` (Bedrock Realms)
    - ``rp://api.minecraftservices.com/`` for Java Edition (rarely
      needed via Sisu, but supported).

    Raises a typed XErr exception on 401, the same way
    :func:`mcapi_auth.authenticate_xsts` does.
    """
    body = {
        "Sandbox": "RETAIL",
        "UseModernGamertag": True,
        "AppId": client_id,
        "AccessToken": "t=" + msa_access_token,
        "DeviceToken": device_token.token,
        "ProofKey": keypair.proof_key(),
        "RelyingParty": relying_party,
    }
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")

    signature = keypair.signature_header(
        method="POST",
        path_and_query="/authorize",
        body=body_bytes,
    )

    async with acquire_client(http_client) as c:
        response = await c.post(
            XBL_SISU_AUTHORIZE_URL,
            content=body_bytes,
            headers={
                "Content-Type": "application/json",
                "Signature": signature,
            },
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
        raise XboxAuthError(
            f"sisu authorize failed: status={response.status_code} body={response.text[:200]!r}"
        )

    data = parse_json_object_auth(response)
    try:
        return XblSisuTokens.model_validate(data)
    except ValidationError as e:
        raise XboxAuthError(
            f"sisu authorize response missing fields: keys={sorted(data.keys())}"
        ) from e

"""Bedrock-Edition client chain.

This module covers the post-XSTS Bedrock pipeline: generating the
session ES384 key-pair, exchanging the XSTS token (scoped to
``https://multiplayer.minecraft.net/``) for a Mojang-signed certificate
chain (``mcChain``), and obtaining the session + multiplayer JWTs that
Bedrock clients need to actually connect.

Bedrock's surface is significantly more complex than Java's:

* **Session key-pair** (ECDSA P-384, a.k.a. ES384) is generated client
  side, persisted across sessions, and used to identify the client to
  Mojang. The public key is sent with the authentication request; the
  Mojang JWT in the returned chain binds that key to the player's
  identity. Servers and other clients later verify message signatures
  against that key.

* **mcChain** is a 2-element JWT chain (``mojangJwt`` +
  ``identityJwt``). ``identityJwt`` carries ``extraData`` with
  ``XUID``, ``identity`` (the UUID), and ``displayName``.

* **MinecraftSession** is the franchise-service session JWT used as a
  Bearer Authorization header for downstream multiplayer calls. It's
  obtained by exchanging the PlayFab session ticket (NOT directly from
  XBL).

* **MinecraftMultiplayerToken** is a server-join token, obtained by
  POSTing the session-key public-key to the franchise multiplayer
  endpoint.

What this module does **not** include:

* The XBL device-token / Sisu signing dance needed to obtain the
  Bedrock-scoped XSTS token from scratch (a sizable client-cert
  flow). Callers obtain the XSTS some other way and pass it in.

* A full ``BedrockAuthManager`` aggregating all stages — caller wires
  the stages themselves (mirrors ``AuthChain`` for Java but with more
  parallel branches).

``cryptography>=43`` is required; install the ``[bedrock]`` extra
(``pip install mcapi-auth[bedrock]``).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Final, cast
from uuid import UUID

import httpx
from pydantic import ValidationError
from whenever import Instant

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
except ImportError as _e:  # pragma: no cover - import-error path
    raise ImportError(
        "mcapi-auth Bedrock support requires the `cryptography` package. "
        "Install with `pip install mcapi-auth[bedrock]`."
    ) from _e

from .._http import acquire_client
from .._models import InstantField, McModel
from ..auth.xbox import XSTSToken
from ..exceptions import HttpError, MinecraftAuthError

__all__ = [
    "BedrockKeyPair",
    "MinecraftCertificateChain",
    "MinecraftMultiplayerToken",
    "MinecraftSession",
    "decode_jwt_payload",
    "generate_bedrock_session_keypair",
    "minecraft_authenticate",
    "start_minecraft_multiplayer_session",
    "start_minecraft_session",
]

# Bedrock client-services endpoints.
_AUTH_URL: Final = "https://multiplayer.minecraft.net/authentication"
_SESSION_START_URL: Final = (
    "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start"
)
_MULTIPLAYER_SESSION_START_URL: Final = (
    "https://authorization.franchise.minecraft-services.net/api/v1.0/multiplayer/session/start"
)

# Public Minecraft Bedrock UUID namespace used to derive a stable UUID
# from the XUID returned in the multiplayer JWT.
_BEDROCK_XUID_NAMESPACE: Final = "pocket-auth-1-xuid:"


# ---------------------------------------------------------------------
# Key pair
# ---------------------------------------------------------------------


class BedrockKeyPair:
    """An ES384 (NIST P-384 / secp384r1) key-pair for Bedrock signing.

    Wraps :mod:`cryptography` private/public key objects. The public
    key is also exposed as a base64-encoded ``SubjectPublicKeyInfo``
    DER blob, which is what Mojang expects in the authentication
    request body.

    Persist the key with :meth:`to_pem` / :meth:`from_pem` so a
    re-launch doesn't invalidate every server's signature cache.
    """

    __slots__ = ("_private_key", "_public_key")

    def __init__(self, private_key: EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP384R1):
            raise ValueError(
                "BedrockKeyPair requires a SECP384R1 (P-384 / ES384) curve, "
                f"got {private_key.curve.name!r}"
            )
        self._private_key: EllipticCurvePrivateKey = private_key
        self._public_key: EllipticCurvePublicKey = private_key.public_key()

    @classmethod
    def generate(cls) -> BedrockKeyPair:
        """Generate a fresh P-384 key-pair."""
        return cls(ec.generate_private_key(ec.SECP384R1()))

    @classmethod
    def from_pem(cls, private_pem: str | bytes) -> BedrockKeyPair:
        """Restore a key-pair from a PEM-encoded private key."""
        data = private_pem.encode("ascii") if isinstance(private_pem, str) else private_pem
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, EllipticCurvePrivateKey):
            raise ValueError("PEM does not contain an EC private key")
        return cls(key)

    @property
    def private_key(self) -> EllipticCurvePrivateKey:
        """The underlying :mod:`cryptography` private-key object."""
        return self._private_key

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        """The underlying :mod:`cryptography` public-key object."""
        return self._public_key

    def private_key_pem(self) -> str:
        """PKCS#8 PEM of the private key (for persistence)."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")

    def public_key_pem(self) -> str:
        """SubjectPublicKeyInfo PEM of the public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def public_key_der(self) -> bytes:
        """Raw SubjectPublicKeyInfo DER of the public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def public_key_der_b64(self) -> str:
        """Standard base64 of :meth:`public_key_der` (Mojang wire format)."""
        return base64.b64encode(self.public_key_der()).decode("ascii")

    def to_pem(self) -> tuple[str, str]:
        """Convenience: ``(private_pem, public_pem)`` for persistence."""
        return self.private_key_pem(), self.public_key_pem()


def generate_bedrock_session_keypair() -> BedrockKeyPair:
    """Generate a new :class:`BedrockKeyPair` (ES384).

    Equivalent to ``BedrockKeyPair.generate()`` — provided as a
    function for symmetry with the rest of the module.
    """
    return BedrockKeyPair.generate()


# ---------------------------------------------------------------------
# JWT helper
# ---------------------------------------------------------------------


def decode_jwt_payload(jwt: str) -> dict[str, Any]:
    """Decode the payload (second segment) of a JWT without verifying.

    The Bedrock cert-chain JWTs are signed by Mojang's public key —
    we don't have it locally, so we treat them as opaque and just
    parse their payloads to surface XUID / display name / identity.

    Args:
        jwt: A compact JWT string ``header.payload.signature``.

    Raises:
        ValueError: The string is not a parseable JWT.
    """
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError(f"not a JWT: expected 3 segments, got {len(parts)}")
    body = parts[1]
    # Compact JWT uses base64url WITHOUT padding; restore it.
    padded = body + "=" * (-len(body) % 4)
    raw = base64.urlsafe_b64decode(padded)
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise ValueError("JWT payload is not a JSON object")
    return cast(dict[str, Any], decoded)


def _jwt_exp_instant(jwt: str) -> Instant | None:
    """Return ``Instant`` for the JWT's ``exp`` claim if present."""
    try:
        payload = decode_jwt_payload(jwt)
    except ValueError:
        return None
    exp = payload.get("exp")
    if isinstance(exp, int | float):
        return Instant.from_timestamp(int(exp))
    return None


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------


class MinecraftCertificateChain(McModel):
    """The Mojang-signed Bedrock client certificate chain ("mcChain").

    Two JWTs:

    * ``mojang_jwt`` — Mojang's certificate chain root, signed by
      Mojang's public key.
    * ``identity_jwt`` — the client identity, signed by the same key
      authenticated by ``mojang_jwt``; payload's ``extraData`` carries
      ``XUID``, ``identity`` (UUID), and ``displayName``.

    The chain expires at the minimum of the two JWTs' ``exp`` claims
    (typically 24h).
    """

    mojang_jwt: str
    identity_jwt: str

    def identity_payload(self) -> dict[str, Any]:
        """Decoded payload of :attr:`identity_jwt`."""
        return decode_jwt_payload(self.identity_jwt)

    def mojang_payload(self) -> dict[str, Any]:
        """Decoded payload of :attr:`mojang_jwt`."""
        return decode_jwt_payload(self.mojang_jwt)

    def _extra_data(self) -> dict[str, Any]:
        payload = self.identity_payload()
        extra = payload.get("extraData")
        if not isinstance(extra, dict):
            raise ValueError("identity JWT missing 'extraData' object")
        return cast(dict[str, Any], extra)

    @property
    def xuid(self) -> str:
        """Bedrock account XUID from the identity JWT."""
        return cast(str, self._extra_data()["XUID"])

    @property
    def display_name(self) -> str:
        """Player display name from the identity JWT."""
        return cast(str, self._extra_data()["displayName"])

    @property
    def identity_uuid(self) -> UUID:
        """Bedrock-side UUID from the identity JWT's ``identity`` field."""
        return UUID(cast(str, self._extra_data()["identity"]))

    @property
    def expires_at(self) -> Instant:
        """Earliest expiry between the two JWTs.

        Falls back to a far-past sentinel if neither JWT has an ``exp``
        claim — which would be a wire-format anomaly worth alerting on.
        """
        candidates = [_jwt_exp_instant(self.mojang_jwt), _jwt_exp_instant(self.identity_jwt)]
        valid = [c for c in candidates if c is not None]
        if not valid:
            return Instant.from_timestamp(0)
        return min(valid)


class MinecraftSession(McModel):
    """Franchise-service session token.

    ``authorization_header`` is sent verbatim as the ``Authorization``
    HTTP header on downstream Bedrock services (multiplayer session
    start, etc).
    """

    __field_aliases__ = {  # noqa: RUF012
        "validUntil": "expires_at",
        "authorizationHeader": "authorization_header",
    }

    expires_at: InstantField
    authorization_header: str

    @property
    def bearer_token(self) -> str | None:
        """Just the token (the part after the scheme), if format is recognised."""
        parts = self.authorization_header.split(" ", 1)
        if len(parts) == 2:
            return parts[1]
        return None


class MinecraftMultiplayerToken(McModel):
    """Bedrock multiplayer "signed token" used to join servers.

    Bedrock clients send this JWT to a server to prove their identity.
    The server (and other clients) verify it against Mojang's public
    key.
    """

    __field_aliases__ = {  # noqa: RUF012
        "validUntil": "expires_at",
        "signedToken": "token",
    }

    expires_at: InstantField
    token: str

    def payload(self) -> dict[str, Any]:
        """Decoded JWT payload of :attr:`token`."""
        return decode_jwt_payload(self.token)

    @property
    def xuid(self) -> str:
        """Player XUID (``xid`` claim)."""
        return cast(str, self.payload()["xid"])

    @property
    def display_name(self) -> str:
        """Player display name (``xname`` claim)."""
        return cast(str, self.payload()["xname"])

    @property
    def uuid(self) -> UUID:
        """Stable client UUID derived from the XUID.

        Matches the Java reference exactly: Bedrock uses
        ``UUID.nameUUIDFromBytes("pocket-auth-1-xuid:<xuid>")``, which is
        an MD5-based (version 3) UUID. The standard library's
        :func:`uuid.uuid5` cannot be used (SHA-1 / version 5), nor can
        :func:`uuid.uuid3` (which requires a namespace UUID, not a raw
        string), so the MD5 byte layout is computed manually below.
        """
        h = hashlib.md5(  # MD5 is required for Java parity
            (_BEDROCK_XUID_NAMESPACE + self.xuid).encode("utf-8")
        ).digest()
        b = bytearray(h)
        b[6] = (b[6] & 0x0F) | 0x30  # version 3
        b[8] = (b[8] & 0x3F) | 0x80  # IETF variant
        return UUID(bytes=bytes(b))


# ---------------------------------------------------------------------
# HTTP requests
# ---------------------------------------------------------------------


def _xsts_authorization_header(xsts: XSTSToken) -> str:
    return f"XBL3.0 x={xsts.userhash};{xsts.token}"


def _raise_http(response: httpx.Response) -> None:
    if response.is_success:
        return
    raise HttpError(
        response.status_code,
        response.text,
        url=str(response.request.url) if response.request else None,
    )


async def minecraft_authenticate(
    xsts: XSTSToken,
    key_pair: BedrockKeyPair,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftCertificateChain:
    """Obtain the Mojang-signed Bedrock certificate chain.

    Args:
        xsts: An :class:`XSTSToken` scoped to the Bedrock relying
            party (``https://multiplayer.minecraft.net/``). The XSTS
            from :func:`mcapi_auth.authenticate_xsts` is scoped to
            the Java RP — callers must obtain a Bedrock-scoped XSTS
            separately.
        key_pair: The client session :class:`BedrockKeyPair`. The
            public key is base64-DER-encoded into the request body.
        http_client: Optional shared :class:`httpx.AsyncClient`.

    Returns:
        A :class:`MinecraftCertificateChain` with ``mojang_jwt`` and
        ``identity_jwt``.
    """
    body = {"identityPublicKey": key_pair.public_key_der_b64()}
    headers = {"Authorization": _xsts_authorization_header(xsts)}
    async with acquire_client(http_client) as client:
        response = await client.post(_AUTH_URL, json=body, headers=headers)
    _raise_http(response)
    try:
        envelope = response.json()
    except ValueError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    if not isinstance(envelope, dict):
        raise MinecraftAuthError(f"unexpected /authentication body: {response.text[:200]}")
    envelope_t = cast(dict[str, Any], envelope)
    chain = envelope_t.get("chain")
    if not isinstance(chain, list) or len(cast(list[Any], chain)) != 2:
        chain_desc = (
            repr(cast(list[Any], chain)) if isinstance(chain, list) else type(chain).__name__
        )
        raise MinecraftAuthError(f"expected 2-element JWT chain, got {chain_desc}")
    chain_t = cast(list[Any], chain)
    if not (isinstance(chain_t[0], str) and isinstance(chain_t[1], str)):
        raise MinecraftAuthError("chain entries must be JWT strings")
    return MinecraftCertificateChain(mojang_jwt=chain_t[0], identity_jwt=chain_t[1])


async def start_minecraft_session(
    play_fab_session_ticket: str,
    *,
    game_version: str,
    device_id: UUID,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftSession:
    """Open a franchise-service session for downstream Bedrock APIs.

    Exchanges the PlayFab session ticket (from
    :func:`~mcapi_auth.playfab_login_with_xbox`) for a
    :class:`MinecraftSession` whose ``authorization_header`` is used
    as the ``Authorization`` header on subsequent Bedrock
    multiplayer-service requests.

    Args:
        play_fab_session_ticket: ``PlayFabToken.session_ticket`` value.
        game_version: Minecraft Bedrock client version string
            (e.g. ``"1.21.50"``). Mojang gatekeeps stale clients.
        device_id: A stable client-supplied UUID — Mojang's telemetry
            keys metrics off this. Generate once per install.
        http_client: Optional shared :class:`httpx.AsyncClient`.
    """
    body = {
        "device": {
            "applicationType": "MinecraftPE",
            "gameVersion": game_version,
            "id": device_id.hex,
            "memory": 32 * 1024 * 1024 * 1024,
            "hardwareMemoryTier": 5,
            "platform": "Windows10",
            "playFabTitleId": "20CA2",
            "storePlatform": "uwp.store",
            "type": "Windows10",
        },
        "user": {
            "language": "en",
            "regionCode": "US",
            "languageCode": "en-US",
            "tokenType": "PlayFab",
            "token": play_fab_session_ticket,
        },
    }
    async with acquire_client(http_client) as client:
        response = await client.post(_SESSION_START_URL, json=body)
    _raise_http(response)
    return _validate_franchise(response, MinecraftSession)


async def start_minecraft_multiplayer_session(
    session: MinecraftSession,
    key_pair: BedrockKeyPair,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftMultiplayerToken:
    """Obtain a multiplayer "signed token" used to join Bedrock servers.

    Args:
        session: A :class:`MinecraftSession` previously obtained via
            :func:`start_minecraft_session`.
        key_pair: The :class:`BedrockKeyPair` whose public key is sent
            to bind the multiplayer token to this client identity.
        http_client: Optional shared :class:`httpx.AsyncClient`.
    """
    body = {"publicKey": key_pair.public_key_der_b64()}
    headers = {"Authorization": session.authorization_header}
    async with acquire_client(http_client) as client:
        response = await client.post(_MULTIPLAYER_SESSION_START_URL, json=body, headers=headers)
    _raise_http(response)
    return _validate_franchise(response, MinecraftMultiplayerToken)


def _validate_franchise[M: McModel](response: httpx.Response, model: type[M]) -> M:
    """Validate a ``{result: {...}}`` franchise-service envelope."""
    try:
        envelope = response.json()
    except ValueError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    result = cast(dict[str, Any], envelope).get("result") if isinstance(envelope, dict) else None
    if not isinstance(result, dict):
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        )
    try:
        return model.model_validate(cast(dict[str, Any], result))
    except ValidationError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e

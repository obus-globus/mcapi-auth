"""Minecraft 1.19+ player chat-signing certificates.

The endpoint ``POST /player/certificates`` on
``api.minecraftservices.com`` returns the RSA key-pair and Mojang
signatures used for the signed-chat protocol introduced in Minecraft
1.19 (and made mandatory by chat reporting in 1.19.1+).

The wire shape::

    {
      "keyPair": {
        "privateKey": "-----BEGIN RSA PRIVATE KEY-----\\n...",
        "publicKey":  "-----BEGIN RSA PUBLIC KEY-----\\n..."
      },
      "publicKeySignature":   "<base64, legacy>",
      "publicKeySignatureV2": "<base64, current>",
      "expiresAt":      "2026-05-18T12:00:00.000000000Z",
      "refreshedAfter": "2026-05-17T18:00:00.000000000Z"
    }

We expose the keys as PEM strings (the wire format) plus a convenience
:meth:`MinecraftPlayerCertificates.public_key_der` /
:meth:`private_key_der` that strips the PEM armor and decodes the
base64 — no ``cryptography`` dependency. Consumers that need to *use*
the keys (e.g. sign a chat message) can load them with their preferred
crypto library.

Cert lifetime is currently ~48h; Mojang advises refreshing whenever
``Instant.now() >= refreshed_after`` even if not yet expired.
"""

from __future__ import annotations

import base64
import logging
from typing import ClassVar, Final

import httpx
from pydantic import ValidationError

from .._constants import API_SERVICES_BASE
from .._http import acquire_client
from .._models import InstantField, McModel
from ..exceptions import HttpError, MinecraftAuthError, UnauthorizedError
from ._session import TokenLike, coerce_token

__all__ = ["MinecraftKeyPair", "MinecraftPlayerCertificates", "fetch_player_certificates"]

logger = logging.getLogger(__name__)

PLAYER_CERTIFICATES_URL: Final = f"{API_SERVICES_BASE}/player/certificates"


def _strip_pem(pem: str, label: str) -> bytes:
    """Strip PEM headers and decode the base64 payload to DER bytes."""
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    body = pem.replace(begin, "").replace(end, "")
    # Mojang's PEMs use MIME-style line breaks. ``base64.b64decode`` is
    # lenient about whitespace, so we don't need to strip manually.
    return base64.b64decode(body)


class MinecraftKeyPair(McModel):
    """The RSA key pair Mojang issues for chat signing.

    Both fields are PEM-armored. Use :meth:`public_key_der` /
    :meth:`private_key_der` to get the raw DER bytes (which is what
    most crypto libraries accept).
    """

    __field_aliases__: ClassVar[dict[str, str]] = {
        "publicKey": "public_key",
        "privateKey": "private_key",
    }

    public_key: str
    private_key: str

    def public_key_der(self) -> bytes:
        """Decode :attr:`public_key` PEM to DER bytes (``RSA PUBLIC KEY``)."""
        return _strip_pem(self.public_key, "RSA PUBLIC KEY")

    def private_key_der(self) -> bytes:
        """Decode :attr:`private_key` PEM to DER bytes (``RSA PRIVATE KEY``)."""
        return _strip_pem(self.private_key, "RSA PRIVATE KEY")


class MinecraftPlayerCertificates(McModel):
    """The full player-certificates payload.

    Field names follow Mojang's wire shape (``expiresAt``,
    ``refreshedAfter``) but are exposed under Pythonic names via
    :data:`McModel.__field_aliases__`.
    """

    __field_aliases__: ClassVar[dict[str, str]] = {
        "keyPair": "key_pair",
        "publicKeySignature": "legacy_public_key_signature",
        "publicKeySignatureV2": "public_key_signature_v2",
        "expiresAt": "expires_at",
        "refreshedAfter": "refreshed_after",
    }

    key_pair: MinecraftKeyPair
    public_key_signature_v2: str
    legacy_public_key_signature: str | None = None
    expires_at: InstantField
    refreshed_after: InstantField

    @property
    def public_key_signature_v2_bytes(self) -> bytes:
        """Decode :attr:`public_key_signature_v2` from base64."""
        return base64.b64decode(self.public_key_signature_v2)

    @property
    def legacy_public_key_signature_bytes(self) -> bytes | None:
        """Decode :attr:`legacy_public_key_signature` from base64, if present."""
        if self.legacy_public_key_signature is None:
            return None
        return base64.b64decode(self.legacy_public_key_signature)


async def fetch_player_certificates(
    token: TokenLike,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftPlayerCertificates:
    """Fetch the player's current chat-signing certificates.

    Accepts any :class:`~mcapi_auth.api._session.TokenLike` — a raw
    access-token string, a :class:`~mcapi_auth.MinecraftSession`, or
    anything exposing ``access_token``.

    The endpoint mints a fresh key-pair on every call — cache the
    result and only re-call once :attr:`MinecraftPlayerCertificates.refreshed_after`
    has passed (or the cert has expired entirely).

    Raises :class:`UnauthorizedError` on 401 (access token rejected),
    :class:`MinecraftAuthError` on other failures.
    """
    access_token = coerce_token(token)
    async with acquire_client(http_client) as c:
        response = await c.post(
            PLAYER_CERTIFICATES_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
    if response.status_code == 401:
        raise UnauthorizedError("access token rejected by /player/certificates")
    if response.status_code >= 400:
        raise MinecraftAuthError(
            f"/player/certificates returned status {response.status_code}: {response.text[:200]}"
        )
    try:
        return MinecraftPlayerCertificates.model_validate(response.json())
    except ValidationError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e

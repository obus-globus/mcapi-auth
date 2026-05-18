"""Mojang sessionserver ``joinServer`` call.
When a Minecraft client connects to an online-mode server, the server
hands it a SHA-1 "server ID hash" and the client must POST it to
``sessionserver.mojang.com/session/minecraft/join`` to prove account
ownership. The server then queries ``hasJoined`` to confirm.

Third-party services (axochat, custom auth gateways, etc.) reuse the
same dance, which is why this primitive belongs in an auth library.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, overload

import httpx

from .._constants import SESSIONSERVER_JOIN_URL
from .._http import acquire_client
from ..exceptions import MinecraftAuthError

if TYPE_CHECKING:
    from .session import MinecraftSession

__all__ = [
    "JoinServerError",
    "compute_server_id_hash",
    "join_server",
    "join_server_with_session",
]


class JoinServerError(MinecraftAuthError):
    """The Mojang sessionserver rejected the joinServer request.

    :attr:`status_code` is the upstream HTTP status (typically 403 for
    "invalid access token" or 503 for transient failure). :attr:`body`
    is the raw response text — Mojang sometimes returns JSON
    ``{"error", "errorMessage"}`` and sometimes plain text, so we don't
    pre-parse.
    """

    def __init__(self, message: str, *, status_code: int, body: str) -> None:
        super().__init__(message)
        self.status_code: int = status_code
        self.body: str = body


@dataclass(frozen=True, slots=True)
class JoinServerRequest:
    """Inputs to :func:`join_server` — collected for logging / replay."""

    access_token: str
    selected_profile: str  # undashed UUID
    server_id: str  # the SHA-1 "server ID hash" from the server


def compute_server_id_hash(
    server_id: str,
    shared_secret: bytes,
    public_key_der: bytes,
) -> str:
    """Compute the Mojang/Notchian "server ID hash" string.

    Implements the quirky signed-hex algorithm Minecraft uses for
    ``hasJoined``: take SHA-1 of (``server_id`` ASCII || shared secret
    || public key DER), interpret the digest as a 160-bit two's-complement
    big-endian integer, and format it as a signed hexadecimal string
    (no leading zeros, no ``0x``, sign-prefixed with ``-`` if negative).

    Server implementations get the server_id during the Encryption
    Request packet (``serverId`` field, an ASCII string up to 20 chars,
    or empty in 1.7+). ``shared_secret`` is the 16-byte AES key the
    client generated, encrypted with the server's RSA public key.
    ``public_key_der`` is the X.509-encoded SubjectPublicKeyInfo blob
    from that same packet.

    Returns the hex string suitable for passing to :func:`join_server`'s
    ``server_id`` parameter.
    """
    h = hashlib.sha1(usedforsecurity=False)
    h.update(server_id.encode("ascii"))
    h.update(shared_secret)
    h.update(public_key_der)
    digest = h.digest()
    # Interpret as signed 160-bit big-endian integer
    n = int.from_bytes(digest, byteorder="big", signed=True)
    if n < 0:
        return "-" + format(-n, "x")
    return format(n, "x")


@overload
async def join_server(
    *,
    access_token: str,
    uuid: str,
    server_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> None: ...


@overload
async def join_server(
    session: MinecraftSession,
    /,
    *,
    server_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> None: ...


async def join_server(
    session: MinecraftSession | None = None,
    /,
    *,
    access_token: str | None = None,
    uuid: str | None = None,
    server_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """POST sessionserver/join. Returns ``None`` on 204, else raises.

    Two call shapes:

    * **Convenience** — pass a :class:`MinecraftSession` and the
      ``server_id`` hash: ``await join_server(session, server_id=...)``.
      Credentials are read from the session.
    * **Explicit** — pass ``access_token`` + ``uuid`` + ``server_id``
      as keyword args.

    ``uuid`` may be dashed or undashed; we strip dashes for the wire
    format Mojang expects.
    """
    if session is not None:
        if access_token is not None or uuid is not None:
            raise TypeError(
                "join_server: pass either a MinecraftSession or access_token+uuid, not both"
            )
        access_token = session.access_token
        uuid = session.uuid
    if access_token is None or uuid is None:
        raise TypeError(
            "join_server: provide either a MinecraftSession positional "
            "argument or both access_token= and uuid= keyword arguments"
        )
    payload = {
        "accessToken": access_token,
        "selectedProfile": uuid.replace("-", ""),
        "serverId": server_id,
    }
    async with acquire_client(http_client) as c:
        response = await c.post(
            SESSIONSERVER_JOIN_URL,
            json=payload,
            headers={"Accept": "application/json"},
        )
    if response.status_code == 204:
        return
    raise JoinServerError(
        f"sessionserver joinServer rejected request: status={response.status_code}",
        status_code=response.status_code,
        body=response.text,
    )


async def join_server_with_session(
    session: MinecraftSession,
    *,
    server_id_str: str,
    shared_secret: bytes,
    public_key_der: bytes,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """High-level convenience: compute the server-ID hash + post joinServer.

    Use this when you have a :class:`MinecraftSession` and the raw
    inputs from the Minecraft Encryption Request packet
    (``server_id_str``, ``shared_secret``, ``public_key_der``). The hash
    is computed via :func:`compute_server_id_hash` and the resulting
    POST goes through :func:`join_server`.

    Equivalent to::

        hash = compute_server_id_hash(server_id_str, shared_secret, public_key_der)
        await join_server(session, server_id=hash, http_client=http_client)
    """
    hashed = compute_server_id_hash(server_id_str, shared_secret, public_key_der)
    await join_server(session, server_id=hashed, http_client=http_client)

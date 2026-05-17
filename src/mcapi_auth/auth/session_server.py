"""Mojang sessionserver ``joinServer`` call.

When a Minecraft client connects to an online-mode server, the server
hands it a SHA-1 "server ID hash" and the client must POST it to
``sessionserver.mojang.com/session/minecraft/join`` to prove account
ownership. The server then queries ``hasJoined`` to confirm.

Third-party services (axochat, custom auth gateways, etc.) reuse the
same dance, which is why this primitive belongs in an auth library.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from .._constants import SESSIONSERVER_JOIN_URL
from .._http import acquire_client
from ..exceptions import MinecraftAuthError

__all__ = ["JoinServerError", "join_server"]


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


async def join_server(
    *,
    access_token: str,
    uuid: str,
    server_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> None:
    """POST sessionserver/join. Returns ``None`` on 204, else raises.

    ``uuid`` may be dashed or undashed; we strip dashes for the wire
    format Mojang expects.
    """
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

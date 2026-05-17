"""Minecraft access-token (JWT) inspection.
The Minecraft ``access_token`` returned by ``login_with_xbox`` is a
JWS-signed JWT. Mojang's public key is not exposed, so signature
verification isn't useful for us — but the payload claims are still
trustworthy as *self-reported* metadata: every token we hold was issued
by Mojang directly to us, so reading its ``exp`` and embedded profile
saves a round-trip to ``/minecraft/profile``.

This module is leaf-pure: no network, no I/O, no third-party deps. The
JWT is decoded manually (base64url + JSON) so :mod:`mcapi_auth` stays a
single-runtime-dep package.
"""


import base64
import binascii
import json
from typing import Any, cast

from whenever import Instant

from .._models import InstantField, McModel
from ..exceptions import McAuthError

__all__ = ["MinecraftTokenInfo", "decode_minecraft_access_token"]


class MinecraftTokenInfo(McModel):
    """Self-reported metadata extracted from a Minecraft access token.

    Every field is best-effort: Mojang has been known to change the
    claim shape, and we don't fail on a missing claim. Callers that
    *require* a value should check for ``None`` before using it.
    """

    expires_at: InstantField | None
    issued_at: InstantField | None
    username: str | None
    uuid: str | None
    raw_claims: dict[str, Any]


class MinecraftTokenDecodeError(McAuthError):
    """The Minecraft access token did not decode as a JWS-style JWT."""


def decode_minecraft_access_token(token: str) -> MinecraftTokenInfo:
    """Decode a Minecraft JWT without verifying its signature.

    Raises :class:`MinecraftTokenDecodeError` if ``token`` is not a
    plausibly-shaped JWS (three base64url segments with a JSON object
    payload).
    """
    if not isinstance(token, str) or not token:  # pyright: ignore[reportUnnecessaryIsInstance]
        raise MinecraftTokenDecodeError("token must be a non-empty string")
    parts = token.split(".")
    if len(parts) != 3:
        raise MinecraftTokenDecodeError(
            f"token does not have three '.'-separated segments (got {len(parts)})"
        )
    payload_segment = parts[1]
    try:
        padded = payload_segment + "=" * (-len(payload_segment) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as e:  # NOSONAR intentional: documents distinct error sources
        raise MinecraftTokenDecodeError(f"payload is not valid base64url: {e}") from e
    try:
        parsed: object = json.loads(decoded_bytes)
    except json.JSONDecodeError as e:
        raise MinecraftTokenDecodeError(f"payload is not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise MinecraftTokenDecodeError(f"payload is JSON {type(parsed).__name__}, expected object")
    claims = cast(dict[str, Any], parsed)
    exp = claims.get("exp")
    nbf = claims.get("nbf")
    username, uuid_no_dashes = _extract_profile(claims)
    return MinecraftTokenInfo(
        expires_at=Instant.from_timestamp(float(exp)) if isinstance(exp, int | float) else None,
        issued_at=Instant.from_timestamp(float(nbf)) if isinstance(nbf, int | float) else None,
        username=username,
        uuid=uuid_no_dashes,
        raw_claims=claims,
    )


def _extract_profile(claims: dict[str, Any]) -> tuple[str | None, str | None]:  # NOSONAR linear JWT-claims fallback chain
    """Find ``(username, uuid)`` in the MC JWT, or ``(None, None)`` if absent.

    Mojang carries the profile two ways:

    * Newer tokens: ``pfd`` is a list of ``{type, name, id}`` entries;
      pick the one with ``type == "mc"``.
    * Older tokens: ``profiles.mc`` is the UUID; no name attached.
    """
    pfd = claims.get("pfd")
    if isinstance(pfd, list):
        pfd_list = cast(list[object], pfd)
        for entry in pfd_list:
            if not isinstance(entry, dict):
                continue
            entry_typed = cast(dict[str, Any], entry)
            if entry_typed.get("type") != "mc":
                continue
            name = entry_typed.get("name")
            uid = entry_typed.get("id")
            return (
                name if isinstance(name, str) and name else None,
                uid.replace("-", "") if isinstance(uid, str) and uid else None,
            )
    profiles = claims.get("profiles")
    if isinstance(profiles, dict):
        profiles_typed = cast(dict[str, Any], profiles)
        mc_uid = profiles_typed.get("mc")
        if isinstance(mc_uid, str) and mc_uid:
            return None, mc_uid.replace("-", "")
    return None, None

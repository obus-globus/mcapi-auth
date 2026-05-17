"""Minecraft entitlements (``/entitlements/mcstore``).
Distinguishes "owns Minecraft: Java Edition" from "owns Bedrock only"
from "Game Pass". Mojang's ``/minecraft/profile`` 404s for any
account without Java, but it doesn't tell you *why* — entitlements
do.
"""


from typing import Any, cast

import httpx

from .._constants import MC_ENTITLEMENTS_URL
from .._http import acquire_client, parse_json_object_auth
from .._models import McModel
from ..exceptions import MinecraftAuthError

__all__ = ["Entitlements", "derive_entitlement_flags", "fetch_entitlements"]


# Item names that together imply "owns Minecraft: Java Edition". Both
# ``game_minecraft`` (the executable license) and ``product_minecraft``
# (the storefront product) are required — Bedrock-only accounts carry
# ``product_minecraft_bedrock`` instead.
_JAVA_ITEMS = frozenset({"game_minecraft", "product_minecraft"})
_BEDROCK_ITEMS = frozenset({"product_minecraft_bedrock"})
_GAME_PASS_ITEMS = frozenset({"product_game_pass_pc", "product_game_pass_ultimate"})


class Entitlements(McModel):
    """Decoded ``/entitlements/mcstore`` response.

    ``items`` is the raw list of item names returned by the server (in
    original order). The boolean flags are the most-common derivations
    — see :func:`derive_entitlement_flags` if you want to compute them
    from a raw item list yourself.
    """

    items: tuple[str, ...]
    has_java: bool
    has_bedrock: bool
    has_game_pass: bool


def derive_entitlement_flags(item_names: list[str] | tuple[str, ...]) -> dict[str, bool]:
    """Return ``{has_java, has_bedrock, has_game_pass}`` from a list of item names."""
    names = set(item_names)
    return {
        "has_java": _JAVA_ITEMS.issubset(names),
        "has_bedrock": bool(names & _BEDROCK_ITEMS),
        "has_game_pass": bool(names & _GAME_PASS_ITEMS),
    }


async def fetch_entitlements(
    access_token: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> Entitlements:
    """Fetch ``/entitlements/mcstore`` and parse it into :class:`Entitlements`.

    Raises :class:`MinecraftAuthError` on non-200 responses.
    """
    async with acquire_client(http_client) as c:
        response = await c.get(
            MC_ENTITLEMENTS_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
    if response.status_code != 200:
        raise MinecraftAuthError(f"entitlements fetch failed: status={response.status_code}")
    data = parse_json_object_auth(response)
    items_raw = data.get("items")
    if not isinstance(items_raw, list):
        raise MinecraftAuthError(
            f"entitlements response missing 'items' array: keys={sorted(data.keys())}"
        )
    items_list = cast(list[object], items_raw)
    names: list[str] = []
    for entry in items_list:
        if isinstance(entry, dict):
            entry_typed = cast(dict[str, Any], entry)
            name = entry_typed.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    flags = derive_entitlement_flags(names)
    return Entitlements(
        items=tuple(names),
        has_java=flags["has_java"],
        has_bedrock=flags["has_bedrock"],
        has_game_pass=flags["has_game_pass"],
    )

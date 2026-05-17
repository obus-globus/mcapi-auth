"""Tests for ``/entitlements/mcstore`` fetch + flag derivation."""

from __future__ import annotations

import pytest
import respx

from mcapi_auth._constants import MC_ENTITLEMENTS_URL
from mcapi_auth.auth.entitlements import derive_entitlement_flags, fetch_entitlements
from mcapi_auth.exceptions import MinecraftAuthError


def test_derive_flags_java_only() -> None:
    flags = derive_entitlement_flags(["game_minecraft", "product_minecraft"])
    assert flags == {"has_java": True, "has_bedrock": False, "has_game_pass": False}


def test_derive_flags_requires_both_java_items() -> None:
    # Only one of the two Java items present — not enough.
    flags = derive_entitlement_flags(["game_minecraft"])
    assert flags["has_java"] is False


def test_derive_flags_bedrock() -> None:
    flags = derive_entitlement_flags(["product_minecraft_bedrock"])
    assert flags == {"has_java": False, "has_bedrock": True, "has_game_pass": False}


def test_derive_flags_game_pass() -> None:
    flags = derive_entitlement_flags(["product_game_pass_ultimate"])
    assert flags["has_game_pass"] is True


def test_derive_flags_empty() -> None:
    flags = derive_entitlement_flags([])
    assert flags == {"has_java": False, "has_bedrock": False, "has_game_pass": False}


@respx.mock
async def test_fetch_entitlements_happy_path() -> None:
    respx.get(MC_ENTITLEMENTS_URL).respond(
        json={
            "items": [
                {"name": "game_minecraft", "signature": "sig1"},
                {"name": "product_minecraft", "signature": "sig2"},
            ],
            "signature": "outer",
            "keyId": "1",
        }
    )
    ent = await fetch_entitlements("mc-token")
    assert ent.items == ("game_minecraft", "product_minecraft")
    assert ent.has_java is True
    assert ent.has_bedrock is False
    assert ent.has_game_pass is False


@respx.mock
async def test_fetch_entitlements_ignores_non_dict_items() -> None:
    respx.get(MC_ENTITLEMENTS_URL).respond(
        json={"items": ["not-a-dict", {"name": "product_minecraft_bedrock"}, {"no_name_field": 1}]}
    )
    ent = await fetch_entitlements("mc-token")
    assert ent.items == ("product_minecraft_bedrock",)
    assert ent.has_bedrock is True


@respx.mock
async def test_fetch_entitlements_raises_on_401() -> None:
    respx.get(MC_ENTITLEMENTS_URL).respond(status_code=401, text="bad token")
    with pytest.raises(MinecraftAuthError, match="status=401"):
        _ = await fetch_entitlements("mc-token")


@respx.mock
async def test_fetch_entitlements_raises_on_missing_items() -> None:
    respx.get(MC_ENTITLEMENTS_URL).respond(json={"signature": "x"})
    with pytest.raises(MinecraftAuthError, match="items"):
        _ = await fetch_entitlements("mc-token")

"""Tests for the texture-property decoder."""

from __future__ import annotations

import base64
import json

import pytest

from mcapi_auth.api import (
    InvalidProfileError,
    ProfileProperty,
    PublicProfile,
    SkinModel,
    decode_texture_property,
    extract_textures,
)


def _encode(payload: dict[str, object]) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def test_decode_slim_skin_with_cape() -> None:
    raw = _encode(
        {
            "timestamp": 1607004245968,
            "profileId": "f1bfcbddc68b49bfaac9fb9d8ce5293d",
            "profileName": "alex",
            "textures": {
                "SKIN": {
                    "url": "http://textures.minecraft.net/texture/abc",
                    "metadata": {"model": "slim"},
                },
                "CAPE": {"url": "http://textures.minecraft.net/texture/cape123"},
            },
        }
    )
    t = decode_texture_property(raw)
    assert t.profile_name == "alex"
    assert t.timestamp_ms == 1607004245968
    assert t.skin is not None
    assert t.skin.model is SkinModel.SLIM
    assert t.skin.url.endswith("/abc")
    assert t.cape is not None
    assert t.cape.url.endswith("/cape123")


def test_decode_classic_default_when_metadata_missing() -> None:
    raw = _encode(
        {
            "profileId": "x",
            "profileName": "y",
            "textures": {"SKIN": {"url": "http://textures.minecraft.net/texture/x"}},
        }
    )
    t = decode_texture_property(raw)
    assert t.skin is not None
    assert t.skin.model is SkinModel.CLASSIC


def test_decode_no_textures_at_all() -> None:
    raw = _encode({"profileId": "x", "profileName": "y", "textures": {}})
    t = decode_texture_property(raw)
    assert t.skin is None
    assert t.cape is None
    assert not t.has_skin
    assert not t.has_cape


def test_decode_invalid_base64_raises_invalid_profile() -> None:
    with pytest.raises(InvalidProfileError):
        _ = decode_texture_property("not!base64@@@")


def test_decode_invalid_json_raises_invalid_profile() -> None:
    bad = base64.b64encode(b"not json").decode("ascii")
    with pytest.raises(InvalidProfileError):
        _ = decode_texture_property(bad)


def test_decode_top_level_not_object_raises() -> None:
    bad = base64.b64encode(b"[1, 2, 3]").decode("ascii")
    with pytest.raises(InvalidProfileError):
        _ = decode_texture_property(bad)


def test_decode_unknown_model_raises() -> None:
    raw = _encode(
        {
            "profileId": "x",
            "profileName": "y",
            "textures": {"SKIN": {"url": "http://t/x", "metadata": {"model": "alien"}}},
        }
    )
    with pytest.raises(InvalidProfileError):
        _ = decode_texture_property(raw)


def test_extract_textures_returns_none_when_no_textures_property() -> None:
    profile = PublicProfile(uuid="a" * 32, name="n", properties=())
    assert extract_textures(profile) is None


def test_extract_textures_decodes_when_present() -> None:
    value = _encode(
        {
            "profileId": "x",
            "profileName": "y",
            "textures": {"SKIN": {"url": "http://t/x", "metadata": {"model": "classic"}}},
        }
    )
    profile = PublicProfile(
        uuid="a" * 32,
        name="n",
        properties=(ProfileProperty(name="textures", value=value),),
    )
    t = extract_textures(profile)
    assert t is not None
    assert t.skin is not None
    assert t.skin.model is SkinModel.CLASSIC


def test_skin_model_from_raw_handles_empty_string_as_classic() -> None:
    assert SkinModel.from_raw(None) is SkinModel.CLASSIC
    assert SkinModel.from_raw("") is SkinModel.CLASSIC
    assert SkinModel.from_raw("slim") is SkinModel.SLIM
    assert SkinModel.from_raw("classic") is SkinModel.CLASSIC

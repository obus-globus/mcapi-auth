"""Decode the base64-encoded ``textures`` property attached to public profiles.

The session-server ``properties[textures].value`` is a base64 string. Decoded,
it's a small JSON document::

    {
        "timestamp": 1607004245968,
        "profileId": "f1bfcbddc68b49bfaac9fb9d8ce5293d",
        "profileName": "123lmfao4",
        "textures": {
            "SKIN": {"url": "...", "metadata": {"model": "slim"}},
            "CAPE": {"url": "..."}
        }
    }

This module turns that into typed Pydantic models. Skin URLs are HTTP (not
HTTPS) because that's how Mojang serves them — callers who want HTTPS can
rewrite the scheme themselves; the texture host (``textures.minecraft.net``)
does support TLS.
"""

from __future__ import annotations

import base64
import json
from enum import StrEnum
from typing import Any, ClassVar, cast

from pydantic import ValidationError, field_validator

from .._models import McModel
from ..exceptions import InvalidProfileError
from .profile import ProfileProperty, PublicProfile


class SkinModel(StrEnum):
    """The skin model used to render the texture.

    - ``CLASSIC`` is the wider "Steve" model (4-pixel arms).
    - ``SLIM`` is the narrower "Alex" model (3-pixel arms).
    """

    CLASSIC = "classic"
    SLIM = "slim"

    @classmethod
    def from_raw(cls, raw: str | None) -> SkinModel:
        """Default to CLASSIC when no metadata.model is set (matches Mojang)."""
        if raw is None or raw == "":
            return cls.CLASSIC
        try:
            return cls(raw.lower())
        except ValueError as e:
            raise InvalidProfileError(f"unknown skin model {raw!r}") from e


class _SkinMetadata(McModel):
    model: str | None = None


class _RawSkinEntry(McModel):
    url: str
    metadata: _SkinMetadata | None = None


class _RawCapeEntry(McModel):
    url: str


class _RawTextureBundle(McModel):
    __field_aliases__: ClassVar[dict[str, str]] = {"SKIN": "skin_entry", "CAPE": "cape_entry"}

    skin_entry: _RawSkinEntry | None = None
    cape_entry: _RawCapeEntry | None = None


class SkinTexture(McModel):
    url: str
    model: SkinModel = SkinModel.CLASSIC


class CapeTexture(McModel):
    url: str


class DecodedTextures(McModel):
    """Structured view of the texture-property payload."""

    __field_aliases__: ClassVar[dict[str, str]] = {
        "profileId": "profile_id",
        "profileName": "profile_name",
        "timestamp": "timestamp_ms",
    }

    profile_id: str = ""
    profile_name: str = ""
    timestamp_ms: int = 0
    skin: SkinTexture | None = None
    cape: CapeTexture | None = None

    @property
    def has_skin(self) -> bool:
        return self.skin is not None

    @property
    def has_cape(self) -> bool:
        return self.cape is not None

    @field_validator("timestamp_ms", mode="before")
    @classmethod
    def _coerce_timestamp(cls, v: Any) -> Any:
        if isinstance(v, bool):
            return 0
        if isinstance(v, (int, float)):
            return int(v)
        return v


def decode_texture_property(value: str) -> DecodedTextures:
    """Decode the base64 ``properties[textures].value`` string.

    Raises:
        InvalidProfileError: When the base64 / JSON / shape is wrong.
    """
    try:
        raw = base64.b64decode(value, validate=False)
        decoded: Any = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise InvalidProfileError(f"texture property is not valid base64+JSON: {e}") from e
    if not isinstance(decoded, dict):
        raise InvalidProfileError(
            f"texture property must decode to an object, got {type(decoded).__name__}"
        )

    decoded_obj = cast("dict[str, Any]", decoded)
    textures_raw: Any = decoded_obj.get("textures") or {}
    if not isinstance(textures_raw, dict):
        raise InvalidProfileError("texture property has a non-object 'textures' field")

    try:
        bundle = _RawTextureBundle.model_validate(textures_raw)
    except ValidationError as e:
        raise InvalidProfileError(f"texture bundle is malformed: {e}") from e

    skin: SkinTexture | None = None
    if bundle.skin_entry is not None:
        meta_model = bundle.skin_entry.metadata.model if bundle.skin_entry.metadata else None
        skin = SkinTexture(url=bundle.skin_entry.url, model=SkinModel.from_raw(meta_model))

    cape: CapeTexture | None = None
    if bundle.cape_entry is not None:
        cape = CapeTexture(url=bundle.cape_entry.url)

    try:
        return DecodedTextures.model_validate({**decoded_obj, "skin": skin, "cape": cape})
    except ValidationError as e:
        raise InvalidProfileError(f"texture property is malformed: {e}") from e


def extract_textures(profile: PublicProfile) -> DecodedTextures | None:
    """Convenience: decode the ``textures`` property on a :class:`PublicProfile`.

    Returns ``None`` if the profile has no textures property (which happens
    for hard-deleted accounts and a handful of edge cases).
    """
    prop: ProfileProperty | None = profile.textures_property
    if prop is None:
        return None
    return decode_texture_property(prop.value)

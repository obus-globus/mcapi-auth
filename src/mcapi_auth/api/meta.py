"""Piston-meta — the launcher/version manifest.
This is what the official launcher reads to know which Minecraft versions
exist and where to download each one's client jar, server jar, asset index,
library JARs, etc.

Entry point: :func:`fetch_version_manifest`. From a manifest you can:

- Iterate :attr:`VersionManifest.versions` (every release + snapshot ever)
- ``manifest.latest_release`` / ``manifest.latest_snapshot`` to find the
  current head versions
- ``manifest.find("1.21.4")`` to pull a single :class:`VersionEntry` by id
- ``await version_entry.fetch_details()`` to expand into a full
  :class:`VersionDetails` with downloads / asset index URLs

We deliberately do NOT model every field of the per-version JSON (there are
dozens of fields the launcher itself only conditionally inspects); instead
:class:`VersionDetails` exposes the ones almost everyone needs (client jar,
server jar, asset-index URL) and keeps the raw dict around as ``.raw`` for
anything else.
"""

from typing import Any, ClassVar

import httpx
from pydantic import Field, ValidationError, model_validator

from .._constants import VERSION_MANIFEST_V2_URL
from .._http import acquire_client, parse_json_object, validate_response
from .._models import InstantField, McModel
from ..exceptions import HttpError, NotFoundError


class DownloadEntry(McModel):
    """A single file the launcher might download for a version."""

    url: str
    sha1: str
    size: int


class VersionDetails(McModel):
    """Expanded per-version JSON.

    Fields beyond the small "everyone uses these" set are accessible via
    :attr:`raw` — that's the parsed JSON dict as Mojang serves it.
    """

    __field_aliases__: ClassVar[dict[str, str]] = {
        "releaseTime": "release_time",
        "mainClass": "main_class",
    }

    id: str
    type: str
    release_time: InstantField
    asset_index_id: str = ""
    asset_index_url: str = ""
    main_class: str | None = None
    client_jar: DownloadEntry | None = None
    server_jar: DownloadEntry | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _project_nested(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        src: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        out: dict[str, Any] = dict(src)
        asset_index = src.get("assetIndex")
        if isinstance(asset_index, dict):
            ai: dict[str, Any] = asset_index  # type: ignore[assignment]
            out.setdefault("asset_index_id", ai.get("id", ""))
            out.setdefault("asset_index_url", ai.get("url", ""))
        downloads = src.get("downloads")
        if isinstance(downloads, dict):
            dl: dict[str, Any] = downloads  # type: ignore[assignment]
            for key, target in (("client", "client_jar"), ("server", "server_jar")):
                entry = dl.get(key)
                if not isinstance(entry, dict):
                    continue
                try:
                    DownloadEntry.model_validate(entry)
                except ValidationError:
                    # Mojang occasionally publishes partial download entries
                    # (missing sha1 / size). Drop them silently rather than
                    # failing the whole VersionDetails parse.
                    continue
                out.setdefault(target, entry)
        out.setdefault("raw", src)
        return out


class VersionEntry(McModel):
    """One row from the version manifest.

    Call :meth:`fetch_details` to retrieve the full per-version JSON.
    """

    __field_aliases__: ClassVar[dict[str, str]] = {
        "releaseTime": "release_time",
        "complianceLevel": "compliance_level",
    }

    id: str
    type: str
    url: str
    release_time: InstantField
    time: InstantField
    sha1: str
    compliance_level: int = 0

    async def fetch_details(
        self, *, http_client: httpx.AsyncClient | None = None
    ) -> VersionDetails:
        async with acquire_client(http_client) as client:
            r = await client.get(self.url)
        if r.status_code != 200:
            raise HttpError(r.status_code, r.text, url=str(r.request.url))
        return validate_response(r, VersionDetails)


class VersionManifest(McModel):
    """The full piston-meta v2 manifest."""

    latest_release: str = ""
    latest_snapshot: str = ""
    versions: tuple[VersionEntry, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def _project_latest(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        src: dict[str, Any] = dict(data)  # type: ignore[arg-type]
        out: dict[str, Any] = dict(src)
        latest = src.get("latest")
        if isinstance(latest, dict):
            lt: dict[str, Any] = latest  # type: ignore[assignment]
            out.setdefault("latest_release", lt.get("release", ""))
            out.setdefault("latest_snapshot", lt.get("snapshot", ""))
        raw_versions = src.get("versions")
        if isinstance(raw_versions, list):
            good: list[Any] = []
            for entry in raw_versions:  # type: ignore[assignment]
                try:
                    VersionEntry.model_validate(entry)
                except ValidationError:
                    # Drop malformed entries silently to keep parity with the
                    # pre-Pydantic implementation; Mojang occasionally publishes
                    # partial rows.
                    continue
                good.append(entry)
            out["versions"] = good
        return out

    def find(self, version_id: str) -> VersionEntry:
        """Look up a version by id (e.g. ``"1.21.4"``).

        Raises :class:`NotFoundError` if the manifest doesn't list it.
        """
        for v in self.versions:
            if v.id == version_id:
                return v
        raise NotFoundError(f"version {version_id!r} not found in manifest")


async def fetch_version_manifest(
    *, http_client: httpx.AsyncClient | None = None
) -> VersionManifest:
    """Download and parse the v2 version manifest."""
    async with acquire_client(http_client) as client:
        r = await client.get(VERSION_MANIFEST_V2_URL)
    if r.status_code != 200:
        raise HttpError(r.status_code, r.text, url=str(r.request.url))
    return validate_response(r, VersionManifest)


__all__ = [
    "DownloadEntry",
    "VersionDetails",
    "VersionEntry",
    "VersionManifest",
    "fetch_version_manifest",
]


# parse_json_object is re-imported for backwards-compat with tests if any.
_ = parse_json_object

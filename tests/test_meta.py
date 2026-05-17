"""Tests for piston-meta version manifest + per-version JSON parsing."""

import pytest
import respx

from mcapi_auth._constants import VERSION_MANIFEST_V2_URL
from mcapi_auth.api import (
    HttpError,
    NotFoundError,
    fetch_version_manifest,
)

_MANIFEST = {
    "latest": {"release": "1.21.4", "snapshot": "25w01a"},
    "versions": [
        {
            "id": "1.21.4",
            "type": "release",
            "url": "https://piston-meta.mojang.com/v1/packages/abc/1.21.4.json",
            "time": "2024-12-03T08:00:00+00:00",
            "releaseTime": "2024-12-03T08:00:00+00:00",
            "sha1": "abc",
            "complianceLevel": 1,
        },
        {
            "id": "25w01a",
            "type": "snapshot",
            "url": "https://piston-meta.mojang.com/v1/packages/def/25w01a.json",
            "time": "2025-01-02T10:00:00+00:00",
            "releaseTime": "2025-01-02T10:00:00+00:00",
            "sha1": "def",
            "complianceLevel": 1,
        },
        {"id": "broken"},  # missing url; should be dropped silently
    ],
}

_VERSION_JSON = {
    "id": "1.21.4",
    "type": "release",
    "mainClass": "net.minecraft.client.main.Main",
    "releaseTime": "2024-12-03T08:00:00+00:00",
    "assetIndex": {
        "id": "21",
        "url": "https://piston-meta.mojang.com/v1/packages/idx/21.json",
        "sha1": "deadbeef",
        "size": 2048,
        "totalSize": 100000,
    },
    "downloads": {
        "client": {
            "url": "https://piston-data.mojang.com/v1/objects/cli/client.jar",
            "sha1": "clientsha",
            "size": 25000000,
        },
        "server": {
            "url": "https://piston-data.mojang.com/v1/objects/srv/server.jar",
            "sha1": "serversha",
            "size": 50000000,
        },
    },
}


@respx.mock
async def test_fetch_version_manifest_parses_latest_and_versions() -> None:
    respx.get(VERSION_MANIFEST_V2_URL).respond(json=_MANIFEST)
    m = await fetch_version_manifest()
    assert m.latest_release == "1.21.4"
    assert m.latest_snapshot == "25w01a"
    assert {v.id for v in m.versions} == {"1.21.4", "25w01a"}  # "broken" is dropped


@respx.mock
async def test_manifest_find_returns_entry() -> None:
    respx.get(VERSION_MANIFEST_V2_URL).respond(json=_MANIFEST)
    m = await fetch_version_manifest()
    entry = m.find("1.21.4")
    assert entry.type == "release"
    assert entry.url.endswith("/1.21.4.json")


@respx.mock
async def test_manifest_find_raises_not_found_for_unknown() -> None:
    respx.get(VERSION_MANIFEST_V2_URL).respond(json=_MANIFEST)
    m = await fetch_version_manifest()
    with pytest.raises(NotFoundError):
        _ = m.find("not.a.real.version")


@respx.mock
async def test_version_entry_fetch_details() -> None:
    respx.get(VERSION_MANIFEST_V2_URL).respond(json=_MANIFEST)
    m = await fetch_version_manifest()
    entry = m.find("1.21.4")
    respx.get(entry.url).respond(json=_VERSION_JSON)
    details = await entry.fetch_details()
    assert details.main_class == "net.minecraft.client.main.Main"
    assert details.client_jar is not None
    assert details.client_jar.size == 25000000
    assert details.server_jar is not None
    assert details.asset_index_id == "21"
    # raw retains everything
    assert details.raw["assetIndex"]["totalSize"] == 100000


@respx.mock
async def test_fetch_version_manifest_5xx_raises_http_error() -> None:
    respx.get(VERSION_MANIFEST_V2_URL).respond(status_code=503, text="down")
    with pytest.raises(HttpError) as info:
        _ = await fetch_version_manifest()
    assert info.value.status_code == 503


@respx.mock
async def test_version_details_omits_unknown_downloads() -> None:
    incomplete = dict(_VERSION_JSON)
    incomplete["downloads"] = {"client": {"url": "x"}}  # missing sha1/size
    respx.get(VERSION_MANIFEST_V2_URL).respond(json=_MANIFEST)
    m = await fetch_version_manifest()
    entry = m.find("1.21.4")
    respx.get(entry.url).respond(json=incomplete)
    details = await entry.fetch_details()
    assert details.client_jar is None
    assert details.server_jar is None

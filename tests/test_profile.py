"""Tests for the public profile / UUID endpoints."""

from __future__ import annotations

import httpx
import pytest
import respx

from mcapi_auth._constants import (
    BULK_USERNAME_TO_UUID_URL,
    USERNAME_TO_UUID_URL,
    UUID_TO_PROFILE_URL,
)
from mcapi_auth.api import (
    BadRequestError,
    NotFoundError,
    RateLimitedError,
    TooManyNamesError,
    get_profile_by_uuid,
    get_uuid_by_name,
    get_uuids_by_names,
)


@respx.mock
async def test_get_uuid_by_name_happy_path() -> None:
    respx.get(f"{USERNAME_TO_UUID_URL}/Notch").respond(
        json={"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"}
    )
    r = await get_uuid_by_name("Notch")
    assert r.uuid == "069a79f444e94726a5befca90e38aaf5"
    assert r.name == "Notch"


@respx.mock
async def test_get_uuid_by_name_404_raises_not_found() -> None:
    respx.get(f"{USERNAME_TO_UUID_URL}/nobodyhasthisname").respond(status_code=404)
    with pytest.raises(NotFoundError):
        _ = await get_uuid_by_name("nobodyhasthisname")


@respx.mock
async def test_get_uuid_by_name_204_also_raises_not_found() -> None:
    respx.get(f"{USERNAME_TO_UUID_URL}/x").respond(status_code=204)
    with pytest.raises(NotFoundError):
        _ = await get_uuid_by_name("x")


@respx.mock
async def test_get_uuid_by_name_400_raises_bad_request() -> None:
    respx.get(f"{USERNAME_TO_UUID_URL}/!").respond(status_code=400, json={"error": "x"})
    with pytest.raises(BadRequestError):
        _ = await get_uuid_by_name("!")


@respx.mock
async def test_get_uuid_by_name_429_surfaces_retry_after() -> None:
    respx.get(f"{USERNAME_TO_UUID_URL}/Notch").respond(
        status_code=429, headers={"Retry-After": "42"}
    )
    with pytest.raises(RateLimitedError) as info:
        _ = await get_uuid_by_name("Notch")
    assert info.value.retry_after == 42.0


@respx.mock
async def test_bulk_lookup_happy_path() -> None:
    respx.post(BULK_USERNAME_TO_UUID_URL).respond(
        json=[
            {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "A"},
            {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "B"},
        ]
    )
    results = await get_uuids_by_names(["A", "B"])
    assert [r.name for r in results] == ["A", "B"]


async def test_bulk_lookup_rejects_more_than_10_names() -> None:
    with pytest.raises(TooManyNamesError):
        _ = await get_uuids_by_names([f"n{i}" for i in range(11)])


async def test_bulk_lookup_empty_is_noop() -> None:
    assert await get_uuids_by_names([]) == []


@respx.mock
async def test_bulk_lookup_drops_malformed_entries() -> None:
    respx.post(BULK_USERNAME_TO_UUID_URL).respond(
        json=[
            {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "A"},
            {"missing": "name"},
            "not even an object",
        ]
    )
    results = await get_uuids_by_names(["A", "B"])
    assert len(results) == 1
    assert results[0].name == "A"


@respx.mock
async def test_get_profile_by_uuid_happy_path() -> None:
    respx.get(f"{UUID_TO_PROFILE_URL}/069a79f444e94726a5befca90e38aaf5").respond(
        json={
            "id": "069a79f444e94726a5befca90e38aaf5",
            "name": "Notch",
            "properties": [{"name": "textures", "value": "abc=="}],
        }
    )
    p = await get_profile_by_uuid("069a79f4-44e9-4726-a5be-fca90e38aaf5")
    assert p.name == "Notch"
    assert p.uuid == "069a79f444e94726a5befca90e38aaf5"
    assert len(p.properties) == 1
    assert p.properties[0].name == "textures"
    assert p.properties[0].signature is None


@respx.mock
async def test_get_profile_by_uuid_signed_adds_query() -> None:
    route = respx.get(f"{UUID_TO_PROFILE_URL}/069a79f444e94726a5befca90e38aaf5").respond(
        json={
            "id": "069a79f444e94726a5befca90e38aaf5",
            "name": "Notch",
            "properties": [{"name": "textures", "value": "v", "signature": "s"}],
        }
    )
    p = await get_profile_by_uuid("069a79f444e94726a5befca90e38aaf5", signed=True)
    assert p.properties[0].signature == "s"
    sent_url: httpx.URL = route.calls.last.request.url
    assert sent_url.params.get("unsigned") == "false"


@respx.mock
async def test_get_profile_by_uuid_204_raises_not_found() -> None:
    respx.get(f"{UUID_TO_PROFILE_URL}/{'0' * 32}").respond(status_code=204)
    with pytest.raises(NotFoundError):
        _ = await get_profile_by_uuid("0" * 32)


@respx.mock
async def test_get_profile_by_uuid_marks_legacy() -> None:
    respx.get(f"{UUID_TO_PROFILE_URL}/{'a' * 32}").respond(
        json={"id": "a" * 32, "name": "Legacy", "properties": [], "legacy": True}
    )
    p = await get_profile_by_uuid("a" * 32)
    assert p.legacy is True

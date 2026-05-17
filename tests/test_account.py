"""Tests for authenticated profile/skin/cape/name endpoints."""

from dataclasses import dataclass

import pytest
import respx
from whenever import Instant

from mcapi_auth._constants import (
    PROFILE_CAPES_ACTIVE_URL,
    PROFILE_NAME_BASE_URL,
    PROFILE_NAMECHANGE_URL,
    PROFILE_SKINS_ACTIVE_URL,
    PROFILE_SKINS_URL,
    PROFILE_URL,
)
from mcapi_auth.api import (
    BadRequestError,
    ForbiddenError,
    NameAvailability,
    NameNotAllowedError,
    NameTakenError,
    NotFoundError,
    RateLimitedError,
    SkinVariant,
    UnauthorizedError,
    change_cape,
    change_name,
    change_skin_from_file,
    change_skin_from_url,
    check_name_availability,
    coerce_token,
    disable_cape,
    get_name_change_eligibility,
    get_own_profile,
    reset_skin,
)

OWN_PROFILE_BODY = {
    "id": "cdb5aee80f904fdda63ba16d38cd6b3b",
    "name": "lukethehacker23",
    "skins": [
        {
            "id": "7800ee13-f75d-40e5-a5b2-9197c3e0125a",
            "state": "ACTIVE",
            "url": "http://textures.minecraft.net/texture/abc",
            "variant": "SLIM",
            "alias": "ALEX",
        }
    ],
    "capes": [
        {
            "id": "2d4de64a-da1b-4196-8e37-20740f6941ad",
            "state": "INACTIVE",
            "url": "http://textures.minecraft.net/texture/cape",
            "alias": "Minecon2012",
        }
    ],
}


@dataclass
class _FakeSession:
    """Minimal duck-type of mcauth.MinecraftSession."""

    access_token: str


def test_coerce_token_accepts_string() -> None:
    assert coerce_token("raw-token") == "raw-token"


def test_coerce_token_accepts_session_like() -> None:
    sess = _FakeSession(access_token="from-session")
    assert coerce_token(sess) == "from-session"


def test_coerce_token_rejects_other_types() -> None:
    with pytest.raises(TypeError):
        _ = coerce_token(12345)  # type: ignore[arg-type]


@respx.mock
async def test_get_own_profile_happy_path() -> None:
    respx.get(PROFILE_URL).respond(json=OWN_PROFILE_BODY)
    p = await get_own_profile("tok")
    assert p.uuid == "cdb5aee80f904fdda63ba16d38cd6b3b"
    assert p.name == "lukethehacker23"
    assert p.active_skin is not None
    assert p.active_skin.variant is SkinVariant.SLIM
    assert p.active_cape is None  # only cape is INACTIVE


@respx.mock
async def test_get_own_profile_accepts_session_object() -> None:
    respx.get(PROFILE_URL).respond(json=OWN_PROFILE_BODY)
    sess = _FakeSession(access_token="tok")
    p = await get_own_profile(sess)
    assert p.name == "lukethehacker23"


@respx.mock
async def test_get_own_profile_401_raises_unauthorized() -> None:
    respx.get(PROFILE_URL).respond(
        status_code=401, json={"error": "UnauthorizedOperationException"}
    )
    with pytest.raises(UnauthorizedError):
        _ = await get_own_profile("bad")


@respx.mock
async def test_get_own_profile_404_raises_not_found() -> None:
    respx.get(PROFILE_URL).respond(status_code=404)
    with pytest.raises(NotFoundError):
        _ = await get_own_profile("tok")


@respx.mock
async def test_get_own_profile_429_with_retry_after() -> None:
    respx.get(PROFILE_URL).respond(status_code=429, headers={"Retry-After": "10"})
    with pytest.raises(RateLimitedError) as info:
        _ = await get_own_profile("tok")
    assert info.value.retry_after == 10.0


@respx.mock
async def test_check_name_availability_available() -> None:
    respx.get(f"{PROFILE_NAME_BASE_URL}/Bob/available").respond(json={"status": "AVAILABLE"})
    r = await check_name_availability("tok", "Bob")
    assert r is NameAvailability.AVAILABLE


@respx.mock
async def test_check_name_availability_duplicate() -> None:
    respx.get(f"{PROFILE_NAME_BASE_URL}/Notch/available").respond(json={"status": "DUPLICATE"})
    r = await check_name_availability("tok", "Notch")
    assert r is NameAvailability.DUPLICATE


@respx.mock
async def test_check_name_availability_not_allowed() -> None:
    respx.get(f"{PROFILE_NAME_BASE_URL}/badword/available").respond(json={"status": "NOT_ALLOWED"})
    r = await check_name_availability("tok", "badword")
    assert r is NameAvailability.NOT_ALLOWED


@respx.mock
async def test_get_name_change_eligibility_parses_dates() -> None:
    respx.get(PROFILE_NAMECHANGE_URL).respond(
        json={
            "changedAt": "2020-12-02T03:11:01Z",
            "createdAt": "2019-03-02T05:44:42Z",
            "nameChangeAllowed": False,
        }
    )
    e = await get_name_change_eligibility("tok")
    assert e.name_change_allowed is False
    assert e.changed_at == Instant.parse_iso("2020-12-02T03:11:01Z")
    assert e.created_at == Instant.parse_iso("2019-03-02T05:44:42Z")


@respx.mock
async def test_get_name_change_eligibility_missing_changed_at() -> None:
    respx.get(PROFILE_NAMECHANGE_URL).respond(
        json={"createdAt": "2019-03-02T05:44:42Z", "nameChangeAllowed": True}
    )
    e = await get_name_change_eligibility("tok")
    assert e.name_change_allowed is True
    assert e.changed_at is None


@respx.mock
async def test_change_name_happy_path() -> None:
    respx.put(f"{PROFILE_NAME_BASE_URL}/NewName").respond(json=OWN_PROFILE_BODY)
    p = await change_name("tok", "NewName")
    assert p.uuid == OWN_PROFILE_BODY["id"]


@respx.mock
async def test_change_name_403_duplicate_raises_name_taken() -> None:
    respx.put(f"{PROFILE_NAME_BASE_URL}/Notch").respond(
        status_code=403,
        json={
            "path": "/minecraft/profile/name/Notch",
            "errorType": "FORBIDDEN",
            "details": {"status": "DUPLICATE"},
        },
    )
    with pytest.raises(NameTakenError):
        _ = await change_name("tok", "Notch")


@respx.mock
async def test_change_name_403_other_raises_forbidden() -> None:
    respx.put(f"{PROFILE_NAME_BASE_URL}/Whatever").respond(
        status_code=403, json={"errorType": "FORBIDDEN"}
    )
    with pytest.raises(ForbiddenError):
        _ = await change_name("tok", "Whatever")


@respx.mock
async def test_change_name_400_raises_name_not_allowed() -> None:
    respx.put(f"{PROFILE_NAME_BASE_URL}/1").respond(
        status_code=400, json={"errorType": "CONSTRAINT_VIOLATION"}
    )
    with pytest.raises(NameNotAllowedError):
        _ = await change_name("tok", "1")


@respx.mock
async def test_change_skin_from_url_sends_variant_and_url() -> None:
    route = respx.post(PROFILE_SKINS_URL).respond(json=OWN_PROFILE_BODY)
    _ = await change_skin_from_url("tok", "http://example/x.png", variant=SkinVariant.SLIM)
    assert route.called
    import json as _json

    body = _json.loads(route.calls.last.request.content)
    assert body == {"url": "http://example/x.png", "variant": "slim"}


@respx.mock
async def test_change_skin_from_url_400_raises_bad_request() -> None:
    respx.post(PROFILE_SKINS_URL).respond(status_code=400, text="bad")
    with pytest.raises(BadRequestError):
        _ = await change_skin_from_url("tok", "http://example/x.png")


@respx.mock
async def test_change_skin_from_file_sends_multipart() -> None:
    route = respx.post(PROFILE_SKINS_URL).respond(json=OWN_PROFILE_BODY)
    _ = await change_skin_from_file("tok", b"\x89PNGfakebytes", variant=SkinVariant.CLASSIC)
    assert route.called
    sent = route.calls.last.request.content
    # multipart body must contain our variant field and the file payload bytes.
    assert b"PNGfakebytes" in sent
    assert b'name="variant"' in sent
    assert b"classic" in sent


@respx.mock
async def test_reset_skin_returns_profile() -> None:
    respx.delete(PROFILE_SKINS_ACTIVE_URL).respond(json=OWN_PROFILE_BODY)
    p = await reset_skin("tok")
    assert p.name == "lukethehacker23"


@respx.mock
async def test_change_cape_sends_cape_id() -> None:
    route = respx.put(PROFILE_CAPES_ACTIVE_URL).respond(json=OWN_PROFILE_BODY)
    _ = await change_cape("tok", "2d4de64a-da1b-4196-8e37-20740f6941ad")
    import json as _json

    body = _json.loads(route.calls.last.request.content)
    assert body == {"capeId": "2d4de64a-da1b-4196-8e37-20740f6941ad"}


@respx.mock
async def test_change_cape_400_raises_bad_request() -> None:
    respx.put(PROFILE_CAPES_ACTIVE_URL).respond(status_code=400, text="nope")
    with pytest.raises(BadRequestError):
        _ = await change_cape("tok", "unknown-cape")


@respx.mock
async def test_disable_cape_returns_profile() -> None:
    respx.delete(PROFILE_CAPES_ACTIVE_URL).respond(json=OWN_PROFILE_BODY)
    p = await disable_cape("tok")
    assert p.active_cape is None

"""Tests for :class:`BedrockAuthManager`."""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from uuid import UUID, uuid4

import respx
from whenever import Instant

from mcapi_auth.api.bedrock import (
    BedrockKeyPair,
    MinecraftCertificateChain,
    MinecraftMultiplayerToken,
    MinecraftSession,
)
from mcapi_auth.api.playfab import PlayFabToken
from mcapi_auth.auth.bedrock_chain import (
    DEFAULT_BEDROCK_GAME_VERSION,
    BedrockAuthManager,
)
from mcapi_auth.auth.msa import MSATokens
from mcapi_auth.auth.xbox_device import XblDeviceKeyPair


def _b64url(obj: object) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_jwt(payload: dict[str, object]) -> str:
    header = _b64url({"alg": "ES384", "typ": "JWT"})
    body = _b64url(payload)
    return f"{header}.{body}.signature"


def _msa(*, refresh: str = "rf", access: str = "msa-access") -> MSATokens:
    return MSATokens(
        access_token=access,
        refresh_token=refresh,
        expires_at=Instant.now().add(seconds=3600),
    )


def _sisu_payload(*, userhash: str = "uhs-1", xsts_token: str = "xsts-1") -> dict[str, Any]:
    return {
        "UserToken": {
            "Token": "user-jwt",
            "NotAfter": "2030-01-01T00:00:00Z",
            "DisplayClaims": {"xui": [{"uhs": userhash}]},
        },
        "TitleToken": {
            "Token": "title-jwt",
            "NotAfter": "2030-01-01T00:00:00Z",
            "DisplayClaims": {"xti": {"tid": "title-1"}},
        },
        "AuthorizationToken": {
            "Token": xsts_token,
            "NotAfter": "2030-01-01T00:00:00Z",
            "DisplayClaims": {"xui": [{"uhs": userhash}]},
        },
    }


def _device_payload() -> dict[str, Any]:
    return {
        "Token": "device-jwt",
        "NotAfter": "2030-01-01T00:00:00Z",
        "DisplayClaims": {"xdi": {"did": "device-id-echoed"}},
    }


def _playfab_payload() -> dict[str, Any]:
    return {
        "code": 200,
        "status": "OK",
        "data": {
            "SessionTicket": "ticket-abc",
            "PlayFabId": "PF1234",
            "EntityToken": {
                "EntityToken": "entity-jwt",
                "TokenExpiration": "2030-01-01T00:00:00Z",
                "Entity": {"Id": "EID", "Type": "title_player_account"},
            },
        },
    }


def _cert_chain_payload() -> dict[str, Any]:
    exp = int(time.time()) + 86400
    mojang = _make_jwt({"exp": exp})
    identity = _make_jwt(
        {
            "exp": exp,
            "extraData": {
                "XUID": "2535400000000001",
                "displayName": "BedrockTester",
                "identity": "11111111-1111-1111-1111-111111111111",
            },
        }
    )
    return {"chain": [mojang, identity]}


def _franchise_session_payload() -> dict[str, Any]:
    return {
        "result": {
            "validUntil": "2030-01-01T00:00:00Z",
            "authorizationHeader": "Bearer session-jwt",
        }
    }


def _multiplayer_session_payload() -> dict[str, Any]:
    exp = int(time.time()) + 3600
    token = _make_jwt({"exp": exp, "xid": "2535400000000001", "xname": "BedrockTester"})
    return {"result": {"validUntil": "2030-01-01T00:00:00Z", "signedToken": token}}


def _mock_all_endpoints() -> dict[str, respx.Route]:
    """Wire respx mocks for every endpoint the manager hits."""
    return {
        "device": respx.post("https://device.auth.xboxlive.com/device/authenticate").respond(
            json=_device_payload()
        ),
        "sisu": respx.post("https://sisu.xboxlive.com/authorize").respond(json=_sisu_payload()),
        "playfab": respx.post("https://20ca2.playfabapi.com/Client/LoginWithXbox").respond(
            json=_playfab_payload()
        ),
        "cert": respx.post("https://multiplayer.minecraft.net/authentication").respond(
            json=_cert_chain_payload()
        ),
        "franchise": respx.post(
            "https://authorization.franchise.minecraft-services.net/api/v1.0/session/start"
        ).respond(json=_franchise_session_payload()),
        "multiplayer": respx.post(
            "https://authorization.franchise.minecraft-services.net/api/v1.0/multiplayer/session/start"
        ).respond(json=_multiplayer_session_payload()),
    }


def test_constructor_generates_persistent_identity_by_default() -> None:
    mgr = BedrockAuthManager(msa=_msa())
    assert isinstance(mgr.device_keypair, XblDeviceKeyPair)
    assert isinstance(mgr.bedrock_keypair, BedrockKeyPair)
    assert isinstance(mgr.device_id, UUID)
    assert mgr.game_version == DEFAULT_BEDROCK_GAME_VERSION


def test_constructor_accepts_supplied_identity() -> None:
    dkp = XblDeviceKeyPair.generate()
    bkp = BedrockKeyPair.generate()
    did = uuid4()
    mgr = BedrockAuthManager(
        msa=_msa(),
        device_keypair=dkp,
        device_id=did,
        bedrock_keypair=bkp,
        game_version="1.21.99",
    )
    assert mgr.device_keypair is dkp
    assert mgr.bedrock_keypair is bkp
    assert mgr.device_id == did
    assert mgr.game_version == "1.21.99"


@respx.mock
async def test_walks_full_chain_to_multiplayer_token() -> None:
    routes = _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())

    mp = await mgr.get_multiplayer_token()
    assert isinstance(mp, MinecraftMultiplayerToken)
    assert mp.display_name == "BedrockTester"

    # Multiplayer chain doesn't touch the Bedrock cert RP — only PlayFab.
    for name in ("device", "sisu", "playfab", "franchise", "multiplayer"):
        assert routes[name].called, f"{name} not called"
        assert routes[name].call_count == 1, f"{name} called {routes[name].call_count}x"
    assert not routes["cert"].called

    # cert_chain is only reached when explicitly requested.
    assert mgr.cert_chain_holder is None
    cert = await mgr.get_certificate_chain()
    assert isinstance(cert, MinecraftCertificateChain)
    assert routes["cert"].call_count == 1
    # Fetching the cert chain required the bedrock-scoped Sisu, so
    # /authorize was hit a second time (different RelyingParty than the
    # PlayFab leg, but same URL — respx counts both).
    assert routes["sisu"].call_count == 2


@respx.mock
async def test_cached_holders_are_not_refetched() -> None:
    routes = _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    _ = await mgr.get_multiplayer_token()
    # Calling again should hit nothing new for stages already cached.
    _ = await mgr.get_multiplayer_token()
    _ = await mgr.get_franchise_session()
    _ = await mgr.get_playfab_token()
    _ = await mgr.get_playfab_sisu()
    _ = await mgr.get_device_token()
    for name in ("device", "playfab", "franchise", "multiplayer"):
        assert routes[name].call_count == 1, f"{name} re-fetched ({routes[name].call_count}x)"
    # Sisu /authorize was hit once for playfab_sisu; bedrock_sisu was
    # never requested in this test, so still 1.
    assert routes["sisu"].call_count == 1


@respx.mock
async def test_dump_load_json_round_trip_preserves_identity_and_state() -> None:
    _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    _ = await mgr.get_multiplayer_token()
    cert = await mgr.get_certificate_chain()

    text = mgr.dump_json()
    parsed = json.loads(text)
    assert "device_keypair_pem" in parsed
    assert "bedrock_keypair_pem" in parsed
    assert parsed["multiplayer_token"] is not None
    assert parsed["cert_chain"] is not None

    restored = BedrockAuthManager.load_json(text)
    # Identity PEMs round-trip.
    assert restored.device_keypair.private_key_pem() == mgr.device_keypair.private_key_pem()
    assert restored.bedrock_keypair.private_key_pem() == mgr.bedrock_keypair.private_key_pem()
    assert restored.device_id == mgr.device_id
    # Cached tokens are restored.
    assert restored.multiplayer_holder is not None
    assert restored.cert_chain_holder is not None
    assert restored.cert_chain_holder.get_cached().xuid == cert.xuid


@respx.mock
async def test_dump_load_with_no_downstream_state() -> None:
    """An MSA-only manager round-trips with None downstream caches."""
    mgr = BedrockAuthManager(msa=_msa())
    text = mgr.dump_json()
    restored = BedrockAuthManager.load_json(text)
    assert restored.device_holder is None
    assert restored.bedrock_sisu_holder is None
    assert restored.multiplayer_holder is None
    assert restored.device_keypair.private_key_pem() == mgr.device_keypair.private_key_pem()


@respx.mock
async def test_msa_rotation_invalidates_downstream() -> None:
    routes = _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    _ = await mgr.get_multiplayer_token()
    # Manually force MSA rotation by replacing under the lock.
    new_msa = MSATokens(
        access_token="msa-access-2",
        refresh_token="rf2",
        expires_at=Instant.now().add(seconds=3600),
    )
    await mgr.msa_holder.replace(new_msa)
    # All downstream holders should have been dropped.
    assert mgr.bedrock_sisu_holder is None
    assert mgr.playfab_sisu_holder is None
    assert mgr.playfab_holder is None
    assert mgr.cert_chain_holder is None
    assert mgr.franchise_holder is None
    assert mgr.multiplayer_holder is None
    # Device token survives — keypair-bound, MSA-independent.
    assert mgr.device_holder is not None

    # Re-walking the chain re-hits sisu/playfab/franchise/multiplayer
    # but NOT device-auth.
    _ = await mgr.get_multiplayer_token()
    assert routes["device"].call_count == 1
    # playfab_sisu hit twice (once initially, once after MSA rotation).
    assert routes["sisu"].call_count == 2
    assert routes["franchise"].call_count == 2
    assert routes["multiplayer"].call_count == 2


@respx.mock
async def test_device_rotation_invalidates_sisu_legs() -> None:
    routes = _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    _ = await mgr.get_multiplayer_token()

    # Replace the device token directly.
    assert mgr.device_holder is not None
    old = mgr.device_holder.get_cached()
    await mgr.device_holder.replace(old.model_copy(update={"token": "new-device-jwt"}))

    assert mgr.bedrock_sisu_holder is None
    assert mgr.playfab_sisu_holder is None
    assert mgr.cert_chain_holder is None
    assert mgr.multiplayer_holder is None

    _ = await mgr.get_multiplayer_token()
    # device-auth was NOT re-hit (we replaced it manually); sisu was.
    assert routes["device"].call_count == 1
    assert routes["sisu"].call_count == 2


@respx.mock
async def test_change_listener_fires_per_stage() -> None:
    _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    seen: list[str] = []
    mgr.on_change(lambda stage, *_: seen.append(stage))

    _ = await mgr.get_multiplayer_token()

    # Order doesn't matter much, but every stage we touched should fire.
    # Multiplayer chain goes through playfab_sisu only (not bedrock_sisu).
    assert "device" in seen
    assert "playfab_sisu" in seen
    assert "playfab" in seen
    assert "franchise_session" in seen
    assert "multiplayer_token" in seen
    # MSA didn't rotate (we set it via the constructor); cert chain
    # wasn't fetched; bedrock_sisu only fires when cert is requested.
    assert "msa" not in seen
    assert "cert_chain" not in seen
    assert "bedrock_sisu" not in seen


@respx.mock
async def test_remove_listener() -> None:
    _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    seen: list[str] = []

    def listener(stage: str, *_: object) -> None:
        seen.append(stage)

    mgr.on_change(listener)
    assert mgr.remove_listener(listener) is True
    assert mgr.remove_listener(listener) is False

    _ = await mgr.get_multiplayer_token()
    assert seen == []


@respx.mock
async def test_listener_exception_does_not_abort_chain() -> None:
    _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())

    def bad(_stage: str, *_args: object) -> None:
        raise RuntimeError("listener boom")

    mgr.on_change(bad)
    # Should complete despite the listener raising on every stage.
    mp = await mgr.get_multiplayer_token()
    assert isinstance(mp, MinecraftMultiplayerToken)


@respx.mock
async def test_xsts_helpers_return_compatible_shape() -> None:
    _mock_all_endpoints()
    mgr = BedrockAuthManager(msa=_msa())
    xsts = await mgr.get_bedrock_xsts()
    assert xsts.token
    assert xsts.userhash
    # Same shape as XSTSToken for cross-compatibility with the existing
    # bedrock / playfab helpers.
    assert hasattr(xsts, "token") and hasattr(xsts, "userhash")


@respx.mock
async def test_from_msa_bridges_existing_token() -> None:
    _mock_all_endpoints()
    msa = _msa(access="bridged", refresh="bridged-rf")
    mgr = BedrockAuthManager.from_msa(msa)
    assert mgr.msa_holder.get_cached() is msa
    _ = await mgr.get_multiplayer_token()


@respx.mock
async def test_load_json_with_explicit_app() -> None:
    """``load_json`` accepts a caller-supplied app config."""
    from mcapi_auth.auth.app_config import MsaApplicationConfig

    mgr = BedrockAuthManager(msa=_msa())
    text = mgr.dump_json()

    app = MsaApplicationConfig.v2(client_id="0000000040159362")
    restored = BedrockAuthManager.load_json(text, app=app)
    assert restored.app is app


def test_persisted_pf_token_dumps_and_reloads_inline() -> None:
    """Pre-populated downstream caches survive a dump/load even without HTTP."""
    msa = _msa()
    dkp = XblDeviceKeyPair.generate()
    bkp = BedrockKeyPair.generate()
    pf = PlayFabToken.model_validate(
        {
            "entity_token": {
                "EntityToken": "entity-jwt",
                "TokenExpiration": "2030-01-01T00:00:00Z",
            },
            "play_fab_id": "PF1234",
            "session_ticket": "tk-1",
        }
    )
    mgr = BedrockAuthManager(
        msa=msa,
        device_keypair=dkp,
        bedrock_keypair=bkp,
        playfab_token=pf,
    )
    text = mgr.dump_json()
    restored = BedrockAuthManager.load_json(text)
    assert restored.playfab_holder is not None
    assert restored.playfab_holder.get_cached().session_ticket == "tk-1"


def test_session_franchise_session_alias_load() -> None:
    """``MinecraftSession`` model accepts wire-format alias for round-trip."""
    sess = MinecraftSession.model_validate(
        {
            "validUntil": "2030-01-01T00:00:00Z",
            "authorizationHeader": "Bearer x",
        }
    )
    mgr = BedrockAuthManager(msa=_msa(), franchise_session=sess)
    assert mgr.franchise_holder is not None
    text = mgr.dump_json()
    restored = BedrockAuthManager.load_json(text)
    assert restored.franchise_holder is not None
    assert restored.franchise_holder.get_cached().authorization_header == "Bearer x"

"""Tests for AccountManager — multi-account directory storage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import respx
from whenever import Instant

from mcapi_auth import (
    AccountManager,
    AccountManagerError,
    AuthChain,
    InvalidAccountLabelError,
    MinecraftSession,
    MsaApplicationConfig,
    UnknownAccountError,
)
from mcapi_auth._constants import (
    MC_LOGIN_WITH_XBOX_URL,
    MC_PROFILE_URL,
    MSA_TOKEN_URL,
    XBL_AUTH_URL,
    XSTS_AUTH_URL,
)


def _make_session() -> MinecraftSession:
    return MinecraftSession(
        access_token="mc-tok",
        refresh_token="msa-ref",
        uuid="069a79f444e94726a5befca90e38aaf5",
        username="Notch",
        msa_access_token="msa-acc",
        msa_access_token_expires_at=Instant.now().add(seconds=3600),
        minecraft_access_token_expires_at=Instant.now().add(seconds=86400),
    )


def test_path_for_validates_label(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    assert mgr.path_for("notch") == tmp_path / "notch.json"
    with pytest.raises(InvalidAccountLabelError):
        mgr.path_for("../etc/passwd")
    with pytest.raises(InvalidAccountLabelError):
        mgr.path_for("with/slash")
    with pytest.raises(InvalidAccountLabelError):
        mgr.path_for(".hidden")
    with pytest.raises(InvalidAccountLabelError):
        mgr.path_for("")


def test_list_labels_empty(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path / "nope")
    assert mgr.list_labels() == []


async def test_save_and_load_round_trip(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    chain = AuthChain.from_session(_make_session())
    await mgr.save("notch", chain)
    assert mgr.exists("notch")
    assert mgr.list_labels() == ["notch"]
    restored = await mgr.load("notch")
    assert restored.app.client_id == chain.app.client_id
    profile = await restored.get_profile()
    assert profile.username == "Notch"


async def test_save_uses_0600_permissions(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    chain = AuthChain.from_session(_make_session())
    await mgr.save("notch", chain)
    path = mgr.path_for("notch")
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


async def test_save_with_custom_app(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    custom_app = MsaApplicationConfig.v1_launcher()
    chain = AuthChain.from_session(_make_session(), app=custom_app)
    await mgr.save("notch", chain)
    restored = await mgr.load("notch")
    assert restored.app.client_id == custom_app.client_id
    assert restored.app.is_v1 is True
    assert restored.app.xbl_use_d_prefix is False


async def test_remove_deletes_file(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    await mgr.save("notch", AuthChain.from_session(_make_session()))
    assert mgr.exists("notch")
    await mgr.remove("notch")
    assert not mgr.exists("notch")


async def test_remove_missing_is_noop(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    await mgr.remove("not-there")  # must not raise


async def test_load_unknown_raises(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    with pytest.raises(UnknownAccountError):
        await mgr.load("ghost")


async def test_load_malformed_json_raises(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(AccountManagerError, match="not valid JSON"):
        await mgr.load("bad")


async def test_load_missing_fields_raises(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "bad.json").write_text(json.dumps({"label": "bad"}))
    with pytest.raises(AccountManagerError, match="missing required"):
        await mgr.load("bad")


async def test_list_labels_ignores_unrelated_files(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    await mgr.save("notch", AuthChain.from_session(_make_session()))
    (tmp_path / "readme.txt").write_text("hi")
    (tmp_path / ".hidden.json").write_text("{}")
    assert mgr.list_labels() == ["notch"]


async def test_load_all_skips_bad_files(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    await mgr.save("good", AuthChain.from_session(_make_session()))
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "broken.json").write_text("{not json")
    result = await mgr.load_all()
    assert "good" in result
    assert "broken" not in result


async def test_make_listener_for_persists_on_change(tmp_path: Path) -> None:
    mgr = AccountManager(tmp_path)
    chain = AuthChain.from_session(_make_session())
    listener = mgr.make_listener_for("notch", chain)
    # Fire the listener manually (simulating chain.on_change dispatch)
    await listener("msa", None, object())
    assert mgr.exists("notch")


@respx.mock
async def test_load_with_xbl_xsts_after_refresh(tmp_path: Path) -> None:
    """After driving the chain past XBL/XSTS, save/load round-trips them too."""
    respx.post(XBL_AUTH_URL).respond(
        json={"Token": "xbl-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(XSTS_AUTH_URL).respond(
        json={"Token": "xsts-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(
        json={"access_token": "fresh-mc-tok", "expires_in": 86400}
    )
    respx.get(MC_PROFILE_URL).respond(
        json={"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"}
    )
    respx.post(MSA_TOKEN_URL).respond(
        json={"access_token": "msa-acc", "refresh_token": "msa-ref", "expires_in": 3600}
    )

    chain = AuthChain.from_session(_make_session())
    _ = await chain.get_xbl_token()
    _ = await chain.get_xsts_token()

    mgr = AccountManager(tmp_path)
    await mgr.save("notch", chain)

    restored = await mgr.load("notch")
    # XBL/XSTS should now be cached — no extra HTTP call needed
    assert restored.xbl_holder is not None
    assert restored.xsts_holder is not None
    assert restored.xbl_holder.get_cached().token == "xbl-tok"
    assert restored.xsts_holder.get_cached().token == "xsts-tok"


def test_save_payload_contains_app_and_chain(tmp_path: Path) -> None:
    """White-box: verify the on-disk JSON has the documented shape."""
    import asyncio

    mgr = AccountManager(tmp_path)
    chain = AuthChain.from_session(_make_session())
    asyncio.run(mgr.save("notch", chain))
    data: Any = json.loads(mgr.path_for("notch").read_text())
    assert data["label"] == "notch"
    assert "app" in data
    assert data["app"]["client_id"] == chain.app.client_id
    assert "chain" in data
    assert "msa" in data["chain"]

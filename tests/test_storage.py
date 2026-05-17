"""Tests for FileTokenStorage."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mcapi_auth.auth.storage import FileTokenStorage, default_storage_path


async def test_load_returns_none_when_file_missing(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "missing.json")
    assert await storage.load() is None


async def test_save_then_load_roundtrips(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "refresh.json")
    await storage.save("rt-abc-123")
    assert await storage.load() == "rt-abc-123"


async def test_save_creates_parent_directory(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "nested" / "deep" / "refresh.json")
    await storage.save("rt-x")
    assert storage.path.exists()
    assert await storage.load() == "rt-x"


async def test_save_writes_with_0600_permissions(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "refresh.json")
    await storage.save("rt-perm")
    mode = stat.S_IMODE(storage.path.stat().st_mode)
    assert mode == 0o600


async def test_clear_removes_file(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "refresh.json")
    await storage.save("rt-clear")
    await storage.clear()
    assert not storage.path.exists()
    # idempotent
    await storage.clear()


async def test_load_returns_none_for_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "refresh.json"
    _ = path.write_text("not-json", encoding="utf-8")
    storage = FileTokenStorage(path)
    assert await storage.load() is None


async def test_load_returns_none_when_json_is_not_object(tmp_path: Path) -> None:
    path = tmp_path / "refresh.json"
    _ = path.write_text(json.dumps(["a", "b"]), encoding="utf-8")
    storage = FileTokenStorage(path)
    assert await storage.load() is None


async def test_load_returns_none_when_field_missing(tmp_path: Path) -> None:
    path = tmp_path / "refresh.json"
    _ = path.write_text(json.dumps({"other": "x"}), encoding="utf-8")
    storage = FileTokenStorage(path)
    assert await storage.load() is None


def test_default_storage_path_honors_xdg_state_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "/tmp/xdg")
    assert default_storage_path() == Path("/tmp/xdg/mcauth/refresh_token.json")


def test_default_storage_path_falls_back_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: Path("/tmp/fake-home"))
    assert default_storage_path() == Path("/tmp/fake-home/.local/state/mcauth/refresh_token.json")


async def test_save_replaces_existing_value(tmp_path: Path) -> None:
    storage = FileTokenStorage(tmp_path / "refresh.json")
    await storage.save("first")
    await storage.save("second")
    assert await storage.load() == "second"
    # No leftover .mcauth-*.tmp files in the parent
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".mcauth-")]
    assert leftovers == []
    _ = os  # quiet unused-import warning on platforms where os is unused


async def test_concurrent_saves_dont_corrupt_file(tmp_path: Path) -> None:
    """Multiple coroutines saving concurrently must leave the file in a valid state."""
    import asyncio as _asyncio

    storage = FileTokenStorage(tmp_path / "refresh.json")
    tokens = [f"token-{i}" for i in range(20)]
    await _asyncio.gather(*(storage.save(t) for t in tokens))
    final = await storage.load()
    assert final in tokens, "concurrent saves left the file in an unrecognized state"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".mcauth-")]
    assert leftovers == [], f"temp files leaked: {leftovers}"


async def test_load_returns_none_on_unreadable_file(tmp_path: Path) -> None:
    """Permission denied on the token file should be swallowed, not propagated."""
    path = tmp_path / "refresh.json"
    _ = path.write_text(json.dumps({"refresh_token": "rt-x"}), encoding="utf-8")
    _ = stat  # appease unused-import warning if running on systems without chmod
    os.chmod(path, 0o000)
    try:
        storage = FileTokenStorage(path)
        # If running as root, chmod is a no-op and load() will succeed — skip
        if os.geteuid() == 0:
            pytest.skip("running as root; chmod 0000 doesn't block reads")
        assert await storage.load() is None
    finally:
        os.chmod(path, 0o600)


@pytest.mark.parametrize(
    "payload", ['{"refresh_token": null}', '{"refresh_token": 12345}', '{"refresh_token": ""}']
)
async def test_load_returns_none_on_wrong_field_type(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "refresh.json"
    _ = path.write_text(payload, encoding="utf-8")
    storage = FileTokenStorage(path)
    assert await storage.load() is None

"""Multi-account chain manager — store + restore many :class:`AuthChain`\\ s.

For programs that need to juggle several Minecraft accounts (chat
bridges, multi-account servers, alt managers), :class:`AccountManager`
provides a directory-of-files store. Each account is one JSON file
holding the :class:`MsaApplicationConfig` *and* the chain snapshot from
:meth:`AuthChain.dump_json`, so restoring an account is a single call.

The on-disk layout::

    ~/.local/state/mcapi_auth/accounts/
        notch.json       # one file per account, mode 0600
        jeb_.json
        herobrine.json

Typical use::

    mgr = AccountManager()
    chain = await AuthChain.login(...)
    await mgr.save(chain.get_profile_cached().username, chain)

    # Next run:
    chain = await mgr.load("notch")
    mc = await chain.get_minecraft_token()

Wire ``chain.on_change`` so token rotations auto-persist::

    chain.on_change(mgr.make_listener("notch"))

Atomic writes (temp file + ``os.replace``) and ``0600`` permissions
match :class:`FileTokenStorage`. Labels must be filename-safe — only
``[A-Za-z0-9._-]`` is accepted, and labels starting with ``.`` are
rejected.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..exceptions import McAuthError
from .app_config import MsaApplicationConfig
from .chain import AuthChain
from .storage import default_storage_path

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import httpx

__all__ = [
    "AccountManager",
    "AccountManagerError",
    "InvalidAccountLabelError",
    "UnknownAccountError",
    "default_accounts_dir",
]

logger = logging.getLogger(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
_SAVE_VERSION = 1


class AccountManagerError(McAuthError):
    """Base error for :class:`AccountManager` failures."""


class InvalidAccountLabelError(AccountManagerError):
    """The given label is not a filename-safe slug."""


class UnknownAccountError(AccountManagerError):
    """There is no on-disk file for the given label."""


def default_accounts_dir() -> Path:
    """Return the XDG state directory used by :class:`AccountManager`."""
    return default_storage_path().parent / "accounts"


def _validate_label(label: str) -> None:
    if not isinstance(label, str) or not _LABEL_RE.match(label):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise InvalidAccountLabelError(
            f"invalid account label {label!r}: must match [A-Za-z0-9._-], "
            f"start with an alphanumeric or underscore, and be ≤64 chars"
        )


def _app_to_dict(app: MsaApplicationConfig) -> dict[str, Any]:
    return asdict(app)


def _app_from_dict(data: dict[str, Any]) -> MsaApplicationConfig:
    return MsaApplicationConfig(**data)


class AccountManager:
    """Directory-backed multi-account store for :class:`AuthChain`.

    Args:
        directory: Storage root. Defaults to
            :func:`default_accounts_dir` (``~/.local/state/mcapi_auth/accounts``).

    The directory is created lazily on first save.
    """

    def __init__(self, directory: Path | None = None) -> None:
        self._dir: Path = directory if directory is not None else default_accounts_dir()

    @property
    def directory(self) -> Path:
        """The on-disk directory holding one JSON file per account."""
        return self._dir

    def path_for(self, label: str) -> Path:
        """Return the on-disk path for ``label`` (does not check existence)."""
        _validate_label(label)
        return self._dir / f"{label}.json"

    def exists(self, label: str) -> bool:
        """``True`` if a file for ``label`` exists on disk."""
        return self.path_for(label).is_file()

    def list_labels(self) -> list[str]:
        """Return all on-disk account labels, sorted alphabetically.

        Files that don't match the label naming rules are ignored.
        """
        if not self._dir.is_dir():
            return []
        labels: list[str] = []
        for entry in self._dir.iterdir():
            if not entry.is_file() or entry.suffix != ".json":
                continue
            label = entry.stem
            if _LABEL_RE.match(label):
                labels.append(label)
        labels.sort()
        return labels

    async def save(self, label: str, chain: AuthChain) -> None:
        """Persist ``chain`` under ``label`` (overwrites any existing file)."""
        _validate_label(label)
        payload = {
            "save_version": _SAVE_VERSION,
            "label": label,
            "app": _app_to_dict(chain.app),
            "chain": json.loads(chain.dump_json()),
        }
        text = json.dumps(payload)
        await asyncio.to_thread(self._save_sync, label, text)

    def _save_sync(self, label: str, text: str) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        target = self._dir / f"{label}.json"
        fd, tmp_path = tempfile.mkstemp(prefix=".mcapi_auth-account-", suffix=".tmp", dir=self._dir)
        tmp = Path(tmp_path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                _ = f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    async def load(
        self,
        label: str,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> AuthChain:
        """Restore the chain previously saved under ``label``.

        Raises :class:`UnknownAccountError` if no file exists,
        :class:`AccountManagerError` if the file is malformed.
        """
        _validate_label(label)
        path = self._dir / f"{label}.json"
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except FileNotFoundError as e:
            raise UnknownAccountError(f"no saved account named {label!r} at {path}") from e
        try:
            parsed: object = json.loads(text)
        except json.JSONDecodeError as e:
            raise AccountManagerError(f"{path} is not valid JSON: {e}") from e
        if not isinstance(parsed, dict):
            raise AccountManagerError(f"{path} is not a JSON object")
        data = cast(dict[str, Any], parsed)
        app_dict = data.get("app")
        chain_dict = data.get("chain")
        if not isinstance(app_dict, dict) or not isinstance(chain_dict, dict):
            raise AccountManagerError(f"{path} is missing required 'app' / 'chain' fields")
        try:
            app = _app_from_dict(cast(dict[str, Any], app_dict))
        except TypeError as e:
            raise AccountManagerError(f"{path}: cannot rebuild MsaApplicationConfig: {e}") from e
        return AuthChain.load_json(
            json.dumps(chain_dict),
            app=app,
            http_client=http_client,
        )

    async def remove(self, label: str) -> None:
        """Delete the on-disk file for ``label``. No-op if absent."""
        _validate_label(label)
        path = self._dir / f"{label}.json"

        def _unlink() -> None:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

        await asyncio.to_thread(_unlink)

    async def load_all(
        self,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> dict[str, AuthChain]:
        """Restore every saved account at once.

        Errors loading any individual account are logged but don't
        abort the whole batch.
        """
        result: dict[str, AuthChain] = {}
        for label in self.list_labels():
            try:
                result[label] = await self.load(label, http_client=http_client)
            except AccountManagerError as e:
                logger.warning("mcapi_auth: skipping account %r: %s", label, e)
        return result

    def make_listener_for(
        self,
        label: str,
        chain: AuthChain,
    ) -> Callable[[str, object, object], Awaitable[None]]:
        """Return an :meth:`AuthChain.on_change` listener that persists ``chain``.

        Usage::

            chain.on_change(mgr.make_listener_for("notch", chain))
        """
        _validate_label(label)

        async def _listener(_stage: str, _old: object, _new: object) -> None:
            try:
                await self.save(label, chain)
            except Exception:
                logger.exception("mcapi_auth: AccountManager auto-save failed for %r", label)

        return _listener

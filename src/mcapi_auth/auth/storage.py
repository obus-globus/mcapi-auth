"""Refresh-token persistence.
By default, the MSA refresh token is stored as JSON in an XDG state file
with ``0600`` permissions. Callers that need anything else (keyring,
encrypted blob, in-memory only) implement the :class:`TokenStorage`
:class:`Protocol` and pass an instance to :func:`mcapi_auth.login_device_code_v1`.

Only the refresh token is persisted — short-lived access tokens are
re-derived on every call.
"""

import asyncio
import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

__all__ = ["FileTokenStorage", "NullTokenStorage", "TokenStorage", "default_storage_path"]

logger = logging.getLogger(__name__)


@runtime_checkable
class TokenStorage(Protocol):
    """Asynchronous storage backend for the MSA refresh token.

    Implementations may be async to allow for keyring / network-backed
    storage; synchronous backends just ``return`` immediately.
    """

    async def load(self) -> str | None:
        """Return the persisted refresh token, or ``None`` if absent."""
        ...

    async def save(self, refresh_token: str) -> None:
        """Persist a new refresh token, replacing any previous value."""
        ...

    async def clear(self) -> None:
        """Remove any persisted refresh token (used on hard auth failure)."""
        ...


class NullTokenStorage:
    """In-memory no-op storage. Forgets the refresh token at shutdown.

    Default for :func:`mcapi_auth.login_device_code_v1` since v0.5.0 — callers that
    want persistence must pass an explicit
    :class:`FileTokenStorage` (or any other ``TokenStorage`` impl).
    """

    async def load(self) -> str | None:  # NOSONAR protocol method, no I/O in this impl
        return None

    async def save(self, refresh_token: str) -> None:  # NOSONAR protocol method, no I/O in this impl
        return

    async def clear(self) -> None:  # NOSONAR protocol method, no I/O in this impl
        return


def default_storage_path() -> Path:
    """The XDG state path where :class:`FileTokenStorage` defaults to."""
    base_env = os.environ.get("XDG_STATE_HOME")
    base = Path(base_env) if base_env else Path.home() / ".local" / "state"
    return base / "mcapi_auth" / "refresh_token.json"


class FileTokenStorage:
    """File-backed token storage with ``0600`` permissions.

    The file is JSON-encoded to leave room for future fields (e.g. tying
    the refresh token to a specific account name / client_id). Atomic
    replace is used on save so a crash mid-write can't corrupt the file.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = path if path is not None else default_storage_path()

    @property
    def path(self) -> Path:
        return self._path

    async def load(self) -> str | None:
        return await asyncio.to_thread(self._load_sync)

    def _load_sync(self) -> str | None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as e:
            logger.warning("mcapi_auth: cannot read refresh-token file %s: %s", self._path, e)
            return None
        try:
            data: object = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("mcapi_auth: refresh-token file %s is not valid JSON", self._path)
            return None
        if not isinstance(data, dict):
            return None
        data_typed = cast(dict[str, object], data)
        token = data_typed.get("refresh_token")
        return token if isinstance(token, str) and token else None

    async def save(self, refresh_token: str) -> None:
        await asyncio.to_thread(self._save_sync, refresh_token)

    def _save_sync(self, refresh_token: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"refresh_token": refresh_token})
        # Atomic write: temp file in the same dir, then os.replace.
        fd, tmp_path = tempfile.mkstemp(prefix=".mcapi_auth-", suffix=".tmp", dir=self._path.parent)
        tmp = Path(tmp_path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                _ = f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()

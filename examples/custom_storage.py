"""Plug a custom `TokenStorage` into `mcapi_auth.login()`.
`FileTokenStorage` (XDG state dir, atomic write, 0600 perms) is fine for
single-user desktop apps. For services, you'll want to put refresh
tokens somewhere else — your DB, a secrets manager, an in-memory cache
for short-lived workers, etc.

This example shows a minimal in-memory storage and a sketch of a
SQLite-backed one. The protocol is just two async methods: `load()`
returning `str | None`, and `save(refresh_token)` returning `None`.
"""

import asyncio
import sqlite3
from pathlib import Path

from mcapi_auth import DeviceCodePrompt, TokenStorage, login


class MemoryTokenStorage:
    """Storage that lives only as long as the process. Useful for tests."""

    def __init__(self) -> None:
        self._token: str | None = None

    async def load(self) -> str | None:
        return self._token

    async def save(self, refresh_token: str) -> None:
        self._token = refresh_token

    async def clear(self) -> None:
        self._token = None


class SQLiteTokenStorage:
    """Single-row SQLite-backed storage. Async-safe via `asyncio.to_thread`."""

    def __init__(self, path: Path, account_id: str = "default") -> None:
        self._path = path
        self._account_id = account_id
        with sqlite3.connect(path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS mcauth_tokens "
                "(account_id TEXT PRIMARY KEY, refresh_token TEXT NOT NULL)"
            )

    async def load(self) -> str | None:
        return await asyncio.to_thread(self._load_sync)

    async def save(self, refresh_token: str) -> None:
        await asyncio.to_thread(self._save_sync, refresh_token)

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear_sync)

    def _load_sync(self) -> str | None:
        with sqlite3.connect(self._path) as conn:
            row = conn.execute(
                "SELECT refresh_token FROM mcauth_tokens WHERE account_id = ?",
                (self._account_id,),
            ).fetchone()
        return None if row is None else str(row[0])

    def _save_sync(self, refresh_token: str) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT INTO mcauth_tokens (account_id, refresh_token) VALUES (?, ?) "
                "ON CONFLICT(account_id) DO UPDATE SET refresh_token = excluded.refresh_token",
                (self._account_id, refresh_token),
            )
            conn.commit()

    def _clear_sync(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute("DELETE FROM mcauth_tokens WHERE account_id = ?", (self._account_id,))
            conn.commit()


async def show_prompt(prompt: DeviceCodePrompt) -> None:
    print(f"Visit {prompt.verification_uri} and enter: {prompt.user_code}")


async def main() -> None:
    storage: TokenStorage = SQLiteTokenStorage(Path("./mcauth-tokens.db"))
    session = await login(storage=storage, on_device_code=show_prompt)
    print(f"Logged in as {session.username}; token persisted to mcauth-tokens.db")


if __name__ == "__main__":
    asyncio.run(main())

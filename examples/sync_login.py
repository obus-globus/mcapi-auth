"""Synchronous usage — for scripts that don't want async/await boilerplate.

Every public async function in :mod:`mcapi_auth` is wrapped under
``mcapi_auth.sync`` so you can call it like a normal blocking function.
Behind the scenes each call spins up a fresh ``asyncio.run(...)`` loop.

This is the right choice for one-off scripts, ``manage.py``-style
commands, and quick experiments. For server-side code that handles
many requests, use the async API instead — the sync facade can't share
connection pools across calls.
"""

from __future__ import annotations

from mcapi_auth import sync as mcapi


def main() -> None:
    # Same arguments and return types as the async ``mcapi_auth.login``.
    session = mcapi.login()

    print(f"Logged in as {session.username} ({session.uuid_dashed})")
    print(f"Access token: {session.access_token[:20]}…")

    profile = mcapi.get_own_profile(token=session.access_token)
    print(f"Profile id: {profile.id}, name: {profile.name}")

    # Anything from the async surface works — get_uuid_by_name,
    # fetch_realms_worlds, change_skin_from_url, etc.
    notch = mcapi.get_uuid_by_name("Notch")
    print(f"Notch's UUID: {notch.id if notch else 'not found'}")


if __name__ == "__main__":
    main()

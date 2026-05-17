"""Reuse a saved refresh token — skip the device-code prompt entirely.

`mcauth.login()` already does this for you transparently (it tries the
stored refresh token first and only falls back to device-code on
failure). This example shows the *low-level* refresh path: take a
refresh token you already have in hand and turn it into a fresh
`MinecraftSession` without touching disk or prompting the user.

Useful when you persist refresh tokens somewhere other than
`FileTokenStorage` (a database, a secrets manager, an env var passed by
your orchestrator, ...).
"""

from __future__ import annotations

import asyncio
import os
import sys

from mcapi_auth import MinecraftSession
from mcapi_auth.auth.minecraft import fetch_profile, login_with_xbox
from mcapi_auth.auth.msa import exchange_refresh_token
from mcapi_auth.auth.xbox import authenticate_xbl, authenticate_xsts


async def main() -> None:
    refresh_token = os.environ.get("MCAUTH_REFRESH_TOKEN")
    if not refresh_token:
        print(
            "Set MCAUTH_REFRESH_TOKEN to a previously-obtained refresh token,\n"
            "e.g. `MCAUTH_REFRESH_TOKEN=$(cat ~/.local/share/mcauth/refresh.json | jq -r .refresh_token) "
            "uv run examples/refresh_token.py`",
            file=sys.stderr,
        )
        sys.exit(1)

    msa = await exchange_refresh_token(refresh_token)
    xbl = await authenticate_xbl(msa.access_token)
    xsts = await authenticate_xsts(xbl.token)
    mc = await login_with_xbox(xbl.userhash, xsts.token)
    profile = await fetch_profile(mc.access_token)

    session = MinecraftSession(
        access_token=mc.access_token,
        refresh_token=msa.refresh_token,
        uuid=profile.uuid,
        username=profile.username,
        msa_access_token=msa.access_token,
        msa_access_token_expires_at=msa.expires_at,
        minecraft_access_token_expires_at=mc.expires_at,
    )
    print(f"Refreshed: {session.username} ({session.uuid_dashed})")
    print(f"New refresh token (truncated): {session.refresh_token[:24]}…")


if __name__ == "__main__":
    asyncio.run(main())

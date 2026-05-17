"""Authorization-code + PKCE flow, *without* the built-in listener.
`login_via_browser()` / `acquire_msa_via_browser()` already wrap this up
with a stdlib HTTP listener — use them when you can. This example is
for the case where you have your *own* HTTP server (FastAPI, Flask,
whatever) and want to integrate the OAuth callback as a route.

Skeleton:

1. Build the authorize URL + remember the PKCE verifier and CSRF state
   in your session store.
2. Redirect the user there.
3. Microsoft redirects them back to ``/cb?code=...&state=...``.
4. In that handler, verify ``state``, then exchange the ``code`` for
   tokens with the matching PKCE verifier.
5. Run the rest of the chain (XBL → XSTS → Mojang) to get a
   `MinecraftSession`.
"""

import asyncio
import secrets

from mcapi_auth import MinecraftSession
from mcapi_auth.auth.auth_code import (
    build_authorize_url,
    create_pkce_challenge,
    exchange_authorization_code,
)
from mcapi_auth.auth.minecraft import fetch_profile, login_with_xbox
from mcapi_auth.auth.xbox import authenticate_xbl, authenticate_xsts

REDIRECT_URI = "http://localhost:8765/cb"


async def step1_kick_off() -> tuple[str, str, str]:
    """Build the URL you'll redirect the user to."""
    pkce = create_pkce_challenge()
    state = secrets.token_urlsafe(24)
    url = build_authorize_url(
        redirect_uri=REDIRECT_URI,
        pkce=pkce,
        state=state,
        prompt="select_account",
    )
    # In a real web app you'd persist (pkce.verifier, state) in the session.
    return url, pkce.verifier, state


async def step2_handle_callback(
    code: str, callback_state: str, *, expected_state: str, pkce_verifier: str
) -> MinecraftSession:
    """Run from your `/cb` route after pulling code+state from the query string."""
    if not secrets.compare_digest(callback_state, expected_state):
        raise RuntimeError("CSRF state mismatch — refuse to continue")

    msa = await exchange_authorization_code(
        redirect_uri=REDIRECT_URI, code=code, pkce_verifier=pkce_verifier
    )
    xbl = await authenticate_xbl(msa.access_token)
    xsts = await authenticate_xsts(xbl.token)
    mc = await login_with_xbox(xbl.userhash, xsts.token)
    profile = await fetch_profile(mc.access_token)
    return MinecraftSession(
        access_token=mc.access_token,
        refresh_token=msa.refresh_token,
        uuid=profile.uuid,
        username=profile.username,
        msa_access_token=msa.access_token,
        msa_access_token_expires_at=msa.expires_at,
        minecraft_access_token_expires_at=mc.expires_at,
    )


async def main() -> None:
    url, verifier, state = await step1_kick_off()
    print("Redirect user to:")
    print(url)
    print()
    print("After Microsoft hits your /cb route, call:")
    print("  step2_handle_callback(code, callback_state,")
    print(f"      expected_state={state!r},")
    print(f"      pkce_verifier={verifier!r})")


if __name__ == "__main__":
    asyncio.run(main())

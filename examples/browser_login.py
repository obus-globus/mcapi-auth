"""Authorization-code (browser) login example.
Demonstrates :func:`mcapi_auth.login_via_browser`. Run with::

    uv run python examples/browser_login.py

What happens:

1. mcapi_auth picks a free localhost TCP port and starts a tiny listener
   on it.
2. Your default browser opens to ``login.microsoftonline.com``. If
   you're already signed in to a Microsoft account, you'll typically
   just see a consent screen (and a "Continue" button) rather than a
   full sign-in form.
3. After you consent, Microsoft redirects to
   ``http://127.0.0.1:<port>/callback?code=...&state=...`` — the
   listener catches that, validates the ``state``, exchanges the code,
   and runs the rest of the chain (XBL → XSTS → Mojang).
4. The refresh token is persisted to the XDG state dir, so re-running
   the script skips the browser flow entirely until that token is
   eventually rotated out.

Pass ``prompt="select_account"`` to ``login_via_browser`` if you want
to force the account picker (useful when more than one MS account is
signed in to the browser).
"""


import asyncio
import logging

from mcapi_auth import login_via_browser


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    session = await login_via_browser(prompt="select_account")
    print(f"Signed in as {session.username} ({session.uuid_dashed})")
    print(f"Access token (truncated): {session.access_token[:24]}...")
    print(f"MC token expires in: {session.minecraft_token_seconds_remaining():.0f}s")


if __name__ == "__main__":
    asyncio.run(main())

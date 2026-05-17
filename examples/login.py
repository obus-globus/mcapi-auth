"""Minimal example: log in, print the resulting profile."""

from __future__ import annotations

import asyncio

from mcapi_auth import DeviceCodePrompt, login


async def show_prompt(prompt: DeviceCodePrompt) -> None:
    print()
    print("=" * 60)
    print(f"  Visit: {prompt.verification_uri}")
    print(f"  Code:  {prompt.user_code}")
    print(f"  Expires in: {prompt.expires_in}s")
    print("=" * 60)
    print()


async def main() -> None:
    session = await login(on_device_code=show_prompt)
    print(f"Logged in as {session.username} ({session.uuid_dashed})")
    print(f"Minecraft access token expires in {session.minecraft_token_seconds_remaining():.0f}s")


if __name__ == "__main__":
    asyncio.run(main())

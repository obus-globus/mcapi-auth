"""Check Minecraft entitlements (Java / Bedrock / Game Pass).
`/minecraft/profile` returns 404 for accounts that don't own the Java
edition — but that's also what you get for Bedrock-only and Game-Pass
users. To tell them apart, hit `/entitlements/mcstore` directly.
"""


import asyncio

from mcapi_auth import derive_entitlement_flags, fetch_entitlements, login


async def main() -> None:
    session = await login()

    raw = await fetch_entitlements(session.access_token)
    print(f"Raw items: {list(raw.items)}")

    print(f"Owns Java edition:  {raw.has_java}")
    print(f"Owns Bedrock:       {raw.has_bedrock}")
    print(f"Has Game Pass:      {raw.has_game_pass}")

    # `derive_entitlement_flags` is the standalone helper if you ever
    # have a bare list of item names and want the flags without
    # round-tripping through the API again:
    flags = derive_entitlement_flags(raw.items)
    print(f"Re-derived flags:   {flags}")


if __name__ == "__main__":
    asyncio.run(main())

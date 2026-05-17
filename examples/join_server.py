"""POST `sessionserver/join` — prove profile ownership in a custom handshake.
This is the same call vanilla clients make during the joinServer step
of the protocol handshake. Useful when implementing a third-party
service that wants to verify a user owns the MC profile they claim
(axochat-style auth, custom server lobbies, etc.).

Typical flow:

1. The server generates a fresh ``serverId`` (random hex blob).
2. The client computes ``hash = SHA1(serverId + sharedSecret + serverPublicKey).hexdigest()``
   and calls ``join_server(...)`` with it.
3. The server then calls Mojang's ``hasJoined`` endpoint to confirm the
   profile / hash pair within the next ~30s.
"""

import asyncio

from mcapi_auth import join_server, login


async def main() -> None:
    session = await login()

    # In real usage these come from your protocol handshake; here we just
    # demo the API shape with a placeholder.
    server_id = "deadbeefcafef00d" + "0" * 24

    await join_server(
        access_token=session.access_token,
        uuid=session.uuid,
        server_id=server_id,
    )
    print(f"joinServer OK for {session.username}; server can now call hasJoined")


if __name__ == "__main__":
    asyncio.run(main())

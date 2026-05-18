"""Bedrock-Edition client chain end-to-end.

Requires the ``[bedrock]`` extra::

    pip install mcapi-auth[bedrock]

The flow is:

1. Normal MSA → XBL → XSTS chain, but the Minecraft RP is
   ``https://multiplayer.minecraft.net/`` (NOT the Java RP). The same
   XBL token can also be exchanged against ``http://playfab.xboxlive.com/``
   for the PlayFab leg.
2. ``minecraft_authenticate`` POSTs the ES384 public key to
   ``multiplayer.minecraft.net/authentication`` and returns the
   ``[mojangJwt, identityJwt]`` certificate chain.
3. ``start_minecraft_session`` exchanges the PlayFab session ticket for
   a franchise-service session JWT.
4. ``start_minecraft_multiplayer_session`` signs the public key with the
   session JWT and returns the multiplayer-ready ``signedToken``.

The ES384 keypair should be **persisted across launches** — Mojang
binds it to the player's account in the identity JWT. Re-generating
it every run means a new "device" on every login.
"""

import asyncio
from pathlib import Path
from uuid import UUID, uuid4

from mcapi_auth import (
    BEDROCK_PLAYFAB_TITLE_ID,
    authenticate_xbl,
    authenticate_xsts,
    playfab_login_with_xbox,
    poll_for_device_code_token,
    request_device_code,
)
from mcapi_auth.api.bedrock import (
    BedrockKeyPair,
    generate_bedrock_session_keypair,
    minecraft_authenticate,
    start_minecraft_multiplayer_session,
    start_minecraft_session,
)

KEYPAIR_PATH = Path("bedrock_keypair.pem")
DEVICE_ID_PATH = Path("bedrock_device.txt")
BEDROCK_GAME_VERSION = "1.21.50"


def load_or_create_keypair() -> BedrockKeyPair:
    if KEYPAIR_PATH.exists():
        return BedrockKeyPair.from_pem(KEYPAIR_PATH.read_text())
    kp = generate_bedrock_session_keypair()
    private_pem, _public_pem = kp.to_pem()
    KEYPAIR_PATH.write_text(private_pem)
    return kp


def load_or_create_device_id() -> UUID:
    if DEVICE_ID_PATH.exists():
        return UUID(DEVICE_ID_PATH.read_text().strip())
    device_id = uuid4()
    DEVICE_ID_PATH.write_text(str(device_id))
    return device_id


async def main() -> None:
    # ---- 1. MSA + XBL ---------------------------------------------
    prompt, pending = await request_device_code()
    print(f"Visit {prompt.verification_uri} and enter code {prompt.user_code}")
    msa = await poll_for_device_code_token(pending)
    xbl = await authenticate_xbl(msa.access_token)

    # ---- 2. Bedrock-scoped XSTS -----------------------------------
    bedrock_xsts = await authenticate_xsts(
        xbl.token,
        relying_party="https://multiplayer.minecraft.net/",
    )

    # ---- 3. PlayFab-scoped XSTS + PlayFab login -------------------
    playfab_xsts = await authenticate_xsts(
        xbl.token,
        relying_party="http://playfab.xboxlive.com/",
    )
    pf = await playfab_login_with_xbox(playfab_xsts, title_id=BEDROCK_PLAYFAB_TITLE_ID)
    print(f"PlayFab id: {pf.play_fab_id}")

    # ---- 4. ES384 keypair (persist across launches!) --------------
    key_pair = load_or_create_keypair()
    device_id = load_or_create_device_id()

    # ---- 5. Minecraft cert chain ----------------------------------
    chain = await minecraft_authenticate(bedrock_xsts, key_pair)
    print(f"XUID:        {chain.xuid}")
    print(f"DisplayName: {chain.display_name}")
    print(f"Identity:    {chain.identity_uuid}")
    print(f"Cert exp:    {chain.expires_at}")

    # ---- 6. Franchise session + signed multiplayer token ----------
    session = await start_minecraft_session(
        pf.session_ticket,
        game_version=BEDROCK_GAME_VERSION,
        device_id=device_id,
    )
    mp = await start_minecraft_multiplayer_session(session, key_pair)
    print(f"MP XUID:     {mp.xuid}")
    print(f"MP UUID:     {mp.uuid}")
    print(f"Signed JWT:  {mp.token[:48]}…")
    print(f"Valid until: {mp.expires_at}")


if __name__ == "__main__":
    asyncio.run(main())

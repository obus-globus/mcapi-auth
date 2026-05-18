"""Bedrock-Edition client chain end-to-end via the Sisu flow.

Requires the ``[bedrock]`` extra::

    pip install mcapi-auth[bedrock]

This script demonstrates the full RaphiMC-style chain:

1. MSA device-code login (any title client id; the example uses the
   Minecraft Win32 / Nintendo Bedrock client ids).
2. ``authenticate_xbl_device`` to get a DeviceToken — keypair + device
   UUID are persisted to disk so re-runs reuse the same identity.
3. ``sisu_authorize`` (one call per relying party) to get TitleToken +
   XSTS scoped to the Bedrock multiplayer service AND to PlayFab.
4. ``playfab_login_with_xbox`` for the PlayFab session ticket.
5. ``minecraft_authenticate`` to bind the ES384 client identity keypair
   to the player's account and receive the ``[mojangJwt, identityJwt]``
   certificate chain.
6. ``start_minecraft_session`` + ``start_minecraft_multiplayer_session``
   to get the signed multiplayer token that the Bedrock client uses to
   join servers.

The ES384 keypair AND the ES256 device keypair AND the device UUID
should all be persisted across launches — Mojang and Xbox both treat
those values as stable device identities. Re-generating them every
run means a new device on every login.
"""

import asyncio
from pathlib import Path
from uuid import UUID, uuid4

from mcapi_auth import (
    BEDROCK_PLAYFAB_TITLE_ID,
    BEDROCK_WIN32_CLIENT_ID,
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
from mcapi_auth.auth.xbox_device import (
    XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY,
    XBL_XSTS_BEDROCK_RELYING_PARTY,
    XblDeviceKeyPair,
    authenticate_xbl_device,
    sisu_authorize,
)

BEDROCK_KEYPAIR_PATH = Path("bedrock_identity.pem")
DEVICE_KEYPAIR_PATH = Path("bedrock_device.pem")
DEVICE_ID_PATH = Path("bedrock_device.txt")
BEDROCK_GAME_VERSION = "1.21.50"


def load_or_create_bedrock_keypair() -> BedrockKeyPair:
    if BEDROCK_KEYPAIR_PATH.exists():
        return BedrockKeyPair.from_pem(BEDROCK_KEYPAIR_PATH.read_text())
    kp = generate_bedrock_session_keypair()
    private_pem, _ = kp.to_pem()
    BEDROCK_KEYPAIR_PATH.write_text(private_pem)
    return kp


def load_or_create_device_keypair() -> XblDeviceKeyPair:
    if DEVICE_KEYPAIR_PATH.exists():
        return XblDeviceKeyPair.from_pem(DEVICE_KEYPAIR_PATH.read_text())
    kp = XblDeviceKeyPair.generate()
    DEVICE_KEYPAIR_PATH.write_text(kp.private_key_pem())
    return kp


def load_or_create_device_id() -> UUID:
    if DEVICE_ID_PATH.exists():
        return UUID(DEVICE_ID_PATH.read_text().strip())
    device_id = uuid4()
    DEVICE_ID_PATH.write_text(str(device_id))
    return device_id


async def main() -> None:
    # ---- 1. MSA device-code login (using a Bedrock title client id) -
    prompt, pending = await request_device_code(client_id=BEDROCK_WIN32_CLIENT_ID)
    print(f"Visit {prompt.verification_uri} and enter code {prompt.user_code}")
    msa = await poll_for_device_code_token(pending, client_id=BEDROCK_WIN32_CLIENT_ID)

    # ---- 2. Persisted device keypair + device UUID -----------------
    device_kp = load_or_create_device_keypair()
    device_id = load_or_create_device_id()

    # ---- 3. DeviceToken -------------------------------------------
    device_token = await authenticate_xbl_device(device_kp, device_id=device_id)
    print(f"DeviceToken expires: {device_token.expires_at}")

    # ---- 4. Sisu to get Bedrock XSTS + PlayFab XSTS in two calls ---
    bedrock_sisu = await sisu_authorize(
        msa.access_token,
        device_token,
        device_kp,
        client_id=BEDROCK_WIN32_CLIENT_ID,
        relying_party=XBL_XSTS_BEDROCK_RELYING_PARTY,
    )
    playfab_sisu = await sisu_authorize(
        msa.access_token,
        device_token,
        device_kp,
        client_id=BEDROCK_WIN32_CLIENT_ID,
        relying_party=XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY,
    )

    # ---- 5. PlayFab login -----------------------------------------
    pf = await playfab_login_with_xbox(
        # XblXstsToken is shape-compatible with the XSTSToken the
        # PlayFab module expects (Token + userhash).
        playfab_sisu.xsts_token,  # type: ignore[arg-type]
        title_id=BEDROCK_PLAYFAB_TITLE_ID,
    )
    print(f"PlayFab id: {pf.play_fab_id}")

    # ---- 6. ES384 identity keypair + Minecraft cert chain ----------
    bedrock_kp = load_or_create_bedrock_keypair()
    chain = await minecraft_authenticate(
        bedrock_sisu.xsts_token,  # type: ignore[arg-type]
        bedrock_kp,
    )
    print(f"XUID:        {chain.xuid}")
    print(f"DisplayName: {chain.display_name}")
    print(f"Identity:    {chain.identity_uuid}")
    print(f"Cert exp:    {chain.expires_at}")

    # ---- 7. Franchise session + signed multiplayer token ----------
    session = await start_minecraft_session(
        pf.session_ticket,
        game_version=BEDROCK_GAME_VERSION,
        device_id=device_id,
    )
    mp = await start_minecraft_multiplayer_session(session, bedrock_kp)
    print(f"MP XUID:     {mp.xuid}")
    print(f"MP UUID:     {mp.uuid}")
    print(f"Signed JWT:  {mp.token[:48]}…")
    print(f"Valid until: {mp.expires_at}")


if __name__ == "__main__":
    asyncio.run(main())

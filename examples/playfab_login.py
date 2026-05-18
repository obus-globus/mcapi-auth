"""PlayFab login: exchange an XSTS token for a PlayFab entity token.

Bedrock-Edition clients log into PlayFab in addition to Xbox Live.
The flow is:

1. Normal MSA → XBL → XSTS chain, but the XSTS RP must be
   ``http://playfab.xboxlive.com/`` (NOT the Java/Minecraft RP).
2. ``playfab_login_with_xbox(xsts, title_id=...)`` exchanges the XSTS
   for a PlayFab session ticket + entity token.
3. ``playfab_get_entity_token(entity_token)`` refreshes just the entity
   token later, no XSTS round-trip needed.

The PlayFab session ticket can then be fed into the Bedrock chain
(see ``bedrock_minimal.py``) to obtain a Minecraft multiplayer token.
"""

import asyncio

from mcapi_auth import (
    BEDROCK_PLAYFAB_TITLE_ID,
    authenticate_xbl,
    authenticate_xsts,
    playfab_get_entity_token,
    playfab_login_with_xbox,
    poll_for_device_code_token,
    request_device_code,
)


async def main() -> None:
    # ---- 1. Get an MSA token via device code -----------------------
    prompt, pending = await request_device_code()
    print(f"Visit {prompt.verification_uri} and enter code {prompt.user_code}")
    msa = await poll_for_device_code_token(pending)

    # ---- 2. Normal XBL leg ----------------------------------------
    xbl = await authenticate_xbl(msa.access_token)

    # ---- 3. PlayFab-scoped XSTS (note the relying_party!) ---------
    pf_xsts = await authenticate_xsts(
        xbl.token,
        relying_party="http://playfab.xboxlive.com/",
    )

    # ---- 4. PlayFab login -----------------------------------------
    pf = await playfab_login_with_xbox(pf_xsts, title_id=BEDROCK_PLAYFAB_TITLE_ID)
    print(f"PlayFab id:        {pf.play_fab_id}")
    print(f"Session ticket:    {pf.session_ticket[:32]}…")
    print(f"Entity id / type:  {pf.entity_token.entity_id} / {pf.entity_token.entity_type}")
    print(f"Entity exp:        {pf.entity_token.expires_at}")

    # ---- 5. Refresh just the entity token later -------------------
    fresh = await playfab_get_entity_token(pf.entity_token)
    print(f"Refreshed entity token exp: {fresh.expires_at}")


if __name__ == "__main__":
    asyncio.run(main())

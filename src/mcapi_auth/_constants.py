"""Endpoint URLs and protocol constants.
Everything that might shift if Microsoft / Mojang move their APIs around
is collected here so refactors stay tight to one file.
"""


from typing import Final

# Public Minecraft Launcher client_id. Every open-source launcher
# (PrismLauncher, etc.) uses this; Microsoft has tolerated it for ~5 years.
# If they ever revoke it, every Minecraft launcher breaks the same day.
#
# Note: this is the Azure-AD UUID form, which works with the
# ``/consumers/oauth2/v2.0/*`` endpoints we use. The same logical client
# also exists in MSA's older Live-Connect compressed form
# ("00000000402b5328"), but that one requires the ``login.live.com``
# ``/oauth20_*.srf`` endpoints which mcapi_auth doesn't currently target —
# don't substitute it without also overriding the auth/token URLs.
MINECRAFT_LAUNCHER_CLIENT_ID: Final = "00000000-402b-4cd3-a82b-c45ab2f1d3f7"

# PrismLauncher's own Azure-AD app. Works against the same
# ``/consumers/oauth2/v2.0/*`` endpoints. Useful as a drop-in
# alternative when you want to attribute auth attempts to a Prism-style
# client without using the (shared) launcher client_id above. Note that
# Prism's redirect URI is the funky ``http://127.0.0.1:1`` — pass it
# explicitly to :func:`mcapi_auth.auth.auth_code.build_authorize_url`.
PRISM_LAUNCHER_CLIENT_ID: Final = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb"
PRISM_LAUNCHER_REDIRECT_URI: Final = "http://127.0.0.1:1"

# Live-Connect "desktop" redirect URI — the canonical out-of-band
# redirect for the launcher's legacy MSA v1 flow. Kept here purely so
# callers integrating with older code paths can reference it by name.
LIVE_CONNECT_DESKTOP_REDIRECT_URI: Final = "https://login.live.com/oauth20_desktop.srf"

# MSA OAuth (consumers tenant — required for personal MS accounts that own MC).
MSA_DEVICE_CODE_URL: Final = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
MSA_TOKEN_URL: Final = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
MSA_SCOPE: Final = "XboxLive.signin offline_access"

# Live Connect v1 OAuth endpoints — used by the *legacy* MSA flow that
# the official Minecraft Launcher still talks to. These accept the
# compressed-form launcher client_id ``MINECRAFT_LAUNCHER_V1_CLIENT_ID``
# and the ``service::user.auth.xboxlive.com::MBI_SSL`` scope.
LIVE_CONNECT_AUTHORIZE_URL: Final = "https://login.live.com/oauth20_authorize.srf"
LIVE_CONNECT_TOKEN_URL: Final = "https://login.live.com/oauth20_token.srf"
LIVE_CONNECT_SCOPE_MBI_SSL: Final = "service::user.auth.xboxlive.com::MBI_SSL"

# Compressed Live-Connect form of the launcher client_id. Same logical
# client as :data:`MINECRAFT_LAUNCHER_CLIENT_ID`, but this is the form
# the v1 ``oauth20_*.srf`` endpoints expect.
MINECRAFT_LAUNCHER_V1_CLIENT_ID: Final = "00000000402b5328"

# SISU (Xbox Sign-In/Sign-Up). Returns XBL/XSTS tokens directly given
# Microsoft browser cookies — no access/refresh token in the result.
SISU_CONNECT_URL: Final = "https://sisu.xboxlive.com/connect/XboxLive/"
SISU_DEFAULT_COBRAND_ID: Final = "8058f65d-ce06-4c30-9559-473c9275a65d"
SISU_DEFAULT_TID: Final = "896928775"
SISU_DEFAULT_RU: Final = "https://www.minecraft.net/msaprofile/msa-profile"

# Default User-Agent for cookie-based flows. Microsoft sometimes 4xxs
# requests that look unlike a real browser. Override via the
# ``user_agent`` parameter on the cookie-login functions if you need
# a more browser-faithful value.
DEFAULT_USER_AGENT: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Xbox Live.
XBL_AUTH_URL: Final = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL: Final = "https://xsts.auth.xboxlive.com/xsts/authorize"
XSTS_RELYING_PARTY: Final = "rp://api.minecraftservices.com/"

# Mojang / Minecraft services.
MC_LOGIN_WITH_XBOX_URL: Final = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_PROFILE_URL: Final = "https://api.minecraftservices.com/minecraft/profile"
MC_ENTITLEMENTS_URL: Final = "https://api.minecraftservices.com/entitlements/mcstore"
SESSIONSERVER_JOIN_URL: Final = "https://sessionserver.mojang.com/session/minecraft/join"

# MSA OAuth authorize endpoint (used by the authorization-code + PKCE flow).
MSA_AUTHORIZE_URL: Final = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"

# Per-request timeout (seconds). Microsoft's device-code poll endpoint is
# slow under load; everything else should be well under 10s.
DEFAULT_HTTP_TIMEOUT: Final = 30.0

# Device-code poll: minimum interval the spec lets the server demand.
# We honor the server's `interval` claim but clamp to this floor.
MIN_DEVICE_CODE_POLL_INTERVAL: Final = 1.0

# XErr codes the XSTS endpoint returns under HTTP 401. Mapped to typed
# exceptions in :mod:`mcapi_auth.exceptions`. Source: every open-source
# launcher's auth notes; these are stable.
#
# Reference: https://wiki.vg/Microsoft_Authentication_Scheme (community)
XERR_NO_XBOX_ACCOUNT: Final = 2148916233
XERR_REGION_BLOCKED: Final = 2148916235
XERR_VERIFY_AGE_REQUIRED: Final = 2148916236
XERR_REQUIRES_ADULT_VERIFICATION: Final = 2148916237
XERR_CHILD_ACCOUNT: Final = 2148916238  # needs Family Pack

__all__ = [
    "API_MOJANG_BASE",
    "API_SERVICES_BASE",
    "BLOCKED_SERVERS_URL",
    "BULK_USERNAME_LOOKUP_MAX",
    "BULK_USERNAME_TO_UUID_URL",
    "DEFAULT_API_USER_AGENT",
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_USER_AGENT",
    "LIVE_CONNECT_AUTHORIZE_URL",
    "LIVE_CONNECT_DESKTOP_REDIRECT_URI",
    "LIVE_CONNECT_SCOPE_MBI_SSL",
    "LIVE_CONNECT_TOKEN_URL",
    "MC_ENTITLEMENTS_URL",
    "MC_LOGIN_WITH_XBOX_URL",
    "MC_PROFILE_URL",
    "MINECRAFT_LAUNCHER_CLIENT_ID",
    "MINECRAFT_LAUNCHER_V1_CLIENT_ID",
    "MIN_DEVICE_CODE_POLL_INTERVAL",
    "MSA_AUTHORIZE_URL",
    "MSA_DEVICE_CODE_URL",
    "MSA_SCOPE",
    "MSA_TOKEN_URL",
    "PISTON_META_BASE",
    "PRISM_LAUNCHER_CLIENT_ID",
    "PRISM_LAUNCHER_REDIRECT_URI",
    "PROFILE_CAPES_ACTIVE_URL",
    "PROFILE_NAMECHANGE_URL",
    "PROFILE_NAME_BASE_URL",
    "PROFILE_SKINS_ACTIVE_URL",
    "PROFILE_SKINS_URL",
    "PROFILE_URL",
    "SESSIONSERVER_JOIN_URL",
    "SESSION_SERVER_BASE",
    "SISU_CONNECT_URL",
    "SISU_DEFAULT_COBRAND_ID",
    "SISU_DEFAULT_RU",
    "SISU_DEFAULT_TID",
    "TEXTURES_HOST",
    "USERNAME_TO_UUID_URL",
    "UUID_TO_PROFILE_URL",
    "VERSION_MANIFEST_V2_URL",
    "XBL_AUTH_URL",
    "XERR_CHILD_ACCOUNT",
    "XERR_NO_XBOX_ACCOUNT",
    "XERR_REGION_BLOCKED",
    "XERR_REQUIRES_ADULT_VERIFICATION",
    "XERR_VERIFY_AGE_REQUIRED",
    "XSTS_AUTH_URL",
    "XSTS_RELYING_PARTY",
]

# --- API (REST) endpoints --------------------------------------------

API_MOJANG_BASE: Final = "https://api.mojang.com"
SESSION_SERVER_BASE: Final = "https://sessionserver.mojang.com"
API_SERVICES_BASE: Final = "https://api.minecraftservices.com"
PISTON_META_BASE: Final = "https://piston-meta.mojang.com"

# Public, no-auth endpoints
USERNAME_TO_UUID_URL: Final = f"{API_MOJANG_BASE}/users/profiles/minecraft"  # /<name>
BULK_USERNAME_TO_UUID_URL: Final = f"{API_MOJANG_BASE}/profiles/minecraft"
UUID_TO_PROFILE_URL: Final = f"{SESSION_SERVER_BASE}/session/minecraft/profile"  # /<uuid>
BLOCKED_SERVERS_URL: Final = f"{SESSION_SERVER_BASE}/blockedservers"

# Authenticated endpoints (require a Microsoft / Minecraft Bearer token)
PROFILE_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile"
PROFILE_SKINS_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile/skins"
PROFILE_SKINS_ACTIVE_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile/skins/active"
PROFILE_CAPES_ACTIVE_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile/capes/active"
PROFILE_NAME_BASE_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile/name"  # /<name>[/available]
PROFILE_NAMECHANGE_URL: Final = f"{API_SERVICES_BASE}/minecraft/profile/namechange"

# Piston meta (launcher metadata)
VERSION_MANIFEST_V2_URL: Final = f"{PISTON_META_BASE}/mc/game/version_manifest_v2.json"

# Max names per bulk POST
BULK_USERNAME_LOOKUP_MAX: Final = 10

# Texture host (everything Mojang serves under this URL is a PNG)
TEXTURES_HOST: Final = "textures.minecraft.net"

# User-Agent used by the regular API client (acquire_client). The cookie
# flows use DEFAULT_USER_AGENT (a browser-faithful string) instead.
DEFAULT_API_USER_AGENT: Final = (
    "mcapi-auth/0.3.0 (+https://github.com/clawdbot-silly-waddle/mcapi-auth)"
)

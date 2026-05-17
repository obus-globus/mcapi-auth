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

# --- Additional well-known Microsoft client_ids ------------------------
#
# All of the ``0000000…`` IDs below are compressed Live-Connect form and
# **only** work against the v1 ``oauth20_*.srf`` endpoints with the
# ``MBI_SSL`` scope. The GUID-form IDs (with dashes) work against the v2
# ``/consumers/oauth2/v2.0/*`` endpoints with the ``XboxLive.signin``
# scope. Source-cross-referenced against:
#
# * https://github.com/PrismarineJS/prismarine-auth (Titles enum)
# * https://github.com/sandertv/gophertunnel (xbox.go device configs)
# * https://github.com/RaphiMC/MinecraftAuth (MsaConstants.java)

# Bedrock platform-specific client_ids. Xbox SISU enforces a
# DeviceType/Version/UserAgent triple that has to match the client_id
# — see the gophertunnel ``xbox.go`` device configs for the values
# Mojang/Xbox actually expect.
BEDROCK_WIN32_CLIENT_ID: Final = "0000000040159362"
BEDROCK_ANDROID_CLIENT_ID: Final = "0000000048183522"
BEDROCK_IOS_CLIENT_ID: Final = "000000004c17c01a"
BEDROCK_NINTENDO_CLIENT_ID: Final = "00000000441cc96b"
BEDROCK_PLAYSTATION_CLIENT_ID: Final = "000000004827c78e"

# Other ``0000000…`` (v1/MBI_SSL) Microsoft client_ids the wider
# ecosystem uses. prismarine-auth exposes these in its ``Titles`` enum.
XBOX_APP_IOS_CLIENT_ID: Final = "000000004c12ae6f"
XBOX_GAMEPASS_IOS_CLIENT_ID: Final = "000000004c20a908"

# v2 / Azure-AD GUID client_ids (work with the consumers v2 endpoints
# and the ``XboxLive.signin`` scope).
EDU_CLIENT_ID: Final = "b36b1432-1a1c-4c82-9b76-24de1cab42f2"
OFFICE365_API_EDITOR_CLIENT_ID: Final = "389b1b32-b5d5-43b2-bddc-84ce938d6737"

# LiquidLauncher / LiquidBounce's shared Azure-AD app. LiquidLauncher's
# ``src-tauri/src/minecraft/auth.rs`` and LiquidBounce's ``mc-authlib``
# ``MicrosoftAccount$AuthMethod.LIQUIDBOUNCE`` both use this client_id
# with the ``XboxLive.signin offline_access`` scope. LB also supports
# ``MINECRAFT_PC`` (== :data:`MINECRAFT_LAUNCHER_V1_CLIENT_ID`) and
# ``MINECRAFT_NINTENDO_SWITCH`` (== :data:`BEDROCK_NINTENDO_CLIENT_ID`)
# as alternative MBI_SSL v1 auth methods.
LIQUIDLAUNCHER_CLIENT_ID: Final = "0add8caf-2cc6-4546-b798-c3d171217dd9"

# Mapping of friendly aliases → client_id strings, for use by CLIs and
# config files. Use :func:`is_v1_client_id` to decide which auth flow
# (v1 OOB / v2 PKCE) to dispatch.
KNOWN_CLIENT_IDS: Final[dict[str, str]] = {
    "java": MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    "prism": PRISM_LAUNCHER_CLIENT_ID,
    "edu": EDU_CLIENT_ID,
    "office365": OFFICE365_API_EDITOR_CLIENT_ID,
    "liquidlauncher": LIQUIDLAUNCHER_CLIENT_ID,
    "liquidbounce": LIQUIDLAUNCHER_CLIENT_ID,
    "bedrock-win32": BEDROCK_WIN32_CLIENT_ID,
    "bedrock-android": BEDROCK_ANDROID_CLIENT_ID,
    "bedrock-ios": BEDROCK_IOS_CLIENT_ID,
    "bedrock-nintendo": BEDROCK_NINTENDO_CLIENT_ID,
    "bedrock-playstation": BEDROCK_PLAYSTATION_CLIENT_ID,
    "xbox-app-ios": XBOX_APP_IOS_CLIENT_ID,
    "xbox-gamepass-ios": XBOX_GAMEPASS_IOS_CLIENT_ID,
}


def is_v1_client_id(client_id: str) -> bool:
    """Return ``True`` if ``client_id`` is the compressed Live-Connect form.

    v1 client_ids are 16 hex chars (no dashes) and only work against
    ``login.live.com/oauth20_*.srf`` with the ``MBI_SSL`` scope. v2 IDs
    are dashed UUIDs and work against ``login.microsoftonline.com/consumers/oauth2/v2.0/*``
    with ``XboxLive.signin``.
    """
    return "-" not in client_id


def resolve_client_id(name_or_id: str) -> str:
    """Resolve an alias from :data:`KNOWN_CLIENT_IDS` or pass through a raw client_id.

    Aliases are looked up case-insensitively. Anything that doesn't
    match an alias is returned verbatim, so callers can freely pass
    raw client_id strings.
    """
    return KNOWN_CLIENT_IDS.get(name_or_id.lower(), name_or_id)


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
    "BEDROCK_ANDROID_CLIENT_ID",
    "BEDROCK_IOS_CLIENT_ID",
    "BEDROCK_NINTENDO_CLIENT_ID",
    "BEDROCK_PLAYSTATION_CLIENT_ID",
    "BEDROCK_WIN32_CLIENT_ID",
    "BLOCKED_SERVERS_URL",
    "BULK_USERNAME_LOOKUP_MAX",
    "BULK_USERNAME_TO_UUID_URL",
    "DEFAULT_API_USER_AGENT",
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_USER_AGENT",
    "EDU_CLIENT_ID",
    "KNOWN_CLIENT_IDS",
    "LIQUIDLAUNCHER_CLIENT_ID",
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
    "OFFICE365_API_EDITOR_CLIENT_ID",
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
    "XBOX_APP_IOS_CLIENT_ID",
    "XBOX_GAMEPASS_IOS_CLIENT_ID",
    "XERR_CHILD_ACCOUNT",
    "XERR_NO_XBOX_ACCOUNT",
    "XERR_REGION_BLOCKED",
    "XERR_REQUIRES_ADULT_VERIFICATION",
    "XERR_VERIFY_AGE_REQUIRED",
    "XSTS_AUTH_URL",
    "XSTS_RELYING_PARTY",
    "is_v1_client_id",
    "resolve_client_id",
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

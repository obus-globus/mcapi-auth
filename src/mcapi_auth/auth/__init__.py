"""Authentication chain: Microsoft → XBL → XSTS → Mojang.
The :mod:`mcapi_auth.auth` subpackage owns everything related to
*getting* a Minecraft access token from a Microsoft account. The public
entry points (:func:`login`, :func:`login_via_browser`,
:class:`MinecraftSession`, …) are also re-exported from the top-level
:mod:`mcapi_auth` namespace for convenience.
"""

from .._constants import (
    LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    MINECRAFT_LAUNCHER_CLIENT_ID,
    PRISM_LAUNCHER_CLIENT_ID,
    PRISM_LAUNCHER_REDIRECT_URI,
)
from ..exceptions import (
    AdultVerificationRequiredError,
    AuthorizationDeclinedError,
    ChildAccountError,
    DeviceCodeExpiredError,
    McAuthError,
    MinecraftAuthError,
    MinecraftProfileNotFoundError,
    MSAAuthError,
    MSAFlowError,
    NoXboxAccountError,
    RegionBlockedError,
    VerifyAgeRequiredError,
    XboxAuthError,
    XSTSError,
    xerr_to_exception,
)
from .auth_code import (
    PKCEChallenge,
    acquire_msa_via_browser,
    build_authorize_url,
    create_pkce_challenge,
    exchange_authorization_code,
)
from .cookies import (
    BrowserCookie,
    CookieAuthError,
    SISUTokens,
    cookies_to_header,
    extract_sisu_token,
    login_with_cookies_msa_v1,
    login_with_cookies_prism,
    login_with_cookies_sisu,
)
from .entitlements import Entitlements, derive_entitlement_flags, fetch_entitlements
from .flow import DeviceCodeCallback, login, login_via_browser
from .minecraft import login_with_xbox
from .msa import (
    DeviceCodePrompt,
    MSATokens,
    exchange_refresh_token,
    poll_for_device_code_token,
    request_device_code,
)
from .session import MinecraftSession
from .session_server import JoinServerError, join_server
from .storage import FileTokenStorage, NullTokenStorage, TokenStorage, default_storage_path
from .token import MinecraftTokenInfo, decode_minecraft_access_token
from .xbox import XboxLiveToken, XSTSToken, authenticate_xbl, authenticate_xsts

__all__ = [
    "LIVE_CONNECT_DESKTOP_REDIRECT_URI",
    "MINECRAFT_LAUNCHER_CLIENT_ID",
    "PRISM_LAUNCHER_CLIENT_ID",
    "PRISM_LAUNCHER_REDIRECT_URI",
    "AdultVerificationRequiredError",
    "AuthorizationDeclinedError",
    "BrowserCookie",
    "ChildAccountError",
    "CookieAuthError",
    "DeviceCodeCallback",
    "DeviceCodeExpiredError",
    "DeviceCodePrompt",
    "Entitlements",
    "FileTokenStorage",
    "JoinServerError",
    "MSAAuthError",
    "MSAFlowError",
    "MSATokens",
    "McAuthError",
    "MinecraftAuthError",
    "MinecraftProfileNotFoundError",
    "MinecraftSession",
    "MinecraftTokenInfo",
    "NoXboxAccountError",
    "NullTokenStorage",
    "PKCEChallenge",
    "RegionBlockedError",
    "SISUTokens",
    "TokenStorage",
    "VerifyAgeRequiredError",
    "XSTSError",
    "XSTSToken",
    "XboxAuthError",
    "XboxLiveToken",
    "acquire_msa_via_browser",
    "authenticate_xbl",
    "authenticate_xsts",
    "build_authorize_url",
    "cookies_to_header",
    "create_pkce_challenge",
    "decode_minecraft_access_token",
    "default_storage_path",
    "derive_entitlement_flags",
    "exchange_authorization_code",
    "exchange_refresh_token",
    "extract_sisu_token",
    "fetch_entitlements",
    "join_server",
    "login",
    "login_via_browser",
    "login_with_cookies_msa_v1",
    "login_with_cookies_prism",
    "login_with_cookies_sisu",
    "login_with_xbox",
    "poll_for_device_code_token",
    "request_device_code",
    "xerr_to_exception",
]

"""REST API surface: public lookups + authed profile/skin/cape/name ops.

The :mod:`mcapi_auth.api` subpackage owns everything related to *using*
a Minecraft access token (and the public lookup endpoints that don't
need one). Top-level convenience names are also re-exported from the
:mod:`mcapi_auth` namespace.
"""

from __future__ import annotations

from .._constants import (
    DEFAULT_API_USER_AGENT,
    DEFAULT_HTTP_TIMEOUT,
)
from ..exceptions import (
    BadRequestError,
    ForbiddenError,
    HttpError,
    InvalidProfileError,
    McApiError,
    NameNotAllowedError,
    NameTakenError,
    NotFoundError,
    RateLimitedError,
    TooManyNamesError,
    UnauthorizedError,
)
from ._session import TokenLike, coerce_token
from .account import (
    CapeEntry,
    NameAvailability,
    NameChangeEligibility,
    OwnProfile,
    SkinEntry,
    SkinVariant,
    change_cape,
    change_name,
    change_skin_from_file,
    change_skin_from_url,
    check_name_availability,
    disable_cape,
    get_name_change_eligibility,
    get_own_profile,
    reset_skin,
)
from .blocked_servers import (
    fetch_blocked_servers,
    hostname_variants,
    is_blocked,
    is_server_blocked,
)
from .meta import (
    DownloadEntry,
    VersionDetails,
    VersionEntry,
    VersionManifest,
    fetch_version_manifest,
)
from .profile import (
    NameLookupResult,
    ProfileProperty,
    PublicProfile,
    get_profile_by_uuid,
    get_uuid_by_name,
    get_uuids_by_names,
)
from .textures import (
    CapeTexture,
    DecodedTextures,
    SkinModel,
    SkinTexture,
    decode_texture_property,
    extract_textures,
)

__all__ = [
    "DEFAULT_API_USER_AGENT",
    "DEFAULT_HTTP_TIMEOUT",
    "BadRequestError",
    "CapeEntry",
    "CapeTexture",
    "DecodedTextures",
    "DownloadEntry",
    "ForbiddenError",
    "HttpError",
    "InvalidProfileError",
    "McApiError",
    "NameAvailability",
    "NameChangeEligibility",
    "NameLookupResult",
    "NameNotAllowedError",
    "NameTakenError",
    "NotFoundError",
    "OwnProfile",
    "ProfileProperty",
    "PublicProfile",
    "RateLimitedError",
    "SkinEntry",
    "SkinModel",
    "SkinTexture",
    "SkinVariant",
    "TokenLike",
    "TooManyNamesError",
    "UnauthorizedError",
    "VersionDetails",
    "VersionEntry",
    "VersionManifest",
    "change_cape",
    "change_name",
    "change_skin_from_file",
    "change_skin_from_url",
    "check_name_availability",
    "coerce_token",
    "decode_texture_property",
    "disable_cape",
    "extract_textures",
    "fetch_blocked_servers",
    "fetch_version_manifest",
    "get_name_change_eligibility",
    "get_own_profile",
    "get_profile_by_uuid",
    "get_uuid_by_name",
    "get_uuids_by_names",
    "hostname_variants",
    "is_blocked",
    "is_server_blocked",
    "reset_skin",
]

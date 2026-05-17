"""Exception types raised by :mod:`mcapi_auth`.
Two parallel trees sit under a single root:

- :class:`McAuthError` covers everything in the Microsoft → XBL → XSTS →
  Mojang token chain (the former ``mcauth`` package).
- :class:`McApiError` covers the REST API surface (the former ``mcapi``
  package): public profile lookups, authed profile/skin/cape ops,
  piston-meta, blocked-servers, texture decode.

Both inherit from :class:`McApiAuthError`, so ``except McApiAuthError``
catches every in-domain failure across both halves of the library.
Network-level failures propagate as :class:`httpx.RequestError`
unchanged — those are not our domain.
"""

from ._constants import (
    XERR_CHILD_ACCOUNT,
    XERR_NO_XBOX_ACCOUNT,
    XERR_REGION_BLOCKED,
    XERR_REQUIRES_ADULT_VERIFICATION,
    XERR_VERIFY_AGE_REQUIRED,
)

__all__ = [
    "AdultVerificationRequiredError",
    "AuthorizationDeclinedError",
    "BadRequestError",
    "ChildAccountError",
    "DeviceCodeExpiredError",
    "ForbiddenError",
    "HttpError",
    "InvalidProfileError",
    "MSAAuthError",
    "MSAFlowError",
    "McApiAuthError",
    "McApiError",
    "McAuthError",
    "MinecraftAuthError",
    "MinecraftProfileNotFoundError",
    "NameNotAllowedError",
    "NameTakenError",
    "NoXboxAccountError",
    "NotFoundError",
    "RateLimitedError",
    "RegionBlockedError",
    "TooManyNamesError",
    "UnauthorizedError",
    "VerifyAgeRequiredError",
    "XSTSError",
    "XboxAuthError",
    "xerr_to_exception",
]


class McApiAuthError(Exception):
    """Common base for every :mod:`mcapi_auth` error.

    Catches both the auth-chain failures (:class:`McAuthError`) and the
    REST-API failures (:class:`McApiError`).
    """


# --- Auth tree (former mcauth) -------------------------------------------


class McAuthError(McApiAuthError):
    """Base class for every failure in the Microsoft → Mojang token chain."""


class MSAAuthError(McAuthError):
    """Base class for Microsoft account authentication failures."""


class MSAFlowError(MSAAuthError):
    """The MSA OAuth flow returned an unexpected response shape."""


class DeviceCodeExpiredError(MSAAuthError):
    """The user did not complete the device-code flow before it expired."""


class AuthorizationDeclinedError(MSAAuthError):
    """The user explicitly declined the device-code authorization prompt."""


class XboxAuthError(McAuthError):
    """Base class for Xbox Live / XSTS failures."""


class XSTSError(XboxAuthError):
    """Generic XSTS rejection — used when the XErr code is unrecognized."""

    def __init__(self, message: str, *, xerr: int | None = None) -> None:
        super().__init__(message)
        self.xerr: int | None = xerr


class NoXboxAccountError(XSTSError):
    """The MSA account does not have an Xbox Live profile attached.

    Mapped from XErr ``2148916233``. The user has to sign in to xbox.com
    once to create the profile.
    """


class RegionBlockedError(XSTSError):
    """The account's region prohibits Xbox Live use.

    Mapped from XErr ``2148916235``.
    """


class VerifyAgeRequiredError(XSTSError):
    """The account must verify its age before Xbox Live will issue tokens.

    Mapped from XErr ``2148916236``.
    """


class AdultVerificationRequiredError(XSTSError):
    """The account requires adult verification (region-specific).

    Mapped from XErr ``2148916237``.
    """


class ChildAccountError(XSTSError):
    """The account is a child account not enrolled in a Family Pack.

    Mapped from XErr ``2148916238``.
    """


class MinecraftAuthError(McAuthError):
    """Base class for Mojang/Minecraft services failures."""


class MinecraftProfileNotFoundError(MinecraftAuthError):
    """The authenticated account does not own Minecraft."""


# --- API tree (former mcapi) ---------------------------------------------


class McApiError(McApiAuthError):
    """Base class for every REST-API-side error."""


class HttpError(McApiError):
    """An HTTP response we did not expect (non-2xx that wasn't otherwise typed)."""

    def __init__(self, status_code: int, body: str, *, url: str | None = None) -> None:
        suffix = f" ({url})" if url else ""
        super().__init__(f"HTTP {status_code}{suffix}: {body[:200]}")
        self.status_code: int = status_code
        self.body: str = body
        self.url: str | None = url


class NotFoundError(McApiError):
    """The requested resource (profile, name, UUID, version, …) does not exist."""


class BadRequestError(McApiError):
    """The server rejected our request as malformed (HTTP 400)."""


class UnauthorizedError(McApiError):
    """The access token is missing, expired, or rejected (HTTP 401)."""


class ForbiddenError(McApiError):
    """The request was authenticated but not permitted (HTTP 403)."""


class RateLimitedError(McApiError):
    """The server returned HTTP 429.

    ``retry_after`` is parsed from the ``Retry-After`` response header
    when present.

    ``rate_limit_result`` carries the value of Mojang's
    ``X-Minecraft-Rate-Limit-Result`` header (observed values:
    ``"OVER_LIMIT"`` on a 429, ``"UNDER_LIMIT"`` on success). The
    header is purely informational — it tracks the response status
    code one-to-one in practice — but is exposed for logging and
    round-tripping.
    """

    def __init__(
        self,
        message: str = "rate limited",
        *,
        retry_after: float | None = None,
        rate_limit_result: str | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after: float | None = retry_after
        self.rate_limit_result: str | None = rate_limit_result


class InvalidProfileError(McApiError):
    """A profile response is structurally broken (missing fields, bad base64, …)."""


class NameTakenError(McApiError):
    """A name-change request was rejected because the name is taken/in-cooldown."""


class NameNotAllowedError(McApiError):
    """Mojang's name filter rejected the desired username."""


class TooManyNamesError(McApiError):
    """The bulk lookup was passed more names than the server accepts (max 10)."""


# --- XErr → exception mapping --------------------------------------------

_XERR_MAP: dict[int, type[XSTSError]] = {
    XERR_NO_XBOX_ACCOUNT: NoXboxAccountError,
    XERR_REGION_BLOCKED: RegionBlockedError,
    XERR_VERIFY_AGE_REQUIRED: VerifyAgeRequiredError,
    XERR_REQUIRES_ADULT_VERIFICATION: AdultVerificationRequiredError,
    XERR_CHILD_ACCOUNT: ChildAccountError,
}

_XERR_MESSAGES: dict[int, str] = {
    XERR_NO_XBOX_ACCOUNT: (
        "the Microsoft account has no Xbox Live profile attached; "
        "sign in to xbox.com once to create one"
    ),
    XERR_REGION_BLOCKED: ("the account's country/region is not allowed to use Xbox Live"),
    XERR_VERIFY_AGE_REQUIRED: (
        "the account must verify its age in Microsoft account settings "
        "before Xbox Live will issue tokens"
    ),
    XERR_REQUIRES_ADULT_VERIFICATION: ("the account requires adult verification (region-specific)"),
    XERR_CHILD_ACCOUNT: (
        "the account is a child account; a parent must add it to a "
        "Microsoft Family group with adult members"
    ),
}


def xerr_to_exception(xerr: int | None) -> XSTSError:
    """Return a typed exception for an XSTS ``XErr`` code."""
    if xerr is None:
        return XSTSError("XSTS authorization failed (no XErr code in response)")
    cls = _XERR_MAP.get(xerr, XSTSError)
    msg = _XERR_MESSAGES.get(xerr, f"XSTS authorization failed with XErr {xerr}")
    return cls(msg, xerr=xerr)

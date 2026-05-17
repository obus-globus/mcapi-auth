""":class:`MsaApplicationConfig` — bundle MSA OAuth endpoint + scope parameters.

Mirrors RaphiMC's ``MsaApplicationConfig`` in spirit: a single
declarative value type that pins ``client_id``, ``scope``, redirect /
authorize / token / device-code URLs, and XBL ``RpsTicket`` prefix into
one object so callers don't have to plumb six keyword arguments through
every helper.

Pre-built classmethods cover the two common cases:

* :meth:`MsaApplicationConfig.v2` — modern consumers v2 endpoint with
  the public Minecraft launcher client_id by default.
* :meth:`MsaApplicationConfig.v1_launcher` — legacy Live-Connect v1
  endpoint with the compressed-form launcher client_id and the
  ``MBI_SSL`` scope.
* :meth:`MsaApplicationConfig.from_known` — resolve a friendly alias
  (``"prism"``, ``"liquidlauncher"``, ``"bedrock-android"``, …) into
  the correctly-configured v1 or v2 config.

The legacy ``login*`` functions still accept the individual
``client_id=`` / ``scope=`` parameters; this class is offered as an
additional ``app=`` keyword on the new :class:`~mcapi_auth.auth.chain.AuthChain`
API and is also useful as a value passed around by application code.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Self

from .._constants import (
    LIVE_CONNECT_AUTHORIZE_URL,
    LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    LIVE_CONNECT_SCOPE_MBI_SSL,
    LIVE_CONNECT_TOKEN_URL,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    MSA_AUTHORIZE_URL,
    MSA_DEVICE_CODE_URL,
    MSA_SCOPE,
    MSA_TOKEN_URL,
    PRISM_LAUNCHER_CLIENT_ID,
    is_v1_client_id,
    resolve_browser_redirect,
    resolve_client_id,
)

__all__ = ["MsaApplicationConfig"]


@dataclass(frozen=True, slots=True)
class MsaApplicationConfig:
    """All MSA-side knobs for a single auth flow, bundled.

    Attributes:
        client_id: The MSA / Azure-AD application client_id. Resolved
            (no alias lookup here — pre-resolve via
            :func:`mcapi_auth.resolve_client_id` if needed).
        scope: OAuth scope. Defaults to the v2 ``XboxLive.signin
            offline_access`` scope.
        authorize_url: Authorization endpoint. v2 by default; flip to
            :data:`mcapi_auth.LIVE_CONNECT_AUTHORIZE_URL` for v1.
        token_url: Token endpoint. v2 by default.
        device_code_url: Device-code endpoint. v1 endpoints don't have
            a device-code flow; for v1 configs this is left at the v2
            value but should not be used.
        redirect_uri: Default redirect URI for the browser flow.
            ``None`` means "let the caller pick" (the loopback flow
            will pick a free port + ``/callback`` unless overridden).
        xbl_use_d_prefix: When ``True`` (the default for v2 / Azure-AD
            client_ids), the MSA access token is prefixed with ``d=``
            before sending to ``user.auth.xboxlive.com``. v1 /
            Live-Connect tokens are sent raw — see
            :func:`mcapi_auth.authenticate_xbl` for details.
        is_v1: ``True`` if this config targets the legacy Live-Connect
            v1 endpoints. Auto-derived from ``client_id`` shape if you
            use the constructor directly; the classmethods set it
            explicitly.
    """

    client_id: str
    scope: str = MSA_SCOPE
    authorize_url: str = MSA_AUTHORIZE_URL
    token_url: str = MSA_TOKEN_URL
    device_code_url: str = MSA_DEVICE_CODE_URL
    redirect_uri: str | None = None
    xbl_use_d_prefix: bool = True
    is_v1: bool = field(default=False)

    @classmethod
    def v2(
        cls,
        client_id: str = PRISM_LAUNCHER_CLIENT_ID,
        *,
        scope: str = MSA_SCOPE,
        redirect_uri: str | None = None,
    ) -> Self:
        """Build a v2 / consumers endpoint config (modern flows)."""
        return cls(
            client_id=client_id,
            scope=scope,
            authorize_url=MSA_AUTHORIZE_URL,
            token_url=MSA_TOKEN_URL,
            device_code_url=MSA_DEVICE_CODE_URL,
            redirect_uri=redirect_uri,
            xbl_use_d_prefix=True,
            is_v1=False,
        )

    @classmethod
    def v1_launcher(
        cls,
        client_id: str = MINECRAFT_LAUNCHER_V1_CLIENT_ID,
        *,
        scope: str = LIVE_CONNECT_SCOPE_MBI_SSL,
        redirect_uri: str = LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    ) -> Self:
        """Build a v1 / Live-Connect endpoint config (legacy launcher / Bedrock)."""
        return cls(
            client_id=client_id,
            scope=scope,
            authorize_url=LIVE_CONNECT_AUTHORIZE_URL,
            token_url=LIVE_CONNECT_TOKEN_URL,
            device_code_url=MSA_DEVICE_CODE_URL,  # unused for v1
            redirect_uri=redirect_uri,
            xbl_use_d_prefix=False,
            is_v1=True,
        )

    @classmethod
    def from_known(cls, alias_or_id: str) -> Self:
        """Resolve a known alias (or raw client_id) into a correctly-shaped config.

        Looks up the alias via :func:`mcapi_auth.resolve_client_id`,
        decides v1 vs v2 from :func:`mcapi_auth.is_v1_client_id`, and
        applies the per-client redirect override from
        :data:`mcapi_auth.KNOWN_CLIENT_REDIRECTS` when present.
        """
        client_id = resolve_client_id(alias_or_id)
        if is_v1_client_id(client_id):
            return cls.v1_launcher(client_id=client_id)
        override = resolve_browser_redirect(client_id)
        # The override is (host, path) without a port; we leave
        # ``redirect_uri`` as ``None`` so the loopback flow can pick a
        # port, but stash the override on the config for callers that
        # want to honor it without an explicit lookup.
        redirect = None
        if override is not None:
            host, path = override
            redirect = f"http://{host}{path}"  # for display / docs
        return cls.v2(client_id=client_id, redirect_uri=redirect)

    def with_redirect(self, redirect_uri: str | None) -> Self:
        """Return a copy with :attr:`redirect_uri` replaced."""
        return replace(self, redirect_uri=redirect_uri)

    def with_scope(self, scope: str) -> Self:
        """Return a copy with :attr:`scope` replaced (e.g. to add extra scopes)."""
        return replace(self, scope=scope)

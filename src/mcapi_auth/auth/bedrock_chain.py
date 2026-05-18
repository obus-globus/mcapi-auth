""":class:`BedrockAuthManager` — full Bedrock auth chain with lazy refresh.

Parallel to :class:`~mcapi_auth.auth.chain.AuthChain` for the Bedrock leg:
holds the persistent identity (device keypair + device id + ES384 client
keypair) and *every* downstream token (MSA → DeviceToken → Sisu (x2) →
PlayFab → certificate chain → franchise session → multiplayer token),
each wrapped in a :class:`~mcapi_auth.auth.holder.Holder` so they refresh
independently when expired.

Mirrors RaphiMC's ``BedrockMinecraftChain`` model: serialise the whole
thing to JSON on every rotation, restore it on next start, and let each
stage refresh on demand instead of re-deriving the full chain from the
MSA refresh token on every cold start.

Typical lifecycle::

    mgr = await BedrockAuthManager.login(
        app=MsaApplicationConfig.from_known("bedrock-win32"),
    )
    mgr.on_change(lambda *_: state.save(mgr.dump_json()))

    while running:
        mp = await mgr.get_multiplayer_token()
        await join_server(mp.token)

    # later, in another process:
    mgr = BedrockAuthManager.load_json(state.load(), app=...)
    cert = await mgr.get_certificate_chain()

The XSTS token surfaced by :meth:`get_bedrock_xsts` /
:meth:`get_playfab_xsts` is a :class:`~mcapi_auth.auth.xbox_device.XblXstsToken`
— shape-compatible with :class:`~mcapi_auth.XSTSToken` (both expose
``.token`` and ``.userhash``), so it drops into any helper that accepts
the latter.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Self
from uuid import UUID, uuid4

import httpx
from whenever import Instant

from .._constants import BEDROCK_WIN32_CLIENT_ID
from .._models import McModel
from ..api.bedrock import (
    BedrockKeyPair,
    MinecraftCertificateChain,
    MinecraftMultiplayerToken,
    MinecraftSession,
    minecraft_authenticate,
    start_minecraft_multiplayer_session,
    start_minecraft_session,
)
from ..api.playfab import PlayFabToken, playfab_login_with_xbox
from .app_config import MsaApplicationConfig
from .flow import _invoke_callback  # pyright: ignore[reportPrivateUsage]
from .holder import Holder
from .msa import (
    DeviceCodePrompt,
    MSATokens,
    exchange_refresh_token,
    poll_for_device_code_token,
    request_device_code,
)
from .xbox_device import (
    XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY,
    XBL_XSTS_BEDROCK_RELYING_PARTY,
    XblDeviceKeyPair,
    XblDeviceToken,
    XblSisuTokens,
    XblXstsToken,
    authenticate_xbl_device,
    sisu_authorize,
)

__all__ = [
    "DEFAULT_BEDROCK_GAME_VERSION",
    "BedrockAuthManager",
    "BedrockChainChangeListener",
]

logger = logging.getLogger(__name__)

DEFAULT_BEDROCK_GAME_VERSION = "1.21.50"
"""Default Minecraft Bedrock client version string used by the franchise session.

Tracks a recent-enough release that Mojang's gatekeeper accepts it.
Override via the ``game_version=`` constructor argument when needed.
"""

# Synthetic XBL device-token / Sisu-XSTS expiry safety: each ``NotAfter``
# is parsed from the response (we set _do_ have typed expiries here),
# but XBL clocks can drift; clamp to a 14h safety bound on top of the
# typed value for the device token to dodge spurious 401 storms.
_DEVICE_TOKEN_MAX_LIFETIME_S = 14 * 3600

type BedrockChainChangeListener = Callable[[str, Any, Any], None | Awaitable[None]]
"""Signature for :class:`BedrockAuthManager` change listeners.

Called as ``(stage_name, old_value, new_value)`` whenever any stage
rotates. ``stage_name`` is one of ``"msa"``, ``"device"``,
``"bedrock_sisu"``, ``"playfab_sisu"``, ``"playfab"``, ``"cert_chain"``,
``"franchise_session"``, ``"multiplayer_token"``.
"""


class _BedrockChainSnapshot(McModel):
    """Plain serialisable form of the Bedrock chain (for dump / load)."""

    msa: MSATokens
    device_keypair_pem: str
    device_id: UUID
    bedrock_keypair_pem: str
    game_version: str = DEFAULT_BEDROCK_GAME_VERSION
    bedrock_client_id: str = BEDROCK_WIN32_CLIENT_ID
    device_token: XblDeviceToken | None = None
    bedrock_sisu: XblSisuTokens | None = None
    playfab_sisu: XblSisuTokens | None = None
    playfab_token: PlayFabToken | None = None
    cert_chain: MinecraftCertificateChain | None = None
    franchise_session: MinecraftSession | None = None
    multiplayer_token: MinecraftMultiplayerToken | None = None
    save_version: int = 1


class BedrockAuthManager:
    """Bedrock auth chain with lazy refresh + change listeners.

    Construction is normally via :meth:`login`, :meth:`from_msa`, or
    :meth:`load_json`. The constructor itself is public for tests and
    advanced use cases.

    Args:
        app: :class:`MsaApplicationConfig` for the OAuth app. Stored
            verbatim; refreshes use the same config. Defaults to a v2
            config bound to :data:`BEDROCK_WIN32_CLIENT_ID`.
        msa: Initial MSA tokens. Required.
        device_keypair: Persistent device keypair (ES256 / P-256). If
            omitted, a fresh one is generated — but persisting it
            across runs avoids looking like a new Xbox device on every
            login.
        device_id: Stable device UUID. Generated if omitted.
        bedrock_keypair: Persistent client identity keypair (ES384 /
            P-384) used for the certificate chain. Generated if omitted.
        bedrock_client_id: Microsoft *title* client id used as the Sisu
            ``AppId``. Defaults to :data:`BEDROCK_WIN32_CLIENT_ID`.
        game_version: Minecraft Bedrock version string sent to the
            franchise service. Override per-build if needed.
        device_token / bedrock_sisu / playfab_sisu / playfab_token /
        cert_chain / franchise_session / multiplayer_token: Cached
            downstream tokens. ``None`` means "re-derive on next access".
        http_client: Optional :class:`httpx.AsyncClient` reused across
            refreshes. A fresh one is acquired per-call otherwise.
    """

    def __init__(
        self,
        *,
        app: MsaApplicationConfig | None = None,
        msa: MSATokens,
        device_keypair: XblDeviceKeyPair | None = None,
        device_id: UUID | None = None,
        bedrock_keypair: BedrockKeyPair | None = None,
        bedrock_client_id: str = BEDROCK_WIN32_CLIENT_ID,
        game_version: str = DEFAULT_BEDROCK_GAME_VERSION,
        device_token: XblDeviceToken | None = None,
        bedrock_sisu: XblSisuTokens | None = None,
        playfab_sisu: XblSisuTokens | None = None,
        playfab_token: PlayFabToken | None = None,
        cert_chain: MinecraftCertificateChain | None = None,
        franchise_session: MinecraftSession | None = None,
        multiplayer_token: MinecraftMultiplayerToken | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._app: MsaApplicationConfig = (
            app if app is not None else MsaApplicationConfig.v2(client_id=bedrock_client_id)
        )
        self._bedrock_client_id = bedrock_client_id
        self._game_version = game_version
        self._http_client = http_client
        self._chain_listeners: list[BedrockChainChangeListener] = []

        self._device_keypair: XblDeviceKeyPair = (
            device_keypair if device_keypair is not None else XblDeviceKeyPair.generate()
        )
        self._device_id: UUID = device_id if device_id is not None else uuid4()
        self._bedrock_keypair: BedrockKeyPair = (
            bedrock_keypair if bedrock_keypair is not None else BedrockKeyPair.generate()
        )

        self._msa = Holder[MSATokens](
            msa,
            refresher=self._refresh_msa,
            expires_at=lambda v: v.expires_at,
            name="MSA",
        )
        self._msa.add_listener(self._make_stage_dispatcher("msa"))
        self._msa.add_listener(self._on_msa_rotated)

        self._device_token: Holder[XblDeviceToken] | None = None
        self._bedrock_sisu: Holder[XblSisuTokens] | None = None
        self._playfab_sisu: Holder[XblSisuTokens] | None = None
        self._playfab_token: Holder[PlayFabToken] | None = None
        self._cert_chain: Holder[MinecraftCertificateChain] | None = None
        self._franchise_session: Holder[MinecraftSession] | None = None
        self._multiplayer_token: Holder[MinecraftMultiplayerToken] | None = None

        if device_token is not None:
            self._device_token = self._build_device_holder(device_token)
        if bedrock_sisu is not None:
            self._bedrock_sisu = self._build_bedrock_sisu_holder(bedrock_sisu)
        if playfab_sisu is not None:
            self._playfab_sisu = self._build_playfab_sisu_holder(playfab_sisu)
        if playfab_token is not None:
            self._playfab_token = self._build_playfab_holder(playfab_token)
        if cert_chain is not None:
            self._cert_chain = self._build_cert_chain_holder(cert_chain)
        if franchise_session is not None:
            self._franchise_session = self._build_franchise_holder(franchise_session)
        if multiplayer_token is not None:
            self._multiplayer_token = self._build_multiplayer_holder(multiplayer_token)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    async def login(
        cls,
        *,
        app: MsaApplicationConfig | None = None,
        on_device_code: Callable[[DeviceCodePrompt], None | Awaitable[None]] | None = None,
        device_keypair: XblDeviceKeyPair | None = None,
        device_id: UUID | None = None,
        bedrock_keypair: BedrockKeyPair | None = None,
        bedrock_client_id: str = BEDROCK_WIN32_CLIENT_ID,
        game_version: str = DEFAULT_BEDROCK_GAME_VERSION,
        prime: bool = True,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Run the device-code flow end-to-end and return a primed manager.

        If ``prime`` is true (the default), the manager drives the chain
        all the way down to the multiplayer token before returning, so
        that callers can immediately ``dump_json()`` a fully-populated
        snapshot. Set ``prime=False`` to skip — useful in tests or when
        the caller only needs the cert chain.
        """
        actual_app = (
            app if app is not None else MsaApplicationConfig.v2(client_id=bedrock_client_id)
        )
        if actual_app.is_v1:
            raise ValueError(
                "BedrockAuthManager.login() targets the v2 Azure-AD endpoints "
                "(the Bedrock client_ids are registered there); pass a v2 "
                "MsaApplicationConfig, not v1_launcher()."
            )
        prompt, pending = await request_device_code(
            client_id=actual_app.client_id, http_client=http_client
        )
        if on_device_code is not None:
            await _invoke_callback(on_device_code, prompt)
        else:
            print(prompt.message or f"Visit {prompt.verification_uri} and enter {prompt.user_code}")
        msa = await poll_for_device_code_token(
            pending, client_id=actual_app.client_id, http_client=http_client
        )
        mgr = cls(
            app=actual_app,
            msa=msa,
            device_keypair=device_keypair,
            device_id=device_id,
            bedrock_keypair=bedrock_keypair,
            bedrock_client_id=bedrock_client_id,
            game_version=game_version,
            http_client=http_client,
        )
        if prime:
            await mgr.get_multiplayer_token()
        return mgr

    @classmethod
    def from_msa(
        cls,
        msa: MSATokens,
        *,
        app: MsaApplicationConfig | None = None,
        device_keypair: XblDeviceKeyPair | None = None,
        device_id: UUID | None = None,
        bedrock_keypair: BedrockKeyPair | None = None,
        bedrock_client_id: str = BEDROCK_WIN32_CLIENT_ID,
        game_version: str = DEFAULT_BEDROCK_GAME_VERSION,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Bridge an existing MSA token into a manager.

        Useful when an :class:`~mcapi_auth.auth.chain.AuthChain` already
        holds a refresh token you'd like to reuse for the Bedrock leg.
        """
        return cls(
            app=app,
            msa=msa,
            device_keypair=device_keypair,
            device_id=device_id,
            bedrock_keypair=bedrock_keypair,
            bedrock_client_id=bedrock_client_id,
            game_version=game_version,
            http_client=http_client,
        )

    @classmethod
    def load_json(
        cls,
        data: str | bytes,
        *,
        app: MsaApplicationConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Restore a manager previously serialised with :meth:`dump_json`.

        The :class:`MsaApplicationConfig` is not serialised; pass the
        same one (or a compatible one) you'd use for a fresh login. If
        omitted, defaults to a v2 config bound to the bedrock title
        client id stored in the snapshot.
        """
        snap = _BedrockChainSnapshot.model_validate_json(data)
        return cls(
            app=app,
            msa=snap.msa,
            device_keypair=XblDeviceKeyPair.from_pem(snap.device_keypair_pem),
            device_id=snap.device_id,
            bedrock_keypair=BedrockKeyPair.from_pem(snap.bedrock_keypair_pem),
            bedrock_client_id=snap.bedrock_client_id,
            game_version=snap.game_version,
            device_token=snap.device_token,
            bedrock_sisu=snap.bedrock_sisu,
            playfab_sisu=snap.playfab_sisu,
            playfab_token=snap.playfab_token,
            cert_chain=snap.cert_chain,
            franchise_session=snap.franchise_session,
            multiplayer_token=snap.multiplayer_token,
            http_client=http_client,
        )

    # ------------------------------------------------------------------
    # Public access
    # ------------------------------------------------------------------

    @property
    def app(self) -> MsaApplicationConfig:
        """The :class:`MsaApplicationConfig` driving this manager."""
        return self._app

    @property
    def device_keypair(self) -> XblDeviceKeyPair:
        """The persistent Xbox device keypair."""
        return self._device_keypair

    @property
    def device_id(self) -> UUID:
        """The persistent device UUID."""
        return self._device_id

    @property
    def bedrock_keypair(self) -> BedrockKeyPair:
        """The persistent ES384 client identity keypair."""
        return self._bedrock_keypair

    @property
    def bedrock_client_id(self) -> str:
        """The Sisu ``AppId`` / Bedrock title client id."""
        return self._bedrock_client_id

    @property
    def game_version(self) -> str:
        """The Bedrock client game-version string used for franchise sessions."""
        return self._game_version

    async def get_msa_tokens(self, *, leeway: float = 30.0) -> MSATokens:
        """Return MSA tokens, refreshing via the refresh-token grant if expired."""
        return await self._msa.get_up_to_date(leeway=leeway)

    async def get_device_token(self, *, leeway: float = 30.0) -> XblDeviceToken:
        """Return the Xbox Live device token, refreshing if expired."""
        if self._device_token is None:
            tok = await authenticate_xbl_device(
                self._device_keypair,
                device_id=self._device_id,
                http_client=self._http_client,
            )
            self._device_token = self._build_device_holder(tok)
            await self._dispatch("device", None, tok)
            return tok
        return await self._device_token.get_up_to_date(leeway=leeway)

    async def get_bedrock_sisu(self, *, leeway: float = 30.0) -> XblSisuTokens:
        """Return the Sisu tokens scoped to ``multiplayer.minecraft.net``."""
        if self._bedrock_sisu is None:
            tokens = await self._do_sisu(XBL_XSTS_BEDROCK_RELYING_PARTY)
            self._bedrock_sisu = self._build_bedrock_sisu_holder(tokens)
            await self._dispatch("bedrock_sisu", None, tokens)
            return tokens
        return await self._bedrock_sisu.get_up_to_date(leeway=leeway)

    async def get_bedrock_xsts(self, *, leeway: float = 30.0) -> XblXstsToken:
        """Convenience: return just the XSTS half of the Bedrock-scoped Sisu."""
        return (await self.get_bedrock_sisu(leeway=leeway)).xsts_token

    async def get_playfab_sisu(self, *, leeway: float = 30.0) -> XblSisuTokens:
        """Return the Sisu tokens scoped to the PlayFab Bedrock RP."""
        if self._playfab_sisu is None:
            tokens = await self._do_sisu(XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY)
            self._playfab_sisu = self._build_playfab_sisu_holder(tokens)
            await self._dispatch("playfab_sisu", None, tokens)
            return tokens
        return await self._playfab_sisu.get_up_to_date(leeway=leeway)

    async def get_playfab_xsts(self, *, leeway: float = 30.0) -> XblXstsToken:
        """Convenience: return just the XSTS half of the PlayFab-scoped Sisu."""
        return (await self.get_playfab_sisu(leeway=leeway)).xsts_token

    async def get_playfab_token(self, *, leeway: float = 30.0) -> PlayFabToken:
        """Return the PlayFab login token, refreshing if expired."""
        if self._playfab_token is None:
            xsts = await self.get_playfab_xsts(leeway=leeway)
            tok = await playfab_login_with_xbox(
                xsts,  # type: ignore[arg-type]
                http_client=self._http_client,
            )
            self._playfab_token = self._build_playfab_holder(tok)
            await self._dispatch("playfab", None, tok)
            return tok
        return await self._playfab_token.get_up_to_date(leeway=leeway)

    async def get_certificate_chain(self, *, leeway: float = 30.0) -> MinecraftCertificateChain:
        """Return the Mojang-signed Bedrock certificate chain."""
        if self._cert_chain is None:
            xsts = await self.get_bedrock_xsts(leeway=leeway)
            chain = await minecraft_authenticate(
                xsts,  # type: ignore[arg-type]
                self._bedrock_keypair,
                http_client=self._http_client,
            )
            self._cert_chain = self._build_cert_chain_holder(chain)
            await self._dispatch("cert_chain", None, chain)
            return chain
        return await self._cert_chain.get_up_to_date(leeway=leeway)

    async def get_franchise_session(self, *, leeway: float = 30.0) -> MinecraftSession:
        """Return the franchise-service :class:`MinecraftSession`."""
        if self._franchise_session is None:
            pf = await self.get_playfab_token(leeway=leeway)
            sess = await start_minecraft_session(
                pf.session_ticket,
                game_version=self._game_version,
                device_id=self._device_id,
                http_client=self._http_client,
            )
            self._franchise_session = self._build_franchise_holder(sess)
            await self._dispatch("franchise_session", None, sess)
            return sess
        return await self._franchise_session.get_up_to_date(leeway=leeway)

    async def get_multiplayer_token(self, *, leeway: float = 30.0) -> MinecraftMultiplayerToken:
        """Return the Bedrock multiplayer "signed token" used to join servers."""
        if self._multiplayer_token is None:
            sess = await self.get_franchise_session(leeway=leeway)
            mp = await start_minecraft_multiplayer_session(
                sess, self._bedrock_keypair, http_client=self._http_client
            )
            self._multiplayer_token = self._build_multiplayer_holder(mp)
            await self._dispatch("multiplayer_token", None, mp)
            return mp
        return await self._multiplayer_token.get_up_to_date(leeway=leeway)

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def on_change(self, cb: BedrockChainChangeListener) -> None:
        """Register a chain-wide listener.

        Fires on every stage rotation with ``(stage_name, old, new)``.
        Useful for "persist on every refresh" patterns::

            mgr.on_change(lambda *_: state.save(mgr.dump_json()))
        """
        self._chain_listeners.append(cb)

    def remove_listener(self, cb: BedrockChainChangeListener) -> bool:
        """Remove a previously-registered chain listener."""
        try:
            self._chain_listeners.remove(cb)
        except ValueError:
            return False
        return True

    @property
    def msa_holder(self) -> Holder[MSATokens]:
        """The MSA :class:`Holder` (always present)."""
        return self._msa

    @property
    def device_holder(self) -> Holder[XblDeviceToken] | None:
        """The device-token :class:`Holder` if built yet, else ``None``."""
        return self._device_token

    @property
    def bedrock_sisu_holder(self) -> Holder[XblSisuTokens] | None:
        """The Bedrock-scoped Sisu :class:`Holder` if built yet, else ``None``."""
        return self._bedrock_sisu

    @property
    def playfab_sisu_holder(self) -> Holder[XblSisuTokens] | None:
        """The PlayFab-scoped Sisu :class:`Holder` if built yet, else ``None``."""
        return self._playfab_sisu

    @property
    def playfab_holder(self) -> Holder[PlayFabToken] | None:
        """The PlayFab-token :class:`Holder` if built yet, else ``None``."""
        return self._playfab_token

    @property
    def cert_chain_holder(self) -> Holder[MinecraftCertificateChain] | None:
        """The certificate-chain :class:`Holder` if built yet, else ``None``."""
        return self._cert_chain

    @property
    def franchise_holder(self) -> Holder[MinecraftSession] | None:
        """The franchise-session :class:`Holder` if built yet, else ``None``."""
        return self._franchise_session

    @property
    def multiplayer_holder(self) -> Holder[MinecraftMultiplayerToken] | None:
        """The multiplayer-token :class:`Holder` if built yet, else ``None``."""
        return self._multiplayer_token

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def dump_json(self, *, indent: int | None = None) -> str:
        """Serialise the manager to JSON (identity + every cached token).

        The :class:`MsaApplicationConfig` itself is *not* serialised
        (it's static config, not state) — pass the same one back to
        :meth:`load_json`. The persistent device + bedrock keypairs and
        the device UUID **are** serialised, so a round-trip preserves
        the player's stable Xbox identity.
        """
        snap = _BedrockChainSnapshot(
            msa=self._msa.get_cached(),
            device_keypair_pem=self._device_keypair.private_key_pem(),
            device_id=self._device_id,
            bedrock_keypair_pem=self._bedrock_keypair.private_key_pem(),
            game_version=self._game_version,
            bedrock_client_id=self._bedrock_client_id,
            device_token=self._device_token.get_cached() if self._device_token else None,
            bedrock_sisu=self._bedrock_sisu.get_cached() if self._bedrock_sisu else None,
            playfab_sisu=self._playfab_sisu.get_cached() if self._playfab_sisu else None,
            playfab_token=self._playfab_token.get_cached() if self._playfab_token else None,
            cert_chain=self._cert_chain.get_cached() if self._cert_chain else None,
            franchise_session=(
                self._franchise_session.get_cached() if self._franchise_session else None
            ),
            multiplayer_token=(
                self._multiplayer_token.get_cached() if self._multiplayer_token else None
            ),
        )
        text = snap.model_dump_json()
        if indent is None:
            return text
        return json.dumps(json.loads(text), indent=indent)

    # ------------------------------------------------------------------
    # Refreshers
    # ------------------------------------------------------------------

    async def _refresh_msa(self, old: MSATokens) -> MSATokens:
        return await exchange_refresh_token(
            old.refresh_token,
            client_id=self._app.client_id,
            http_client=self._http_client,
            token_url=self._app.token_url,
            scope=self._app.scope,
        )

    async def _refresh_device_token(self, old: XblDeviceToken) -> XblDeviceToken:
        del old
        return await authenticate_xbl_device(
            self._device_keypair,
            device_id=self._device_id,
            http_client=self._http_client,
        )

    async def _do_sisu(self, relying_party: str) -> XblSisuTokens:
        msa = await self.get_msa_tokens()
        device = await self.get_device_token()
        return await sisu_authorize(
            msa.access_token,
            device,
            self._device_keypair,
            client_id=self._bedrock_client_id,
            relying_party=relying_party,
            http_client=self._http_client,
        )

    async def _refresh_bedrock_sisu(self, old: XblSisuTokens) -> XblSisuTokens:
        del old
        return await self._do_sisu(XBL_XSTS_BEDROCK_RELYING_PARTY)

    async def _refresh_playfab_sisu(self, old: XblSisuTokens) -> XblSisuTokens:
        del old
        return await self._do_sisu(XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY)

    async def _refresh_playfab_token(self, old: PlayFabToken) -> PlayFabToken:
        del old
        xsts = await self.get_playfab_xsts()
        return await playfab_login_with_xbox(
            xsts,  # type: ignore[arg-type]
            http_client=self._http_client,
        )

    async def _refresh_cert_chain(
        self, old: MinecraftCertificateChain
    ) -> MinecraftCertificateChain:
        del old
        xsts = await self.get_bedrock_xsts()
        return await minecraft_authenticate(
            xsts,  # type: ignore[arg-type]
            self._bedrock_keypair,
            http_client=self._http_client,
        )

    async def _refresh_franchise_session(self, old: MinecraftSession) -> MinecraftSession:
        del old
        pf = await self.get_playfab_token()
        return await start_minecraft_session(
            pf.session_ticket,
            game_version=self._game_version,
            device_id=self._device_id,
            http_client=self._http_client,
        )

    async def _refresh_multiplayer_token(
        self, old: MinecraftMultiplayerToken
    ) -> MinecraftMultiplayerToken:
        del old
        sess = await self.get_franchise_session()
        return await start_minecraft_multiplayer_session(
            sess, self._bedrock_keypair, http_client=self._http_client
        )

    # ------------------------------------------------------------------
    # Holder builders
    # ------------------------------------------------------------------

    def _device_token_expiry(self, value: XblDeviceToken) -> Instant:
        # Clamp the typed NotAfter to a max safety lifetime — XBL device
        # tokens are nominally ~24h but their clocks drift; rotating
        # well before that avoids occasional 401 storms.
        typed = value.expires_at
        bound = Instant.now().add(seconds=_DEVICE_TOKEN_MAX_LIFETIME_S)
        return min(typed, bound)

    def _build_device_holder(self, value: XblDeviceToken) -> Holder[XblDeviceToken]:
        h = Holder[XblDeviceToken](
            value,
            refresher=self._refresh_device_token,
            expires_at=self._device_token_expiry,
            name="XblDeviceToken",
        )
        h.add_listener(self._make_stage_dispatcher("device"))
        h.add_listener(self._on_device_rotated)
        return h

    def _build_bedrock_sisu_holder(self, value: XblSisuTokens) -> Holder[XblSisuTokens]:
        h = Holder[XblSisuTokens](
            value,
            refresher=self._refresh_bedrock_sisu,
            expires_at=lambda v: v.xsts_token.expires_at,
            name="BedrockSisu",
        )
        h.add_listener(self._make_stage_dispatcher("bedrock_sisu"))
        h.add_listener(self._on_bedrock_sisu_rotated)
        return h

    def _build_playfab_sisu_holder(self, value: XblSisuTokens) -> Holder[XblSisuTokens]:
        h = Holder[XblSisuTokens](
            value,
            refresher=self._refresh_playfab_sisu,
            expires_at=lambda v: v.xsts_token.expires_at,
            name="PlayFabSisu",
        )
        h.add_listener(self._make_stage_dispatcher("playfab_sisu"))
        h.add_listener(self._on_playfab_sisu_rotated)
        return h

    def _build_playfab_holder(self, value: PlayFabToken) -> Holder[PlayFabToken]:
        h = Holder[PlayFabToken](
            value,
            refresher=self._refresh_playfab_token,
            expires_at=lambda v: v.expires_at,
            name="PlayFabToken",
        )
        h.add_listener(self._make_stage_dispatcher("playfab"))
        h.add_listener(self._on_playfab_rotated)
        return h

    def _build_cert_chain_holder(
        self, value: MinecraftCertificateChain
    ) -> Holder[MinecraftCertificateChain]:
        h = Holder[MinecraftCertificateChain](
            value,
            refresher=self._refresh_cert_chain,
            expires_at=lambda v: v.expires_at,
            name="MinecraftCertificateChain",
        )
        h.add_listener(self._make_stage_dispatcher("cert_chain"))
        return h

    def _build_franchise_holder(self, value: MinecraftSession) -> Holder[MinecraftSession]:
        h = Holder[MinecraftSession](
            value,
            refresher=self._refresh_franchise_session,
            expires_at=lambda v: v.expires_at,
            name="MinecraftSession",
        )
        h.add_listener(self._make_stage_dispatcher("franchise_session"))
        h.add_listener(self._on_franchise_rotated)
        return h

    def _build_multiplayer_holder(
        self, value: MinecraftMultiplayerToken
    ) -> Holder[MinecraftMultiplayerToken]:
        h = Holder[MinecraftMultiplayerToken](
            value,
            refresher=self._refresh_multiplayer_token,
            expires_at=lambda v: v.expires_at,
            name="MinecraftMultiplayerToken",
        )
        h.add_listener(self._make_stage_dispatcher("multiplayer_token"))
        return h

    def _make_stage_dispatcher(self, stage: str) -> Callable[[Any, Any], Awaitable[None]]:
        async def _dispatcher(old: Any, new: Any) -> None:
            await self._dispatch(stage, old, new)

        return _dispatcher

    # ------------------------------------------------------------------
    # Invalidation cascade
    # ------------------------------------------------------------------

    async def _on_msa_rotated(self, _old: MSATokens | None, _new: MSATokens) -> None:
        # MSA rotation invalidates everything that consumes the access
        # token. The device token doesn't (it's keypair-bound), so it
        # stays.
        self._invalidate_below_device()

    async def _on_device_rotated(self, _old: XblDeviceToken | None, _new: XblDeviceToken) -> None:
        # Device token rotation invalidates the Sisu legs (which embed
        # the DeviceToken in their request) and everything below.
        self._invalidate_below_device()

    def _invalidate_below_device(self) -> None:
        self._bedrock_sisu = None
        self._playfab_sisu = None
        self._playfab_token = None
        self._cert_chain = None
        self._franchise_session = None
        self._multiplayer_token = None

    async def _on_bedrock_sisu_rotated(
        self, _old: XblSisuTokens | None, _new: XblSisuTokens
    ) -> None:
        self._cert_chain = None

    async def _on_playfab_sisu_rotated(
        self, _old: XblSisuTokens | None, _new: XblSisuTokens
    ) -> None:
        self._playfab_token = None
        self._franchise_session = None
        self._multiplayer_token = None

    async def _on_playfab_rotated(self, _old: PlayFabToken | None, _new: PlayFabToken) -> None:
        self._franchise_session = None
        self._multiplayer_token = None

    async def _on_franchise_rotated(
        self, _old: MinecraftSession | None, _new: MinecraftSession
    ) -> None:
        self._multiplayer_token = None

    async def _dispatch(self, stage: str, old: Any, new: Any) -> None:
        for cb in list(self._chain_listeners):
            try:
                result = cb(stage, old, new)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception(
                    "mcapi_auth: bedrock chain listener %r raised on stage %s; continuing",
                    cb,
                    stage,
                )

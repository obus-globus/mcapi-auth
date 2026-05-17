""":class:`AuthChain` — full Microsoft → Minecraft state with lazy refresh.

Where :class:`mcapi_auth.MinecraftSession` is a flat snapshot of the
final auth state (good enough for short-lived scripts), :class:`AuthChain`
is the *full* token chain — MSA, XBL, XSTS, Minecraft, profile — wrapped
in :class:`~mcapi_auth.auth.holder.Holder` so each stage refreshes
independently when expired.

Mirrors RaphiMC's ``JavaAuthManager`` model: serialise the whole thing
to JSON, restore it on next start, and individual tokens get refreshed
on demand rather than re-deriving the full chain from the MSA refresh
token on every cold start.

Typical lifecycle::

    chain = await AuthChain.login(app=MsaApplicationConfig.from_known("prism"))
    chain.on_change(lambda old, new: state.save(chain.dump_json()))

    while running:
        mc = await chain.get_minecraft_token()      # refreshes if needed
        await do_stuff(mc.access_token)

    # later, in another process:
    chain = AuthChain.load_json(state.load(), app=...)
    mc = await chain.get_minecraft_token()
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Self

import httpx
from whenever import Instant

from .._models import InstantField, McModel
from .app_config import MsaApplicationConfig
from .flow import _invoke_callback  # pyright: ignore[reportPrivateUsage]
from .holder import Holder
from .minecraft import MinecraftProfile, MinecraftToken, fetch_profile, login_with_xbox
from .msa import (
    DeviceCodePrompt,
    MSATokens,
    exchange_refresh_token,
    poll_for_device_code_token,
    request_device_code,
)
from .session import MinecraftSession
from .xbox import XboxLiveToken, XSTSToken, authenticate_xbl, authenticate_xsts

__all__ = ["AuthChain", "ChainChangeListener"]

logger = logging.getLogger(__name__)

type ChainChangeListener = Callable[[str, Any, Any], None | Awaitable[None]]
"""Signature for chain-wide listeners.

Called as ``(stage_name, old_value, new_value)`` whenever any stage's
holder rotates. ``stage_name`` is one of ``"msa"``, ``"xbl"``,
``"xsts"``, ``"minecraft"``, ``"profile"``.
"""


class _ChainSnapshot(McModel):
    """Plain serialisable form of the chain (for dump / load)."""

    msa: MSATokens
    xbl: XboxLiveToken | None = None
    xsts: XSTSToken | None = None
    minecraft: MinecraftToken | None = None
    profile: MinecraftProfile | None = None
    # XBL and XSTS tokens have no typed expiry on the wire — we
    # synthesise one (~14h) at acquisition time and persist it so
    # restored chains don't treat stale tokens as fresh.
    xbl_expires_at: InstantField | None = None
    xsts_expires_at: InstantField | None = None
    save_version: int = 2


class AuthChain:
    """Full Microsoft → Minecraft auth chain with lazy refresh + listeners.

    Construction is normally via :meth:`login`, :meth:`from_session`,
    or :meth:`load_json`. The constructor itself is public for tests
    and advanced use cases.

    Args:
        app: :class:`MsaApplicationConfig` describing the OAuth app.
            Stored verbatim; refreshes use the same config.
        msa: Initial MSA tokens. Required (the rest of the chain can
            be re-derived from a fresh MSA token).
        xbl / xsts / minecraft / profile: Cached downstream tokens.
            If ``None``, the next call to :meth:`get_minecraft_token`
            re-derives them.
        http_client: Optional :class:`httpx.AsyncClient` reused across
            refreshes. One is acquired per-call otherwise.
    """

    def __init__(
        self,
        *,
        app: MsaApplicationConfig,
        msa: MSATokens,
        xbl: XboxLiveToken | None = None,
        xsts: XSTSToken | None = None,
        minecraft: MinecraftToken | None = None,
        profile: MinecraftProfile | None = None,
        xbl_expires_at: Instant | None = None,
        xsts_expires_at: Instant | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._app = app
        self._http_client = http_client
        self._chain_listeners: list[ChainChangeListener] = []
        # Synthetic per-stage expiries for XBL/XSTS (no typed expiry on the wire).
        self._xbl_expires_at: Instant | None = None
        self._xsts_expires_at: Instant | None = None

        self._msa = Holder[MSATokens](
            msa,
            refresher=self._refresh_msa,
            expires_at=lambda v: v.expires_at,
            name="MSA",
        )
        self._msa.add_listener(self._make_stage_dispatcher("msa"))
        # Add an invalidation listener so downstream stages get rebuilt
        # on MSA rotation. They are recomputed lazily on next access.
        self._msa.add_listener(self._on_msa_rotated)

        # Downstream holders are created lazily because they need
        # tokens we may not have yet. We use a sentinel of None and
        # build a Holder once we have a real value.
        self._xbl: Holder[XboxLiveToken] | None = None
        self._xsts: Holder[XSTSToken] | None = None
        self._minecraft: Holder[MinecraftToken] | None = None
        self._profile: Holder[MinecraftProfile] | None = None
        if xbl is not None:
            self._xbl = self._build_xbl_holder(xbl, expires_at=xbl_expires_at)
        if xsts is not None:
            self._xsts = self._build_xsts_holder(xsts, expires_at=xsts_expires_at)
        if minecraft is not None:
            self._minecraft = self._build_mc_holder(minecraft)
        if profile is not None:
            self._profile = self._build_profile_holder(profile)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    async def login(
        cls,
        *,
        app: MsaApplicationConfig | None = None,
        on_device_code: Callable[[DeviceCodePrompt], None | Awaitable[None]] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Run the device-code flow end-to-end and return a fresh chain.

        For the browser flow, use :func:`mcapi_auth.login_via_browser`
        to obtain a :class:`MinecraftSession`, then call
        :meth:`from_session`.
        """
        actual_app = app if app is not None else MsaApplicationConfig.v2()
        if actual_app.is_v1:
            raise ValueError(
                "AuthChain.login() doesn't support v1 client_ids "
                "(device-code endpoint is v2 only). Use a v2 MsaApplicationConfig."
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
        chain = cls(app=actual_app, msa=msa, http_client=http_client)
        # Drive the downstream stages once so callers can immediately
        # dump_json() if they want.
        await chain.get_minecraft_token()
        await chain.get_profile()
        return chain

    @classmethod
    def from_session(
        cls,
        session: MinecraftSession,
        *,
        app: MsaApplicationConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Bridge an existing :class:`MinecraftSession` into a chain.

        We only have the MSA+MC tokens in a session (XBL/XSTS aren't
        retained); the chain will re-derive XBL/XSTS the next time a
        Minecraft token refresh is needed.
        """
        actual_app = app if app is not None else MsaApplicationConfig.v2()
        msa = MSATokens(
            access_token=session.msa_access_token,
            refresh_token=session.refresh_token,
            expires_at=session.msa_access_token_expires_at,
        )
        mc = MinecraftToken(
            access_token=session.access_token,
            expires_at=session.minecraft_access_token_expires_at,
        )
        profile = MinecraftProfile(uuid=session.uuid, username=session.username)
        return cls(app=actual_app, msa=msa, minecraft=mc, profile=profile, http_client=http_client)

    @classmethod
    def load_json(
        cls,
        data: str | bytes,
        *,
        app: MsaApplicationConfig,
        http_client: httpx.AsyncClient | None = None,
    ) -> Self:
        """Restore a chain previously serialised with :meth:`dump_json`.

        The :class:`MsaApplicationConfig` is not serialised — pass the
        same one (or a compatible one) you'd use for a fresh login.
        """
        snap = _ChainSnapshot.model_validate_json(data)
        return cls(
            app=app,
            msa=snap.msa,
            xbl=snap.xbl,
            xsts=snap.xsts,
            minecraft=snap.minecraft,
            profile=snap.profile,
            xbl_expires_at=snap.xbl_expires_at,
            xsts_expires_at=snap.xsts_expires_at,
            http_client=http_client,
        )

    # ------------------------------------------------------------------
    # Public access
    # ------------------------------------------------------------------

    @property
    def app(self) -> MsaApplicationConfig:
        """The :class:`MsaApplicationConfig` driving this chain."""
        return self._app

    async def get_msa_tokens(self, *, leeway: float = 30.0) -> MSATokens:
        """Return MSA tokens, refreshing via the refresh-token grant if expired."""
        return await self._msa.get_up_to_date(leeway=leeway)

    async def get_xbl_token(self, *, leeway: float = 30.0) -> XboxLiveToken:
        """Return the Xbox Live token, refreshing if expired."""
        if self._xbl is None:
            msa = await self.get_msa_tokens(leeway=leeway)
            xbl = await authenticate_xbl(
                msa.access_token,
                use_d_prefix=self._app.xbl_use_d_prefix,
                http_client=self._http_client,
            )
            self._xbl = self._build_xbl_holder(xbl)
            await self._dispatch("xbl", None, xbl)
            return xbl
        return await self._xbl.get_up_to_date(leeway=leeway)

    async def get_xsts_token(self, *, leeway: float = 30.0) -> XSTSToken:
        """Return the XSTS token, refreshing if expired."""
        if self._xsts is None:
            xbl = await self.get_xbl_token(leeway=leeway)
            xsts = await authenticate_xsts(xbl.token, http_client=self._http_client)
            self._xsts = self._build_xsts_holder(xsts)
            await self._dispatch("xsts", None, xsts)
            return xsts
        return await self._xsts.get_up_to_date(leeway=leeway)

    async def get_minecraft_token(self, *, leeway: float = 30.0) -> MinecraftToken:
        """Return the Minecraft access token, refreshing if expired."""
        if self._minecraft is None:
            xsts = await self.get_xsts_token(leeway=leeway)
            mc = await login_with_xbox(xsts.userhash, xsts.token, http_client=self._http_client)
            self._minecraft = self._build_mc_holder(mc)
            await self._dispatch("minecraft", None, mc)
            return mc
        return await self._minecraft.get_up_to_date(leeway=leeway)

    async def get_profile(self) -> MinecraftProfile:
        """Return the cached :class:`MinecraftProfile`, fetching it if missing.

        The profile is not auto-refreshed (it doesn't expire), but
        :meth:`refresh_profile` exists to force a re-fetch when names
        change.
        """
        if self._profile is None:
            mc = await self.get_minecraft_token()
            profile = await fetch_profile(mc.access_token, http_client=self._http_client)
            self._profile = self._build_profile_holder(profile)
            await self._dispatch("profile", None, profile)
        return self._profile.get_cached()

    async def refresh_profile(self) -> MinecraftProfile:
        """Force a re-fetch of the Minecraft profile (e.g. after a name change)."""
        mc = await self.get_minecraft_token()
        new = await fetch_profile(mc.access_token, http_client=self._http_client)
        if self._profile is None:
            self._profile = self._build_profile_holder(new)
            await self._dispatch("profile", None, new)
        else:
            await self._profile.replace(new)
        return new

    async def to_session(self) -> MinecraftSession:
        """Snapshot the chain into a flat :class:`MinecraftSession`."""
        msa = await self.get_msa_tokens()
        mc = await self.get_minecraft_token()
        profile = await self.get_profile()
        return MinecraftSession(
            access_token=mc.access_token,
            refresh_token=msa.refresh_token,
            uuid=profile.uuid,
            username=profile.username,
            msa_access_token=msa.access_token,
            msa_access_token_expires_at=msa.expires_at,
            minecraft_access_token_expires_at=mc.expires_at,
        )

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def on_change(self, cb: ChainChangeListener) -> None:
        """Register a chain-wide listener.

        Fires on every stage rotation with ``(stage_name, old, new)``.
        Useful for "persist on every refresh" patterns::

            chain.on_change(lambda *_: state.save(chain.dump_json()))
        """
        self._chain_listeners.append(cb)

    def remove_listener(self, cb: ChainChangeListener) -> bool:
        """Remove a previously-registered chain listener."""
        try:
            self._chain_listeners.remove(cb)
        except ValueError:
            return False
        return True

    @property
    def msa_holder(self) -> Holder[MSATokens]:
        """The underlying MSA :class:`Holder` — for per-stage listeners."""
        return self._msa

    @property
    def xbl_holder(self) -> Holder[XboxLiveToken] | None:
        """The XBL :class:`Holder` if one has been built yet, else ``None``."""
        return self._xbl

    @property
    def xsts_holder(self) -> Holder[XSTSToken] | None:
        """The XSTS :class:`Holder` if one has been built yet, else ``None``."""
        return self._xsts

    @property
    def minecraft_holder(self) -> Holder[MinecraftToken] | None:
        """The Minecraft token :class:`Holder` if built yet, else ``None``."""
        return self._minecraft

    @property
    def profile_holder(self) -> Holder[MinecraftProfile] | None:
        """The profile :class:`Holder` if built yet, else ``None``."""
        return self._profile

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def dump_json(self, *, indent: int | None = None) -> str:
        """Serialise the entire chain to JSON.

        Includes any cached XBL/XSTS/MC tokens, so a subsequent
        :meth:`load_json` round-trips the state — downstream holders
        will be rebuilt without an extra refresh on first access.
        """
        snap = _ChainSnapshot(
            msa=self._msa.get_cached(),
            xbl=self._xbl.get_cached() if self._xbl is not None else None,
            xsts=self._xsts.get_cached() if self._xsts is not None else None,
            minecraft=self._minecraft.get_cached() if self._minecraft is not None else None,
            profile=self._profile.get_cached() if self._profile is not None else None,
            xbl_expires_at=self._xbl_expires_at if self._xbl is not None else None,
            xsts_expires_at=self._xsts_expires_at if self._xsts is not None else None,
        )
        text = snap.model_dump_json()
        if indent is None:
            return text
        # Re-encode through json.dumps to apply indent (avoid pulling in
        # another option on Pydantic's side).
        return json.dumps(json.loads(text), indent=indent)

    # ------------------------------------------------------------------
    # Private refresh callables (one per holder)
    # ------------------------------------------------------------------

    async def _refresh_msa(self, old: MSATokens) -> MSATokens:
        return await exchange_refresh_token(
            old.refresh_token,
            client_id=self._app.client_id,
            http_client=self._http_client,
            token_url=self._app.token_url,
            scope=self._app.scope,
        )

    async def _refresh_xbl(self, old: XboxLiveToken) -> XboxLiveToken:
        del old
        msa = await self.get_msa_tokens()
        return await authenticate_xbl(
            msa.access_token,
            use_d_prefix=self._app.xbl_use_d_prefix,
            http_client=self._http_client,
        )

    async def _refresh_xsts(self, old: XSTSToken) -> XSTSToken:
        del old
        xbl = await self.get_xbl_token()
        return await authenticate_xsts(xbl.token, http_client=self._http_client)

    async def _refresh_mc(self, old: MinecraftToken) -> MinecraftToken:
        del old
        xsts = await self.get_xsts_token()
        return await login_with_xbox(xsts.userhash, xsts.token, http_client=self._http_client)

    async def _refresh_profile(self, old: MinecraftProfile) -> MinecraftProfile:
        del old
        mc = await self.get_minecraft_token()
        return await fetch_profile(mc.access_token, http_client=self._http_client)

    # ------------------------------------------------------------------
    # Holder builders
    # ------------------------------------------------------------------

    def _build_xbl_holder(
        self, value: XboxLiveToken, *, expires_at: Instant | None = None
    ) -> Holder[XboxLiveToken]:
        # XBL tokens don't expose a typed expiry — they're valid for
        # ~16h. Treat them as expiring 14h after acquisition. The
        # actual expiry is stored on the chain (so it survives
        # round-tripping through dump_json/load_json) and bumped on
        # every successful refresh.
        self._xbl_expires_at = (
            expires_at if expires_at is not None else Instant.now().add(seconds=14 * 3600)
        )
        h = Holder[XboxLiveToken](
            value,
            refresher=self._refresh_xbl,
            expires_at=lambda _v: self._xbl_expires_at or Instant.now(),
            name="XBL",
        )
        h.add_listener(self._bump_xbl_expiry)
        h.add_listener(self._make_stage_dispatcher("xbl"))
        return h

    def _build_xsts_holder(
        self, value: XSTSToken, *, expires_at: Instant | None = None
    ) -> Holder[XSTSToken]:
        self._xsts_expires_at = (
            expires_at if expires_at is not None else Instant.now().add(seconds=14 * 3600)
        )
        h = Holder[XSTSToken](
            value,
            refresher=self._refresh_xsts,
            expires_at=lambda _v: self._xsts_expires_at or Instant.now(),
            name="XSTS",
        )
        h.add_listener(self._bump_xsts_expiry)
        h.add_listener(self._make_stage_dispatcher("xsts"))
        return h

    def _build_mc_holder(self, value: MinecraftToken) -> Holder[MinecraftToken]:
        h = Holder[MinecraftToken](
            value,
            refresher=self._refresh_mc,
            expires_at=lambda v: v.expires_at,
            name="Minecraft",
        )
        h.add_listener(self._make_stage_dispatcher("minecraft"))
        return h

    def _build_profile_holder(self, value: MinecraftProfile) -> Holder[MinecraftProfile]:
        # Profiles don't expire; refresh only on explicit replace().
        # Use an Instant far in the future as the expiry.
        sentinel = Instant.now().add(seconds=10 * 365 * 24 * 3600)
        h = Holder[MinecraftProfile](
            value,
            refresher=self._refresh_profile,
            expires_at=lambda _v: sentinel,
            name="MinecraftProfile",
        )
        h.add_listener(self._make_stage_dispatcher("profile"))
        return h

    def _make_stage_dispatcher(self, stage: str) -> Callable[[Any, Any], Awaitable[None]]:
        async def _dispatcher(old: Any, new: Any) -> None:
            await self._dispatch(stage, old, new)

        return _dispatcher

    async def _on_msa_rotated(self, _old: MSATokens | None, _new: MSATokens) -> None:
        # MSA rotation invalidates everything downstream. Drop the
        # cached holders; they'll be lazily rebuilt on next access.
        self._xbl = None
        self._xsts = None
        self._minecraft = None
        # Drop the synthetic expiries too so stale ones can't leak.
        self._xbl_expires_at = None
        self._xsts_expires_at = None
        # Profile may stay (UUID is stable across MSA rotations for the
        # same account). If callers want a fresh one they can call
        # refresh_profile().

    async def _bump_xbl_expiry(self, _old: XboxLiveToken | None, _new: XboxLiveToken) -> None:
        self._xbl_expires_at = Instant.now().add(seconds=14 * 3600)

    async def _bump_xsts_expiry(self, _old: XSTSToken | None, _new: XSTSToken) -> None:
        self._xsts_expires_at = Instant.now().add(seconds=14 * 3600)

    async def _dispatch(self, stage: str, old: Any, new: Any) -> None:
        for cb in list(self._chain_listeners):
            try:
                result = cb(stage, old, new)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception(
                    "mcapi_auth: chain listener %r raised on stage %s; continuing",
                    cb,
                    stage,
                )

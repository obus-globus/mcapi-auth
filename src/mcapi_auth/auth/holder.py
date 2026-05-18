""":class:`Holder` — lazy refresh wrapper with change listeners.

Inspired by ``net.raphimc.minecraftauth.util.holder.Holder``. Wraps a
single mutable value that has an "expires at" instant and a refresh
callable. Callers fetch the value via :meth:`get_up_to_date`, which
refreshes if the value has expired (with optional leeway), and emits a
change event to registered listeners whenever the value rotates.

The Holder doesn't know anything about Minecraft auth specifically —
it's reused for every stage of the chain (MSA, XBL, XSTS, MC). The
chain-level orchestration lives in :mod:`mcapi_auth.auth.chain`.

Example::

    async def refresh(old: MSATokens) -> MSATokens:
        return await exchange_refresh_token(old.refresh_token, ...)

    holder = Holder(initial_tokens, refresher=refresh,
                    expires_at=lambda t: t.expires_at)
    holder.add_listener(lambda old, new: print("MSA rotated"))
    current = await holder.get_up_to_date()    # refreshes if expired

Listeners may be sync or async. Async ones are awaited before
:meth:`get_up_to_date` returns. Listener exceptions are logged but
do not prevent the rotation from being observed.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable

from whenever import Instant

__all__ = ["ChangeListener", "Holder"]

logger = logging.getLogger(__name__)

type ChangeListener[T] = Callable[[T | None, T], None | Awaitable[None]]
"""Signature for :class:`Holder` change listeners.

Called with ``(old_value, new_value)`` whenever the held value rotates.
On the *initial* set (i.e. construction), ``old_value`` is ``None``.
"""


class Holder[T]:
    """Lazy-refresh wrapper around a single expiring value.

    Args:
        value: Initial value.
        refresher: Async callable invoked with the current value to
            produce a refreshed one. Called by :meth:`get_up_to_date`
            when the value has expired (or when ``force=True``).
        expires_at: Callable mapping a value to its expiry instant.
            The Holder doesn't assume a particular field name so it
            works uniformly for ``MSATokens.expires_at`` /
            ``MinecraftToken.expires_at`` / etc.
        name: Optional name used in log messages. Defaults to the
            class name of the value.

    Listeners can be registered via :meth:`add_listener` and fire on
    every successful refresh. The listener list itself is not
    serialised; persistent state should be reattached after
    :meth:`mcapi_auth.auth.chain.AuthChain.load_json`.
    """

    def __init__(
        self,
        value: T,
        *,
        refresher: Callable[[T], Awaitable[T]],
        expires_at: Callable[[T], Instant],
        name: str | None = None,
    ) -> None:
        self._value: T = value
        self._refresher: Callable[[T], Awaitable[T]] = refresher
        self._expires_at: Callable[[T], Instant] = expires_at
        self._name: str = name or type(value).__name__
        self._listeners: list[ChangeListener[T]] = []
        self._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        """Human-readable name used in log messages."""
        return self._name

    def get_cached(self) -> T:
        """Return the cached value without checking for expiry."""
        return self._value

    def expires_at_instant(self) -> Instant:
        """Return the expiry :class:`~whenever.Instant` of the cached value."""
        return self._expires_at(self._value)

    def seconds_remaining(self, *, now: Instant | None = None) -> float:
        """Signed seconds until the cached value expires."""
        current = now if now is not None else Instant.now()
        return (self._expires_at(self._value) - current).total("seconds")

    def expired(self, *, leeway: float = 0.0, now: Instant | None = None) -> bool:
        """``True`` once the cached value has expired minus ``leeway``."""
        return self.seconds_remaining(now=now) - leeway <= 0

    async def get_up_to_date(self, *, leeway: float = 30.0, force: bool = False) -> T:
        """Return the value, refreshing it first if necessary.

        Args:
            leeway: Seconds of safety margin. The value is refreshed
                if it expires within ``leeway`` seconds. Defaults to
                30s, which comfortably covers downstream stage latency.
            force: Refresh unconditionally.

        Refresh is serialised by an internal lock — concurrent callers
        share one refresh, not N.
        """
        if not force and not self.expired(leeway=leeway):
            return self._value
        async with self._lock:
            # Re-check under the lock (someone else may have refreshed).
            if not force and not self.expired(leeway=leeway):
                return self._value
            old = self._value
            try:
                new = await self._refresher(old)
            except Exception:
                logger.debug("mcapi_auth: refresh of %s holder failed", self._name)
                raise
            if new is old:
                return old
            self._value = new
            await self._fire_listeners(old, new)
            return new

    def set(self, value: T) -> None:
        """Replace the value without firing listeners.

        Used by deserialization and tests. Application code normally
        rotates via :meth:`get_up_to_date`, which fires listeners.
        """
        self._value = value

    async def replace(self, value: T) -> None:
        """Replace the value and fire listeners synchronously."""
        old = self._value
        if value is old:
            return
        self._value = value
        await self._fire_listeners(old, value)

    def add_listener(self, cb: ChangeListener[T]) -> None:
        """Register a callback fired on every rotation.

        Listeners run in registration order. Async listeners are
        awaited; sync listeners are invoked directly. Exceptions are
        logged and swallowed so one bad listener doesn't break the
        chain.
        """
        self._listeners.append(cb)

    def remove_listener(self, cb: ChangeListener[T]) -> bool:
        """Remove a previously-registered listener. Returns whether one was removed."""
        try:
            self._listeners.remove(cb)
        except ValueError:
            return False
        return True

    async def _fire_listeners(self, old: T | None, new: T) -> None:
        for cb in tuple(self._listeners):
            try:
                result = cb(old, new)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception(
                    "mcapi_auth: %s holder listener %r raised; continuing",
                    self._name,
                    cb,
                )

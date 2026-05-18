"""Synchronous facade for mcapi_auth's async API.

Every public async function in :mod:`mcapi_auth` is wrapped here so
that synchronous code (CLI scripts, Django/Flask views, tests) can
call them without ``asyncio.run`` boilerplate.

Usage::

    from mcapi_auth import sync as mcapi

    session = mcapi.login()
    profile = mcapi.get_own_profile(session=session)
    print(profile.name)

Caveats:
    * Each call spins up a fresh event loop via :func:`asyncio.run`.
      **Do not call these wrappers from inside a running asyncio
      loop** — call the async functions directly instead. Doing so
      will raise ``RuntimeError: asyncio.run() cannot be called from
      a running event loop``.
    * If you need to share an :class:`httpx.AsyncClient` across many
      calls for connection pooling, you almost certainly want the
      async API. The sync facade is for ad-hoc usage where the
      one-loop-per-call overhead is irrelevant.
    * Types of the wrapped functions are preserved at runtime
      (``functools.wraps`` + ``inspect.signature``) but static type
      checkers see ``Any``-returning callables unless you also
      install the bundled ``sync.pyi`` stub (this file ships one
      alongside it).

The set of exposed wrappers is computed dynamically from
:mod:`mcapi_auth`'s public async surface via :pep:`562` module
``__getattr__``. To see what is available::

    >>> from mcapi_auth import sync
    >>> print(sorted(sync.__all__))
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable, Coroutine
from typing import Any, cast

import mcapi_auth as _root

_WRAPPED: dict[str, Callable[..., Any]] = {}


def _wrap[T](fn: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., T]:
    """Return a sync wrapper that runs ``fn`` in a fresh event loop."""

    @functools.wraps(fn)
    def wrapper(*args: object, **kwargs: object) -> T:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — happy path.
            return asyncio.run(fn(*args, **kwargs))
        raise RuntimeError(
            f"mcapi_auth.sync.{fn.__name__}() cannot be called from inside a "
            "running asyncio event loop. Use the async function directly: "
            f"`from mcapi_auth import {fn.__name__}`."
        )

    return wrapper


def _public_async_names() -> list[str]:
    """Names in :mod:`mcapi_auth` that resolve to public async functions."""
    out: list[str] = []
    for name in getattr(_root, "__all__", dir(_root)):
        if name.startswith("_"):
            continue
        obj = getattr(_root, name, None)
        if obj is None:
            continue
        if inspect.iscoroutinefunction(obj):
            out.append(name)
    return sorted(out)


__all__: list[str] = _public_async_names()  # pyright: ignore[reportUnsupportedDunderAll]


def __getattr__(name: str) -> Callable[..., Any]:
    if name in _WRAPPED:
        return _WRAPPED[name]
    if name.startswith("_"):
        raise AttributeError(name)
    obj = getattr(_root, name, None)
    if obj is None or not inspect.iscoroutinefunction(obj):
        raise AttributeError(
            f"module 'mcapi_auth.sync' has no attribute {name!r} "
            "(only public async functions from mcapi_auth are wrapped)"
        )
    wrapped = _wrap(cast("Callable[..., Coroutine[Any, Any, Any]]", obj))
    _WRAPPED[name] = wrapped
    return wrapped


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(_WRAPPED) | {"__all__", "__dir__"})


# Eagerly expose ``inspect.signature``-friendly attributes so
# ``help(mcapi_auth.sync.login)`` shows something useful out of the box.
# Eagerly expose ``inspect.signature``-friendly attributes so
# ``help(mcapi_auth.sync.login)`` shows something useful out of the box.
def _populate_eager() -> None:
    for name in __all__:
        try:
            _WRAPPED[name] = _wrap(
                cast("Callable[..., Coroutine[Any, Any, Any]]", getattr(_root, name))
            )
        except AttributeError, TypeError:  # pragma: no cover - defensive
            continue


_populate_eager()


def signature_of(name: str) -> inspect.Signature:
    """Return the :class:`inspect.Signature` of the wrapped async fn.

    Useful for introspection — preserved verbatim from the async original.
    """
    obj = getattr(_root, name)
    if not inspect.iscoroutinefunction(obj):
        raise ValueError(f"{name!r} is not an async function in mcapi_auth")
    return inspect.signature(obj)

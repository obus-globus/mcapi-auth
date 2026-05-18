"""Tests for the synchronous facade in :mod:`mcapi_auth.sync`."""

from __future__ import annotations

import asyncio
import inspect

import httpx
import pytest
import respx

import mcapi_auth
from mcapi_auth import sync


def test_sync_module_exports_async_surface() -> None:
    """Every public async function in mcapi_auth has a sync wrapper."""
    async_names = {
        n for n in mcapi_auth.__all__ if inspect.iscoroutinefunction(getattr(mcapi_auth, n, None))
    }
    assert async_names, "mcapi_auth should export at least one async function"
    missing = async_names - set(sync.__all__)
    assert not missing, f"sync facade is missing wrappers for: {sorted(missing)}"


def test_sync_wrapper_is_callable_and_not_a_coroutine_function() -> None:
    fn = sync.get_uuid_by_name
    assert callable(fn)
    assert not inspect.iscoroutinefunction(fn)


@respx.mock
def test_sync_call_executes_and_returns_value() -> None:
    """A wrapped function should execute end-to-end via asyncio.run."""
    route = respx.get("https://api.mojang.com/users/profiles/minecraft/Notch").mock(
        return_value=httpx.Response(
            200,
            json={"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"},
        ),
    )
    result = sync.get_uuid_by_name("Notch")
    assert route.called
    assert result is not None
    assert result.name == "Notch"


def test_sync_wrapper_rejects_running_loop() -> None:
    """Calling a sync wrapper from inside a running asyncio loop must raise."""

    async def caller() -> None:
        with pytest.raises(RuntimeError, match="running asyncio event loop"):
            sync.get_uuid_by_name("Notch")

    asyncio.run(caller())


def test_dynamic_getattr_for_unwrapped_names() -> None:
    """Names not eagerly cached should still resolve via __getattr__."""
    # exchange_authorization_code is in mcapi_auth (async); confirm dynamic lookup works
    fn = sync.exchange_authorization_code
    assert callable(fn)
    assert not inspect.iscoroutinefunction(fn)


def test_unknown_attribute_raises() -> None:
    with pytest.raises(AttributeError):
        _ = sync.this_does_not_exist  # pyright: ignore[reportAttributeAccessIssue]


def test_signature_of_returns_real_signature() -> None:
    sig = sync.signature_of("get_uuid_by_name")
    assert "name" in sig.parameters

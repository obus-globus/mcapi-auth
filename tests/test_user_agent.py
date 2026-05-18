"""Tests for the configurable default User-Agent."""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
import respx

from mcapi_auth import (
    get_default_user_agent,
    set_default_user_agent,
)
from mcapi_auth._constants import DEFAULT_API_USER_AGENT
from mcapi_auth._http import acquire_client


@pytest.fixture(autouse=True)
def _reset_user_agent() -> Iterator[None]:
    """Restore the default User-Agent after every test."""
    original = get_default_user_agent()
    yield
    set_default_user_agent(original)


def test_default_user_agent_matches_constant() -> None:
    assert get_default_user_agent() == DEFAULT_API_USER_AGENT
    assert DEFAULT_API_USER_AGENT.startswith("mcapi-auth/")


def test_set_default_user_agent_updates_value() -> None:
    set_default_user_agent("my-app/1.2.3 (+https://example.org)")
    assert get_default_user_agent() == "my-app/1.2.3 (+https://example.org)"


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_set_default_user_agent_rejects_blank(bad: str) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        set_default_user_agent(bad)


@respx.mock
async def test_fallback_client_uses_overridden_user_agent() -> None:
    set_default_user_agent("my-app/2.0.0")
    route = respx.get("https://example.test/ping").respond(json={"ok": True})

    async with acquire_client(None) as client:
        response = await client.get("https://example.test/ping")

    assert response.status_code == 200
    assert route.calls.last.request.headers["user-agent"] == "my-app/2.0.0"


@respx.mock
async def test_caller_supplied_client_keeps_its_user_agent() -> None:
    """A user-provided client must NOT be mutated by ``set_default_user_agent``."""
    set_default_user_agent("library-default/9.9.9")
    route = respx.get("https://example.test/ping").respond(json={"ok": True})

    async with (
        httpx.AsyncClient(headers={"User-Agent": "caller-app/4.5.6"}) as caller,
        acquire_client(caller) as client,
    ):
        assert client is caller
        await client.get("https://example.test/ping")

    assert route.calls.last.request.headers["user-agent"] == "caller-app/4.5.6"


@respx.mock
async def test_user_agent_change_takes_effect_on_next_acquire() -> None:
    respx.get("https://example.test/ping").respond(json={"ok": True})

    set_default_user_agent("first/1.0")
    async with acquire_client(None) as c1:
        await c1.get("https://example.test/ping")
    first_ua = respx.calls.last.request.headers["user-agent"]

    set_default_user_agent("second/2.0")
    async with acquire_client(None) as c2:
        await c2.get("https://example.test/ping")
    second_ua = respx.calls.last.request.headers["user-agent"]

    assert first_ua == "first/1.0"
    assert second_ua == "second/2.0"

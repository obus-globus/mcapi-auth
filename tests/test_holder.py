"""Tests for :class:`mcapi_auth.Holder`."""

import asyncio
from dataclasses import dataclass

from whenever import Instant

from mcapi_auth import Holder


@dataclass(frozen=True)
class _Token:
    value: str
    expires_at: Instant


def _make_token(value: str, in_seconds: float) -> _Token:
    return _Token(value=value, expires_at=Instant.now().add(seconds=in_seconds))


async def test_get_up_to_date_returns_cached_when_fresh() -> None:
    initial = _make_token("a", 3600)
    refresh_calls: list[int] = []

    async def refresher(old: _Token) -> _Token:
        refresh_calls.append(1)
        return _make_token("b", 3600)

    h = Holder(initial, refresher=refresher, expires_at=lambda t: t.expires_at)
    got = await h.get_up_to_date()
    assert got is initial
    assert refresh_calls == []


async def test_get_up_to_date_refreshes_when_expired() -> None:
    expired = _make_token("a", -10)

    async def refresher(_old: _Token) -> _Token:
        return _make_token("b", 3600)

    h = Holder(expired, refresher=refresher, expires_at=lambda t: t.expires_at)
    got = await h.get_up_to_date()
    assert got.value == "b"
    assert h.get_cached().value == "b"


async def test_force_refresh_runs_even_when_fresh() -> None:
    h = Holder(
        _make_token("a", 3600),
        refresher=lambda _old: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )
    new = await h.get_up_to_date(force=True)
    assert new.value == "b"


async def _refresh_async(value: str) -> _Token:
    return _make_token(value, 3600)


async def test_listeners_fire_on_rotation() -> None:
    rotations: list[tuple[str | None, str]] = []

    async def listener(old: _Token | None, new: _Token) -> None:
        rotations.append((old.value if old else None, new.value))

    h = Holder(
        _make_token("a", -1),
        refresher=lambda _o: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )
    h.add_listener(listener)
    await h.get_up_to_date()
    assert rotations == [("a", "b")]


async def test_listener_exception_does_not_break_rotation() -> None:
    def bad_listener(_old: _Token | None, _new: _Token) -> None:
        raise RuntimeError("nope")

    good_calls: list[str] = []

    def good_listener(_old: _Token | None, new: _Token) -> None:
        good_calls.append(new.value)

    h = Holder(
        _make_token("a", -1),
        refresher=lambda _o: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )
    h.add_listener(bad_listener)
    h.add_listener(good_listener)
    new = await h.get_up_to_date()
    assert new.value == "b"
    assert good_calls == ["b"]


async def test_concurrent_get_up_to_date_only_refreshes_once() -> None:
    refresh_count = 0

    async def refresher(_old: _Token) -> _Token:
        nonlocal refresh_count
        refresh_count += 1
        await asyncio.sleep(0.01)
        return _make_token("b", 3600)

    h = Holder(
        _make_token("a", -1),
        refresher=refresher,
        expires_at=lambda t: t.expires_at,
    )
    results = await asyncio.gather(*[h.get_up_to_date() for _ in range(10)])
    assert all(r.value == "b" for r in results)
    assert refresh_count == 1


async def test_remove_listener() -> None:
    h = Holder(
        _make_token("a", -1),
        refresher=lambda _o: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )

    def cb(_o: _Token | None, _n: _Token) -> None:
        pass

    h.add_listener(cb)
    assert h.remove_listener(cb) is True
    assert h.remove_listener(cb) is False


def test_seconds_remaining_and_expired() -> None:
    h = Holder(
        _make_token("a", 100),
        refresher=lambda _o: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )
    assert h.seconds_remaining() > 0
    assert not h.expired()
    h2 = Holder(
        _make_token("a", -10),
        refresher=lambda _o: _refresh_async("b"),
        expires_at=lambda t: t.expires_at,
    )
    assert h2.expired()

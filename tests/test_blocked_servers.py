"""Tests for the blocked-servers helpers."""

import hashlib

import respx

from mcapi_auth._constants import BLOCKED_SERVERS_URL
from mcapi_auth.api import (
    fetch_blocked_servers,
    hostname_variants,
    is_blocked,
    is_server_blocked,
)


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("iso-8859-1")).hexdigest()


def test_hostname_variants_for_hostname() -> None:
    assert hostname_variants("mc.example.com") == [
        "mc.example.com",
        "*.example.com",
        "*.com",
    ]


def test_hostname_variants_for_ipv4() -> None:
    assert hostname_variants("192.168.0.1") == [
        "192.168.0.1",
        "192.168.0.*",
        "192.168.*",
        "192.*",
    ]


def test_hostname_variants_lowercases_and_strips_trailing_dot() -> None:
    assert hostname_variants("MC.Example.COM.") == [
        "mc.example.com",
        "*.example.com",
        "*.com",
    ]


def test_hostname_variants_for_empty_returns_empty() -> None:
    assert hostname_variants("") == []
    assert hostname_variants("   ") == []


def test_hostname_variants_normalizes_leading_zero_ipv4_octets() -> None:
    # Mojang's blocklist stores the canonical decimal form; we must
    # strip leading zeros before hashing or wildcards never match.
    assert hostname_variants("192.168.001.1") == [
        "192.168.1.1",
        "192.168.1.*",
        "192.168.*",
        "192.*",
    ]


def test_hostname_variants_treats_invalid_ipv4_like_hostname() -> None:
    # "999.1.1.1" isn't a valid IPv4 — fall back to label-based wildcards.
    assert hostname_variants("999.1.1.1") == [
        "999.1.1.1",
        "*.1.1.1",
        "*.1.1",
        "*.1",
    ]


def test_is_blocked_returns_true_for_exact_match() -> None:
    blocklist = frozenset([_sha1("evil.example.com")])
    assert is_blocked("evil.example.com", blocklist) is True


def test_is_blocked_returns_true_for_subdomain_wildcard() -> None:
    blocklist = frozenset([_sha1("*.example.com")])
    assert is_blocked("anything.example.com", blocklist) is True


def test_is_blocked_returns_true_for_ipv4_wildcard() -> None:
    blocklist = frozenset([_sha1("192.168.*")])
    assert is_blocked("192.168.5.42", blocklist) is True


def test_is_blocked_returns_false_for_unmatched_host() -> None:
    blocklist = frozenset([_sha1("evil.example.com")])
    assert is_blocked("good.example.org", blocklist) is False


def test_is_blocked_accepts_iterable_blocklist() -> None:
    blocklist = [_sha1("*.example.com")]
    assert is_blocked("a.example.com", blocklist) is True


@respx.mock
async def test_fetch_blocked_servers_parses_lines() -> None:
    respx.get(BLOCKED_SERVERS_URL).respond(text="abc123\n  \nDEF456\n\nghi789\n", status_code=200)
    s = await fetch_blocked_servers()
    assert s == frozenset({"abc123", "def456", "ghi789"})


@respx.mock
async def test_is_server_blocked_e2e() -> None:
    target_hash = _sha1("*.griefer.net")
    respx.get(BLOCKED_SERVERS_URL).respond(text=target_hash, status_code=200)
    assert await is_server_blocked("play.griefer.net") is True


@respx.mock
async def test_is_server_blocked_returns_false_when_not_listed() -> None:
    respx.get(BLOCKED_SERVERS_URL).respond(text=_sha1("other.host"), status_code=200)
    assert await is_server_blocked("play.griefer.net") is False

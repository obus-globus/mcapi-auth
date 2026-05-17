"""Mojang's SHA1 server blocklist.
The endpoint at ``sessionserver.mojang.com/blockedservers`` returns a
newline-separated list of SHA1 hashes. Each hash is computed over the
lowercase server hostname (or IP) encoded as ISO-8859-1, with wildcards
walked from the most-specific subdomain outward (and from the least-
significant octet for IPv4):

    mc.example.com
    *.example.com
    *.com

    192.168.0.1
    192.168.0.*
    192.168.*
    192.*

Clients hash each variant and check membership in the blocklist; a match
on any variant means the client refuses to connect.

This module provides:

- :func:`fetch_blocked_servers` to download the list (returns the raw set
  of SHA1 strings as Mojang sends them).
- :func:`hostname_variants` to enumerate the candidate strings for a host.
- :func:`is_server_blocked` to combine the two: returns ``True`` if the
  given host would be refused by the vanilla client.
"""


import hashlib
from collections.abc import Iterable

import httpx

from .._constants import BLOCKED_SERVERS_URL
from .._http import acquire_client
from ..exceptions import HttpError


async def fetch_blocked_servers(*, http_client: httpx.AsyncClient | None = None) -> frozenset[str]:
    """Download the current blocklist as an immutable set of lowercase SHA1 hex strings."""
    async with acquire_client(http_client) as client:
        r = await client.get(BLOCKED_SERVERS_URL)
    if r.status_code != 200:
        raise HttpError(r.status_code, r.text, url=str(r.request.url))
    return frozenset(line.strip().lower() for line in r.text.splitlines() if line.strip())


def _sha1_iso_8859_1(value: str) -> str:
    return hashlib.sha1(value.lower().encode("iso-8859-1")).hexdigest()


def _ipv4_octets(host: str) -> list[int] | None:
    """If ``host`` is a dotted-quad IPv4 literal, return its 4 numeric octets.

    Accepts leading-zero octets like ``192.168.001.1`` (Java's
    ``InetAddress`` historically parsed them as decimal) and normalizes them
    to canonical decimal form. Mojang's blocklist hashes the canonical
    decimal form, so we must normalize before hashing or else our wildcards
    would never match. Rejects any non-decimal noise.
    """
    parts = host.split(".")
    if len(parts) != 4:
        return None
    octets: list[int] = []
    for p in parts:
        if not p.isdigit():
            return None
        n = int(p)
        if n > 255:
            return None
        octets.append(n)
    return octets


def hostname_variants(host: str) -> list[str]:
    """Enumerate every variant of ``host`` that the vanilla client checks.

    For IPv4 addresses, wildcards collapse from the right
    (``a.b.c.d`` → ``a.b.c.*`` → ``a.b.*`` → ``a.*``).
    For hostnames, the leftmost label is replaced with ``*`` repeatedly
    (``mc.example.com`` → ``*.example.com`` → ``*.com``).

    The host itself is always the first entry (normalized: lowercase, trimmed,
    trailing-dot-stripped; IPv4 octets are decimal-normalized).
    """
    host = host.strip().lower().rstrip(".")
    if not host:
        return []

    octets = _ipv4_octets(host)
    if octets is not None:
        canonical_parts = [str(n) for n in octets]
        variants: list[str] = [".".join(canonical_parts)]
        for i in range(len(canonical_parts) - 1, 0, -1):
            variants.append(".".join(canonical_parts[:i]) + ".*")
        return variants

    parts = host.split(".")
    variants = [host]
    for i in range(1, len(parts)):
        variants.append("*." + ".".join(parts[i:]))
    return variants


def is_blocked(host: str, blocklist: Iterable[str]) -> bool:
    """Return True if any variant of ``host`` hashes into ``blocklist``."""
    block = blocklist if isinstance(blocklist, (set, frozenset)) else frozenset(blocklist)
    return any(_sha1_iso_8859_1(variant) in block for variant in hostname_variants(host))


async def is_server_blocked(
    host: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """One-shot helper: download the list and check ``host`` against it."""
    blocklist = await fetch_blocked_servers(http_client=http_client)
    return is_blocked(host, blocklist)

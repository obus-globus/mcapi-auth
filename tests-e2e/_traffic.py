"""Shared httpdbg → Markdown traffic logger for the E2E suite.

Two callers depend on this module:

  * ``test_api_coverage.py`` — bulk read-only Mojang API coverage,
    with per-label sections and netloc filtering. Uses
    :func:`decompress_body` + :func:`redact_header_value` and its
    own framing.
  * ``test_bedrock_chain.py`` — full Bedrock auth chain via
    ``BedrockAuthManager.login(prime=True)``. Uses the all-in-one
    :func:`write_traffic_log`.

Primitives:

  * :data:`REDACTED_HEADERS` — header names whose values should be
    censored in any log.
  * :func:`redact_header_value` — apply that censorship.
  * :func:`decompress_body` — gzip / zlib decompress if the magic
    bytes match; returns the raw content otherwise.
  * :func:`redact_token_fields` — scrub common token-shaped JSON
    fields (``access_token``, ``EntityToken``, …) from a string.
  * :func:`summarize_body` — convenience: decompress + decode +
    redact + truncate.
  * :func:`write_traffic_log` — full Markdown report writer.
"""

from __future__ import annotations

import contextlib
import gzip
import re
import zlib
from pathlib import Path
from typing import Any

REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-xbl-authorization",
        "x-authorization",
        "proxy-authorization",
        "x-entitytoken",
        "signature",
        "www-authenticate",
    }
)

# JSON token-shaped fields seen across OAuth/MSA/XBL/Mojang/PlayFab.
_TOKEN_FIELDS = (
    "access_token",
    "refresh_token",
    "id_token",
    "EntityToken",
    "XSTSToken",
    "sessionTicket",
    "SessionTicket",
    "serverId",
    "sharedSecret",
    "publicKey",
    "publicKeySignature",
    "publicKeySignatureV2",
    "privateKey",
)
_TOKEN_FIELD_RE = re.compile(
    r'("(?:' + "|".join(_TOKEN_FIELDS) + r')"\s*:\s*")[^"]*(")'
)
# Bare "Token": "<jwt>" pattern (Xbox uses this casing).
_BARE_TOKEN_RE = re.compile(r'("Token"\s*:\s*")[^"]+(")')
# Inline "Bearer <token>" strings inside header values.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[\w.\-=+/]+")


def redact_header_value(name: str, value: str) -> str:
    """Return ``<redacted>`` for sensitive header names, otherwise value
    with any inline ``Bearer …`` substring scrubbed."""
    if name.lower() in REDACTED_HEADERS:
        return "<redacted>"
    return _BEARER_RE.sub("Bearer <redacted>", value)


def decompress_body(content: bytes) -> bytes:
    """Return ``content`` un-gzipped / un-zlibbed when the magic bytes match."""
    if content[:2] == b"\x1f\x8b":
        with contextlib.suppress(Exception):
            return gzip.decompress(content)
    if content[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        with contextlib.suppress(Exception):
            return zlib.decompress(content)
    return content


def redact_token_fields(text: str) -> str:
    """Scrub token-shaped JSON fields from ``text``."""
    text = _TOKEN_FIELD_RE.sub(r"\1<redacted>\2", text)
    text = _BARE_TOKEN_RE.sub(r"\1<redacted>\2", text)
    return text


def summarize_body(content: bytes | None, *, max_chars: int = 4000) -> str:
    """Decompress, decode, redact, and truncate an HTTP body for logging."""
    if not content:
        return "<empty>"
    raw = decompress_body(content)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(content)} bytes binary>"
    text = redact_token_fields(text)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... [truncated, {len(text) - max_chars} bytes more]"
    return text


def write_traffic_log(
    records: Any,  # httpdbg.HTTPRecords — not annotated to avoid the missing-stubs import
    *,
    path: Path,
    title: str,
    intro: str = "",
) -> int:
    """Render ``records`` to a Markdown report at ``path``. Returns bytes written."""
    lines: list[str] = [f"# {title}", ""]
    if intro:
        lines.extend([intro, ""])
    idx = 0
    for _rid, rec in records.requests.items():
        if rec.method == "CONNECT":
            continue
        idx += 1
        lines.append(f"## {idx}. `{rec.method} {rec.url}` → {rec.status_code}")
        lines.append("")
        lines.append("### Request headers")
        lines.append("```")
        for h in rec.request.headers:
            lines.append(f"{h.name}: {redact_header_value(h.name, h.value)}")
        lines.append("```")
        if rec.request.content:
            lines.append("### Request body")
            lines.append("```")
            lines.append(summarize_body(rec.request.content))
            lines.append("```")
        lines.append("### Response headers")
        lines.append("```")
        for h in rec.response.headers:
            lines.append(f"{h.name}: {redact_header_value(h.name, h.value)}")
        lines.append("```")
        lines.append("### Response body")
        lines.append("```")
        lines.append(summarize_body(rec.response.content))
        lines.append("```")
        lines.append("")
    path.write_text("\n".join(lines))
    return path.stat().st_size

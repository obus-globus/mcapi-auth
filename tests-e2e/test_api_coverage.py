"""End-to-end exercise of every read-only Minecraft API helper in mcapi-auth.

Logs every captured HTTP request and response (status, headers, body preview)
to ``tests-e2e/API_TRAFFIC_LOG.md`` via the ``httpdbg`` library. Auth-bearing
headers are redacted so the log is safe to commit.

Run with::

    env HTTPS_PROXY= HTTP_PROXY= https_proxy= http_proxy= DISPLAY=:99 \\
        uv run --active pytest tests-e2e/test_api_coverage.py -v -s \\
            --log-cli-level=INFO --capture=no
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from httpdbg import HTTPRecords, httprecord  # pyright: ignore[reportMissingImports]

sys.path.insert(0, str(Path(__file__).parent))
from _consent import drive_consent_until_loopback
from _traffic import (
    REDACTED_HEADERS as _BASE_REDACTED_HEADERS,
)
from _traffic import (
    decompress_body,
    redact_token_fields,
)
from _traffic import (
    redact_header_value as _base_redact_header_value,
)

from mcapi_auth import login_browser_v2
from mcapi_auth.api import (
    account,
    blocked_servers,
    meta,
    player_certificates,
    playfab,
    realms,
    textures,
)
from mcapi_auth.api import (
    profile as profile_api,
)
from mcapi_auth.auth import AuthChain
from mcapi_auth.auth.app_config import MsaApplicationConfig

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)

LOG_PATH = Path(__file__).parent / "API_TRAFFIC_LOG.md"
# Extends the shared set with one extra benign-but-noisy XBL header.
SENSITIVE_HEADER_NAMES = _BASE_REDACTED_HEADERS | {"x-xbl-contract-version"}
REDACTED = "<redacted>"
NETLOCS_OF_INTEREST = (
    "minecraftservices.com",
    "minecraft.net",
    "mojang.com",
    "xboxlive.com",
    "playfab.com",
    "launchermeta.mojang.com",
    "piston-meta.mojang.com",
    "sessionserver.mojang.com",
    "api.mojang.com",
)


def _redact_value(name: str, value: str) -> str:
    if name.lower() in SENSITIVE_HEADER_NAMES:
        return REDACTED
    return _base_redact_header_value(name, value)


def _redact_body(raw: bytes | None) -> str:
    if not raw:
        return ""
    data = decompress_body(bytes(raw))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(data)} bytes binary>"
    text = redact_token_fields(text)
    if len(text) > 4000:
        return text[:4000] + f"\n... [truncated, total {len(data)} decoded bytes]"
    return text


def _headers_to_list(headers: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        for h in headers:
            n = getattr(h, "name", None)
            v = getattr(h, "value", None)
            if n is None:
                continue
            out.append((str(n), _redact_value(str(n), str(v))))
    except TypeError:
        pass
    return out


def _format_record(r: Any) -> str | None:
    if r.method == "CONNECT":
        return None
    netloc = (r.netloc or "").lower()
    if not any(n in netloc for n in NETLOCS_OF_INTEREST):
        return None
    parts: list[str] = []
    parts.append(f"### {r.method} {r.url}")
    parts.append(f"- **Status:** {r.status_code}")
    if r.request is not None:
        parts.append("**Request headers:**")
        parts.append("```")
        for n, v in _headers_to_list(r.request.headers):
            parts.append(f"{n}: {v}")
        parts.append("```")
        body = _redact_body(getattr(r.request, "content", None))
        if body:
            parts.append("**Request body:**")
            parts.append("```")
            parts.append(body)
            parts.append("```")
    if r.response is not None:
        parts.append("**Response headers:**")
        parts.append("```")
        for n, v in _headers_to_list(r.response.headers):
            parts.append(f"{n}: {v}")
        parts.append("```")
        body = _redact_body(getattr(r.response, "content", None))
        if body:
            parts.append("**Response body:**")
            parts.append("```")
            parts.append(body)
            parts.append("```")
    parts.append("")
    return "\n".join(parts)


def _flush_records(label: str, records: HTTPRecords, sink: list[str]) -> None:
    sink.append(f"\n## {label}\n")
    any_rendered = False
    for r in list(records.requests.values()):
        block = _format_record(r)
        if block:
            sink.append(block)
            any_rendered = True
    if not any_rendered:
        sink.append("_(no in-scope HTTP traffic captured)_\n")
    records.reset()


async def _do_login(browser_context: BrowserContext) -> AuthChain:
    page = await browser_context.new_page()
    try:

        async def open_browser(url: str) -> None:
            async def go() -> None:
                with suppress(Exception):
                    await page.goto(url)
                with suppress(Exception):
                    await drive_consent_until_loopback(
                        page,
                        expected_redirect_host_prefix="127.0.0.1",
                        timeout_s=60.0,
                        flow_context="api_coverage / login_browser_v2",
                    )

            _task = asyncio.create_task(go())
            _ = _task

        session = await login_browser_v2(open_browser=open_browser)
    finally:
        with suppress(Exception):
            await page.close()
    return AuthChain.from_session(session, app=MsaApplicationConfig.v2())


@pytest.mark.asyncio
async def test_api_coverage(browser_context: BrowserContext) -> None:
    chain = await _do_login(browser_context)
    session = await chain.to_session()
    xsts = await chain.get_xsts_token()

    sink: list[str] = []
    sink.append("# mcapi-auth — Minecraft API Coverage Log\n")
    sink.append(
        "Generated by `tests-e2e/test_api_coverage.py`. Every captured request and\n"
        "response is recorded below; bearer tokens and cookies have been redacted.\n"
    )

    records = HTTPRecords()

    async def section(label: str, coro_factory: Any) -> Any:
        with httprecord(records):
            try:
                value = await coro_factory()
                status = "ok"
                error: str | None = None
            except Exception as exc:
                value = None
                status = "error"
                error = f"{type(exc).__name__}: {exc}"
                logger.warning("[%s] raised: %s", label, error)
        sink.append(f"\n## {label}\n")
        sink.append(f"- **Outcome:** `{status}`")
        if error:
            sink.append(f"- **Error:** `{error}`")
        if value is not None and not isinstance(value, (bytes, bytearray)):
            try:
                preview = value.model_dump_json(indent=2)  # type: ignore[union-attr]
            except AttributeError:
                try:
                    preview = json.dumps(value, default=str, indent=2)
                except Exception:
                    preview = repr(value)
            if len(preview) > 4000:
                preview = preview[:4000] + "\n... [truncated]"
            sink.append("**Parsed result:**")
            sink.append("```json")
            sink.append(preview)
            sink.append("```")
        any_rendered = False
        for r in list(records.requests.values()):
            block = _format_record(r)
            if block:
                sink.append(block)
                any_rendered = True
        if not any_rendered:
            sink.append("_(no in-scope HTTP traffic captured)_\n")
        records.reset()
        return value

    # ---- profile lookups (public, no auth) ----
    notch = await section(
        "profile.get_uuid_by_name('Notch')",
        lambda: profile_api.get_uuid_by_name("Notch"),
    )
    await section(
        "profile.get_uuids_by_names(['Notch','Dinnerbone','jeb_'])",
        lambda: profile_api.get_uuids_by_names(["Notch", "Dinnerbone", "jeb_"]),
    )
    if notch is not None:
        public = await section(
            f"profile.get_profile_by_uuid({notch.uuid!r})",
            lambda: profile_api.get_profile_by_uuid(notch.uuid),
        )
        await section(
            f"profile.get_profile_by_uuid({notch.uuid!r}, signed=True)",
            lambda: profile_api.get_profile_by_uuid(notch.uuid, signed=True),
        )
        if public is not None:
            decoded = textures.extract_textures(public)
            sink.append("\n## textures.extract_textures(Notch)\n")
            sink.append("- **Outcome:** `ok` (pure decoder, no HTTP)")
            sink.append("```json")
            sink.append(json.dumps(decoded.model_dump() if decoded else None, default=str, indent=2))
            sink.append("```")

    # ---- meta + blocklist (public) ----
    manifest = await section(
        "meta.fetch_version_manifest()",
        lambda: meta.fetch_version_manifest(),
    )
    if manifest is not None and manifest.versions:
        latest_release_id = manifest.latest_release
        latest = next((v for v in manifest.versions if v.id == latest_release_id), manifest.versions[0])
        # fetch_version_details may or may not exist; try
        details_fn = getattr(meta, "fetch_version_details", None)
        if details_fn is not None:
            await section(
                f"meta.fetch_version_details({latest.id!r})",
                lambda: details_fn(latest),
            )
    await section(
        "blocked_servers.fetch_blocked_servers()",
        lambda: blocked_servers.fetch_blocked_servers(),
    )

    # ---- authenticated own-account endpoints ----
    own = await section(
        "account.get_own_profile(session)",
        lambda: account.get_own_profile(session),
    )
    await section(
        "account.get_name_change_eligibility(session)",
        lambda: account.get_name_change_eligibility(session),
    )
    await section(
        "account.check_name_availability(session, 'thisnamealmostcertainlyexists')",
        lambda: account.check_name_availability(session, "thisnamealmostcertainlyexists"),
    )
    await section(
        "account.check_name_availability(session, 'fjkldsajfkldsajfkldsajfkldsaj')",
        lambda: account.check_name_availability(session, "fjkldsajfkldsajfkldsajfkldsaj"),
    )

    # ---- player certs ----
    await section(
        "player_certificates.fetch_player_certificates(session)",
        lambda: player_certificates.fetch_player_certificates(session),
    )

    # ---- realms (Java) ----
    await section(
        "realms.fetch_realms_compatible(session)",
        lambda: realms.fetch_realms_compatible(session),
    )
    await section(
        "realms.is_realms_available(session)",
        lambda: realms.is_realms_available(session),
    )
    await section(
        "realms.is_realms_tos_agreed(session)",
        lambda: realms.is_realms_tos_agreed(session),
    )
    worlds = await section(
        "realms.fetch_realms_worlds(session)",
        lambda: realms.fetch_realms_worlds(session),
    )
    if worlds:
        w0 = worlds[0]
        await section(
            f"realms.fetch_realms_world(session, {w0.world_id})",
            lambda: realms.fetch_realms_world(session, w0.world_id),
        )
        await section(
            f"realms.fetch_realms_join_info(session, {w0.world_id})",
            lambda: realms.fetch_realms_join_info(session, w0.world_id),
        )

    # ---- PlayFab (uses XSTS for a Bedrock-flavoured title) ----
    pf_token = await section(
        "playfab.playfab_login_with_xbox(xsts)",
        lambda: playfab.playfab_login_with_xbox(xsts),
    )
    if pf_token is not None:
        await section(
            "playfab.playfab_get_entity_token(pf_token.entity_token)",
            lambda: playfab.playfab_get_entity_token(pf_token.entity_token),
        )

    LOG_PATH.write_text("\n".join(sink) + "\n", encoding="utf-8")
    logger.info("API traffic log written to %s (%d sections)", LOG_PATH, sum(1 for s in sink if s.startswith("## ")))
    assert own is not None, "expected own profile to succeed"

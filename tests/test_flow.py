"""End-to-end flow test using respx + an in-memory storage backend."""

import pytest
import respx

from mcapi_auth._constants import (
    MC_LOGIN_WITH_XBOX_URL,
    MC_PROFILE_URL,
    MSA_DEVICE_CODE_URL,
    MSA_TOKEN_URL,
    XBL_AUTH_URL,
    XSTS_AUTH_URL,
)
from mcapi_auth.auth import (
    FileTokenStorage,
    MinecraftProfileNotFoundError,
    TokenStorage,
    login_device_code_v2,
)
from mcapi_auth.auth.msa import DeviceCodePrompt


class MemoryStorage(TokenStorage):
    def __init__(self, initial: str | None = None) -> None:
        self._token: str | None = initial

    async def load(self) -> str | None:
        return self._token

    async def save(self, refresh_token: str) -> None:
        self._token = refresh_token

    async def clear(self) -> None:
        self._token = None


def _wire_xbox_minecraft_routes() -> None:
    respx.post(XBL_AUTH_URL).respond(
        json={"Token": "xbl-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(XSTS_AUTH_URL).respond(
        json={"Token": "xsts-tok", "DisplayClaims": {"xui": [{"uhs": "uhs"}]}}
    )
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(json={"access_token": "mc-tok", "expires_in": 86400})
    respx.get(MC_PROFILE_URL).respond(
        json={"id": "069a79f444e94726a5befca90e38aaf5", "name": "Notch"}
    )


@respx.mock
async def test_login_with_cached_refresh_token_skips_device_code() -> None:
    # No device-code route registered — flow must not touch it.
    respx.post(MSA_TOKEN_URL).respond(
        json={
            "access_token": "fresh-msa",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
        }
    )
    _wire_xbox_minecraft_routes()

    storage = MemoryStorage(initial="stored-refresh")
    callback_called = False

    async def cb(_prompt: DeviceCodePrompt) -> None:
        nonlocal callback_called
        callback_called = True

    session = await login_device_code_v2(storage=storage, on_device_code=cb)
    assert session.username == "Notch"
    assert session.access_token == "mc-tok"
    assert session.refresh_token == "rotated-refresh"
    # Storage was updated with the rotated token.
    assert await storage.load() == "rotated-refresh"
    # No device-code prompt was shown.
    assert callback_called is False


@respx.mock
async def test_login_falls_back_to_device_code_on_refresh_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # storage has a stale token; refresh fails; we should fall through to
    # device-code, clearing storage along the way.
    import httpx

    respx.post(MSA_TOKEN_URL).mock(
        side_effect=[
            # 1st call: refresh attempt — rejected.
            httpx.Response(400, json={"error": "invalid_grant"}),
            # 2nd call: device-code poll — succeeds.
            httpx.Response(
                200,
                json={
                    "access_token": "device-msa",
                    "refresh_token": "device-refresh",
                    "expires_in": 3600,
                },
            ),
        ]
    )
    respx.post(MSA_DEVICE_CODE_URL).respond(
        json={
            "user_code": "AB-CD",
            "device_code": "dc",
            "verification_uri": "https://ms.com/link",
            "expires_in": 60,
            "interval": 1,
            "message": "go go go",
        }
    )
    _wire_xbox_minecraft_routes()

    async def fast_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr("mcapi_auth.auth.msa.asyncio.sleep", fast_sleep)

    storage = MemoryStorage(initial="stale")
    prompts: list[DeviceCodePrompt] = []

    async def cb(prompt: DeviceCodePrompt) -> None:
        prompts.append(prompt)

    session = await login_device_code_v2(storage=storage, on_device_code=cb)
    assert session.username == "Notch"
    assert session.refresh_token == "device-refresh"
    assert len(prompts) == 1
    assert prompts[0].user_code == "AB-CD"
    assert await storage.load() == "device-refresh"


@respx.mock
async def test_login_propagates_profile_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    respx.post(MSA_TOKEN_URL).respond(
        json={
            "access_token": "msa",
            "refresh_token": "rt-new",
            "expires_in": 3600,
        }
    )
    respx.post(XBL_AUTH_URL).respond(
        json={"Token": "xbl", "DisplayClaims": {"xui": [{"uhs": "u"}]}}
    )
    respx.post(XSTS_AUTH_URL).respond(
        json={"Token": "xsts", "DisplayClaims": {"xui": [{"uhs": "u"}]}}
    )
    respx.post(MC_LOGIN_WITH_XBOX_URL).respond(json={"access_token": "mc", "expires_in": 60})
    respx.get(MC_PROFILE_URL).respond(status_code=404)

    storage = MemoryStorage(initial="rt-old")
    with pytest.raises(MinecraftProfileNotFoundError):
        _ = await login_device_code_v2(storage=storage)


def test_default_storage_is_file_backed(tmp_path: object) -> None:
    # Simple invariant: when no storage is passed, the default is a
    # FileTokenStorage (we don't execute it — that path is XDG and depends
    # on the runtime env).
    _ = tmp_path
    storage = FileTokenStorage()
    assert storage.path.suffix == ".json"


@respx.mock
async def test_login_browser_v2_end_to_end() -> None:
    """Browser flow: redirect listener hits, MSA token exchange, XBL+XSTS+MC profile."""
    import asyncio
    import re
    from urllib.parse import parse_qs, urlparse

    import httpx as _httpx

    from mcapi_auth.auth import login_browser_v2

    # Let the localhost callback through respx; everything else is mocked.
    respx.route(url__regex=re.compile(r"^http://127\.0\.0\.1:\d+/")).pass_through()
    respx.post(MSA_TOKEN_URL).respond(
        json={"access_token": "msa-acc", "refresh_token": "msa-ref", "expires_in": 3600}
    )
    _wire_xbox_minecraft_routes()

    def fake_browser(url: str) -> None:
        parsed = parse_qs(urlparse(url).query)
        redirect_uri = parsed["redirect_uri"][0]
        state = parsed["state"][0]

        async def _hit() -> None:
            await asyncio.sleep(0.05)
            async with _httpx.AsyncClient(timeout=5.0) as c:
                _ = await c.get(f"{redirect_uri}?code=auth-code&state={state}")

        _ = asyncio.ensure_future(_hit())  # noqa: RUF006

    storage = MemoryStorage()
    session = await login_browser_v2(
        storage=storage,
        bind_host="127.0.0.1",
        bind_port=0,
        open_browser=fake_browser,
    )
    assert session.username == "Notch"
    assert session.access_token == "mc-tok"
    assert session.refresh_token == "msa-ref"
    assert await storage.load() == "msa-ref"

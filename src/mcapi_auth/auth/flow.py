"""High-level orchestration of stages 1-5."""

import inspect
import logging
from collections.abc import Awaitable, Callable

import httpx

from .._constants import (
    LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    LIVE_CONNECT_SCOPE_MBI_SSL,
    LIVE_CONNECT_TOKEN_URL,
    MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    MSA_SCOPE,
    PRISM_LAUNCHER_CLIENT_ID,
)
from ..exceptions import MSAFlowError
from .auth_code import acquire_msa_via_browser, acquire_msa_via_browser_v1
from .minecraft import fetch_profile, login_with_xbox
from .msa import (
    DeviceCodePrompt,
    MSATokens,
    exchange_refresh_token,
    poll_for_device_code_token,
    request_device_code,
)
from .session import MinecraftSession
from .storage import NullTokenStorage, TokenStorage
from .xbox import authenticate_xbl, authenticate_xsts

__all__ = ["DeviceCodeCallback", "login", "login_via_browser", "login_via_browser_v1"]

logger = logging.getLogger(__name__)

type DeviceCodeCallback = Callable[[DeviceCodePrompt], None | Awaitable[None]]
"""Sync or async callable invoked exactly once with the device-code prompt.

Default implementation prints to stdout. Pass your own to integrate with
a Discord bot, GUI, etc. If your callback is ``async``, it's awaited;
sync callables are invoked directly.
"""


def _default_prompt(prompt: DeviceCodePrompt) -> None:
    # Library code normally doesn't print, but this single user-facing
    # interaction is the whole point of device-code flow — and the
    # alternative ("silently hang") is strictly worse. Callers who care
    # supply their own callback.
    message = prompt.message or (
        f"Visit {prompt.verification_uri} and enter code {prompt.user_code}"
    )
    print(message)


async def _invoke_callback(cb: DeviceCodeCallback, prompt: DeviceCodePrompt) -> None:
    result = cb(prompt)
    if inspect.isawaitable(result):
        await result


async def login(
    *,
    storage: TokenStorage | None = None,
    on_device_code: DeviceCodeCallback | None = None,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftSession:
    """Run the full MSA → XBL → XSTS → Mojang flow end-to-end.

    Order of operations:

    1. If ``storage.load()`` returns a refresh token, try to use it.
       On success we skip stages 1-2 entirely.
    2. Otherwise (or on refresh failure) run the device-code flow. The
       prompt is delivered via ``on_device_code`` (defaults to ``print``).
    3. XBL → XSTS → ``login_with_xbox`` → profile fetch.
    4. Persist the (possibly rotated) refresh token via ``storage.save()``.

    Args:
        storage: Refresh-token persistence backend. Defaults to
            :class:`NullTokenStorage` — i.e. **no persistence**, every
            call starts a fresh device-code flow. Pass an explicit
            :class:`FileTokenStorage` (or any other ``TokenStorage``
            impl) to keep the rotated refresh token across runs.
        on_device_code: Awaitable called with the
            :class:`~mcapi_auth.auth.msa.DeviceCodePrompt` when the user needs to
            visit a URL. Only invoked when refresh-token reuse fails.
        client_id: MSA OAuth client_id. Defaults to the well-known
            public Minecraft Launcher client_id.
        http_client: Pre-configured :class:`httpx.AsyncClient` to reuse.
            One is created (and torn down) per call if omitted.

    Returns:
        A :class:`MinecraftSession` carrying the Minecraft access token,
        UUID, username, and rotated refresh token.
    """
    actual_storage: TokenStorage = storage if storage is not None else NullTokenStorage()
    prompt_cb: DeviceCodeCallback = (
        on_device_code if on_device_code is not None else _default_prompt
    )

    msa_tokens = await _acquire_msa_tokens(
        storage=actual_storage,
        prompt_cb=prompt_cb,
        client_id=client_id,
        http_client=http_client,
    )

    xbl = await authenticate_xbl(msa_tokens.access_token, http_client=http_client)
    xsts = await authenticate_xsts(xbl.token, http_client=http_client)
    mc_token = await login_with_xbox(xsts.userhash, xsts.token, http_client=http_client)
    profile = await fetch_profile(mc_token.access_token, http_client=http_client)

    await actual_storage.save(msa_tokens.refresh_token)

    return MinecraftSession(
        access_token=mc_token.access_token,
        refresh_token=msa_tokens.refresh_token,
        uuid=profile.uuid,
        username=profile.username,
        msa_access_token=msa_tokens.access_token,
        msa_access_token_expires_at=msa_tokens.expires_at,
        minecraft_access_token_expires_at=mc_token.expires_at,
    )


async def _acquire_msa_tokens(
    *,
    storage: TokenStorage,
    prompt_cb: DeviceCodeCallback,
    client_id: str,
    http_client: httpx.AsyncClient | None,
) -> MSATokens:
    refresh_token = await storage.load()
    if refresh_token is not None:
        try:
            return await exchange_refresh_token(
                refresh_token, client_id=client_id, http_client=http_client
            )
        except MSAFlowError as e:
            logger.info(
                "mcapi_auth: stored refresh token rejected (%s), falling back to device-code",
                type(e).__name__,
            )
            await storage.clear()

    prompt, pending = await request_device_code(client_id=client_id, http_client=http_client)
    await _invoke_callback(prompt_cb, prompt)
    return await poll_for_device_code_token(pending, client_id=client_id, http_client=http_client)


async def login_via_browser(
    *,
    storage: TokenStorage | None = None,
    client_id: str = PRISM_LAUNCHER_CLIENT_ID,
    bind_host: str = "127.0.0.1",
    bind_port: int = 0,
    redirect_path: str = "/callback",
    prompt: str | None = None,
    scope: str = MSA_SCOPE,
    open_browser: Callable[[str], None | Awaitable[None]] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftSession:
    """Run the full auth chain via the authorization-code (browser) flow.

    Mirror of :func:`login` but uses
    :func:`mcapi_auth.auth.auth_code.acquire_msa_via_browser` for the MSA step
    instead of device-code: a localhost HTTP listener is started, the
    user's browser is opened to the MSA authorize URL, and we wait for
    the redirect callback (validating CSRF ``state``).

    The refresh-token reuse path is identical to :func:`login` — if
    ``storage`` already has a valid refresh token, we skip the browser
    dance entirely. The browser is only opened when refresh fails or no
    token is stored.

    Args:
        storage: Refresh-token persistence backend. Defaults to
            :class:`NullTokenStorage` (no persistence). Pass an
            explicit :class:`FileTokenStorage` for cross-run reuse.
        client_id: MSA OAuth client_id. Defaults to the public
            Minecraft Launcher client_id.
        bind_host: Host to bind the local listener on
            (``127.0.0.1`` by default).
        bind_port: TCP port to bind to. ``0`` (default) picks a free port.
        redirect_path: Path the OAuth redirect must hit
            (``/callback`` by default).
        prompt: Optional ``prompt`` param to forward to the authorize
            endpoint (e.g. ``"select_account"`` to force the picker).
        scope: OAuth scope to request.
        open_browser: Callable invoked with the authorize URL. Defaults
            to :func:`webbrowser.open`. Pass a custom one (e.g. a logger
            that just prints the URL) to suppress the automatic open.
        http_client: Pre-configured :class:`httpx.AsyncClient` to reuse.

    Returns:
        A :class:`MinecraftSession` carrying the Minecraft access token,
        UUID, username, and rotated refresh token.
    """
    actual_storage: TokenStorage = storage if storage is not None else NullTokenStorage()

    msa_tokens: MSATokens | None = None
    refresh_token = await actual_storage.load()
    if refresh_token is not None:
        try:
            msa_tokens = await exchange_refresh_token(
                refresh_token, client_id=client_id, http_client=http_client
            )
        except MSAFlowError as e:
            logger.info(
                "mcapi_auth: stored refresh token rejected, falling back to browser flow: %s", e
            )
            await actual_storage.clear()

    if msa_tokens is None:
        msa_tokens = await acquire_msa_via_browser(
            client_id=client_id,
            bind_host=bind_host,
            bind_port=bind_port,
            redirect_path=redirect_path,
            prompt=prompt,
            scope=scope,
            open_browser=open_browser,
            http_client=http_client,
        )

    xbl = await authenticate_xbl(msa_tokens.access_token, http_client=http_client)
    xsts = await authenticate_xsts(xbl.token, http_client=http_client)
    mc_token = await login_with_xbox(xsts.userhash, xsts.token, http_client=http_client)
    profile = await fetch_profile(mc_token.access_token, http_client=http_client)

    await actual_storage.save(msa_tokens.refresh_token)

    return MinecraftSession(
        access_token=mc_token.access_token,
        refresh_token=msa_tokens.refresh_token,
        uuid=profile.uuid,
        username=profile.username,
        msa_access_token=msa_tokens.access_token,
        msa_access_token_expires_at=msa_tokens.expires_at,
        minecraft_access_token_expires_at=mc_token.expires_at,
    )


async def login_via_browser_v1(
    *,
    storage: TokenStorage | None = None,
    client_id: str = MINECRAFT_LAUNCHER_V1_CLIENT_ID,
    redirect_uri: str = LIVE_CONNECT_DESKTOP_REDIRECT_URI,
    scope: str = LIVE_CONNECT_SCOPE_MBI_SSL,
    open_browser: Callable[[str], None | Awaitable[None]] | None = None,
    prompt_for_code: Callable[[str], str | Awaitable[str]] | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> MinecraftSession:
    """Run the full auth chain via the **legacy Live-Connect v1** flow.

    Mirror of :func:`login_via_browser` but talks to
    ``login.live.com/oauth20_*.srf`` with the compressed Minecraft
    Launcher client_id (``00000000402b5328`` by default) and the
    ``MBI_SSL`` scope. Useful when the modern v2 endpoints reject
    your account / tenant or you specifically want parity with the
    historical launcher behaviour.

    Unlike the v2 browser flow this uses an **out-of-band paste-back**
    UX: the ``00000000402b5328`` client_id is registered only against
    the OOB ``oauth20_desktop.srf`` redirect, so we open the browser,
    let the user complete sign-in, and then prompt them to paste the
    resulting redirected URL back into the terminal.

    Refresh-token reuse honours the v1 endpoint and scope.

    See :func:`acquire_msa_via_browser_v1` for parameter semantics
    (``redirect_uri``, ``prompt_for_code``, ``open_browser``).
    """
    actual_storage: TokenStorage = storage if storage is not None else NullTokenStorage()

    msa_tokens: MSATokens | None = None
    refresh_token = await actual_storage.load()
    if refresh_token is not None:
        try:
            msa_tokens = await exchange_refresh_token(
                refresh_token,
                client_id=client_id,
                http_client=http_client,
                token_url=LIVE_CONNECT_TOKEN_URL,
                scope=scope,
            )
        except MSAFlowError as e:
            logger.info(
                "mcapi_auth: stored v1 refresh token rejected, falling back to browser flow: %s",
                e,
            )
            await actual_storage.clear()

    if msa_tokens is None:
        msa_tokens = await acquire_msa_via_browser_v1(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            open_browser=open_browser,
            prompt_for_code=prompt_for_code,
            http_client=http_client,
        )

    xbl = await authenticate_xbl(msa_tokens.access_token, http_client=http_client)
    xsts = await authenticate_xsts(xbl.token, http_client=http_client)
    mc_token = await login_with_xbox(xsts.userhash, xsts.token, http_client=http_client)
    profile = await fetch_profile(mc_token.access_token, http_client=http_client)

    await actual_storage.save(msa_tokens.refresh_token)

    return MinecraftSession(
        access_token=mc_token.access_token,
        refresh_token=msa_tokens.refresh_token,
        uuid=profile.uuid,
        username=profile.username,
        msa_access_token=msa_tokens.access_token,
        msa_access_token_expires_at=msa_tokens.expires_at,
        minecraft_access_token_expires_at=mc_token.expires_at,
    )

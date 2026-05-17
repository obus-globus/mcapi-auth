# mcapi-auth

> ⚠️ **Project status: alpha.** API surface may change without warning until 1.0.

Async, typed Python library that covers both halves of "talking to the
Mojang/Microsoft Minecraft stack":

- **Auth** (`mcapi_auth.auth`) — the 5-stage Microsoft → Xbox → Mojang
  handshake to turn a Microsoft account into a Minecraft access token +
  UUID + username, plus the related helpers (auth-code/PKCE, browser
  redirect listener, cookie-based silent flows, entitlements,
  joinServer, refresh-token storage, JWT decode).
- **API** (`mcapi_auth.api`) — the public + authed Mojang/Minecraft REST
  surface: UUID lookups, public profile + texture decode, blocked
  servers, authed profile / skin / cape / name endpoints, piston-meta
  version manifest.

This is the merger of the previously separate `mcauth` and `mcapi`
packages; see [`CHANGELOG.md`](CHANGELOG.md) for the migration notes.

Requires **Python 3.13+**. Runtime dependencies: `httpx`, `pydantic >= 2`,
`whenever >= 0.10`.

## Installation

```bash
pip install mcapi-auth                # once published
# or, from source:
git clone git@github.com:clawdbot-silly-waddle/mcapi-auth.git
cd mcapi-auth
uv sync
```

## Quickstart — auth + a couple of API calls

```python
import asyncio
from mcapi_auth import login, get_own_profile, get_uuid_by_name

async def main() -> None:
    session = await login()                       # Microsoft → Minecraft token
    print(session.username, session.uuid_dashed)

    profile = await get_own_profile(session)      # accepts session or raw str
    print(profile.skins, profile.capes)

    other = await get_uuid_by_name("Notch")       # public lookup, no auth
    print(other)

asyncio.run(main())
```

First run: a URL + 8-character code is printed; visit, paste, sign in.
Subsequent runs reuse the persisted refresh token.

## Package layout

```
mcapi_auth/
├── auth/      # token-chain stages, cookie flows, storage, JWT decode
├── api/       # public lookups + authed profile/skin/cape/name + piston-meta
└── exceptions # unified McApiAuthError tree (McAuthError + McApiError)
```

Everyday names are re-exported from the top level so most code can do
`from mcapi_auth import X`. Reach into the subpackages for niche
helpers (e.g. `from mcapi_auth.auth.auth_code import ...` for the
PKCE flow).

## Browser-driven login (no codes to type)

If your app can open a browser, `login_via_browser()` is friendlier:
it spins up a localhost listener, opens the MSA authorize URL, catches
the redirect, and validates CSRF state — all stdlib, no extra deps.

```python
from mcapi_auth import login_via_browser

session = await login_via_browser(prompt="select_account")
```

See [`examples/browser_login.py`](examples/browser_login.py) for a
runnable script.

## Custom prompt display

```python
from mcapi_auth import DeviceCodePrompt, login

async def show(prompt: DeviceCodePrompt) -> None:
    await channel.send(
        f"Sign in here within {prompt.expires_in}s: {prompt.verification_uri}\n"
        f"Code: `{prompt.user_code}`"
    )

session = await login(on_device_code=show)
```

## Custom token storage

```python
from mcapi_auth import TokenStorage, login

class MemoryStorage(TokenStorage):
    def __init__(self) -> None:
        self._token: str | None = None
    async def load(self) -> str | None: return self._token
    async def save(self, refresh_token: str) -> None: self._token = refresh_token
    async def clear(self) -> None: self._token = None

session = await login(storage=MemoryStorage())
```

The default storage (`FileTokenStorage`) writes JSON to
`$XDG_STATE_HOME/mcauth/refresh_token.json` (or `~/.local/state/mcauth/...`)
with `0600` permissions and atomic replace on save. (The on-disk path
is kept under `mcauth/` so refresh tokens persisted by the old
standalone `mcauth` package are picked up transparently.)

## Public API endpoints

The `mcapi_auth.api` half wraps Mojang's public + authed REST surface:

```python
from mcapi_auth import (
    # public — no auth
    get_uuid_by_name, get_uuids_by_names, get_profile_by_uuid,
    extract_textures, fetch_blocked_servers, is_server_blocked,
    fetch_version_manifest,
    # authed — pass a session or a raw access-token str
    get_own_profile, change_skin_from_url, change_skin_from_file,
    reset_skin, change_cape, disable_cape,
    check_name_availability, change_name, get_name_change_eligibility,
)

uuid = await get_uuid_by_name("Notch")
profile = await get_profile_by_uuid(uuid.id)
decoded = extract_textures(profile)            # skin URL, cape URL, slim/classic
print(decoded.skin.url, decoded.skin.model)

manifest = await fetch_version_manifest()
print(manifest.latest_release, manifest.latest_snapshot)
```

Every authed endpoint accepts either a raw access-token string or any
object exposing an `.access_token` attribute — which is exactly what
`MinecraftSession` provides, so you can pass the result of `login()`
directly.

## Typed errors

Two parallel hierarchies live under a single root:

```
McApiAuthError
├── McAuthError                         (auth-chain failures)
│   ├── MSAAuthError
│   │   ├── MSAFlowError
│   │   ├── DeviceCodeExpiredError
│   │   └── AuthorizationDeclinedError
│   ├── XboxAuthError
│   │   └── XSTSError                   (carries XErr code)
│   │       ├── NoXboxAccountError      # 2148916233
│   │       ├── RegionBlockedError      # 2148916235
│   │       ├── VerifyAgeRequiredError  # 2148916236
│   │       ├── AdultVerificationRequiredError  # 2148916237
│   │       └── ChildAccountError       # 2148916238 (needs Family Pack)
│   └── MinecraftAuthError
│       └── MinecraftProfileNotFoundError
└── McApiError                          (REST API failures)
    ├── HttpError                       (status_code, body, url)
    ├── NotFoundError
    ├── BadRequestError                 # 400
    ├── UnauthorizedError               # 401
    ├── ForbiddenError                  # 403
    ├── RateLimitedError                # 429, carries retry_after
    ├── InvalidProfileError
    ├── NameTakenError
    ├── NameNotAllowedError
    └── TooManyNamesError
```

`MCAuthError` is preserved as an alias of `McAuthError` for back-compat.
Network-level failures (`httpx.RequestError`, `TimeoutError`) propagate
unchanged — those aren't this library's domain.

## Reusing an `httpx.AsyncClient`

Every public function accepts an optional `http_client=` so callers can
plug in custom timeouts, proxies, transport mocks, retry transports,
caching transports, etc:

```python
async with httpx.AsyncClient(timeout=15.0, proxy="http://...") as client:
    session = await login(http_client=client)
    profile = await get_own_profile(session, http_client=client)
```

### Retries and HTTP caching

`mcapi-auth` doesn't bake in a retry or caching layer — they're
`httpx`-level concerns, so attach them to the client you pass in.

- [`httpx-retries`](https://pypi.org/project/httpx-retries/) for
  exponential-backoff retries:

  ```python
  from httpx_retries import Retry, RetryTransport

  retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
  async with httpx.AsyncClient(transport=RetryTransport(retry=retry)) as client:
      ...
  ```

  Be conservative with retry counts on the MSA / XSTS / Mojang token
  endpoints — they're rate-limit-sensitive. Public lookup endpoints
  (`api.mojang.com`) are friendlier; respect `Retry-After` on 429.

- [`hishel`](https://hishel.com/) for RFC 9111 HTTP caching. Mojang's
  public profile / piston-meta / blocked-servers endpoints return
  `Cache-Control` headers; wrapping the client in a hishel cache
  transport gives you transparent revalidation for free. Token-mint
  endpoints (`login.live.com`, XBL, XSTS, `loginWithXbox`) shouldn't be
  cached — they correctly emit no-store, so they pass through.

## Cookie-based bulk auth

For unattended automation against accounts you own,
`mcapi_auth.auth.cookies` ports the three flows that work from a
captured Microsoft session without typing a password:

```python
from mcapi_auth import (
    login_with_cookies_msa_v1,
    login_with_cookies_sisu,
    login_with_cookies_prism,
    CookieAuthError,
    BrowserCookie,
)

# Flow 1 — Live-Connect "Java public client": returns MSA access+refresh
tokens = await login_with_cookies_msa_v1("MSPAuth=...; MSPProf=...")

# Flow 2 — SISU (Xbox SSO): returns XBL/XSTS tokens (no refresh available)
sisu = await login_with_cookies_sisu("MSPAuth=...; MSPProf=...")

# Flow 3 — Prism Launcher (Azure-AD consumers): accepts structured cookies
tokens = await login_with_cookies_prism([
    BrowserCookie(name="MSPAuth", value="...", domain=".live.com"),
    BrowserCookie(name="MSPProf", value="...", domain=".live.com"),
])
```

Cookie acquisition is intentionally out of scope — bring your own
Selenium / nodriver / playwright session. See
[`examples/cookie_login.py`](examples/cookie_login.py) for the
"try MSA-v1, fall back to SISU on `CookieAuthError`" pattern.

> ⚠️ These primitives let you act as an account using its session
> cookies. Only use them on accounts you own or have explicit
> permission to automate.

## Beyond `login()`

A few additional auth-side helpers:

- `mcapi_auth.auth.auth_code` — authorization-code + PKCE entry point
  for desktop apps that prefer a localhost redirect over device-code.
- `mcapi_auth.decode_minecraft_access_token(token)` — decode the MC JWT
  offline to read `exp` / username / UUID from the embedded `pfd` claim.
- `mcapi_auth.fetch_entitlements(access_token)` — `/entitlements/mcstore`
  → `has_java` / `has_bedrock` / `has_game_pass`. Distinguishes "doesn't
  own MC" from "owns Bedrock only" (`/minecraft/profile` 404s in both).
- `mcapi_auth.join_server(...)` —
  `sessionserver.mojang.com/session/minecraft/join`, for proving profile
  ownership during a third-party-server handshake.

## More examples

See [`examples/`](examples/) for runnable scripts covering each entry
point: device-code, browser-driven, refresh-token reuse, cookie-based
bulk auth, custom storage, manual auth-code integration, entitlements,
joinServer, and offline JWT decode.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run basedpyright
```

## Why not `msal`?

Microsoft's official library is ~7 MB of code that mostly handles
enterprise tenants we don't need. The device-code flow is ~50 lines
hand-rolled with `httpx` — see `src/mcapi_auth/auth/msa.py`.

## Client-ID disclaimer

By default we use the public Minecraft Launcher `client_id`
(`00000000-402b-4cd3-a82b-c45ab2f1d3f7`) that every open-source launcher
relies on. Microsoft has tolerated this for ~5 years; if they ever
revoke it, every Minecraft launcher on Earth breaks the same day. Pass
a different `client_id=` to `login()` if you have your own MSA app
registration.

## License

MIT. See [`LICENSE`](./LICENSE).

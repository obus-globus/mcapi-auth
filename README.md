# mcapi-auth

[![CI](https://github.com/clawdbot-silly-waddle/mcapi-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/clawdbot-silly-waddle/mcapi-auth/actions/workflows/ci.yml)
![coverage](https://img.shields.io/badge/coverage-85.3%25-green)
![python](https://img.shields.io/badge/python-3.14+-blue)
![license](https://img.shields.io/badge/license-MIT-green)

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

Requires **Python 3.14+**. Runtime dependencies: `httpx`, `pydantic >= 2`,
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
from mcapi_auth import login_device_code_v1, get_own_profile, get_uuid_by_name

async def main() -> None:
    session = await login_device_code_v1()       # Microsoft → Minecraft token
    # Pass ``storage=FileTokenStorage()`` to persist the refresh token
    # across runs — by default tokens live only in memory.
    print(session.username, session.uuid_dashed)

    profile = await get_own_profile(session)      # accepts session or raw str
    print(profile.skins, profile.capes)

    other = await get_uuid_by_name("Notch")       # public lookup, no auth
    print(other)

asyncio.run(main())
```

First run: a URL + 8-character code is printed; visit, paste, sign in.
To persist the refresh token across runs (so subsequent launches skip
the interactive step), pass ``storage=FileTokenStorage()`` to
``login_device_code_v1()``. The default ``NullTokenStorage`` keeps state in memory
only.

## Synchronous usage

If you can't or don't want to write async code (one-off scripts,
Django/Flask views), use the sync facade — every public async function
is exposed as a blocking wrapper that runs in a fresh event loop:

```python
from mcapi_auth import sync as mcapi

session = mcapi.login()                       # blocks until done
profile = mcapi.get_own_profile(token=session.access_token)
print(profile.name, profile.id)
```

Caveats:

- Each call spins up a fresh `asyncio.run(...)` loop — fine for ad-hoc
  scripts, not great if you want connection pooling across many calls.
- **Do not call `mcapi_auth.sync.*` from inside a running asyncio
  loop.** It will raise — use the async API directly in that case.
- The full async surface (~73 functions including `login`, `refresh_*`,
  `get_*`, `change_*`, `fetch_*`, `is_*`, `accept_*`, `start_*`) is
  available. `from mcapi_auth import sync; dir(sync)` lists them.

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

If your app can open a browser, `login_browser_v2()` is friendlier:
it spins up a localhost listener, opens the MSA authorize URL, catches
the redirect, and validates CSRF state — all stdlib, no extra deps.

```python
from mcapi_auth import login_browser_v2

session = await login_browser_v2(prompt="select_account")
```

See [`examples/browser_login.py`](examples/browser_login.py) for a
runnable script.

## Custom prompt display

```python
from mcapi_auth import DeviceCodePrompt, login_device_code_v1

async def show(prompt: DeviceCodePrompt) -> None:
    await channel.send(
        f"Sign in here within {prompt.expires_in}s: {prompt.verification_uri}\n"
        f"Code: `{prompt.user_code}`"
    )

session = await login_device_code_v1(on_device_code=show)
```

## Custom token storage

```python
from mcapi_auth import TokenStorage, login_device_code_v1

class MemoryStorage(TokenStorage):
    def __init__(self) -> None:
        self._token: str | None = None
    async def load(self) -> str | None: return self._token
    async def save(self, refresh_token: str) -> None: self._token = refresh_token
    async def clear(self) -> None: self._token = None

session = await login_device_code_v1(storage=MemoryStorage())
```

The default storage (`FileTokenStorage`) writes JSON to
`$XDG_STATE_HOME/mcapi_auth/refresh_token.json` (falling back to
`~/.local/state/mcapi_auth/refresh_token.json`) with `0600` permissions
and atomic replace on save.

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
`MinecraftSession` provides, so you can pass the result of `login_device_code_v1()`
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

`MCAuthError` was an alias of `McAuthError` in 0.3.x; it was removed in
0.4. Network-level failures (`httpx.RequestError`, `TimeoutError`)
propagate unchanged — those aren't this library's domain.

## Reusing an `httpx.AsyncClient`

Every public function accepts an optional `http_client=` so callers can
plug in custom timeouts, proxies, transport mocks, retry transports,
caching transports, etc:

```python
async with httpx.AsyncClient(timeout=15.0, proxy="http://...") as client:
    session = await login_device_code_v1(http_client=client)
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

### Customising the default `User-Agent`

When you don't pass `http_client=`, the library builds a fallback
client that sends `User-Agent: mcapi-auth/<version>`. Override it
process-wide with:

```python
from mcapi_auth import set_default_user_agent, get_default_user_agent

set_default_user_agent("my-app/1.2.3 (+https://example.org/contact)")
print(get_default_user_agent())  # "my-app/1.2.3 (…)"
```

Caller-supplied clients are never mutated — if you pass your own
`httpx.AsyncClient`, its headers stay exactly as you configured them.
Blank values are rejected with `ValueError`.

## Cookie-based bulk auth

For unattended automation against accounts you own,
`mcapi_auth.auth.cookies` ports the three flows that work from a
captured Microsoft session without typing a password:

```python
from mcapi_auth import (
    login_with_cookies_msa_v1,
    login_with_cookies_sisu,
    login_with_cookies_msa_v2_loopback,
    CookieAuthError,
    BrowserCookie,
)

# Flow 1 — Live-Connect "Java public client": returns MSA access+refresh
tokens = await login_with_cookies_msa_v1("MSPAuth=...; MSPProf=...")

# Flow 2 — SISU (Xbox SSO): returns XBL/XSTS tokens (no refresh available)
sisu = await login_with_cookies_sisu("MSPAuth=...; MSPProf=...")

# Flow 3 — Prism Launcher (Azure-AD consumers): accepts structured cookies
tokens = await login_with_cookies_msa_v2_loopback([
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

## Beyond `login_device_code_v1()`

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

## Long-running apps — `AuthChain` + `Holder`

For apps that hold a single account open for hours/days,
`mcapi_auth.AuthChain` wraps the full MSA → XBL → XSTS → Minecraft
token chain with per-stage lazy refresh and listeners. Each stage is a
`Holder[T]` that knows how to refresh itself when expired; downstream
holders are invalidated automatically on MSA rotation.

```python
from mcapi_auth import AuthChain, MsaApplicationConfig

# Default: v1 device-code flow with the official MC launcher client_id.
chain = await AuthChain.login()

# For v2 / Azure-AD instead:
# chain = await AuthChain.login(
#     flow="device_code_v2", app=MsaApplicationConfig.from_known("prism")
# )

# Persist on every rotation:
chain.on_change(lambda stage, _old, _new: state.save(chain.dump_json()))

while running:
    mc = await chain.get_minecraft_token()    # refreshes if expired
    await do_stuff(mc.access_token)
```

Restoring across restarts retains XBL+XSTS so you don't re-derive the
chain on cold start:

```python
chain = AuthChain.load_json(state.load(), app=MsaApplicationConfig.v1_launcher())
mc = await chain.get_minecraft_token()   # uses cached values when fresh
```

`MsaApplicationConfig` bundles `(client_id, scope, authorize_url,
token_url, device_code_url, redirect_uri, xbl_use_d_prefix, is_v1)` so
the same config can be threaded through every helper:

- `MsaApplicationConfig.v2(client_id=...)` — modern consumers endpoint.
- `MsaApplicationConfig.v1_launcher(client_id=...)` — legacy
  Live-Connect endpoint, MBI_SSL scope, raw RPS ticket.
- `MsaApplicationConfig.from_known(alias)` — resolve an alias
  (`"prism"`, `"java"`, `"liquidlauncher"`, `"bedrock-android"`, …)
  into the correctly-shaped v1 or v2 config, with the known redirect
  override applied.

## Realms (Java edition)

```python
from mcapi_auth import (
    accept_realms_tos,
    fetch_realms_join_info,
    fetch_realms_worlds,
    is_realms_tos_agreed,
)

if not await is_realms_tos_agreed(session):
    await accept_realms_tos(session)

for world in await fetch_realms_worlds(session):
    print(world.world_id, world.name, world.owner_username)

info = await fetch_realms_join_info(session, world.world_id)
print(info.host, info.port)
```

All Realms calls accept any `MinecraftSession`-like object (anything
exposing `access_token` + `uuid` + `username`), including an
`AuthChain.to_session()` result. The `version=` cookie defaults to
`mcapi_auth.DEFAULT_REALMS_GAME_VERSION` (currently `"1.21.4"`); pass
`game_version="..."` to override.

Bedrock realms are not implemented (Bedrock uses a different API and
different XSTS relying party).

## Player chat-signing certificates (1.19+)

Minecraft 1.19 introduced signed chat (and chat reporting in 1.19.1+);
the client must fetch a Mojang-signed RSA key-pair from
`/player/certificates` and sign outbound messages with it.

```python
from mcapi_auth import fetch_player_certificates

certs = await fetch_player_certificates(session)
print(certs.expires_at, certs.refreshed_after)
public_der = certs.key_pair.public_key_der()        # raw DER bytes
mojang_sig = certs.public_key_signature_v2_bytes    # base64-decoded
```

`MinecraftKeyPair.public_key` / `private_key` are PEM strings;
`.public_key_der()` / `.private_key_der()` strip the PEM armor and
base64-decode for you. No `cryptography` dependency — load the keys
with your preferred crypto library if you need to sign.

## PlayFab login (Bedrock telemetry)

Minecraft: Bedrock Edition logs into PlayFab in addition to Xbox Live,
using an XSTS token. Once authenticated you get a PlayFab entity token
(short-lived JWT used by the title service), a stable PlayFab account
id, and a long-lived session ticket.

```python
from mcapi_auth import (
    BEDROCK_PLAYFAB_TITLE_ID,
    playfab_get_entity_token,
    playfab_login_with_xbox,
)

# `xsts` here is an mcapi_auth.XSTSToken — for PlayFab you usually
# want an XSTS issued against rp `http://playfab.xboxlive.com/`,
# which differs from the Minecraft RP. Get it however you like; this
# function only consumes the token.
pf = await playfab_login_with_xbox(xsts, title_id=BEDROCK_PLAYFAB_TITLE_ID)
print(pf.play_fab_id, pf.session_ticket, pf.entity_token.expires_at)

# Refresh just the entity token later, no XSTS round-trip needed:
new_entity = await playfab_get_entity_token(pf.entity_token)
```

This module covers the PlayFab piece only — see the Bedrock section
below for the rest of the client chain.

## Bedrock Edition client chain

Optional, requires the ``[bedrock]`` extra (which pulls in
``cryptography>=43`` for the ES384 keypair):

```bash
pip install mcapi-auth[bedrock]
```

Once an XSTS token scoped to Bedrock's relying party
(``https://multiplayer.minecraft.net/``) and a PlayFab session ticket
are in hand, you can run the rest of the chain:

```python
from mcapi_auth.api.bedrock import (
    generate_bedrock_session_keypair,
    minecraft_authenticate,
    start_minecraft_session,
    start_minecraft_multiplayer_session,
)
from uuid import uuid4

key_pair = generate_bedrock_session_keypair()        # ES384 / P-384
chain = await minecraft_authenticate(bedrock_xsts, key_pair)
print(chain.xuid, chain.display_name, chain.expires_at)

session = await start_minecraft_session(
    pf.session_ticket,
    game_version="1.21.50",
    device_id=uuid4(),
)
mp = await start_minecraft_multiplayer_session(session, key_pair)
print(mp.xuid, mp.uuid, mp.token)
```

The ES384 keypair should be persisted across launches — Mojang binds
it to the player's account in the ``identityJwt``. Use
``BedrockKeyPair.to_pem()`` / ``BedrockKeyPair.from_pem()`` for storage.

> **Note:** ``mcapi_auth``'s built-in ``authenticate_xsts()`` is
> scoped to the Java relying party. For a Bedrock-scoped XSTS use
> the Sisu flow in ``mcapi_auth.auth.xbox_device`` (added in 0.12.0)
> — it returns a UserToken, TitleToken, *and* an XSTSToken in one
> call, all bound to a persistent device keypair. See
> ``examples/bedrock_minimal.py``.

### Sisu flow / device-token authentication

For Bedrock and other Microsoft *title* client ids, the plain
``user.auth.xboxlive.com`` + ``xsts.auth.xboxlive.com`` chain is
insufficient — you need a TitleToken as well, which only the Sisu
endpoint mints. The ``mcapi_auth.auth.xbox_device`` module wraps it:

```python
from mcapi_auth import BEDROCK_WIN32_CLIENT_ID
from mcapi_auth.auth.xbox_device import (
    XBL_XSTS_BEDROCK_RELYING_PARTY,
    XblDeviceKeyPair,
    authenticate_xbl_device,
    sisu_authorize,
)
from uuid import uuid4

# Persist these across launches; Xbox treats them as a device identity.
device_kp = XblDeviceKeyPair.generate()
device_id = uuid4()

device_token = await authenticate_xbl_device(device_kp, device_id=device_id)

sisu = await sisu_authorize(
    msa.access_token,
    device_token,
    device_kp,
    client_id=BEDROCK_WIN32_CLIENT_ID,
    relying_party=XBL_XSTS_BEDROCK_RELYING_PARTY,
)
print(sisu.xsts_token.token, sisu.user_token.userhash, sisu.title_token.title_id)
```

The returned ``sisu.xsts_token`` is shape-compatible with
``mcapi_auth.XSTSToken`` (same ``.token`` / ``.userhash`` attributes)
and can be passed straight to ``minecraft_authenticate``,
``playfab_login_with_xbox``, or any of the other XSTS-consuming helpers.
Requires the ``[bedrock]`` extra (for ``cryptography``).

### BedrockAuthManager: full chain with lazy refresh

For long-running clients, ``BedrockAuthManager`` (added in 0.13.0) is
the Bedrock equivalent of ``AuthChain`` — it owns the stable Xbox
identity (device keypair + UUID + ES384 client keypair) and every
downstream token (MSA, DeviceToken, the two Sisu legs, PlayFab,
certificate chain, franchise session, multiplayer token), each in a
``Holder`` that refreshes on demand:

```python
from mcapi_auth.auth.bedrock_chain import BedrockAuthManager

mgr = await BedrockAuthManager.login()
mgr.on_change(lambda *_: state.save(mgr.dump_json()))

while running:
    mp = await mgr.get_multiplayer_token()   # auto-refreshes
    await join_server(mp.token)

# later, in another process:
mgr = BedrockAuthManager.load_json(state.load())
cert = await mgr.get_certificate_chain()
```

`BedrockAuthManager.login()` accepts both v1 and v2 client_ids. By
default it builds a `MsaApplicationConfig.v1_launcher(client_id=
bedrock_client_id)` and threads the matching `device_code_url` /
`token_url` / `scope` through the MSA layer — so every Bedrock
client_id (Win32, Android, iOS, Nintendo, PlayStation), which is only
registered against Microsoft's legacy `login.live.com/oauth20_*.srf`
endpoints, works without an explicit config.

> **Bootstrap shortcut:** the Bedrock-Win32 client_id is registered
> against a custom-protocol redirect that browsers can't follow, so for
> a first-time browser-driven bootstrap you can drive the MSA leg with
> the Java launcher's client_id (`MINECRAFT_LAUNCHER_V1_CLIENT_ID`) —
> XBL entitlement is keyed off the resulting Xbox profile, not off the
> MSA client_id — and pass `bedrock_client_id=BEDROCK_WIN32_CLIENT_ID`
> to `BedrockAuthManager.from_msa(...)` so the rest of the chain still
> targets the Bedrock relying party. The refreshed snapshot stores the
> Bedrock client_id and uses it on subsequent refreshes.

Persistence keeps the device keypair + UUID stable across runs (Xbox
remembers them as a single device identity), and only the stages whose
inputs actually changed are invalidated on refresh — e.g. an MSA
rotation re-runs the Sisu legs but keeps the DeviceToken.

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
a different `client_id=` to `login_device_code_v1()` if you have your own MSA app
registration.

## Known client_id catalog

`mcapi_auth.KNOWN_CLIENT_IDS` maps friendly aliases to well-known
Microsoft client_ids used across the Minecraft ecosystem. v1 (16-hex,
no dashes) IDs work against `login.live.com/oauth20_*.srf` with the
`MBI_SSL` scope; v2 (Azure-AD GUID) IDs work against
`login.microsoftonline.com/consumers/oauth2/v2.0/*` with
`XboxLive.signin offline_access`.

The matrix below is what each `client_id` actually accepts as a
`redirect_uri`, as derived from probing every entry end-to-end against
the v1 and v2 `authorize` endpoints. Use the listed flow:

| alias                  | type | accepted redirect_uri(s)                                 | flow                  |
|--|--|--|--|
| `java`                 | v1   | OOB only (`oauth20_desktop.srf`)                         | `login_browser_v1`  |
| `bedrock-android`      | v1   | OOB only                                                 | `login_browser_v1`  |
| `bedrock-ios`          | v1   | OOB only                                                 | `login_browser_v1`  |
| `bedrock-nintendo`     | v1   | OOB only                                                 | `login_browser_v1`  |
| `bedrock-playstation`  | v1   | OOB only                                                 | `login_browser_v1`  |
| `bedrock-win32`        | v1   | **broken upstream** for OOB. Use `java` / `MINECRAFT_LAUNCHER_V1_CLIENT_ID` for the MSA leg and `bedrock_client_id=BEDROCK_WIN32_CLIENT_ID` on `BedrockAuthManager` — XBL entitlement keys off the resulting Xbox profile, not the MSA client_id. | (MSA via `java`) |
| `xbox-app-ios`         | v1   | OOB only                                                 | `login_browser_v1`  |
| `xbox-gamepass-ios`    | v1   | OOB only                                                 | `login_browser_v1`  |
| `prism` *(default)*    | v2   | `http://{127.0.0.1,localhost}:*/` (root path)            | `login_browser_v2` or `login_device_code_v2` |
| `liquidlauncher`/`liquidbounce` | v2 | `http://localhost:*/login`                          | `login_browser_v2` or `login_device_code_v2` |
| `edu`                  | v2   | none — no loopback registered                            | `login_device_code_v1` only |
| `office365`            | v2   | none — no loopback registered                            | `login_device_code_v1` only |

Helpers:

- `is_v1_client_id(client_id)` — decide between v1/v2 endpoint families.
- `resolve_client_id(name_or_id)` — alias → client_id lookup.
- `resolve_browser_redirect(client_id)` — returns
  `(bind_host, redirect_path)` for clients with a known registered
  loopback URI (currently `prism`, `liquidlauncher`); `None` otherwise.
- `is_browser_unsupported(client_id)` — `True` if
  `login_browser_v2` (v2 loopback) cannot succeed for this client_id:
  every v1 ID (rejected by the v2 endpoint as `AADSTS70001`) plus
  every v2 ID without a loopback URL registered (`edu`, `office365`).

## License

MIT. See [`LICENSE`](./LICENSE).

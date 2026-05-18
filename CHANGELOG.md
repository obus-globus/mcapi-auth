# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0] - 2026-05-18

### Changed

- **Breaking: renamed and split the headline ``login`` entry points** so
  every name encodes both the **mechanism** and the **API version**. The
  old unqualified ``login()`` is gone; callers must pick explicitly.
  - ``login()`` (v2 device-code) → ``login_device_code_v2()``
  - ``login_via_browser()`` → ``login_browser_v2()``
  - ``login_via_browser_v1()`` → ``login_browser_v1()``
  - **New:** ``login_device_code_v1()`` — v1 / Live-Connect device-code
    flow with the official Minecraft Launcher's v1 client_id as the
    default. Hits ``login.live.com/oauth20_connect.srf`` for the
    device-code request and ``login.live.com/oauth20_token.srf`` for the
    poll, uses the ``MBI_SSL`` scope, and sends the XBL ``RpsTicket``
    without the ``d=`` prefix (parity with the official launcher).
- ``AuthChain.login()`` now accepts a ``flow: AuthChainFlow`` keyword
  (``Literal["device_code_v1", "device_code_v2"]``), defaulting to
  ``"device_code_v1"``. v1 is the new default everywhere because it
  matches what the official Minecraft Launcher does (more permissive
  XBL tokens, no Azure-AD consent prompts).
- ``request_device_code`` / ``poll_for_device_code_token`` gained
  ``scope``, ``device_code_url`` / ``token_url`` and ``is_v1`` keyword
  arguments so the same primitives drive both v1 and v2 device-code.
  Defaults preserve the previous v2 behaviour.
- ``MsaApplicationConfig.v1_launcher()`` now sets ``device_code_url`` to
  the proper ``oauth20_connect.srf`` endpoint (was previously left at
  the v2 URL with a comment claiming v1 had no device-code flow — it
  does, per RaphiMC/MinecraftAuth's ``MsaEnvironment.LIVE``).

### Added

- New constant ``LIVE_CONNECT_DEVICE_CODE_URL =
  "https://login.live.com/oauth20_connect.srf"``.
- New type alias ``AuthChainFlow`` for the ``flow=`` keyword on
  ``AuthChain.login``.

## [0.14.0] - 2026-05-18

### Changed

- **Breaking: renamed ``login_with_cookies_prism`` →
  ``login_with_cookies_msa_v2_loopback``.** The function isn't tied to
  PrismLauncher — it implements the generic MSA v2 client + loopback
  redirect flow on the Azure-AD ``consumers`` endpoints, and works for
  any v2 client_id with a ``http://127.0.0.1:*`` redirect URI registered
  (currently Prism and LiquidLauncher). The new name matches the
  existing ``login_with_cookies_msa_v1`` for symmetry. No deprecation
  alias is shipped; update callers directly.
- Internal helpers ``_exchange_prism_code``, ``_handle_prism_html_flow``,
  ``_handle_prism_interstitial`` were correspondingly renamed to
  ``_exchange_v2_loopback_code``, ``_handle_v2_loopback_html_flow``,
  ``_handle_v2_loopback_interstitial``.

### Added

- Cookie-flow ``client_id`` matrix tests: 12 parametrised tests
  verifying every known v1 / v2 client_id is threaded into the
  underlying OAuth ``client_id`` parameter verbatim, in both the
  authorize URL query and the token-exchange POST body. Catches
  regressions where the helper might lower-case a hex id, drop dashes,
  or substitute its default.

## [0.13.0] - 2026-05-18

### Added

- **``BedrockAuthManager`` — full Bedrock-leg auth chain** with lazy
  refresh and change listeners (parallel to the existing
  ``AuthChain`` for the Java leg).
  - Holds every stage in its own ``Holder``: MSA → DeviceToken →
    Bedrock-Sisu / PlayFab-Sisu → PlayFabToken → certificate chain →
    franchise session → multiplayer token.
  - Persists the stable Xbox device identity (ES256 device keypair +
    device UUID) and the ES384 client identity keypair across
    serialise / restore round-trips, so the player isn't seen as a
    new device on every cold start.
  - ``dump_json()`` / ``load_json()`` serialise the full state
    (identity + every cached token).
  - ``on_change(stage, old, new)`` listener fires on every rotation;
    invalidation cascades drop only the downstream stages whose
    inputs changed (e.g. MSA rotation keeps the device token).
  - ``login()`` runs the device-code flow end-to-end and (by default)
    primes the chain all the way down to the multiplayer token so a
    caller can immediately ``dump_json()``.
  - ``from_msa()`` bridges an existing ``AuthChain``'s MSA tokens
    into a Bedrock manager without re-running device code.
- ``DEFAULT_BEDROCK_GAME_VERSION`` constant for the franchise-service
  ``gameVersion`` field; overridable per manager.

### Notes

- The XSTS tokens surfaced by ``get_bedrock_xsts`` /
  ``get_playfab_xsts`` remain ``XblXstsToken`` instances — shape-
  compatible with ``XSTSToken`` (both have ``.token`` and
  ``.userhash``); ``# type: ignore[arg-type]`` is still required at
  the call site for static type-checkers. A proper protocol
  unification is on the roadmap.

## [0.12.0] - 2026-05-18

### Added

- **Sisu / Xbox-Live device-token authentication** (new
  ``mcapi_auth.auth.xbox_device`` module, requires the ``[bedrock]``
  extra for the ``cryptography`` dep — same as ``api.bedrock``):
  - ``XblDeviceKeyPair`` — ES256 / NIST P-256 device keypair with
    PEM round-trip, ``ProofKey`` JWK helper, and the Xbox-specific
    ``Signature`` header builder (Windows-epoch timestamp +
    ECDSA-SHA256 in P1363 raw r||s format).
  - ``authenticate_xbl_device(keypair, *, device_type, device_id)``
    — POSTs to ``device.auth.xboxlive.com/device/authenticate``,
    returns an ``XblDeviceToken``.
  - ``sisu_authorize(msa_token, device_token, keypair, *, client_id,
    relying_party)`` — POSTs to ``sisu.xboxlive.com/authorize``,
    returns ``XblSisuTokens`` (UserToken + TitleToken + XSTSToken in
    one round-trip). 401 responses are translated to typed XErr
    exceptions just like :func:`mcapi_auth.authenticate_xsts`.
  - Constants ``XBL_XSTS_BEDROCK_RELYING_PARTY``,
    ``XBL_XSTS_BEDROCK_PLAYFAB_RELYING_PARTY``,
    ``XBL_XSTS_BEDROCK_REALMS_RELYING_PARTY`` for the common Sisu
    audiences.
- ``examples/bedrock_minimal.py`` rewritten to use the full Sisu
  flow end-to-end (persisted device keypair + device UUID, two
  ``sisu_authorize`` calls for the multiplayer and PlayFab audiences,
  ES384 identity keypair, ``minecraft_authenticate``, session JWT,
  signed multiplayer token).
- ``examples/playfab_login.py`` now uses
  ``https://b980a380.minecraft.playfabapi.com/`` as the PlayFab XSTS
  relying party (matching the Java reference) and references the
  Sisu-based bedrock example.

### Notes

- The returned ``XblXstsToken`` is shape-compatible with the existing
  ``mcapi_auth.XSTSToken`` (both expose ``.token`` and ``.userhash``),
  so it can be passed directly to ``minecraft_authenticate``,
  ``playfab_login_with_xbox``, etc. — a ``# type: ignore[arg-type]``
  may be needed at the call site since the static types differ. A
  proper protocol unification is on the roadmap.

## [0.11.0] - 2026-05-18

### Added

- ``mcapi_auth.set_default_user_agent(str)`` and
  ``mcapi_auth.get_default_user_agent()`` — process-wide overrides for
  the ``User-Agent`` header used by the library's *fallback*
  :class:`httpx.AsyncClient` (the one built when a caller does not pass
  ``http_client=``). Caller-supplied clients are never mutated — their
  headers remain whatever their owner configured. Blank values are
  rejected with :class:`ValueError`.

## [0.10.1] - 2026-05-18

### Fixed

- ``DEFAULT_API_USER_AGENT`` was hardcoded to ``mcapi-auth/0.3.0`` and
  never updated. It is now derived from package metadata
  (``importlib.metadata.version``) so it tracks the real release
  automatically.

### Changed

- ``MinecraftMultiplayerToken.uuid`` docstring rewritten — previously
  it incorrectly described the derivation as ``uuid5`` when the actual
  implementation is MD5-based (version 3) for Java parity.
- Removed the unused ``uuid5`` import and its ``_ = uuid5``
  suppression line from ``api.bedrock``.
- ``README`` quickstart now mentions that the default ``login()``
  storage keeps tokens in memory; ``FileTokenStorage()`` is needed for
  cross-run persistence.

## [0.10.0] - 2026-05-18

### Added

- **Bedrock Edition client chain primitives** (new `mcapi_auth.api.bedrock`
  module, requires the optional `bedrock` extra → `pip install
  mcapi-auth[bedrock]`):
  - ``BedrockKeyPair`` — ES384 / NIST P-384 client identity keypair with
    ``.generate()``, PEM round-trip (``.to_pem()`` / ``.from_pem()``),
    and SubjectPublicKeyInfo DER / base64 helpers for wire use.
  - ``MinecraftCertificateChain`` — wraps the 2-element
    ``[mojangJwt, identityJwt]`` chain Mojang returns and exposes
    ``xuid``, ``display_name``, ``identity_uuid``, and ``expires_at``
    (earliest of the two ``exp`` claims).
  - ``MinecraftSession`` / ``MinecraftMultiplayerToken`` for the
    `authorization.franchise.minecraft-services.net` session+multiplayer
    endpoints (PlayFab → session JWT → multiplayer signed token).
    ``MinecraftMultiplayerToken.uuid`` derives the Bedrock player UUID
    via the Java-compatible MD5 namespace (``pocket-auth-1-xuid:<xuid>``).
  - ``decode_jwt_payload(jwt)`` — base64url middle-segment parser for
    unverified inspection of Bedrock JWTs.
  - ``minecraft_authenticate(xsts, key_pair)`` — POSTs to
    `multiplayer.minecraft.net/authentication` with a Bedrock-scoped
    XSTS token (the caller is responsible for obtaining one — the
    existing ``authenticate_xsts`` helper is Java-scoped).
  - ``start_minecraft_session(playfab_session_ticket, *, game_version,
    device_id)`` and ``start_minecraft_multiplayer_session(session,
    key_pair)``.
- ``cryptography>=43`` is exposed as an optional dependency under the
  ``bedrock`` extra; ``import mcapi_auth.api.bedrock`` raises a clear
  ``ImportError`` with install instructions if it is missing.

### Notes

- This is a focused slice of Bedrock support — keypair, mcChain
  authentication, session token, and signed multiplayer token. Full
  Sisu / XBL-device-token flows and a high-level ``BedrockAuthManager``
  are out of scope for 0.10.0.

## [0.9.0] - 2026-05-18

### Added

- **PlayFab login** (Bedrock telemetry / title service):
  - ``PlayFabToken`` (entity token + PlayFab account id + session ticket).
  - ``PlayFabEntityToken`` (the ``X-EntityToken`` JWT + entity id/type +
    expiry). ``PlayFabEntityToken.from_api_payload`` flattens the
    PlayFab API's nested ``Entity`` object.
  - ``playfab_login_with_xbox(xsts, *, title_id=...)`` — exchanges an
    XSTS token for a ``PlayFabToken`` against
    ``POST {title}.playfabapi.com/Client/LoginWithXbox``. Defaults to
    the retail Bedrock title id (``20CA2``); pass
    ``EDU_PLAYFAB_TITLE_ID`` for Education Edition.
  - ``playfab_get_entity_token(entity_token)`` — refreshes only the
    entity token (cheap; no XSTS round-trip) against
    ``POST {title}.playfabapi.com/Authentication/GetEntityToken``.
  - ``PlayFabError`` exposes ``status_code``, ``error``,
    ``error_message``, ``error_code``.
  - ``BEDROCK_PLAYFAB_TITLE_ID`` (``"20CA2"``) and
    ``EDU_PLAYFAB_TITLE_ID`` (``"6955F"``) constants.

  Note: this is the PlayFab piece only. Bedrock's full chain (ES384
  keypair, ``mcChain`` signing, multiplayer token) is still pending.

## [0.8.3] - 2026-05-17

### Changed

- SonarQube cleanup of new-in-0.8.0+ code: drop redundant
  ``ValueError`` from ``except (ValidationError, ValueError)`` in
  ``realms.py`` and ``player_certificates.py`` (Pydantic's
  ``ValidationError`` already extends ``ValueError``). Convert
  ``_bump_xbl_expiry`` / ``_bump_xsts_expiry`` from ``async def`` to
  plain ``def`` since they perform no awaits — the ``Holder`` listener
  interface accepts both shapes.

## [0.8.2] - 2026-05-17

### Fixed

- **AuthChain XBL/XSTS expiry now persists across ``dump_json`` →
  ``load_json``.** Previously the synthetic 14-hour expiry was
  recomputed at every holder construction, including deserialisation,
  which would treat a 13-hour-old cached XBL/XSTS token as fresh and
  cause downstream 401s after restoring a stale chain snapshot. The
  snapshot now stores the expiry alongside each token; restored
  holders use the persisted value. v1 snapshots (without expiries)
  still load — the missing fields default to ``None`` and fall back
  to ``now + 14h``, matching pre-0.8.2 behaviour.
- AuthChain ``_on_msa_rotated`` also clears the cached XBL/XSTS
  expiries so a stale persisted expiry can't leak across an MSA
  rotation.

## [0.8.1] - 2026-05-17

### Added

- **``MinecraftPlayerCertificates``** + ``fetch_player_certificates`` —
  the ``POST /player/certificates`` endpoint (Minecraft 1.19+ signed
  chat). Returns ``MinecraftKeyPair`` (PEM strings + DER decode
  helpers), ``public_key_signature_v2`` (base64 + decoded bytes
  property), the legacy ``public_key_signature``, plus ``expires_at``
  and ``refreshed_after`` instants. Accepts any ``TokenLike``.
  No ``cryptography`` dependency — keys exposed as PEM/DER bytes for
  callers to load with their preferred crypto library.

## [0.8.0] - 2026-05-17

### Added

- **``MsaApplicationConfig``** — frozen dataclass bundling the MSA OAuth
  parameters (``client_id``, ``scope``, ``authorize_url``,
  ``token_url``, ``device_code_url``, ``redirect_uri``,
  ``xbl_use_d_prefix``, ``is_v1``) for reuse across calls. Comes with
  ``MsaApplicationConfig.v2()`` / ``.v1_launcher()`` factories and
  ``.from_known(alias)`` to resolve a friendly alias from
  ``KNOWN_CLIENT_IDS`` into a correctly-shaped v1 or v2 config.
- **``Holder[T]``** — generic lazy-refresh wrapper. Wraps a value that
  has an expiry instant + an async refresher; ``get_up_to_date()``
  refreshes if expired (with optional ``leeway`` and ``force``).
  Supports sync + async change listeners via ``add_listener``; a single
  in-flight refresh is shared across concurrent callers.
  Inspired by ``net.raphimc.minecraftauth.util.holder.Holder``.
- **``AuthChain``** — full MSA → XBL → XSTS → Minecraft state with
  per-stage ``Holder`` wrapping. Exposes ``get_msa_tokens()``,
  ``get_xbl_token()``, ``get_xsts_token()``, ``get_minecraft_token()``,
  ``get_profile()`` (all lazy-refreshing); ``on_change(cb)`` for
  chain-wide listeners receiving ``(stage_name, old, new)``;
  ``dump_json()``/``load_json()`` for full state serialisation
  (including cached XBL/XSTS tokens) so cold starts skip the chain when
  nothing has expired; ``from_session(...)`` to bridge an existing
  ``MinecraftSession``; ``to_session()`` to snapshot back into the flat
  form. MSA rotation invalidates downstream holders automatically.
- **Realms API** (``mcapi_auth.api.realms``) — Java edition Realms
  surface: ``fetch_realms_worlds``, ``fetch_realms_world``,
  ``fetch_realms_join_info``, ``fetch_realms_compatible``,
  ``is_realms_available``, ``is_realms_tos_agreed``,
  ``accept_realms_tos``. Pydantic models: ``RealmsWorld``,
  ``RealmsJoinInfo``, ``RealmsPlayer``, ``RealmsCompatibility``.
  Typed ``RealmsTosError`` raised when an account hasn't accepted the
  TOS. All endpoints accept any ``TokenLike`` that exposes ``uuid`` +
  ``username`` (i.e. ``MinecraftSession``); raw access tokens require
  explicit ``uuid=`` / ``username=`` kwargs.
  Bedrock realms remain out of scope.
- ``DEFAULT_REALMS_GAME_VERSION`` constant (default ``"1.21.4"``)
  exposed for callers that need to override the ``version`` cookie.

### Notes

- Bedrock-edition full chain, ``MinecraftPlayerCertificates``, and
  PlayFab tokens deliberately remain unimplemented and are tracked for
  later work; see the README "Roadmap" section.

## [0.7.4] - 2026-05-17

### Changed

- ``BROWSER_UNSUPPORTED_CLIENT_IDS`` now also includes every v1 /
  Live-Connect client_id in the catalog (``java``, ``bedrock-*``,
  ``xbox-app-ios``, ``xbox-gamepass-ios``). Correction to 0.7.3:
  previously this set listed only the two v2 GUIDs without a registered
  loopback URL (``edu``, ``office365``). v1 IDs are also incompatible
  with :func:`mcapi_auth.auth.flow.login_via_browser` (which targets
  the v2 ``consumers`` endpoint and rejects v1 client_ids as
  ``AADSTS70001``).
- Expanded docstrings on ``KNOWN_CLIENT_REDIRECTS``,
  ``BROWSER_UNSUPPORTED_CLIENT_IDS``, and ``is_browser_unsupported``
  to record the redirect-URI matrix derived from probing every entry
  in ``KNOWN_CLIENT_IDS``.

### Notes

- End-to-end probe via the ``liquidchat-loopback-probe`` tool
  confirmed that no v1 client_id in the catalog accepts any loopback
  redirect — earlier probe results that classified
  ``bedrock-playstation``, ``xbox-app-ios``, and ``xbox-gamepass-ios``
  as accepting localhost were false positives from a title-based
  classifier; the actual error renders in the response body via JS.

## [0.7.3] - 2026-05-17

### Added

- `KNOWN_CLIENT_REDIRECTS` now includes Prism Launcher
  (`c36a9fb6-…`): registered as `http://127.0.0.1:*/` (root path, any
  port). Without this override the default `/callback` path was
  rejected with `invalid_request` at the authorize step.
- `BROWSER_UNSUPPORTED_CLIENT_IDS` frozenset + `is_browser_unsupported(client_id)`
  helper. Lists client_ids whose Azure-AD app has no loopback reply URL
  registered (`edu`, `office365`), for which any `login_via_browser`
  attempt would fail at the authorize step. Callers should fall back
  to device-code.

### Notes

- Probed every entry in `KNOWN_CLIENT_IDS` against the v1 and v2
  authorize endpoints with `{127.0.0.1,localhost}:*` × `{/, /callback,
  /login}` to derive these mappings.
- `bedrock-win32` (`0000000040159362`) appears retired upstream — even
  the OOB redirect now returns `invalid_request`. No client-side fix
  possible; document only.

## [0.7.2] - 2026-05-17

### Added

- ``KNOWN_CLIENT_REDIRECTS`` mapping + ``resolve_browser_redirect()``
  helper. Maps a client_id to the ``(bind_host, redirect_path)`` pair
  that the Azure app registration expects, so callers of
  ``login_via_browser`` can match the registered reply URI. Currently
  pins LiquidLauncher / LiquidBounce's client to
  ``("localhost", "/login")``.

## [0.7.1] - 2026-05-17

### Added

- ``LIQUIDLAUNCHER_CLIENT_ID`` constant
  (``0add8caf-2cc6-4546-b798-c3d171217dd9``) — the v2 Azure-AD app shared
  by LiquidLauncher (``src-tauri/src/minecraft/auth.rs``) and LiquidBounce
  (``mc-authlib``'s ``MicrosoftAccount$AuthMethod.LIQUIDBOUNCE``). Exposed
  through ``KNOWN_CLIENT_IDS`` as both ``liquidlauncher`` and
  ``liquidbounce`` (they're the same client_id).

## [0.7.0] - 2026-05-17

### Added

- A catalog of well-known Microsoft client_ids cross-referenced
  against `gophertunnel`, `prismarine-auth`, and `RaphiMC/MinecraftAuth`.
  New constants in :mod:`mcapi_auth` (and re-exported from
  :mod:`mcapi_auth.auth`):
  * ``BEDROCK_WIN32_CLIENT_ID = "0000000040159362"``
  * ``BEDROCK_ANDROID_CLIENT_ID = "0000000048183522"``
  * ``BEDROCK_IOS_CLIENT_ID = "000000004c17c01a"``
  * ``BEDROCK_NINTENDO_CLIENT_ID = "00000000441cc96b"`` (Switch)
  * ``BEDROCK_PLAYSTATION_CLIENT_ID = "000000004827c78e"``
  * ``XBOX_APP_IOS_CLIENT_ID = "000000004c12ae6f"``
  * ``XBOX_GAMEPASS_IOS_CLIENT_ID = "000000004c20a908"``
  * ``EDU_CLIENT_ID = "b36b1432-1a1c-4c82-9b76-24de1cab42f2"``
  * ``OFFICE365_API_EDITOR_CLIENT_ID = "389b1b32-b5d5-43b2-bddc-84ce938d6737"``
- ``KNOWN_CLIENT_IDS`` — a ``dict[str, str]`` mapping friendly aliases
  (``"java"``, ``"prism"``, ``"bedrock-nintendo"``, …) to the
  respective client_id strings, suitable for CLI ``--client-id`` flags.
- :func:`is_v1_client_id` — returns ``True`` for compressed
  Live-Connect client_ids (16 hex chars, no dashes), ``False`` for
  Azure-AD GUIDs. Use this to decide which auth flow to dispatch.
- :func:`resolve_client_id` — looks up an alias in
  ``KNOWN_CLIENT_IDS`` case-insensitively; passes raw IDs through.

## [0.6.2] - 2026-05-17

### Fixed

- ``login_via_browser_v1`` now calls ``authenticate_xbl`` with
  ``use_d_prefix=False``. MBI_SSL tokens minted by the Live-Connect v1
  endpoint are pre-formed RPS tickets that XBL ``/authenticate``
  expects raw — prefixing them with ``d=`` caused a 401
  ``XBL authenticate failed: status=401``.

## [0.6.1] - 2026-05-17

### Changed

- ``acquire_msa_via_browser_v1`` and ``login_via_browser_v1`` no
  longer try to use a localhost-redirect listener. The compressed
  Live-Connect client_id ``00000000402b5328`` is only registered
  against the OOB ``oauth20_desktop.srf`` redirect, so an arbitrary
  ``http://127.0.0.1:<port>/callback`` URI is rejected by Microsoft
  with ``invalid_request: The provided value for the input parameter
  'redirect_uri' is not valid``. The flow is now **paste-back**:
  open the browser, sign in, and paste the redirected URL (or just
  the ``code=`` value) back into the terminal. New kwargs:
  ``redirect_uri``, ``prompt_for_code``. Removed obsolete kwargs:
  ``bind_host``, ``bind_port``, ``redirect_path``, ``success_html``
  on the v1 helpers.

### Added

- ``_parse_oob_response`` (internal) accepts a bare authorization
  code, a full redirected URL, or a bare query string, and surfaces
  ``error=`` responses via :class:`MSAFlowError`.

## [0.6.0] - 2026-05-17

### Added

- ``login_via_browser_v1`` and ``acquire_msa_via_browser_v1`` — a
  full-chain interactive browser login that targets the legacy
  Live-Connect v1 endpoints (``login.live.com/oauth20_*.srf``) using
  the compressed Minecraft Launcher client_id
  (``MINECRAFT_LAUNCHER_V1_CLIENT_ID = "00000000402b5328"``) and the
  ``MBI_SSL`` scope. Useful when the modern v2 device-code / auth-code
  flow is unavailable for an account or you specifically want parity
  with what the official launcher historically did. No PKCE (v1
  predates it); CSRF still protected via ``state``.
- ``MINECRAFT_LAUNCHER_V1_CLIENT_ID`` re-exported from the top-level
  ``mcapi_auth`` namespace alongside the existing v2 client_id
  constants.

### Changed

- ``build_authorize_url``, ``exchange_authorization_code``,
  ``acquire_msa_via_browser``, and ``exchange_refresh_token`` now take
  optional ``authorize_url`` / ``token_url`` / ``use_pkce`` / ``scope``
  kwargs so they can drive either the v2 or v1 endpoints. v2 remains
  the default behavior.

## [0.5.0] - 2026-05-17

### Changed (breaking)

- ``mcapi_auth.login`` and ``mcapi_auth.auth_code_login`` no longer
  default to file-backed refresh-token persistence. The new default
  ``storage`` is :class:`NullTokenStorage` (in-memory no-op), so the
  library never writes to disk unless the caller asks it to. To
  restore the previous behavior, pass
  ``storage=FileTokenStorage()`` explicitly (the path defaults to
  ``$XDG_STATE_HOME/mcapi_auth/refresh_token.json`` as before).

### Added

- ``NullTokenStorage`` exported from the top-level package as a
  no-op ``TokenStorage`` implementation suitable for short-lived
  scripts and tests.

## [0.4.2] - 2026-05-17

### Changed

- Default ``client_id`` for the MSA device-code / auth-code flows is
  now ``PRISM_LAUNCHER_CLIENT_ID``
  (``c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb``). Microsoft decommissioned
  the historical launcher client ID
  ``00000000-402b-4cd3-a82b-c45ab2f1d3f7`` against the
  ``/consumers/oauth2/v2.0/*`` endpoints — it now returns
  ``AADSTS700016: Application … was not found in the directory``.
  The constant is kept exported for callers who explicitly need it.

## [0.4.1] - 2026-05-17

### Added

- ``RateLimitedError.rate_limit_result`` — the value of Mojang's
  ``X-Minecraft-Rate-Limit-Result`` response header (observed values:
  ``"OVER_LIMIT"`` on 429, ``"UNDER_LIMIT"`` on success). Populated by
  every 429 path in ``mcapi_auth.api.profile`` and
  ``mcapi_auth.api.account``. The header is essentially redundant with
  the HTTP status code in practice but is now surfaced for logging /
  round-tripping.

## [0.4.0] - 2026-05-17

### Changed (breaking)

- **Bumped minimum Python to 3.14** (PEP 749 — lazy annotations are
  the default, so ``from __future__ import annotations`` was dropped
  from every module).
- **Removed the ``MCAuthError`` back-compat alias.** Use ``McAuthError``
  directly.
- **Refresh-token storage path moved.** ``FileTokenStorage`` now uses
  ``$XDG_STATE_HOME/mcapi_auth/refresh_token.json`` (previously
  ``mcauth/...``). Migrate stored tokens by moving the file.
- **Renamed ``mcapi_auth.auth._flow`` → ``mcapi_auth.auth.flow``.** It
  was private-by-name but exports the headline ``login`` /
  ``login_via_browser`` functions; the public re-exports at
  ``mcapi_auth.{login, login_via_browser}`` are unchanged.
- **Removed ``timeout=`` kwargs** from ``acquire_msa_via_browser``,
  ``login_via_browser``, ``login_with_cookies_msa_v1``,
  ``login_with_cookies_sisu``, and ``login_with_cookies_prism``.
  Callers that need a bounded wait should wrap the call with
  ``async with asyncio.timeout(N):`` (and catch the plain
  ``TimeoutError`` instead of the previously-internal
  ``_CallbackTimeoutError``). HTTP-level timeouts on the default
  internal ``httpx.AsyncClient`` are fixed to ``DEFAULT_HTTP_TIMEOUT``;
  pass your own ``http_client=`` to override.
- **``success_html`` is now ``str``** (was ``bytes``) on
  ``acquire_msa_via_browser``. Encoded to UTF-8 internally.

### Changed

- **Callbacks can be sync or async.** ``DeviceCodeCallback`` is now
  ``Callable[[DeviceCodePrompt], None | Awaitable[None]]`` and
  ``open_browser`` is ``Callable[[str], None | Awaitable[None]]``.
  Pass a coroutine function and it's awaited; pass a plain function
  and it's invoked directly.

### Added

- ``MinecraftSession.dump()`` and ``MinecraftSession.load()`` for
  full-session JSON round-tripping. Lets callers cache the whole
  session (including the Minecraft access token) and skip the entire
  MSA→XBL→XSTS→MC chain on cold start while the access token is still
  valid.
- MkDocs Material + mkdocstrings docs scaffold under ``docs/``,
  buildable with ``uv run --group docs mkdocs serve``.

### Fixed

- ``InstantField`` now uses ``PlainValidator`` instead of
  ``BeforeValidator``, fixing ``model_validate_json`` on models that
  contain instant fields (the previous combination silently rejected
  any deserialised JSON containing instants).
- ``_handle_prism_html_flow`` split into smaller helpers
  (``_extract_server_data``, ``_pick_session_id``,
  ``_build_tile_params``) — same behaviour, half the cognitive
  complexity.

## [0.3.0] — Merged `mcauth` + `mcapi` into `mcapi-auth`

### Changed (breaking)

- **Package renamed.** The previously separate `mcauth` (auth-chain)
  and `mcapi` (REST API) libraries are merged into a single package,
  `mcapi-auth`, with two sub-namespaces:

  - `mcapi_auth.auth` — everything from the old `mcauth`
  - `mcapi_auth.api` — everything from the old `mcapi`

  Everyday names are also re-exported from the top level
  (`from mcapi_auth import login, get_own_profile, …`) for convenience.
- **Import paths.** Update existing code:
  - `from mcauth import X` → `from mcapi_auth import X` (or
    `from mcapi_auth.auth import X`)
  - `from mcauth.<sub> import X` → `from mcapi_auth.auth.<sub> import X`
  - `from mcapi import X` → `from mcapi_auth import X` (or
    `from mcapi_auth.api import X`)
  - `from mcapi.<sub> import X` → `from mcapi_auth.api.<sub> import X`
- **Exception hierarchy unified** under a new `McApiAuthError` root:

  ```
  McApiAuthError
  ├── McAuthError    (was mcauth.exceptions.MCAuthError; alias preserved)
  └── McApiError     (was mcapi.exceptions.McApiError)
  ```

  Catching `McApiAuthError` covers every in-domain failure across both
  halves of the library. `MCAuthError` is preserved as an alias of
  `McAuthError` for back-compat.
- **`DEFAULT_USER_AGENT` semantics.** Two distinct UAs are now exposed
  in `mcapi_auth._constants`: `DEFAULT_USER_AGENT` (browser-faithful,
  used by the cookie flows that Microsoft rejects without one) and
  `DEFAULT_API_USER_AGENT` (`mcapi-auth/<version>`, used by the REST
  client when no `http_client=` is supplied).

### Added

- A unified top-level `mcapi_auth` namespace that re-exports the most
  common entry points from both halves of the library.
- `mcapi_auth._http.validate_response[M: McModel](response, model) -> M`
  helper that wraps `pydantic.ValidationError` as `HttpError` for the
  REST endpoints.
- `mcapi_auth._http.parse_json_object_auth` — the auth-side variant of
  `parse_json_object` that raises `McAuthError` (preserving the
  pre-merge mcauth behavior for callers that catch the auth tree).

### Removed

- `mcapi`'s soft-dependency dance for `MinecraftSession` interop: with
  the merge, the duck-typed `TokenLike` protocol still works, and
  `coerce_token` is also accepted on `MinecraftSession` directly
  without any extras.

### Migration

Drop-in for most code:

```python
# before
from mcauth import login, MinecraftSession
from mcapi import get_own_profile, get_uuid_by_name

# after
from mcapi_auth import login, MinecraftSession, get_own_profile, get_uuid_by_name
```

If you imported submodules directly, rewrite as shown above. The
exception class names (e.g. `XSTSError`, `HttpError`, `NotFoundError`)
are unchanged.

## [0.2.0] — Pydantic v2 + whenever

### Changed (breaking)

- `MinecraftSession`, `MinecraftToken`, `MinecraftProfile`, `MSATokens`,
  `DeviceCodePrompt`, `XboxLiveToken`, `XSTSToken`, `Entitlements`, and
  `MinecraftTokenInfo` are now Pydantic v2 `BaseModel` subclasses
  instead of `@dataclass`. Constructors still accept Python field names,
  but mutation raises `pydantic.ValidationError` (no more
  `dataclasses.FrozenInstanceError`), and equality / `repr` follow
  Pydantic semantics.
- Every token-expiry field is now `whenever.Instant` instead of a
  unix-`float`. This includes `MSATokens.expires_at`,
  `MinecraftToken.expires_at`, `MinecraftSession.{msa_access_token_expires_at,
  minecraft_access_token_expires_at, issued_at}`, and
  `MinecraftTokenInfo.{expires_at, issued_at}`.
- `MinecraftSession.minecraft_token_seconds_remaining(now=)` now takes
  `Instant | None` instead of `float | None`. The returned value is
  still a `float` (seconds).
- `mcauth` now declares `pydantic >= 2` and `whenever >= 0.10` as
  runtime dependencies.

### Added

- `mcauth._models.McModel` (frozen, `extra="ignore"`,
  `arbitrary_types_allowed=True`) as the shared Pydantic base, with the
  same `__field_aliases__` + `model_validator(mode="before")` mechanism
  as mcapi.
- `mcauth._models.InstantField` — an `Annotated[Instant, ...]` type
  with a `BeforeValidator` (parses ISO-8601) and a `PlainSerializer`
  (re-emits ISO-8601 in JSON).

### Removed / fixed

- Hand-rolled `_extract_xbox_token` helper in `mcauth.xbox` —
  `_XboxTokenBase` folds the `DisplayClaims.xui[0].uhs` extraction into
  a `model_validator(mode="before")` shared by `XboxLiveToken` and
  `XSTSToken`.
- Removed remaining `{data!r}` / `{response.text!r}` token-leak risks
  in xbox / minecraft / msa / entitlements error messages; replaced
  with `keys=sorted(...)` or pure status codes.

## [0.1.0]
- Initial release.

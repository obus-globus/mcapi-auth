# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

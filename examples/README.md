# mcauth examples

Runnable examples covering each entry point and helper. Sorted from
"most common" at the top to "low-level / niche" at the bottom.

## Full login flows

- **[`login.py`](login.py)** — the basic device-code flow. Print the
  user-code + URL, wait for the user, return a `MinecraftSession`.
  Persists the refresh token to the default XDG-state location, so
  re-runs skip the prompt.

- **[`browser_login.py`](browser_login.py)** — authorization-code +
  PKCE with the built-in localhost listener. Opens the browser, catches
  the redirect, returns a `MinecraftSession`. Friendliest for desktop
  apps.

- **[`refresh_token.py`](refresh_token.py)** — bring your own refresh
  token (env var, DB, secrets manager, …) and turn it into a
  `MinecraftSession` without any prompt.

- **[`cookie_login.py`](cookie_login.py)** — bulk-auth from captured
  browser cookies via `mcauth.cookies`. Tries the MSA-v1 (Live-Connect)
  flow first and falls back to SISU on `CookieAuthError`.

## Customization

- **[`custom_storage.py`](custom_storage.py)** — implement the
  `TokenStorage` protocol against an in-memory store and a SQLite-backed
  store. Useful for services that don't want the default file storage.

- **[`auth_code_manual.py`](auth_code_manual.py)** — authorization-code
  flow *without* the built-in listener. For integrating the OAuth
  callback as a route in your own HTTP server (FastAPI, Flask, …).
  Shows how to handle the CSRF `state` and the PKCE verifier round-trip.

## Helpers

- **[`entitlements.py`](entitlements.py)** — call
  `fetch_entitlements()` and inspect the Java / Bedrock / Game-Pass
  flags. Distinguishes "doesn't own MC" from "owns Bedrock only" when
  `/minecraft/profile` returns 404.

- **[`join_server.py`](join_server.py)** — POST `sessionserver/join`
  for proving profile ownership during a third-party server handshake.

- **[`decode_token.py`](decode_token.py)** — decode a Minecraft access
  token offline (no network) to read `exp`, `iat`, and the embedded
  username/UUID from the `pfd` claim. CLI: `python decode_token.py <jwt>`.

## Running the examples

```bash
uv sync
uv run python examples/login.py
```

Most examples write the refresh token to the default
`FileTokenStorage` location (`~/.local/state/mcauth/refresh_token`),
so re-running them won't re-prompt until that token rotates out.

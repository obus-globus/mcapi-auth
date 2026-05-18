# End-to-end tests

These tests exercise the **full live** Microsoft → Xbox → Minecraft auth
chain against real Microsoft endpoints, using a real account.

They are **excluded from the default pytest run** (`testpaths` in
`pyproject.toml` only points at `tests/`). To run them:

```bash
uv sync --group e2e
uv run --active playwright install chromium
# One-time bootstrap (headed — log into your MS account in the browser
# that opens, then press Enter in the terminal):
uv run --active python tests-e2e/bootstrap_login.py
# Run the suite:
uv run --active pytest tests-e2e -v -m e2e
```

`tests-e2e/.user-data/` is gitignored; treat it like a credential (it contains your live MS session).

## Architecture

`bootstrap_login.py` opens a headed Chromium against
`https://login.live.com/`, you sign in once, then it dumps the browser
context (cookies + localStorage) to `storage_state.json`. Every
subsequent test loads that file into a fresh Playwright context, so the
MS session is reused and consent screens auto-complete.

Per-flow drivers in `test_*.py`:

| Flow                            | What Playwright does                                   |
|---------------------------------|--------------------------------------------------------|
| `device_code_v1` / `_v2`        | Opens `microsoft.com/link`, types the user code, picks the signed-in account, clicks Allow. |
| `browser_v2` (loopback)         | Opens the consent URL the library returns; MS auto-redirects to `127.0.0.1:<port>/?code=…`; local listener completes. |
| `browser_v1` (OOB)              | Same idea but the redirect is `login.live.com/oauth20_desktop.srf?code=…`; Playwright extracts the code from `page.url`. |
| `cookies_msa_v1`                | Dumps cookies from saved context, formats into the lib's `cookies` dict, calls `login_with_cookies_msa_v1`. |
| `cookies_msa_v2_loopback`       | Same but with the v2 cookie set. |
| `cookies_sisu`                  | Same but with the SISU cookie set (xboxlive.com). |
| `realms_and_join`               | After any successful chain: `fetch_realms_worlds`, `AuthChain` dump/load round-trip, `join_server` smoke test. |
| `api_coverage`                  | Drives every read-only and write helper in `mcapi_auth.api.*` against the live account in one shot — profile lookup, name-change eligibility, name availability, blocked-servers, version manifest, player certs, Realms (compatible / TOS / worlds / world / join-info / `accept_realms_tos`), PlayFab login + entity-token. All HTTP traffic is dumped to `API_TRAFFIC_LOG.md` with bearer/cookie redaction via the shared `_traffic.py` primitives. |
| `bedrock_chain` / `bedrock_chain_live` | `bedrock_chain.py` drives `BedrockAuthManager.login(prime=True)` via device-code and is **skipped** on non-Bedrock-entitled accounts. `bedrock_chain_live.py` (gated on `MCAPI_E2E_BEDROCK=1`) loads a previously-primed snapshot from `~/.config/mcapi-auth-e2e/bedrock_chain_state.json` and exercises the chain segments `get_multiplayer_token()` would shortcut past: `get_certificate_chain()` (Bedrock-RP SISU → `multiplayer.minecraft.net/authentication`) and `get_bedrock_sisu()`. The refreshed snapshot is written back so the test remains evergreen. |
| `skin_roundtrip` / `change_skin_from_url` / `cape_and_reset_roundtrip` / `change_name_rejected` | Per-endpoint round-trip / rejection-path tests against the live account. |

## Shared infrastructure

* `_consent.py` — drives Microsoft's interstitial consent screens
  (account picker, "Stay signed in?", "Yes/Continue").
* `_traffic.py` — converts an `httpdbg.HTTPRecords` stream into a
  redacted Markdown traffic log. Exposes both primitives
  (`decompress_body`, `redact_header_value`, `redact_token_fields`,
  `summarize_body`) and an all-in-one writer (`write_traffic_log`).
  Used by both `test_api_coverage` and the Bedrock tests.

## Bootstrapping a Bedrock-entitled account

The shared `ATemmtion` account is Java-only and immediately fails
PlayFab SISU with `401 (body='')` — surfaced by the
`body_excerpt=` field that `XSTSError` carries (see
`src/mcapi_auth/exceptions.py`). To exercise the Bedrock chain you
need an account with Bedrock entitlement (Minecraft for Windows / a
Bedrock realm subscription / etc.). Bootstrap via:

```bash
unset WAYLAND_DISPLAY XDG_SESSION_TYPE
env PYTHONUNBUFFERED=1 DISPLAY=:99 uv run --active python \
    /tmp/bedrock_browser_login.py
```

That script opens a fresh Playwright Chromium (visible on
`DISPLAY=:99`), navigates to the v1 Live-Connect OAuth page using the
**Java launcher** client_id (since `bedrock-win32` doesn't accept the
OOB redirect), captures the OAuth code, exchanges it for MSA tokens,
calls `BedrockAuthManager.from_msa(..., bedrock_client_id=
BEDROCK_WIN32_CLIENT_ID)`, primes every holder, and dumps the snapshot
to `~/.config/mcapi-auth-e2e/bedrock_chain_state.json`. Re-runs of
`test_bedrock_chain_live` then run headless from the snapshot.

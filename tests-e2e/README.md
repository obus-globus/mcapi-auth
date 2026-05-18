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

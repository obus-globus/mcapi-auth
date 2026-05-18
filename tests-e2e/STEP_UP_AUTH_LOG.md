# MS Step-Up Auth Log (E2E)

Each row records a flow that hit a Microsoft step-up-auth wall — i.e.
**despite** the persisted MS session in `tests-e2e/.user-data/`, MS
demanded extra verification (phone push, password, etc.) before
honoring the request.

Goal: figure out which flows are actually usable for a fully
unattended bot account vs. which fundamentally require a human.

| Date       | Flow                | client_id (alias)            | Step in flow                                          | Wall                                            | Notes |
|------------|---------------------|------------------------------|-------------------------------------------------------|-------------------------------------------------|-------|
| 2026-05-18 | `login_device_code_v2` | `PRISM_LAUNCHER_CLIENT_ID`   | After typing user_code at `microsoft.com/devicelogin`, before consent | "Get a code to sign in" — phone push or password | First time MS sees this Azure app from a device-code flow with this account. |


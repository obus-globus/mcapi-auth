# mcapi-auth

Async Python client for the full Microsoft → Minecraft authentication
chain and the Mojang REST APIs.

```python
import asyncio
from mcapi_auth import login

async def main():
    session = await login()
    print(f"Hello, {session.username} ({session.uuid_dashed})")

asyncio.run(main())
```

## Features

- **Full token chain** — MSA device-code or browser auth-code → XBL → XSTS → Mojang
- **Refresh-token persistence** via `FileTokenStorage` (XDG-compliant)
  or any custom `TokenStorage` you implement
- **Mojang REST** — profile, textures, blocked-servers, piston-meta
- **Typed** — fully annotated, basedpyright-clean, Pydantic v2 models
- **httpx-based** — bring your own `AsyncClient` for proxies, retries,
  caching, etc.

## Install

```sh
uv add mcapi-auth
```

See the [quick start](quickstart.md) or the API reference for details.

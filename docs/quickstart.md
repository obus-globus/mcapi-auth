# Quick start

## Device-code (CLI)

```python
import asyncio
from mcapi_auth import login

async def main():
    session = await login()
    print(session.access_token)

asyncio.run(main())
```

On first run, the library prints a `https://microsoft.com/link` URL and
an 8-character code; enter it in your browser. On subsequent runs the
stored refresh token is used silently.

## Browser auth-code

```python
from mcapi_auth import login_via_browser

session = await login_via_browser()
```

Opens the default browser and listens on `127.0.0.1:<random>` for the
OAuth callback. Wrap the call with `async with asyncio.timeout(N):` if
you want a bounded wait.

## Full-session caching

`MinecraftSession.dump()` / `MinecraftSession.load()` round-trip the
whole session (not just the refresh token) so you can skip the entire
token chain on cold start when the Minecraft access token is still
valid:

```python
from pathlib import Path
from mcapi_auth import MinecraftSession, login

cache = Path("session.json")

if cache.exists():
    session = MinecraftSession.load(cache.read_text())
    if session.minecraft_token_expired():
        session = await login()        # refresh-token path, no UI
        cache.write_text(session.dump())
else:
    session = await login()
    cache.write_text(session.dump())
```

## REST APIs

```python
from mcapi_auth import get_uuid_by_name, get_profile_by_uuid, extract_textures

uuid = (await get_uuid_by_name("Notch")).id
profile = await get_profile_by_uuid(uuid)
textures = extract_textures(profile)
print(textures.skin.url)
```

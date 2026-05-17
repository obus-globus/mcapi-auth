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
session = await login()
Path("session.json").write_text(session.dump())

# later...
cached = MinecraftSession.load(Path("session.json").read_text())
if not cached.minecraft_token_expired():
    use(cached)  # skip the auth chain entirely
```

## REST APIs

```python
from mcapi_auth import get_profile_by_name, get_textures

uuid = (await get_profile_by_name("Notch")).id
textures = await get_textures(uuid)
print(textures.skin_url)
```

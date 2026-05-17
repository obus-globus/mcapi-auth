"""Decode a Minecraft access token offline (no network call).
The MC token is a JWT. The `pfd` claim embeds the player's UUID and
username, and `exp` tells you when it expires. Useful for:

- Cheaply checking "is this cached token still valid?" without burning
  an HTTP round-trip.
- Pulling the profile name/UUID out of a token you got handed by some
  other component (e.g. a launcher bridge).
"""


import sys

from whenever import Instant

from mcapi_auth import decode_minecraft_access_token


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <minecraft_access_token>", file=sys.stderr)
        sys.exit(1)

    info = decode_minecraft_access_token(sys.argv[1])
    print(f"Subject UUID:  {info.uuid}")
    print(f"Username:      {info.username}")
    if info.expires_at is not None:
        seconds_left = max(0.0, (info.expires_at - Instant.now()).total("seconds"))
        print(f"Expires in:    {seconds_left:.0f}s  (at {info.expires_at.format_iso()})")
    else:
        print("Expires in:    <no exp claim>")
    if info.issued_at is not None:
        print(f"Issued at:     {info.issued_at.format_iso()}")


if __name__ == "__main__":
    main()

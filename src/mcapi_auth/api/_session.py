"""Adapter for the ``token: str | MinecraftSession`` parameter style.
Authed endpoints accept either a raw Minecraft access-token string OR any
object that exposes an ``access_token`` attribute — which is precisely the
shape of :class:`mcapi_auth.MinecraftSession`.

The duck-typed check means the API half of the library has zero hard coupling to the auth half;
you can plug in any session-like object (a custom dataclass, a Pydantic
model, …) as long as it carries the token in the same attribute name.
"""


from typing import Protocol, runtime_checkable


@runtime_checkable
class _HasAccessToken(Protocol):
    @property
    def access_token(self) -> str: ...


# Public type alias for documentation / signatures.
type TokenLike = str | _HasAccessToken


def coerce_token(token: TokenLike) -> str:
    """Extract a raw access-token string from a ``TokenLike`` value.

    Raises ``TypeError`` if the value is neither a string nor exposes an
    ``access_token`` attribute.
    """
    if isinstance(token, str):
        return token
    # Duck-type the .access_token attribute. We use getattr (not the Protocol
    # isinstance check) because the latter triggers basedpyright's
    # reportUnnecessaryIsInstance — `TokenLike` already narrows out `str` above.
    access_attr = getattr(token, "access_token", None)
    if isinstance(access_attr, str):
        return access_attr
    raise TypeError(
        f"token must be a str or expose an .access_token attribute, got {type(token).__name__}"
    )

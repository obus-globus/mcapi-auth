"""The :class:`MinecraftSession` returned by a successful authentication."""

from pydantic import Field
from whenever import Instant

from .._models import InstantField, McModel

__all__ = ["MinecraftSession"]


def _now() -> Instant:
    return Instant.now()


class MinecraftSession(McModel):
    """A successful Minecraft authentication.

    All fields are required. Construct via :func:`mcapi_auth.login_device_code_v1` rather than
    instantiating directly.

    Attributes:
        access_token: Bearer token for ``api.minecraftservices.com`` and
            for Mojang's ``sessionserver`` joinServer call.
        refresh_token: Microsoft OAuth refresh token. Persist this (see
            :mod:`mcapi_auth.auth.storage`) to skip the device-code flow next time.
        uuid: Undashed UUID returned by ``/minecraft/profile``. Matches
            Mojang's wire format for ``selectedProfile``.
        username: Current Minecraft username for ``uuid``.
        msa_access_token: The underlying Microsoft access token. Rarely
            useful — kept for callers that need to hit other MS APIs.
        msa_access_token_expires_at: Instant at which the MSA
            access token expires.
        minecraft_access_token_expires_at: Instant at which the
            Minecraft access token expires (typically ~24h after issue).
    """

    access_token: str
    refresh_token: str
    uuid: str
    username: str
    msa_access_token: str
    msa_access_token_expires_at: InstantField
    minecraft_access_token_expires_at: InstantField
    # ``issued_at`` is convenience metadata; not part of the auth state.
    issued_at: InstantField = Field(default_factory=_now)

    @property
    def uuid_dashed(self) -> str:
        """The UUID in canonical dashed form (e.g. ``069a79f4-44e9-...``).

        Mojang returns the undashed form from ``/minecraft/profile``;
        most APIs accept either, but consumers that want to display the
        UUID usually want it dashed.
        """
        u = self.uuid
        if "-" in u:
            return u
        if len(u) != 32:
            return u
        return f"{u[0:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}"

    def minecraft_token_seconds_remaining(self, *, now: Instant | None = None) -> float:
        """Signed seconds until :attr:`access_token` expires."""
        current = now if now is not None else Instant.now()
        return (self.minecraft_access_token_expires_at - current).total("seconds")

    def minecraft_token_expired(self, *, now: Instant | None = None, leeway: float = 0.0) -> bool:
        """``True`` once the Minecraft access token has expired (minus ``leeway``)."""
        return self.minecraft_token_seconds_remaining(now=now) - leeway <= 0

    def dump(self) -> str:
        """Serialise the whole session to a JSON string.

        Pair with :meth:`load` for full-session caching: skip the entire
        MSA→XBL→XSTS→MC token chain on cold start when the Minecraft
        access token hasn't expired yet (cheaper than even a single
        refresh-token exchange).
        """
        return self.model_dump_json()

    @classmethod
    def load(cls, data: str | bytes) -> MinecraftSession:
        """Inverse of :meth:`dump` — parse a JSON blob back into a session."""
        return cls.model_validate_json(data)

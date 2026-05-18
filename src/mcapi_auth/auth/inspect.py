"""Debug + introspection helpers for :class:`AuthChain` and tokens.

These helpers are pure-Python read-only views over already-cached
chain state. They never make network calls and never expose secret
material — token strings are truncated and refresh-token-style fields
are redacted.

Common uses:

* "Is my account broken or is my code broken?" — :func:`describe_chain`
  pretty-prints every cached stage with its expiry / time-to-live.
* Logging / observability — :func:`chain_state_summary` returns a
  JSON-friendly dict for structured logs and metrics.
* Token claim peeking — :func:`describe_minecraft_token` decodes the
  Mojang access token's JWT claims and formats them as text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from whenever import Instant

from .token import decode_minecraft_access_token

if TYPE_CHECKING:
    from .chain import AuthChain
    from .holder import Holder

__all__ = [
    "StageSummary",
    "chain_state_summary",
    "describe_chain",
    "describe_minecraft_token",
    "redact_token",
]


def redact_token(token: str | None, *, keep: int = 8) -> str:
    """Return ``token`` truncated to its first ``keep`` chars + an ellipsis.

    Returns ``"<none>"`` for ``None`` or empty inputs. Strings shorter
    than or equal to ``keep`` are returned verbatim (they're already
    too short to be meaningfully secret).
    """
    if not token:
        return "<none>"
    if len(token) <= keep:
        return token
    return f"{token[:keep]}…({len(token)} chars)"


@dataclass(frozen=True, slots=True)
class StageSummary:
    """One row in :func:`chain_state_summary`."""

    name: str
    present: bool
    expires_at: Instant | None
    seconds_remaining: float | None
    expired: bool
    token_preview: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "present": self.present,
            "expires_at": self.expires_at.format_iso() if self.expires_at else None,
            "seconds_remaining": self.seconds_remaining,
            "expired": self.expired,
            "token_preview": self.token_preview,
        }


def _summarise_holder(
    name: str,
    holder: Holder[Any] | None,
    *,
    token_attr: str | None = None,
) -> StageSummary:
    if holder is None:
        return StageSummary(
            name=name,
            present=False,
            expires_at=None,
            seconds_remaining=None,
            expired=True,
            token_preview=None,
        )
    value = holder.get_cached()
    expires_at = holder.expires_at_instant()
    remaining = holder.seconds_remaining()
    preview: str | None = None
    if token_attr is not None:
        preview = redact_token(getattr(value, token_attr, None))
    return StageSummary(
        name=name,
        present=True,
        expires_at=expires_at,
        seconds_remaining=remaining,
        expired=remaining <= 0.0,
        token_preview=preview,
    )


def chain_state_summary(chain: AuthChain) -> list[StageSummary]:
    """Snapshot the cached state of every chain stage as :class:`StageSummary` rows."""
    rows: list[StageSummary] = [
        _summarise_holder("msa", chain.msa_holder, token_attr="access_token"),
        _summarise_holder("xbl", chain.xbl_holder, token_attr="token"),
        _summarise_holder("xsts", chain.xsts_holder, token_attr="token"),
        _summarise_holder("minecraft", chain.minecraft_holder, token_attr="access_token"),
    ]
    profile_holder = chain.profile_holder
    if profile_holder is not None:
        profile = profile_holder.get_cached()
        username = getattr(profile, "username", None) or getattr(profile, "name", "?")
        uuid = getattr(profile, "uuid", None) or getattr(profile, "id", "?")
        rows.append(
            StageSummary(
                name="profile",
                present=True,
                expires_at=None,
                seconds_remaining=None,
                expired=False,
                token_preview=f"{username} <{uuid}>",
            )
        )
    else:
        rows.append(
            StageSummary(
                name="profile",
                present=False,
                expires_at=None,
                seconds_remaining=None,
                expired=True,
                token_preview=None,
            )
        )
    return rows


def _format_remaining(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds <= 0:
        return f"EXPIRED ({-seconds:,.0f}s ago)"
    if seconds < 60:
        return f"{seconds:,.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:,.1f}min"
    if seconds < 86400:
        return f"{seconds / 3600:,.1f}hr"
    return f"{seconds / 86400:,.1f}d"


def describe_chain(chain: AuthChain) -> str:
    """Return a human-readable multi-line snapshot of an :class:`AuthChain`.

    Example output::

        AuthChain  app=launcher-v1  client_id=00000000402b5328
          msa       ✓  expires in 59min   (EwAIA...)
          xbl       ✓  expires in 16hr    (eyJhb...)
          xsts      ✓  expires in 16hr    (eyJhb...)
          minecraft ✓  expires in 23hr    (eyJhb...)
          profile   ✓  Notch <069a79f444e94726a5befca90e38aaf5>
    """
    rows = chain_state_summary(chain)
    app = chain.app
    header = f"AuthChain  client_id={app.client_id}  v1={app.is_v1}"
    lines: list[str] = [header]
    for row in rows:
        mark = "✓" if row.present and not row.expired else ("·" if row.present else "✗")
        remaining = _format_remaining(row.seconds_remaining)
        preview = f"  ({row.token_preview})" if row.token_preview else ""
        lines.append(f"  {row.name:<10} {mark}  {remaining:<20}{preview}")
    return "\n".join(lines)


def describe_minecraft_token(token: str) -> str:
    """Decode a Minecraft access-token JWT and format its claims as text.

    Wraps :func:`mcapi_auth.decode_minecraft_access_token` and formats
    the resulting :class:`MinecraftTokenInfo` for human consumption.
    Does *not* validate signatures — purely informational.
    """
    info = decode_minecraft_access_token(token)
    issued = info.issued_at.format_iso() if info.issued_at else "<missing>"
    expires = info.expires_at.format_iso() if info.expires_at else "<missing>"
    lines = [
        "Minecraft access token (JWT, signed server-side)",
        f"  username:    {info.username or '<missing>'}",
        f"  uuid:        {info.uuid or '<missing>'}",
        f"  issued at:   {issued}",
        f"  expires at:  {expires}",
        f"  claim count: {len(info.raw_claims)}",
    ]
    return "\n".join(lines)

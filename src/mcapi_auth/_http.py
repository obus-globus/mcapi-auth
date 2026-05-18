"""Shared HTTP-client plumbing.
Every public function in :mod:`mcapi_auth` accepts an optional
``http_client: httpx.AsyncClient`` so callers can plug in custom
timeouts, proxies, transport mocks, retry transports (``httpx-retries``),
caching transports (``hishel``), etc. If none is provided we build a
private one just for that call.

Use :func:`acquire_client` as an async context manager — it yields the
caller's client if they passed one (and does NOT close it), otherwise it
creates and closes one for them.

The fallback client's ``User-Agent`` header is controlled by
:func:`set_default_user_agent` / :func:`get_default_user_agent`. The
initial value is :data:`mcapi_auth._constants.DEFAULT_API_USER_AGENT`
(``mcapi-auth/<version>``). Setting it has **no effect** on
caller-supplied :class:`httpx.AsyncClient` instances — those keep
whatever headers their owner configured.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, cast

import httpx
from pydantic import ValidationError

from ._constants import DEFAULT_API_USER_AGENT, DEFAULT_HTTP_TIMEOUT
from ._models import McModel
from .exceptions import HttpError, McAuthError

__all__ = [
    "acquire_client",
    "bearer_headers",
    "get_default_user_agent",
    "parse_json_object",
    "parse_json_object_auth",
    "set_default_user_agent",
    "validate_response",
]


_default_user_agent: str = DEFAULT_API_USER_AGENT


def get_default_user_agent() -> str:
    """Return the ``User-Agent`` used by fallback API clients.

    This is the value :func:`acquire_client` applies when the caller did
    not pass their own :class:`httpx.AsyncClient`. Caller-supplied
    clients keep whatever headers their owner configured.
    """
    return _default_user_agent


def set_default_user_agent(user_agent: str) -> None:
    """Override the ``User-Agent`` used by fallback API clients.

    Applies to every subsequent :func:`acquire_client` call that does
    not receive an explicit ``http_client``. It does **not** mutate
    already-constructed clients or override headers on
    caller-supplied :class:`httpx.AsyncClient` instances — only the
    library's own fallback client is affected.

    Pass an empty string or whitespace-only value and a
    :class:`ValueError` is raised; this avoids accidentally sending
    blank User-Agent headers (which some upstream APIs reject).
    """
    if not user_agent or not user_agent.strip():
        raise ValueError("user_agent must be a non-empty string")
    global _default_user_agent
    _default_user_agent = user_agent


@asynccontextmanager
async def acquire_client(
    client: httpx.AsyncClient | None,
) -> AsyncGenerator[httpx.AsyncClient]:
    """Yield a ready-to-use :class:`httpx.AsyncClient`.

    If the caller supplied one, yield it as-is (caller owns its
    lifecycle). Otherwise build, yield, and close one scoped to this
    call. The fallback client carries a default ``User-Agent`` and
    ``Accept: application/json`` so REST endpoints behave sensibly.
    """
    if client is not None:
        yield client
        return

    async with httpx.AsyncClient(
        timeout=DEFAULT_HTTP_TIMEOUT,
        headers={"User-Agent": _default_user_agent, "Accept": "application/json"},
    ) as owned:
        yield owned


def bearer_headers(access_token: str) -> dict[str, str]:
    """Build the standard ``Authorization`` header for authed endpoints."""
    return {"Authorization": f"Bearer {access_token}"}


def parse_json_object(response: httpx.Response) -> dict[str, Any]:
    """Decode ``response`` as a JSON object or raise :class:`HttpError`.

    httpx's ``.json()`` happily returns ``str``, ``list``, or ``None`` if
    the server lies about content-type. We want a strict dict-or-die so
    downstream code can assume the shape.
    """
    try:
        data: Any = response.json()
    except ValueError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e
    if not isinstance(data, dict):
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        )
    return cast(dict[str, Any], data)


def parse_json_object_auth(response: httpx.Response) -> dict[str, Any]:
    """Decode ``response`` as a JSON object or raise :class:`McAuthError`.

    Same shape check as :func:`parse_json_object` but raises an
    auth-tree exception, which is what the token-chain stages
    (:mod:`mcapi_auth.auth.msa`, ``xbox``, etc.) want to surface.
    """
    try:
        data: object = response.json()
    except ValueError as e:
        raise McAuthError(
            f"server returned non-JSON body (status {response.status_code}): {e}"
        ) from e
    if not isinstance(data, dict):
        raise McAuthError(
            f"server returned JSON {type(data).__name__}, expected object "
            f"(status {response.status_code})"
        )
    return cast(dict[str, Any], data)


def validate_response[M: McModel](response: httpx.Response, model: type[M]) -> M:
    """Parse ``response`` as JSON and validate it into ``model``.

    Pydantic ``ValidationError`` is wrapped in :class:`HttpError` so the
    library's public exception surface stays stable. The original
    ``ValidationError`` is attached as ``__cause__`` for debugging.
    """
    data = parse_json_object(response)
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise HttpError(
            response.status_code,
            response.text,
            url=str(response.request.url) if response.request else None,
        ) from e

"""Shared HTTP-client plumbing.
Every public function in :mod:`mcapi_auth` accepts an optional
``http_client: httpx.AsyncClient`` so callers can plug in custom
timeouts, proxies, transport mocks, retry transports (``httpx-retries``),
caching transports (``hishel``), etc. If none is provided we build a
private one just for that call.

Use :func:`acquire_client` as an async context manager — it yields the
caller's client if they passed one (and does NOT close it), otherwise it
creates and closes one for them.
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
    "parse_json_object",
    "parse_json_object_auth",
    "validate_response",
]


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
        headers={"User-Agent": DEFAULT_API_USER_AGENT, "Accept": "application/json"},
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

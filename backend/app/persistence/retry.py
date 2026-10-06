"""Narrow retries for transient Supabase gateway/PostgREST clock skew."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from postgrest.exceptions import APIError

_RESULT = TypeVar("_RESULT")
_RETRY_DELAYS_SECONDS = (0.3, 0.9)
_FUTURE_ISSUED_JWT = "jwt issued at future"


async def execute_with_clock_skew_retry(
    execute: Callable[[], Awaitable[_RESULT]],
) -> _RESULT:
    """Retry only the known transient PGRST303 future-iat rejection.

    PostgREST rejects this request before executing its SQL statement, so retrying
    the exact response is safe for reads, updates, inserts, and RPC calls. Other
    auth failures and all other database errors are propagated immediately.
    """
    for delay in (*_RETRY_DELAYS_SECONDS, None):
        try:
            return await execute()
        except APIError as exc:
            is_clock_skew = (
                exc.code == "PGRST303"
                and isinstance(exc.message, str)
                and exc.message.strip().casefold() == _FUTURE_ISSUED_JWT
            )
            if not is_clock_skew or delay is None:
                raise
            await asyncio.sleep(delay)

    raise AssertionError("The bounded PostgREST retry loop must return or raise.")

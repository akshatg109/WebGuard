"""Small per-process sliding-window limits keyed by verified user ID."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable
from math import ceil
from time import monotonic
from typing import Protocol

from app.config import ScanRateLimitSettings


class RateLimitSettings(Protocol):
    max_requests: int
    window_seconds: int


class InMemoryPerUserRateLimiter:
    """Rate-limit requests by a verified user ID within one process.

    This MVP control is process-local; deployments with multiple workers or
    replicas need a shared/gateway limit as well.
    """

    _MAX_TRACKED_USERS = 10_000

    def __init__(
        self,
        settings: RateLimitSettings,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.settings = settings
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def consume(self, user_id: str) -> int | None:
        """Return retry-after seconds when over budget, otherwise ``None``."""
        now = self._clock()
        cutoff = now - self.settings.window_seconds
        async with self._lock:
            timestamps = self._events.get(user_id)
            if timestamps is not None:
                while timestamps and timestamps[0] <= cutoff:
                    timestamps.popleft()
                if not timestamps:
                    del self._events[user_id]
                    timestamps = None
                elif len(timestamps) >= self.settings.max_requests:
                    return max(1, ceil(timestamps[0] + self.settings.window_seconds - now))

            if timestamps is None:
                if len(self._events) >= self._MAX_TRACKED_USERS:
                    self._events.pop(next(iter(self._events)))
                timestamps = deque()
            timestamps.append(now)
            # Dict insertion order doubles as a bounded LRU queue for user
            # buckets that have expired but are not currently being accessed.
            self._events.pop(user_id, None)
            self._events[user_id] = timestamps
            return None


class InMemoryScanRateLimiter(InMemoryPerUserRateLimiter):
    """Backward-compatible name for the scan-creation limiter."""

    def __init__(
        self,
        settings: ScanRateLimitSettings | None = None,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        super().__init__(settings or ScanRateLimitSettings.from_environment(), clock=clock)

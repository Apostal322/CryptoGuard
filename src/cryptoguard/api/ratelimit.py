"""In-process token-bucket rate limiter keyed by client address.

Suitable for a single local process. A multi-instance deployment needs a shared limiter
(or a reverse proxy doing the limiting).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable


class TokenBucketLimiter:
    def __init__(
        self,
        per_minute: int,
        *,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = float(per_minute)
        self._refill_per_second = per_minute / 60.0
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def acquire(self, key: str) -> float:
        """Take one token. Returns 0 if allowed, else the seconds until a token is available."""
        now = self._clock()
        tokens, last = self._buckets.pop(key, (self._capacity, now))
        tokens = min(self._capacity, tokens + (now - last) * self._refill_per_second)
        if tokens >= 1.0:
            tokens -= 1.0
            wait = 0.0
        else:
            wait = (1.0 - tokens) / self._refill_per_second
        self._buckets[key] = (tokens, now)
        while len(self._buckets) > self._max_keys:
            self._buckets.popitem(last=False)  # bounded memory: drop least recently seen
        return wait

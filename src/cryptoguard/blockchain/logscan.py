"""Bounded, newest-first ``eth_getLogs`` scanning shared by all event-based discovery.

The window is split into chunks; a chunk the provider refuses as too large is halved; the
scan stops at a request budget. Because chunks are processed newest-first and contiguously,
what was scanned is always one range ``[scanned_from, to_block]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.errors import (
    BlockRangeTooLargeError,
    LogFilterRestrictedError,
    LogQueryTooLargeError,
    ScanBudgetExceededError,
)

Topics = list[str | list[str] | None]


@dataclass(frozen=True)
class LogScan:
    logs: list[dict[str, Any]]
    from_block: int
    to_block: int
    scanned_from: int
    requests: int
    splits: int
    exhausted: bool

    @property
    def complete(self) -> bool:
        return not self.exhausted and self.scanned_from == self.from_block


ADDRESS_FILTER_HINT = (
    " Name specific token contracts to scan (API: tokens, CLI: --token), or configure a "
    "provider that serves wallet-wide log queries."
)


async def scan_logs(
    provider: EthereumProvider,
    *,
    topics: Topics,
    from_block: int,
    to_block: int,
    chunk_blocks: int,
    max_requests: int,
    address: list[str] | None = None,
) -> LogScan:
    pending: list[tuple[int, int]] = []
    next_high = to_block
    lowest_scanned = to_block + 1
    requests = splits = 0
    logs: list[dict[str, Any]] = []
    exhausted = False

    while True:
        if not pending:
            if next_high < from_block:
                break
            low = max(from_block, next_high - chunk_blocks + 1)
            pending.append((low, next_high))
            next_high = low - 1
        if requests >= max_requests:
            exhausted = True
            break
        low, high = pending.pop()
        requests += 1
        try:
            batch = await provider.get_logs(
                from_block=low, to_block=high, address=address, topics=topics
            )
        except (LogQueryTooLargeError, BlockRangeTooLargeError):
            if low == high:
                raise
            middle = (low + high) // 2
            pending.append((low, middle))
            pending.append((middle + 1, high))  # popped first: keeps newest-first contiguity
            splits += 1
            continue
        except LogFilterRestrictedError as exc:
            if address is not None:
                raise
            raise LogFilterRestrictedError(
                exc.message + ADDRESS_FILTER_HINT, details=exc.details
            ) from None
        logs.extend(batch)
        lowest_scanned = low

    if lowest_scanned > to_block:
        raise ScanBudgetExceededError(
            "The log request budget was exhausted before any block range was scanned."
        )
    return LogScan(logs, from_block, to_block, lowest_scanned, requests, splits, exhausted)

"""Activity-rate anomalies against the wallet's own past, in block time.

Event time is the block number (12-second slots since the Merge; a missed slot makes a
block span 24 s, so "300 blocks" is about an hour, not exactly). Transactions inside one
block are ordered but have no separate timestamps, so the resolution is one block.

Series, counted per bin of ``bin_blocks`` blocks:

- ``transfers``: ERC-20 transfers plus native-ETH sends of the wallet;
- ``zero_value``: zero-value transfers in either direction;
- ``unsolicited_incoming``: incoming transfers from an address the wallet had not sent to
  before (decided with the data available at that transfer);
- ``new_counterparties``: addresses seen for the first time.

A bin counts as **observed** only if both the transfer scan and the wallet-transaction scan
covered all of it; other bins are *missing*, never zero. A bin's expected level is the
median of strictly earlier observed bins (optionally a trailing window of them), its scale
``max(1.4826 * MAD, sqrt(median + 1))``. The floor stops a single event after a quiet
history from looking extreme: with median 0 one event scores 1. No score is produced until
``min_history`` observed bins exist.

The score is a robust z-statistic. It is not a probability, and for count data near zero it
is not normally distributed; thresholds are set from the evaluation, not from z-tables.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from cryptoguard.analytics.observations import ObservationSet

Series = Literal["transfers", "zero_value", "unsolicited_incoming", "new_counterparties"]
SERIES: tuple[Series, ...] = (
    "transfers",
    "zero_value",
    "unsolicited_incoming",
    "new_counterparties",
)
MAD_SCALE = 1.4826


@dataclass
class ActivityBin:
    from_block: int
    to_block: int
    observed: bool
    counts: dict[str, int] = field(default_factory=dict)
    transactions: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class BinScore:
    from_block: int
    to_block: int
    series: Series
    observed: int | None
    expected: float | None
    scale: float | None
    score: float | None
    history_bins: int
    status: Literal["scored", "missing", "insufficient_history"]


def activity_bins(
    observations: ObservationSet, *, bin_blocks: int = 300, start_block: int | None = None
) -> list[ActivityBin]:
    """Bins ending exactly at the cutoff, going back to ``start_block`` (default: first
    covered block)."""
    if bin_blocks <= 0:
        raise ValueError("bin_blocks must be positive")
    cutoff = observations.cutoff_block
    cov = observations.coverage
    first = start_block
    if first is None:
        first = min((r.from_block for r in cov.transfers), default=cutoff)
    bins: list[ActivityBin] = []
    end = cutoff
    while end - bin_blocks + 1 >= first:
        start = end - bin_blocks + 1
        bins.append(ActivityBin(start, end, cov.both_cover(start, end)))
        end = start - 1
    bins.reverse()
    if not bins:
        return bins

    wallet = observations.wallet
    sent_to: set[str] = set()
    seen: set[str] = set()
    origin = bins[0].from_block
    for e in observations.all_events():
        outgoing = e.sender == wallet
        other = e.recipient if outgoing else e.sender
        labels: list[str] = ["transfers"]
        if e.value == 0:
            labels.append("zero_value")
        if not outgoing and other not in sent_to:
            labels.append("unsolicited_incoming")
        if other not in seen:
            labels.append("new_counterparties")
        if outgoing and e.value > 0:
            sent_to.add(other)
        seen.add(other)
        if e.block_number < origin:
            continue  # history before the first bin still shapes "new" and "unsolicited"
        b = bins[(e.block_number - origin) // bin_blocks]
        for label in labels:
            b.counts[label] = b.counts.get(label, 0) + 1
            txs = b.transactions.setdefault(label, [])
            if e.transaction_hash not in txs and len(txs) < 10:
                txs.append(e.transaction_hash)
    return bins


def robust_scores(
    bins: Sequence[ActivityBin],
    series: Series,
    *,
    min_history: int = 12,
    history_window: int | None = None,
) -> list[BinScore]:
    scores: list[BinScore] = []
    past: list[int] = []
    for b in bins:
        if not b.observed:
            scores.append(
                BinScore(
                    b.from_block, b.to_block, series, None, None, None, None, len(past), "missing"
                )
            )
            continue
        count = b.counts.get(series, 0)
        history = past[-history_window:] if history_window else past
        if len(history) < min_history:
            scores.append(
                BinScore(
                    b.from_block,
                    b.to_block,
                    series,
                    count,
                    None,
                    None,
                    None,
                    len(history),
                    "insufficient_history",
                )
            )
        else:
            median = statistics.median(history)
            mad = statistics.median(abs(x - median) for x in history)
            scale = max(MAD_SCALE * mad, math.sqrt(median + 1))
            scores.append(
                BinScore(
                    b.from_block,
                    b.to_block,
                    series,
                    count,
                    float(median),
                    scale,
                    (count - median) / scale,
                    len(history),
                    "scored",
                )
            )
        past.append(count)
    return scores


def ewma_scores(
    bins: Sequence[ActivityBin], series: Series, *, alpha: float = 0.1, min_history: int = 12
) -> list[float | None]:
    """Baseline: exponentially weighted mean/variance of earlier observed bins."""
    out: list[float | None] = []
    mean: float | None = None
    var = 0.0
    n = 0
    for b in bins:
        if not b.observed:
            out.append(None)
            continue
        x = float(b.counts.get(series, 0))
        if mean is None or n < min_history:
            out.append(None)
        else:
            out.append((x - mean) / max(math.sqrt(var), math.sqrt(mean + 1)))
        if mean is None:
            mean = x
        else:
            diff = x - mean
            mean += alpha * diff
            var = (1 - alpha) * (var + alpha * diff * diff)
        n += 1
    return out


@dataclass(frozen=True)
class ActivityAnomaly:
    series: Series
    from_block: int
    to_block: int
    observed: int
    expected: float
    score: float
    history_bins: int
    transactions: tuple[str, ...]
    statement: str


STATEMENTS: dict[Series, str] = {
    "transfers": "Transaction activity in this window is well above the wallet's observed history.",
    "zero_value": "Unusually many zero-value transfers compared with the wallet's observed "
    "history.",
    "unsolicited_incoming": "Unusually many incoming transfers from addresses the wallet never "
    "paid, compared with its observed history.",
    "new_counterparties": "Unusually many first-time counterparties compared with the wallet's "
    "observed history.",
}


def detect_bursts(
    observations: ObservationSet,
    *,
    series: Sequence[Series] = SERIES,
    bin_blocks: int = 300,
    threshold: float = 4.0,
    min_count: int = 3,
    min_history: int = 12,
    last_bins: int | None = None,
) -> tuple[list[ActivityAnomaly], dict[str, int]]:
    """Bins whose robust score reaches ``threshold`` with at least ``min_count`` events.

    Returns the anomalies and per-status bin counts (so "nothing found" can be told apart
    from "not enough observed history to judge").
    """
    bins = activity_bins(observations, bin_blocks=bin_blocks)
    found: list[ActivityAnomaly] = []
    status: dict[str, int] = {"scored": 0, "missing": 0, "insufficient_history": 0}
    for s in series:
        scores = robust_scores(bins, s, min_history=min_history)
        window = scores[-last_bins:] if last_bins else scores
        index = {(b.from_block, b.to_block): b for b in bins}
        for sc in window:
            status[sc.status] += 1
            if (
                sc.status == "scored"
                and sc.score is not None
                and sc.observed is not None
                and sc.expected is not None
                and sc.score >= threshold
                and sc.observed >= min_count
            ):
                b = index[(sc.from_block, sc.to_block)]
                found.append(
                    ActivityAnomaly(
                        series=s,
                        from_block=sc.from_block,
                        to_block=sc.to_block,
                        observed=sc.observed,
                        expected=sc.expected,
                        score=sc.score,
                        history_bins=sc.history_bins,
                        transactions=tuple(b.transactions.get(s, [])),
                        statement=STATEMENTS[s],
                    )
                )
    found.sort(key=lambda a: (a.from_block, a.series))
    return found, status

"""Screen hard-negative candidates against every locally known poisoning record (Phase 11.5).

A candidate that overlaps a known attack must never be used as a negative. A candidate
with no known overlap is **not** benign: it is only unscreened-positive.

Match levels, strongest first:

1. ``exact_event``: same victim, lookalike and transaction as a known attempt;
2. ``exact_tx``: same planting transaction;
3. ``victim_lookalike``: the same victim-lookalike pair, another transaction;
4. ``shared_infrastructure``: the lookalike (or a counterfeit token contract) is a known
   attacker address elsewhere;
5. ``related_campaign``: the same victim was attacked with a lookalike of the same
   imitated counterparty;
6. ``weak_similarity``: nothing above, but the candidate's lookalike resembles a known
   lookalike of the same victim (similarity is not evidence of malice);
7. ``none``.

Statuses: levels 1-4 give ``known_positive_overlap``, level 5 gives
``potential_positive_overlap``, and level 6 or 7 gives ``no_known_overlap``, or
``insufficient_information`` when no screening source covers the candidate's block.
Neither of the last two means verified benign.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from cryptoguard.ml.candidates import similar

SCREEN_VERSION = "contamination/1"
Level = Literal[
    "exact_event",
    "exact_tx",
    "victim_lookalike",
    "shared_infrastructure",
    "related_campaign",
    "weak_similarity",
    "none",
]
Status = Literal[
    "known_positive_overlap",
    "potential_positive_overlap",
    "no_known_overlap",
    "insufficient_information",
]
LEVEL_STATUS: dict[str, Status] = {
    "exact_event": "known_positive_overlap",
    "exact_tx": "known_positive_overlap",
    "victim_lookalike": "known_positive_overlap",
    "shared_infrastructure": "known_positive_overlap",
    "related_campaign": "potential_positive_overlap",
    "weak_similarity": "no_known_overlap",
    "none": "no_known_overlap",
}


@dataclass(frozen=True)
class KnownAttack:
    """One known poisoning record from any source (no label strength implied beyond the
    source's own)."""

    source: str  # e.g. "tsuchiya-archive", "poison-hunter", "tsuchiya-payoff", "incident"
    victim: str | None
    lookalike: str
    tx: str | None
    imitated: str | None = None
    token: str | None = None  # a counterfeit token contract, when the source says so


@dataclass(frozen=True)
class Coverage:
    """Block range a source screened; a candidate outside every range cannot be screened."""

    source: str
    from_block: int
    to_block: int


@dataclass
class KnownIndex:
    coverage: list[Coverage] = field(default_factory=list)
    events: dict[tuple[str, str, str], set[str]] = field(default_factory=lambda: defaultdict(set))
    txs: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    pairs: dict[tuple[str, str], set[str]] = field(default_factory=lambda: defaultdict(set))
    lookalikes: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    counterfeit: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    imitated_by_victim: dict[tuple[str, str], set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    lookalikes_by_victim: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add(self, k: KnownAttack) -> None:
        look = k.lookalike.lower()
        self.lookalikes[look].add(k.source)
        if k.token:
            self.counterfeit[k.token.lower()].add(k.source)
        if k.tx:
            self.txs[k.tx.lower()].add(k.source)
        if k.victim:
            v = k.victim.lower()
            self.pairs[(v, look)].add(k.source)
            self.lookalikes_by_victim[v].add(look)
            if k.tx:
                self.events[(v, look, k.tx.lower())].add(k.source)
            if k.imitated:
                self.imitated_by_victim[(v, k.imitated.lower())].add(k.source)

    def extend(self, attacks: Iterable[KnownAttack]) -> KnownIndex:
        for k in attacks:
            self.add(k)
        return self


@dataclass(frozen=True)
class Screened:
    level: Level
    status: Status
    sources: tuple[str, ...]


def screen(
    *,
    victim: str,
    lookalike: str,
    tx: str,
    block: int,
    imitated: str | None,
    token: str | None,
    index: KnownIndex,
) -> Screened:
    v, look, t = victim.lower(), lookalike.lower(), tx.lower()
    checks: list[tuple[Level, set[str]]] = [
        ("exact_event", index.events.get((v, look, t), set())),
        ("exact_tx", index.txs.get(t, set())),
        ("victim_lookalike", index.pairs.get((v, look), set())),
        (
            "shared_infrastructure",
            index.lookalikes.get(look, set()) | index.counterfeit.get((token or "").lower(), set()),
        ),
        (
            "related_campaign",
            index.imitated_by_victim.get((v, imitated.lower()), set()) if imitated else set(),
        ),
    ]
    for level, sources in checks:
        if sources:
            return Screened(level, LEVEL_STATUS[level], tuple(sorted(sources)))
    covered = any(c.from_block <= block <= c.to_block for c in index.coverage)
    status: Status = "no_known_overlap" if covered else "insufficient_information"
    if any(similar(look, k) for k in index.lookalikes_by_victim.get(v, ())):
        return Screened("weak_similarity", status, ())
    return Screened("none", status, ())


def summary(results: Sequence[Screened]) -> dict[str, object]:
    return {
        "screen_version": SCREEN_VERSION,
        "candidates": len(results),
        "by_level": dict(Counter(r.level for r in results)),
        "by_status": dict(Counter(r.status for r in results)),
        "by_source": dict(Counter(s for r in results for s in r.sources)),
    }


def by_level_counts(results: Mapping[str, Screened]) -> dict[str, int]:
    return dict(Counter(r.level for r in results.values()))

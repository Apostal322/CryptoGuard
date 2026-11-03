"""Within-victim lookalike prioritization at a cutoff before the payoff (Phase 12.1).

Research task ``lookalike-prioritization/1`` (pre-registered in docs/ml/protocol-12.1.md):
a victim that later made a source-confirmed payoff had k >= 2 distinct lookalikes plant
transfers to it beforehand. At a cutoff before the payoff, rank those candidates with
point-in-time features; the observed outcome is which one the victim paid. This measures
which signals order *known candidates* by the risk that the victim copies them. It is not
detection: every candidate is a source-flagged planting, the population is conditioned on a
payoff happening, and nothing here estimates precision, recall or FPR.

Data (all local, 0 RPC requests):

- ``archive_subset.sqlite``: every archive row touching a payoff victim. For a study victim
  this holds all of the source's poisoning, intended and payoff rows, but not its ordinary
  activity, so "no earlier payment observed" is ``None`` (not observed), never zero.
- ``research/graph_context.sqlite`` (``graph_context_scan``): every archive row touching any
  candidate lookalike or planting transaction. Rivals and paid lookalikes are then covered
  alike; the older subset covered only paid lookalikes, which would leak the outcome into
  any cross-victim feature.

Protected: the wallets of both frozen review cohorts and the incident victims are excluded
before anything is computed, rows touching a protected wallet never become a graph edge, and
the review keys and manifests are never read.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TASK = "lookalike-prioritization/1"
PROTOCOL = "protocol-12.1/1"
FEATURE_VERSION = "lookalike-features/1"
GRAPH_DB = "graph_context.sqlite"
RESEARCH_DIR = "research"
DAY = 7_200  # blocks, about one day; fixed by the protocol
FEATURES = ("B0", "B1", "B2", "B3", "T0", "T1", "T2", "T3", "T4", "G1", "G2", "G3", "NC")
_ROWS = (
    "select line, block, tx, token, sender, receiver, sender_is_victim, value_usd, flags, "
    "intended from transfers"
)

Value = float | None  # None: not observed. 0 means observed and none.


@dataclass(frozen=True, slots=True)
class Row:
    line: int
    block: int
    tx: str
    token: str
    sender: str
    receiver: str
    sender_is_victim: bool | None
    value_usd: float | None
    flags: int
    intended: str | None


@dataclass(frozen=True, slots=True)
class Episode:
    """One victim's first confirmed payoff and the source-flagged plantings before it.

    ``plantings`` and ``victim_out`` hold only rows strictly before ``payoff_block``; rows in
    the payoff block itself have no known order relative to it and are counted in
    ``same_block_rows`` instead."""

    victim: str
    payoff_block: int
    paid: str
    plantings: tuple[Row, ...]  # poisoning rows between the victim and a lookalike
    victim_out: tuple[Row, ...]  # the victim's own non-poisoning outgoing rows
    same_block_rows: int

    @property
    def candidates(self) -> tuple[str, ...]:
        return tuple(sorted({lookalike_of(r, self.victim) for r in self.plantings}))


def lookalike_of(row: Row, victim: str) -> str:
    """The non-victim party of a planting (incoming transfers and spoofed transfer-froms)."""
    return row.receiver if row.sender == victim else row.sender


def _row(t: Sequence[Any]) -> Row:
    siv = None if t[6] is None else bool(t[6])
    usd = None if t[7] is None or t[7] != t[7] else float(t[7])
    return Row(t[0], t[1], t[2], t[3], t[4], t[5], siv, usd, t[8], t[9])


def protected_wallets(poisoning_dir: Path) -> frozenset[str]:
    """Wallets of both frozen review cohorts, read from the blinded sheets only."""
    from cryptoguard.ml.review_sample import read_sheet

    sheets = (
        poisoning_dir / "review_sample" / "reviewer_sheet.jsonl",
        poisoning_dir / "hard_negative" / "cohort_v1" / "reviewer_sheet.jsonl",
    )
    return frozenset(r["wallet"].lower() for s in sheets for r in read_sheet(s))


def protected_entities(poisoning_dir: Path) -> tuple[frozenset[str], frozenset[str]]:
    """Addresses (wallets and addresses under review) and transactions of the 95 frozen
    items, from the blinded sheets only."""
    from cryptoguard.ml.review_sample import read_sheet

    sheets = (
        poisoning_dir / "review_sample" / "reviewer_sheet.jsonl",
        poisoning_dir / "hard_negative" / "cohort_v1" / "reviewer_sheet.jsonl",
    )
    addresses: set[str] = set()
    txs: set[str] = set()
    for s in sheets:
        for r in read_sheet(s):
            addresses |= {r["wallet"].lower(), r["address_under_review"].lower()}
            txs.add(r["transaction"].lower())
    return frozenset(addresses), frozenset(txs)


def protected_overlap(
    episodes: Sequence[Episode], addresses: frozenset[str], txs: frozenset[str]
) -> list[bool]:
    """Per episode: does it share an entity with a frozen item (a candidate or planting
    counterparty that is a protected address, or a planting tx that is a protected tx), or
    sit in the same protocol linkage group as an episode that does (campaign overlap)."""
    direct = [
        bool(set(e.candidates) & addresses)
        or any(r.tx in txs or {r.sender, r.receiver} & addresses for r in e.plantings)
        for e in episodes
    ]
    grp, _ = protocol_groups(episodes)
    tainted = {g for g, d in zip(grp, direct, strict=True) if d}
    return [g in tainted for g in grp]


def episode_from_rows(victim: str, rows: Iterable[Row]) -> Episode | str:
    """The episode for one victim, or the reason it is ineligible."""
    from cryptoguard.ml.tsuchiya_archive import PAYOFF, POISONING

    ordered = sorted(set(rows), key=lambda r: (r.block, r.line))
    payoffs = [r for r in ordered if r.flags & PAYOFF and r.sender == victim]
    if not payoffs:
        return "no_confirmed_payoff_row"
    t = payoffs[0].block
    paid = {r.receiver for r in payoffs if r.block == t}
    if len(paid) != 1:
        return "several_lookalikes_paid_in_payoff_block"
    plantings, out, same_block = [], [], 0
    for r in ordered:
        if r.block > t:
            break
        if r.flags & POISONING and victim in (r.sender, r.receiver):
            if lookalike_of(r, victim) == victim:
                continue
            if r.block == t:
                same_block += 1
            else:
                plantings.append(r)
        elif r.sender == victim and not r.flags & PAYOFF and r.block < t:
            out.append(r)
    ep = Episode(victim, t, paid.pop(), tuple(plantings), tuple(out), same_block)
    if ep.paid not in ep.candidates:
        return "paid_lookalike_planted_no_earlier_transfer"
    if len(ep.candidates) < 2:
        return "single_candidate"
    return ep


def load_episodes(poisoning_dir: Path) -> tuple[list[Episode], dict[str, int]]:
    """Eligible episodes (sorted by victim) and the count of every exclusion reason."""
    targets = json.loads((poisoning_dir / "archive_targets.json").read_text(encoding="utf-8"))
    groups = targets["groups"]
    excluded: Counter[str] = Counter()
    protected = protected_wallets(poisoning_dir)
    incident = set(groups["incident_victims"])
    victims = []
    for v in sorted(groups["payoff_victims"]):
        if v in protected:
            excluded["protected_review_wallet"] += 1
        elif v in incident:
            excluded["incident_victim"] += 1
        else:
            victims.append(v)
    con = _connect(poisoning_dir / "archive_subset.sqlite")
    episodes = []
    try:
        for v in victims:
            rows = map(_row, con.execute(_ROWS + " where sender = ? or receiver = ?", (v, v)))
            ep = episode_from_rows(v, rows)
            if isinstance(ep, str):
                excluded[ep] += 1
            else:
                episodes.append(ep)
    finally:
        con.close()
    return episodes, dict(sorted(excluded.items()))


def _connect(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(path)
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


# --- the symmetric graph-context pass ----------------------------------------------------


def graph_context_scan(data_dir: Path, poisoning_dir: Path) -> dict[str, Any]:
    """One archive pass storing every row touching any candidate lookalike or planting
    transaction of the study episodes (rivals included). About 25 minutes, bounded memory."""
    from cryptoguard.ml.annotation import atomic_write
    from cryptoguard.ml.fetch import TSUCHIYA_FILES, verify_local
    from cryptoguard.ml.hard_negative_archive import ARCHIVE
    from cryptoguard.ml.tsuchiya_archive import build_targets, load_targets, scan

    episodes, _ = load_episodes(poisoning_dir)
    manifest = build_targets(
        {
            "candidate_lookalikes": {c for e in episodes for c in e.candidates},
            "planting_txs": {r.tx for e in episodes for r in e.plantings},
        }
    )
    out_dir = poisoning_dir / RESEARCH_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_path = out_dir / "graph_context_targets.json"
    atomic_write(targets_path, json.dumps(manifest).encode())
    archive = data_dir / "tsuchiya2025" / ARCHIVE
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    work = out_dir / "spill"
    summary = scan(
        archive,
        load_targets(targets_path),
        out_dir / GRAPH_DB,
        work_dir=work,
        source_sha256=source["sha256"],
    )
    if work.exists() and not any(work.iterdir()):
        work.rmdir()
    return summary


def victim_of(row: Row) -> str | None:
    """The victim side of an archive row, from the source's ``is_sender_victim``."""
    if row.sender_is_victim is None:
        return None
    return row.sender if row.sender_is_victim else row.receiver


Edge = tuple[int, int, str]  # (block, line, victim)
EdgeKeep = Callable[[int, int], bool]  # (block, line) -> keep


def _lookalike_edge(r: Row, lookalike: str, exclude: frozenset[str]) -> tuple[bool, Edge] | None:
    """``(is_payoff, edge)`` when row ``r`` is a typed edge of ``lookalike``. Shared by the
    lazy and the preloaded index, so both build exactly the same edges."""
    from cryptoguard.ml.tsuchiya_archive import PAYOFF, POISONING

    v = victim_of(r)
    if v is None or v == lookalike or r.sender in exclude or r.receiver in exclude:
        return None
    if r.flags & POISONING and lookalike_of(r, v) == lookalike:
        return False, (r.block, r.line, v)
    if r.flags & PAYOFF and r.sender == v and r.receiver == lookalike:
        return True, (r.block, r.line, v)
    return None


def _tx_edge(r: Row, exclude: frozenset[str]) -> Edge | None:
    from cryptoguard.ml.tsuchiya_archive import POISONING

    v = victim_of(r)
    if v is None or not r.flags & POISONING or r.sender in exclude or r.receiver in exclude:
        return None
    return (r.block, r.line, v)


class GraphIndex:
    """Typed, time-stamped cross-victim edges of lookalikes, built lazily per address.

    - ``planted``: lookalike -> victim, a poisoning row (zero-value, tiny or counterfeit);
    - ``paid_by``: victim -> lookalike, a confirmed payoff row (source-labelled);
    - ``in_tx``: planting tx -> victim, for batch size.

    Only the source's ``is_sender_victim`` decides the victim side; rows without it are
    skipped. Token contracts are never a node, so shared public tokens link nothing. Every
    query takes a cutoff and sees only edges at or before it. Rows touching an ``exclude``d
    address (the frozen review wallets) never become an edge."""

    def __init__(
        self,
        fetch_lookalike: Callable[[str], Iterable[Row]],
        fetch_tx: Callable[[str], Iterable[Row]],
        *,
        keep: Callable[[Row], bool] | None = None,
        exclude: frozenset[str] = frozenset(),
    ) -> None:
        self._fetch_l, self._fetch_tx, self._keep = fetch_lookalike, fetch_tx, keep
        self._exclude = exclude
        self._l: dict[str, tuple[list[Edge], list[Edge]]] = {}
        self._tx: dict[str, list[Edge]] = {}

    def _edges(self, lookalike: str) -> tuple[list[Edge], list[Edge]]:
        if lookalike not in self._l:
            planted: set[Edge] = set()
            paid: set[Edge] = set()
            for r in self._fetch_l(lookalike):
                if self._keep is not None and not self._keep(r):
                    continue
                e = _lookalike_edge(r, lookalike, self._exclude)
                if e is not None:
                    (paid if e[0] else planted).add(e[1])
            self._l[lookalike] = (sorted(planted), sorted(paid))
        return self._l[lookalike]

    def _tx_edges(self, tx: str) -> list[Edge]:
        if tx not in self._tx:
            edges: set[Edge] = set()
            for r in self._fetch_tx(tx):
                if self._keep is not None and not self._keep(r):
                    continue
                e = _tx_edge(r, self._exclude)
                if e is not None:
                    edges.add(e)
            self._tx[tx] = sorted(edges)
        return self._tx[tx]

    @staticmethod
    def _victims(edges: list[Edge], cutoff: int, since: int | None) -> set[str]:
        hi = bisect_right(edges, (cutoff, math.inf, ""))
        return {v for b, _, v in edges[:hi] if since is None or b > since}

    def prior_victims(self, lookalike: str, cutoff: int, since: int | None = None) -> set[str]:
        return self._victims(self._edges(lookalike)[0], cutoff, since)

    def prior_payers(self, lookalike: str, cutoff: int, since: int | None = None) -> set[str]:
        return self._victims(self._edges(lookalike)[1], cutoff, since)

    def tx_victims(self, tx: str, cutoff: int) -> set[str]:
        return self._victims(self._tx_edges(tx), cutoff, None)


def sqlite_graph(
    path: Path,
    keep: Callable[[Row], bool] | None = None,
    exclude: frozenset[str] = frozenset(),
) -> GraphIndex:
    con = _connect(path)
    by_l = _ROWS + " where sender = ? or receiver = ?"

    def fetch_l(a: str) -> list[Row]:
        return [_row(t) for t in con.execute(by_l, (a, a))]

    def fetch_tx(tx: str) -> list[Row]:
        return [_row(t) for t in con.execute(_ROWS + " where tx = ?", (tx,))]

    return GraphIndex(fetch_l, fetch_tx, keep=keep, exclude=exclude)


@dataclass(frozen=True)
class PreloadedEdges:
    """Every typed edge of a fixed set of lookalikes and planting txs, built in one
    sequential pass. A lazy index does one random-access lookup per address instead: on the
    research database that was 96 ms per lookalike and 512 ms per tx on a shared HDD, against
    13 s for a sequential scan of all 1.3M rows."""

    planted: dict[str, list[Edge]]
    paid: dict[str, list[Edge]]
    tx: dict[str, list[Edge]]

    def index(self, keep: EdgeKeep | None = None) -> GraphIndex:
        """A ``GraphIndex`` over these edges; ``keep`` filters on (block, line). Asking for an
        address or tx outside the preloaded sets raises, rather than silently seeing none."""

        def pick(edges: list[Edge]) -> list[Edge]:
            return edges if keep is None else [e for e in edges if keep(e[0], e[1])]

        g = GraphIndex(_unloaded, _unloaded)
        g._l = {a: (pick(self.planted[a]), pick(self.paid[a])) for a in self.planted}
        g._tx = {t: pick(e) for t, e in self.tx.items()}
        return g


def _unloaded(key: str) -> list[Row]:
    raise KeyError(f"{key} is not in the preloaded graph")


def preload_graph(
    rows: Iterable[Row],
    lookalikes: Iterable[str],
    txs: Iterable[str],
    exclude: frozenset[str] = frozenset(),
) -> PreloadedEdges:
    """One pass over ``rows``, with the lazy index's per-row edge rules."""
    looks, tx_set = frozenset(lookalikes), frozenset(txs)
    planted: dict[str, set[Edge]] = {a: set() for a in looks}
    paid: dict[str, set[Edge]] = {a: set() for a in looks}
    in_tx: dict[str, set[Edge]] = {t: set() for t in tx_set}
    names: dict[str, str] = {}  # one string object per victim
    for r in rows:
        for lk in {r.sender, r.receiver} & looks:
            e = _lookalike_edge(r, lk, exclude)
            if e is not None:
                b, line, v = e[1]
                (paid if e[0] else planted)[lk].add((b, line, names.setdefault(v, v)))
        if r.tx in tx_set:
            te = _tx_edge(r, exclude)
            if te is not None:
                in_tx[r.tx].add((te[0], te[1], names.setdefault(te[2], te[2])))
    return PreloadedEdges(
        {a: sorted(v) for a, v in planted.items()},
        {a: sorted(v) for a, v in paid.items()},
        {t: sorted(v) for t, v in in_tx.items()},
    )


def sqlite_rows(path: Path) -> Iterator[Row]:
    """Every row of a research database, in storage order (sequential I/O)."""
    con = _connect(path)
    try:
        for t in con.execute(_ROWS + " order by line"):
            yield _row(t)
    finally:
        con.close()


def memory_graph(rows: Iterable[Row], exclude: frozenset[str] = frozenset()) -> GraphIndex:
    """A graph over rows held in memory (tests and small studies)."""
    by_addr: defaultdict[str, list[Row]] = defaultdict(list)
    by_tx: defaultdict[str, list[Row]] = defaultdict(list)
    for r in rows:
        by_addr[r.sender].append(r)
        if r.receiver != r.sender:
            by_addr[r.receiver].append(r)
        by_tx[r.tx].append(r)
    return GraphIndex(lambda a: by_addr.get(a, []), lambda t: by_tx.get(t, []), exclude=exclude)


# --- features ----------------------------------------------------------------------------


@dataclass(frozen=True)
class View:
    """How an episode is observed: the cutoff lag and the robustness transformations."""

    lag: int = 1  # cutoff c = payoff_block - lag
    victim_lookback: int | None = None  # victim rows only in (c - lookback, c]
    victim_drop: float = 0.0  # share of the victim's outgoing rows removed
    seed: int = 0

    def cutoff(self, ep: Episode) -> int:
        return ep.payoff_block - self.lag

    def keeps_victim_row(self, r: Row, c: int) -> bool:
        if self.victim_lookback is not None and r.block <= c - self.victim_lookback:
            return False
        return not _dropped(r.line, self.victim_drop, self.seed)


def _dropped(line: int, fraction: float, seed: int) -> bool:
    if fraction <= 0:
        return False
    h = hashlib.sha256(f"{seed}:{line}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64 < fraction


def graph_keep(drop: float, seed: int = 0) -> Callable[[Row], bool]:
    """Row filter for graph robustness: drop a share of rows (seeded)."""
    return lambda r: not _dropped(r.line, drop, seed)


def graph_keep_edge(drop: float, seed: int = 0) -> EdgeKeep:
    """``graph_keep`` for a preloaded index: the same rows survive."""
    return lambda _block, line: not _dropped(line, drop, seed)


@dataclass
class TokenIndex:
    """Study victims planted per token contract, for the negative control NC."""

    by_token: dict[str, list[tuple[int, str]]] = field(default_factory=dict)

    @classmethod
    def build(cls, episodes: Iterable[Episode]) -> TokenIndex:
        acc: defaultdict[str, set[tuple[int, str]]] = defaultdict(set)
        for e in episodes:
            for r in e.plantings:
                acc[r.token].add((r.block, e.victim))
        return cls({t: sorted(v) for t, v in acc.items()})

    def victims(self, token: str, cutoff: int, exclude: str) -> int:
        rows = self.by_token.get(token, [])
        hi = bisect_right(rows, (cutoff, "￿"))
        return len({v for _, v in rows[:hi] if v != exclude})


def candidate_features(
    ep: Episode,
    view: View,
    graph: GraphIndex | None,
    tokens: TokenIndex | None,
    *,
    graph_lookback: int | None = None,
) -> dict[str, dict[str, Value]] | None:
    """Features of every candidate at the view's cutoff, or None when the episode is not
    evaluable there (the paid lookalike has not planted yet, or fewer than 2 candidates)."""
    from cryptoguard.detectors.poisoning import PoisoningConfig, affix_match, is_lookalike
    from cryptoguard.ml.tsuchiya_archive import COUNTERFEIT, TINY, ZERO

    c = view.cutoff(ep)
    plantings = [r for r in ep.plantings if r.block <= c]
    by_l: defaultdict[str, list[Row]] = defaultdict(list)
    for r in plantings:
        by_l[lookalike_of(r, ep.victim)].append(r)
    if ep.paid not in by_l or len(by_l) < 2:
        return None
    out = [r for r in ep.victim_out if r.block <= c and view.keeps_victim_row(r, c)]
    uses: defaultdict[str, list[int]] = defaultdict(list)
    for r in out:
        uses[r.receiver].append(r.block)
    cfg = PoisoningConfig()
    since = None if graph_lookback is None else c - graph_lookback
    result: dict[str, dict[str, Value]] = {}
    for lk, rows in sorted(by_l.items()):
        tx_block: dict[str, int] = {}
        for r in rows:
            tx_block[r.tx] = min(tx_block.get(r.tx, r.block), r.block)
        last = max(rows, key=lambda r: (r.block, r.line))
        f: dict[str, Value] = {}
        # B0 / B3 / T3: the production similarity against the victim's own recipients.
        if not uses:
            f["B0"] = f["B3"] = f["T3"] = None
        else:
            best: tuple[int, int, str] | None = None
            for ref, blocks in uses.items():
                m = is_lookalike(lk, ref, cfg)
                if m is not None:
                    key = (m[0] + m[1], max(blocks), ref)
                    best = key if best is None or key > best else best
            if best is None:
                f["B0"], f["B3"], f["T3"] = 0.0, 0.0, None
            else:
                f["B0"] = float(best[0])
                f["B3"] = float(len(uses[best[2]]))
                f["T3"] = 1.0 if last.block > best[1] else 0.0
        intended = [r.intended for r in rows if r.intended and r.intended != lk]
        f["B1"] = float(max(sum(affix_match(lk, i)) for i in intended)) if intended else None
        if last.flags & COUNTERFEIT:
            f["B2"] = 2.0
        elif last.flags & TINY:
            f["B2"] = 3.0
        elif last.flags & ZERO:
            f["B2"] = 1.0
        else:
            f["B2"] = None
        f["T0"] = -float(c - last.block)
        f["T1"] = float(len(tx_block))
        f["T2"] = sum(math.exp(-(c - b) / DAY) for b in tx_block.values())
        f["T4"] = float(sum(1 for b in tx_block.values() if b > c - DAY))
        if graph is None:
            f["G1"] = f["G2"] = f["G3"] = None
        else:
            f["G1"] = float(len(graph.prior_victims(lk, c, since) - {ep.victim}))
            f["G2"] = float(len(graph.prior_payers(lk, c, since) - {ep.victim}))
            sizes = [len(graph.tx_victims(tx, c)) for tx in tx_block]
            f["G3"] = float(max(sizes)) if sizes and max(sizes) > 0 else None
        f["NC"] = None if tokens is None else float(tokens.victims(last.token, c, ep.victim))
        result[lk] = f
    return result


# --- methods and metrics -----------------------------------------------------------------

Scores = dict[str, float]


def single(feature: str) -> Callable[[Mapping[str, Mapping[str, Value]]], Scores | None]:
    def score(feats: Mapping[str, Mapping[str, Value]]) -> Scores | None:
        vals = {lk: f[feature] for lk, f in feats.items()}
        if any(v is None for v in vals.values()):
            return None  # abstain: missing evidence is never ranked as risk or safety
        return {lk: float(v) for lk, v in vals.items() if v is not None}

    score.__name__ = feature
    return score


def normalized_ranks(values: Mapping[str, float]) -> dict[str, float]:
    """Average ranks scaled to [0, 1]; 1 is the highest value. All equal -> all 0.5."""
    order = sorted(values, key=lambda k: values[k])
    k = len(order)
    ranks: dict[str, float] = {}
    i = 0
    while i < k:
        j = i
        while j + 1 < k and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2
        for n in range(i, j + 1):
            ranks[order[n]] = avg / (k - 1) if k > 1 else 0.5
        i = j + 1
    return ranks


def hybrid(
    components: Sequence[str],
) -> Callable[[Mapping[str, Mapping[str, Value]]], Scores | None]:
    """H_fixed: mean normalized rank of the components that do not abstain."""

    def score(feats: Mapping[str, Mapping[str, Value]]) -> Scores | None:
        parts = [s for s in (single(c)(feats) for c in components) if s is not None]
        if not parts:
            return None
        ranked = [normalized_ranks(p) for p in parts]
        return {lk: sum(r[lk] for r in ranked) / len(ranked) for lk in feats}

    score.__name__ = "H(" + ",".join(components) + ")"
    return score


HYBRID = ("B1", "B3", "T2", "G1")


def top1(scores: Scores | None, paid: str, k: int) -> float:
    """1/m if the paid candidate is among the m tied at the top; abstention = random."""
    if scores is None:
        return 1.0 / k
    top = max(scores.values())
    m = sum(1 for v in scores.values() if v == top)
    return 1.0 / m if scores[paid] == top else 0.0


def mrr(scores: Scores | None, paid: str, k: int) -> float:
    """Expected reciprocal rank of the paid candidate under random tie-breaking."""
    if scores is None:
        return sum(1 / j for j in range(1, k + 1)) / k
    p = scores[paid]
    better = sum(1 for v in scores.values() if v > p)
    tied = sum(1 for v in scores.values() if v == p)
    return sum(1 / (better + j) for j in range(1, tied + 1)) / tied


# --- groups, split and inference ---------------------------------------------------------


def groups(episodes: Sequence[Episode], *, by_tx: bool = True) -> list[int]:
    """Union-find over episodes sharing a candidate lookalike (and a planting tx)."""
    parent = list(range(len(episodes)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[str, int] = {}
    for i, e in enumerate(episodes):
        keys = [f"l:{c}" for c in e.candidates]
        if by_tx:
            keys += [f"t:{r.tx}" for r in e.plantings]
        for key in keys:
            if key in seen:
                a, b = find(i), find(seen[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                seen[key] = i
    roots = [find(i) for i in range(len(episodes))]
    names = {r: n for n, r in enumerate(sorted(set(roots)))}
    return [names[r] for r in roots]


def protocol_groups(episodes: Sequence[Episode]) -> tuple[list[int], str]:
    g = groups(episodes, by_tx=True)
    largest = max(Counter(g).values())
    if largest > 0.2 * len(episodes):
        return groups(episodes, by_tx=False), "candidate_lookalike"
    return g, "candidate_lookalike_and_planting_tx"


def temporal_split(
    episodes: Sequence[Episode], grp: Sequence[int], test_share: float = 0.4
) -> list[str]:
    """Groups ordered by their earliest payoff; the latest go to test until it holds at
    least ``test_share`` of episodes."""
    start: dict[int, int] = {}
    size: Counter[int] = Counter(grp)
    for e, g in zip(episodes, grp, strict=True):
        start[g] = min(start.get(g, e.payoff_block), e.payoff_block)
    test: set[int] = set()
    n = 0
    for g in sorted(start, key=lambda g: (start[g], g), reverse=True):
        if n >= test_share * len(episodes):
            break
        test.add(g)
        n += size[g]
    return ["test" if g in test else "dev" for g in grp]


def paired(
    d: Sequence[float],
    grp: Sequence[int],
    *,
    seed: int = 20261102,
    n_boot: int = 2_000,
    n_perm: int = 10_000,
) -> dict[str, Any]:
    """Mean paired difference, group-bootstrap 95% interval and group sign-flip p-value."""
    import numpy as np

    d_arr = np.asarray(d, dtype=float)
    g_arr = np.asarray(grp)
    ids, inv = np.unique(g_arr, return_inverse=True)
    sums = np.bincount(inv, weights=d_arr)
    counts = np.bincount(inv)
    rng = np.random.default_rng(seed)
    n_g = len(ids)
    pick = rng.integers(0, n_g, size=(n_boot, n_g))
    boot = sums[pick].sum(axis=1) / counts[pick].sum(axis=1)
    obs = sums.sum() / counts.sum()
    signs = rng.choice((-1.0, 1.0), size=(n_perm, n_g))
    null = np.abs(signs @ sums) / counts.sum()
    p = (1 + int((null >= abs(obs) - 1e-12).sum())) / (n_perm + 1)
    lo, hi = np.percentile(boot, [2.5, 97.5])
    return {
        "mean": float(obs),
        "ci95": [float(lo), float(hi)],
        "p": p,
        "episodes": len(d_arr),
        "groups": n_g,
    }


def holm(ps: Mapping[str, float]) -> dict[str, float]:
    order = sorted(ps, key=lambda k: ps[k])
    adj: dict[str, float] = {}
    running = 0.0
    for i, k in enumerate(order):
        running = max(running, min(1.0, (len(order) - i) * ps[k]))
        adj[k] = running
    return adj


def decision(diff: Mapping[str, Any], p_holm: float, margin: float = 0.05) -> str:
    lo, hi = diff["ci95"]
    if p_holm < 0.05 and (lo > 0 or hi < 0) and abs(diff["mean"]) >= margin:
        return "supported" if diff["mean"] > 0 else "reversed"
    if -margin < lo and hi < margin:
        return "null"
    return "inconclusive"

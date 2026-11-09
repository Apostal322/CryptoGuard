"""Research candidate selection under adversarial pressure (protocol 12.7,
``adversarial-selection/1``). Research only: nothing here is read by the detector.

Generation (``candidate_evidence.build``) and preservation (``page`` / ``group_records``)
are unchanged. This module only **reorders** the groups of one result: every selector
returns a permutation of its input, so no candidate or record is ever added, removed or
duplicated, and the bounded summary shows the first K of that order.

Features a selector may read, all known before the cutoff: ``bits`` = 4 x affix (the
expected key-search work, in bits, to match that affix of one specific reference), the
reference bucket (``candidate_evidence.bucket_of``), the latest planting position and the
mechanisms. The support level, the missing list and receipt status are never read, and no
selector sees the oracle target of a benchmark.

The proposed selector **P1, work-weighted group-discounted selection (WGS)**: order each
bucket by bits, then a keyed hash; member j (0-based) gets priority ``bits - lambda * j``;
order globally by priority, then the bucket's best bits, then the hash. With lambda = 4 the
j-th lookalike of the same reference must be one hex character more similar than a
lookalike of another reference to be shown first. P1 never reads time, so planting a newer
decoy buys nothing, and a reference bucket's first member cannot be displaced by any number
of weaker decoys (see ``displacement_bound``). It cannot beat the identifiability limit:
among more than K candidates that are equal in every feature, no ordering guarantees which
K are shown (protocol 12.7, section 3).
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any

from cryptoguard.ml import candidate_evidence as ce

SELECTOR_VERSION = "adversarial-selection/1"
METHODS = (
    "B0",  # similarity, then recency (the 12.6.1 presentation order)
    "B1",  # recency, then similarity
    "B2",  # evidence level first: negative reference only (H5 failed)
    "B3",  # mechanism round-robin
    "B4",  # reference round-robin (lambda = infinity, recency ties)
    "B5",  # cover every reference bucket once, then fill in B0 order
    "B6",  # B0 with keyed-hash ties instead of recency
    "P1",  # work-weighted group-discounted selection (proposed)
    "random",  # negative control: seeded random permutation
    "revrec",  # negative control: oldest first
)


@dataclass(frozen=True)
class Selector:
    method: str = "P1"
    seed: int = 0  # public here, for reproducibility; a deployment would keep it secret
    lam: float = 4.0  # bits per additional member of the same bucket (P1); math.inf allowed
    tie: str = "hash"  # P1 within-bucket ties: "hash" or "recency" (ablation A-rec)
    nosim: bool = False  # ablation A-nosim: bits := 0
    nomech: bool = False  # ablation A-nomech: every unreferenced candidate in one bucket
    # P1b (post hoc): break ties between buckets with a keyed hash of the *bucket*. P1 as
    # registered uses the member's hash, and a flooded bucket's leader is the minimum of many
    # hashes, so flooding wins ties; a bucket hash is independent of bucket size.
    bucket_tie: bool = False

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise ValueError(f"unknown method {self.method!r}")
        if self.tie not in ("hash", "recency"):
            raise ValueError(f"unknown tie rule {self.tie!r}")
        if not (self.lam >= 0):
            raise ValueError("lam must be >= 0")

    @property
    def label(self) -> str:
        if self.method != "P1":
            return self.method
        lam = "inf" if math.isinf(self.lam) else f"{self.lam:g}"
        parts = [f"{'P1b' if self.bucket_tie else 'P1'}[lam={lam}"]
        if self.tie != "hash":
            parts.append(f"tie={self.tie}")
        if self.nosim:
            parts.append("nosim")
        if self.nomech:
            parts.append("nomech")
        return ",".join(parts) + "]"


def config_hash(sel: Selector) -> str:
    payload = {"version": SELECTOR_VERSION, **asdict(sel)}
    if math.isinf(sel.lam):
        payload["lam"] = "inf"
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


# --- features (pre-cutoff only) -------------------------------------------------------------


def bits(g: ce.CandidateGroup) -> int:
    """Expected key-search work in bits to produce this affix for one reference."""
    return 4 * (g.affix or 0)


def bucket(g: ce.CandidateGroup, *, nomech: bool = False) -> str:
    b = ce.bucket_of(g)
    return "mech:*" if nomech and b.startswith("mech:") else b


def keyed(seed: int, lookalike: str) -> int:
    return int(hashlib.sha256(f"{seed}:{lookalike}".encode()).hexdigest()[:16], 16)


def _recent(g: ce.CandidateGroup) -> tuple[int, int, int]:
    return (-g.last_position[0], -g.last_position[1], -g.last_position[2])


def _old(g: ce.CandidateGroup) -> tuple[int, int, int]:
    return g.last_position


# --- orders ---------------------------------------------------------------------------------


def _round_robin(
    buckets: Sequence[Sequence[ce.CandidateGroup]],
) -> list[ce.CandidateGroup]:
    out: list[ce.CandidateGroup] = []
    depth = max((len(b) for b in buckets), default=0)
    for j in range(depth):
        out.extend(b[j] for b in buckets if j < len(b))
    return out


def _partition(
    groups: Sequence[ce.CandidateGroup], key: Callable[[ce.CandidateGroup], str]
) -> dict[str, list[ce.CandidateGroup]]:
    parts: dict[str, list[ce.CandidateGroup]] = {}
    for g in groups:
        parts.setdefault(key(g), []).append(g)
    return parts


def order(groups: Sequence[ce.CandidateGroup], sel: Selector) -> list[ce.CandidateGroup]:
    """The full order of ``groups`` under ``sel``: always a permutation of the input,
    independent of the input's order."""
    gs = sorted(groups, key=lambda g: g.lookalike)  # input-order invariance
    m = sel.method
    if m == "B0":
        return sorted(gs, key=ce.presentation_key)
    if m == "B1":
        return sorted(gs, key=lambda g: (_recent(g), -bits(g), g.lookalike))
    if m == "B2":
        return sorted(gs, key=ce.evidence_order_key)
    if m == "revrec":
        return sorted(gs, key=lambda g: (_old(g), g.lookalike))
    if m == "random":
        out = list(gs)
        random.Random(sel.seed).shuffle(out)  # noqa: S311 - negative control, not security
        return out
    if m == "B6":
        return sorted(gs, key=lambda g: (-bits(g), keyed(sel.seed, g.lookalike), g.lookalike))
    if m in ("B3", "B4", "B5"):
        if m == "B3":
            parts = _partition(gs, lambda g: "+".join(g.mechanisms))
        else:
            parts = _partition(gs, lambda g: bucket(g))
        within = {k: sorted(v, key=ce.presentation_key) for k, v in parts.items()}
        if m == "B3":
            keys = sorted(within, key=lambda k: (ce.presentation_key(within[k][0]), k))
        else:
            keys = sorted(within, key=lambda k: (-bits(within[k][0]), k))
        if m in ("B3", "B4"):
            return _round_robin([within[k] for k in keys])
        firsts = sorted((within[k][0] for k in keys), key=ce.presentation_key)
        chosen = {id(g) for g in firsts}
        rest = sorted((g for g in gs if id(g) not in chosen), key=ce.presentation_key)
        return firsts + rest
    return _p1(gs, sel)


def _p1(gs: Sequence[ce.CandidateGroup], sel: Selector) -> list[ce.CandidateGroup]:
    def b(g: ce.CandidateGroup) -> int:
        return 0 if sel.nosim else bits(g)

    def tie(g: ce.CandidateGroup) -> tuple[Any, ...]:
        if sel.tie == "recency":
            return _recent(g)
        return (keyed(sel.seed, g.lookalike),)

    parts = _partition(gs, lambda g: bucket(g, nomech=sel.nomech))
    keyed_rows: list[tuple[tuple[Any, ...], ce.CandidateGroup]] = []
    for key, members in parts.items():
        members.sort(key=lambda g: (-b(g), tie(g), g.lookalike))
        best = b(members[0])
        between: tuple[Any, ...] = (keyed(sel.seed, "bucket:" + key),) if sel.bucket_tie else ()
        for j, g in enumerate(members):
            if math.isinf(sel.lam):
                k: tuple[Any, ...] = (j, -b(g), -best, *between, tie(g), g.lookalike)
            else:
                k = (-(b(g) - sel.lam * j), -best, *between, tie(g), g.lookalike)
            keyed_rows.append((k, g))
    keyed_rows.sort(key=lambda kv: kv[0])
    return [g for _, g in keyed_rows]


def select(result: ce.EvidenceResult, sel: Selector) -> ce.EvidenceResult:
    """The same result with its groups in ``sel``'s order, labelled with the method and its
    configuration hash; summaries and pages then expose that order."""
    ordered = order(result.groups, sel)
    if len(ordered) != len(result.groups):  # a permutation by construction; checked anyway
        raise AssertionError("a selector must return a permutation of its input")
    return replace(result, groups=tuple(ordered), order=sel.label, order_config=config_hash(sel))


# --- the provable bound ---------------------------------------------------------------------


def displacement_bound(
    groups: Sequence[ce.CandidateGroup], target_bucket: str, lam: float, *, nomech: bool = False
) -> int | None:
    """Upper bound on the 1-based position of the first member of ``target_bucket`` under
    P1 with this ``lam``: 1 + sum over other buckets of the members whose priority can
    reach the target bucket's best bits. It does not depend on how many weaker members a
    bucket has. None when the bucket is empty or lam is not positive."""
    if not lam > 0:
        return None
    best: dict[str, int] = {}
    size: dict[str, int] = {}
    for g in groups:
        k = bucket(g, nomech=nomech)
        best[k] = max(best.get(k, -1), bits(g))
        size[k] = size.get(k, 0) + 1
    if target_bucket not in best:
        return None
    b = best[target_bucket]
    total = 1
    for k, bk in best.items():
        if k == target_bucket or bk < b:
            continue
        reach = 1 if math.isinf(lam) else int((bk - b) // lam) + 1  # round j = 0 only at inf
        total += min(size[k], reach)
    return total

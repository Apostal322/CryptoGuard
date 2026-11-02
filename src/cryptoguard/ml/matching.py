"""Deterministic coarsened exact matching between source-labelled positive candidates and
unlabeled hard-negative candidates, with balance diagnostics (Phase 11.5).

Matching describes *comparability*, never labels.

- Units match only when every coarsened covariate is equal. A missing covariate is its
  own level and never imputed.
- Matches are drawn without replacement, up to ``ratio`` candidates per positive, in
  keyed-hash order, so ties break deterministically.
- Positives and candidates without support are reported as unmatched, not forced.

Only information available at the observation cutoff may be a covariate. Outcomes,
future campaign membership, final labels and model scores are refused by name.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

MATCH_VERSION = "cem/1"
FORBIDDEN = frozenset(
    {
        "payoff",
        "paid",
        "loss",
        "outcome",
        "label",
        "source_label",
        "score",
        "prediction",
        "campaign_after",
        "later_payment",
    }
)
Value = str | int | float | bool | None


class MatchingError(ValueError):
    pass


@dataclass(frozen=True)
class Unit:
    id: str
    covariates: Mapping[str, Value]  # coarsened values used for exact matching
    numeric: Mapping[str, float | None]  # raw values for balance diagnostics


def _rank(seed: str, unit_id: str) -> str:
    return hashlib.sha256(f"{seed}|{unit_id}".encode()).hexdigest()


def cem(
    positives: Sequence[Unit],
    candidates: Sequence[Unit],
    *,
    keys: Sequence[str],
    ratio: int = 1,
    seed: str = MATCH_VERSION,
) -> dict[str, Any]:
    bad = [k for k in keys if any(f in k.lower() for f in FORBIDDEN)]
    if bad:
        raise MatchingError(f"refusing post-cutoff or label covariates: {bad}")
    if ratio < 1:
        raise MatchingError("ratio must be at least 1")
    ids = [u.id for u in (*positives, *candidates)]
    if len(set(ids)) != len(ids):
        raise MatchingError("unit ids repeat across or within the two sets")

    def cell(u: Unit) -> tuple[Value, ...]:
        return tuple(u.covariates.get(k) for k in keys)

    pool: dict[tuple[Value, ...], list[Unit]] = defaultdict(list)
    for c in sorted(candidates, key=lambda u: _rank(seed, u.id)):
        pool[cell(c)].append(c)
    pairs: list[tuple[str, str]] = []
    unmatched_pos: list[str] = []
    for p in sorted(positives, key=lambda u: _rank(seed, u.id)):
        bucket = pool.get(cell(p), [])
        take, pool[cell(p)] = bucket[:ratio], bucket[ratio:]
        if not take:
            unmatched_pos.append(p.id)
        pairs += [(p.id, c.id) for c in take]
    matched_c = {c for _, c in pairs}
    matched_p = {p for p, _ in pairs}
    pos_cells = {cell(p) for p in positives}
    return {
        "match_version": MATCH_VERSION,
        "keys": list(keys),
        "ratio": ratio,
        "pairs": pairs,
        "matched_positives": len(matched_p),
        "unmatched_positives": unmatched_pos,
        "matched_candidates": len(matched_c),
        "unmatched_candidates": [c.id for c in candidates if c.id not in matched_c],
        "candidates_without_support": sum(1 for c in candidates if cell(c) not in pos_cells),
        "balance_before": balance(positives, candidates),
        "balance_after": balance(
            [p for p in positives if p.id in matched_p],
            [c for c in candidates if c.id in matched_c],
        ),
    }


def smd(a: Sequence[float], b: Sequence[float]) -> float | None:
    """Standardized mean difference (pooled SD). None when undefined."""
    if len(a) < 2 or len(b) < 2:
        return None
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    va = sum((x - ma) ** 2 for x in a) / (len(a) - 1)
    vb = sum((x - mb) ** 2 for x in b) / (len(b) - 1)
    sd = math.sqrt((va + vb) / 2)
    if sd == 0:
        return 0.0 if ma == mb else None
    return (ma - mb) / sd


def balance(positives: Sequence[Unit], candidates: Sequence[Unit]) -> dict[str, Any]:
    names = sorted({k for u in (*positives, *candidates) for k in u.numeric})
    out: dict[str, Any] = {"positives": len(positives), "candidates": len(candidates)}
    for k in names:
        a = [v for u in positives if (v := u.numeric.get(k)) is not None]
        b = [v for u in candidates if (v := u.numeric.get(k)) is not None]
        out[k] = {
            "smd": smd(a, b),
            "missing_positive": len(positives) - len(a),
            "missing_candidate": len(candidates) - len(b),
        }
    return out

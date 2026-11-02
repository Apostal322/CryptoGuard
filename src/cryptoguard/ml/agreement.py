"""Agreement between two reviewers on nominal labels (exact arithmetic, no fabricated values).

Undefined statistics are returned as ``None`` with a reason, never as 0:
- Cohen's kappa is undefined when there are no paired items, or when chance agreement is 1
  (both reviewers used one and the same category for every item).
- Gwet's AC1 uses the fixed category set, so it is defined whenever items exist. Its
  chance term is (1/(K-1)) * sum_k pi_k (1 - pi_k), with pi_k the mean of the two
  reviewers' shares (Gwet 2008). It is reported alongside kappa because kappa is unstable
  when one category dominates, which is expected here.

Weighted kappa is not offered: the decision categories have no justified ordering.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from fractions import Fraction
from typing import Any

from cryptoguard.ml.annotation import ATTEMPT
from cryptoguard.ml.review import DECISION_TIER

DECISIONS: tuple[str, ...] = tuple(DECISION_TIER)
BINARY: tuple[str, ...] = ("attempt", "not_attempt")


def binary(decision: str) -> str:
    """Protocol §7: confirmed or likely attempt versus every other decision."""
    return "attempt" if decision in ATTEMPT else "not_attempt"


def agreement(
    a: Mapping[str, str], b: Mapping[str, str], categories: Sequence[str] = DECISIONS
) -> dict[str, Any]:
    """Compare two reviewers' labels keyed by item. Items labelled by only one reviewer
    are counted as unpaired, not dropped silently."""
    unknown = sorted({*a.values(), *b.values()} - set(categories))
    if unknown:
        raise ValueError(f"labels outside the category set: {unknown}")
    paired = sorted(set(a) & set(b))
    n = len(paired)
    matrix = {x: dict.fromkeys(categories, 0) for x in categories}
    for i in paired:
        matrix[a[i]][b[i]] += 1
    out: dict[str, Any] = {
        "categories": list(categories),
        "paired_items": n,
        "unpaired": {"only_a": len(set(a) - set(b)), "only_b": len(set(b) - set(a))},
        "counts_a": dict(Counter(a[i] for i in paired)),
        "counts_b": dict(Counter(b[i] for i in paired)),
        "confusion": matrix,  # rows: reviewer A, columns: reviewer B
        "disagreements": n - sum(matrix[x][x] for x in categories),
    }
    if n == 0:
        reason = "no item was labelled by both reviewers"
        return out | {
            "observed_agreement": None,
            "cohen_kappa": None,
            "kappa_note": reason,
            "gwet_ac1": None,
            "ac1_note": reason,
        }
    po = Fraction(sum(matrix[x][x] for x in categories), n)
    pa = {x: Fraction(sum(matrix[x].values()), n) for x in categories}
    pb = {x: Fraction(sum(matrix[y][x] for y in categories), n) for x in categories}
    pe = sum(pa[x] * pb[x] for x in categories)
    out["observed_agreement"] = float(po)
    if pe == 1:
        out |= {
            "cohen_kappa": None,
            "kappa_note": "undefined: both reviewers used a single, identical category",
        }
    else:
        out |= {"cohen_kappa": float((po - pe) / (1 - pe)), "kappa_note": None}
    k = len(categories)
    pi = {x: (pa[x] + pb[x]) / 2 for x in categories}
    pe_ac1 = sum(pi[x] * (1 - pi[x]) for x in categories) / (k - 1)
    out |= {"gwet_ac1": float((po - pe_ac1) / (1 - pe_ac1)), "ac1_note": None}
    return out

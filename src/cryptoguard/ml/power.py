"""Sample-size planning for false-positive-rate claims (Phase 11.6). Planning only:
nothing here collects data.

Question: how many independently reviewed *legitimate* events are needed so that the
upper bound of a two-sided 95% Wilson interval on the FPR falls below a target? The
assumption is that the true FPR is a stated fraction of the target.

Clustering inflates the need. Events from one wallet or campaign are correlated, so the
effective sample size is ``n / deff`` with ``deff = 1 + (m - 1) * icc`` (``m`` events per
cluster, ``icc`` the intra-cluster correlation). The required ``n`` is multiplied by
``deff``.
"""

from __future__ import annotations

import math
from typing import Any

from cryptoguard.ml.sample_design import wilson


def negatives_needed(target_fpr: float, true_fpr: float, *, max_n: int = 1_000_000) -> int | None:
    """Smallest n whose expected Wilson 95% upper bound (at the true FPR) is below target."""
    if not 0 <= true_fpr < target_fpr <= 1:
        raise ValueError("need 0 <= true_fpr < target_fpr <= 1")
    lo, hi = 1, max_n
    if (wilson(true_fpr, hi) or (0, 1))[1] >= target_fpr:
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if (wilson(true_fpr, mid) or (0, 1))[1] < target_fpr:
            hi = mid
        else:
            lo = mid + 1
    return lo


def design_effect(per_cluster: float, icc: float) -> float:
    return 1 + (per_cluster - 1) * icc


def plan_table(targets: tuple[float, ...] = (0.10, 0.05, 0.01),
               ratios: tuple[float, ...] = (0.0, 0.5),
               deffs: tuple[float, ...] = (1.0, 1.5, 2.0)) -> list[dict[str, Any]]:  # fmt: skip
    rows = []
    for target in targets:
        for ratio in ratios:
            n = negatives_needed(target, target * ratio)
            rows.append({
                "target_fpr": target,
                "assumed_true_fpr": target * ratio,
                "negatives_iid": n,
                **{f"negatives_deff_{d}": (math.ceil(n * d) if n else None) for d in deffs},
            })  # fmt: skip
    return rows


def _binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))


def clopper_pearson_upper(k: int, n: float, alpha: float = 0.05) -> float:
    """Exact one-sided (1 - alpha) upper bound for k events in n trials. A non-integer n
    (an effective sample size) is rounded down, which is conservative."""
    m = math.floor(n)
    if m <= 0 or k > m:
        return 1.0
    if k == m:
        return 1.0
    lo, hi = k / m, 1.0
    for _ in range(100):  # bisection on P(X <= k | p) = alpha
        mid = (lo + hi) / 2
        if _binom_cdf(k, m, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def bound_table(sizes: tuple[int, ...] = (30, 35, 50, 100, 300, 1000),
                deffs: tuple[float, ...] = (1.0, 2.0)) -> list[dict[str, Any]]:  # fmt: skip
    """What n reviewed legitimate events can show about FPR: the upper bound when 0 or 1
    of them is flagged. One-sided 95% exact (Clopper-Pearson) and two-sided 95% Wilson;
    clustering divides n by the design effect."""
    rows = []
    for n in sizes:
        for d in deffs:
            n_eff = n / d
            rows.append({
                "negatives": n,
                "design_effect": d,
                "effective_n": round(n_eff, 1),
                "upper_0_flagged_cp_one_sided": round(clopper_pearson_upper(0, n_eff), 4),
                "upper_1_flagged_cp_one_sided": round(clopper_pearson_upper(1, n_eff), 4),
                "upper_0_flagged_wilson_two_sided": round((wilson(0.0, n_eff) or (0, 1))[1], 4),
            })  # fmt: skip
    return rows

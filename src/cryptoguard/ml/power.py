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


# --- paired exposure comparisons (protocol 12.8, section 12) --------------------------------
#
# Two methods are scored on the same incidents (exposed within K or not). Incidents where
# both agree carry no information about which is better; only the discordant ones do. Under
# H0 a discordant incident favours either method with probability 1/2 (exact sign test,
# equivalently McNemar's exact test).


def _binom_pmf(k: int, n: int, p: float) -> float:
    if p <= 0.0:
        return 1.0 if k == 0 else 0.0
    if p >= 1.0:
        return 1.0 if k == n else 0.0
    log = (
        math.lgamma(n + 1)
        - math.lgamma(k + 1)
        - math.lgamma(n - k + 1)
        + k * math.log(p)
        + (n - k) * math.log1p(-p)
    )
    return math.exp(log)


def _binom_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""
    return min(1.0, sum(_binom_pmf(i, n, p) for i in range(max(k, 0), n + 1)))


def sign_test_power(n_discordant: int, p_better: float, alpha: float = 0.05) -> dict[str, Any]:
    """Exact one-sided sign test on ``n_discordant`` discordant incidents. ``p_better`` is
    the probability that a discordant incident favours the truly better method. Returns the
    critical count (None when even n of n is not significant), the attained size and power."""
    critical = next(
        (k for k in range(n_discordant + 1) if _binom_sf(k, n_discordant, 0.5) <= alpha), None
    )
    if critical is None:
        return {"n_discordant": n_discordant, "critical": None, "size": 0.0, "power": 0.0}
    return {
        "n_discordant": n_discordant,
        "critical": critical,
        "size": round(_binom_sf(critical, n_discordant, 0.5), 5),
        "power": round(_binom_sf(critical, n_discordant, p_better), 4),
    }


def discordant_needed(
    p_better: float, power: float = 0.8, alpha: float = 0.05, max_n: int = 2_000
) -> int | None:
    """Smallest number of discordant incidents from which the exact test keeps at least the
    target power (the exact test's power is saw-toothed, so the next 10 sizes are checked)."""
    if not 0.5 < p_better <= 1.0:
        return None
    for n in range(1, max_n + 1):
        if all(sign_test_power(m, p_better, alpha)["power"] >= power for m in range(n, n + 11)):
            return n
    return None


def incidents_needed(
    p_better: float,
    discordance: float,
    *,
    power: float = 0.8,
    alpha: float = 0.05,
    eligible_rate: float = 1.0,
    deff: float = 1.0,
) -> dict[str, Any]:
    """Incidents to screen so that the expected number of independent discordant incidents
    reaches ``discordant_needed``. ``discordance``: share of eligible incidents on which the
    two methods disagree; ``eligible_rate``: share of screened incidents that are eligible
    and evaluable; ``deff``: cluster design effect (1 = every incident its own cluster).
    Every input is an assumption to be stated, not a constant of nature."""
    for name, v in (("discordance", discordance), ("eligible_rate", eligible_rate)):
        if not 0.0 < v <= 1.0:
            raise ValueError(f"{name} must be in (0, 1]")
    if deff < 1.0:
        raise ValueError("deff must be >= 1")
    d = discordant_needed(p_better, power, alpha)
    if d is None:
        return {"discordant_needed": None, "eligible_needed": None, "screened_needed": None}
    eligible = math.ceil(d * deff / discordance)
    return {
        "p_better": p_better,
        "discordance": discordance,
        "power": power,
        "alpha": alpha,
        "eligible_rate": eligible_rate,
        "deff": deff,
        "discordant_needed": d,
        "eligible_needed": eligible,
        "screened_needed": math.ceil(eligible / eligible_rate),
    }


def paired_plan_grid(
    p_better: tuple[float, ...] = (0.7, 0.8, 0.9),
    discordance: tuple[float, ...] = (0.1, 0.3, 0.5),
    eligible_rate: float = 0.5,
    deff: float = 1.0,
) -> list[dict[str, Any]]:
    return [
        incidents_needed(p, d, eligible_rate=eligible_rate, deff=deff)
        for p in p_better
        for d in discordance
    ]

"""Univariate Hawkes process with an exponential kernel, fitted by maximum likelihood.

    lambda(t) = mu + sum_{t_i < t} alpha * exp(-beta (t - t_i)),   mu, alpha, beta > 0

The branching ratio ``n = alpha / beta`` is the expected number of events each event
triggers; the process is stationary only when ``n < 1``, so the fit constrains it. Times
are in blocks. The log-likelihood on [0, T] is

    sum_i log lambda(t_i) - mu T - (alpha / beta) sum_i (1 - exp(-beta (T - t_i)))

computed with the usual O(N) recursion. Used for evaluation only: it is compared with a
homogeneous Poisson process (``alpha = 0``) on held-out data before any product use.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

MAX_BRANCHING = 0.99


@dataclass(frozen=True)
class HawkesFit:
    mu: float
    alpha: float
    beta: float
    log_likelihood: float
    events: int
    horizon: float
    converged: bool

    @property
    def branching_ratio(self) -> float:
        return self.alpha / self.beta


def log_likelihood(
    times: Sequence[float], horizon: float, mu: float, alpha: float, beta: float
) -> float:
    if mu <= 0 or alpha < 0 or beta <= 0:
        return -math.inf
    total = 0.0
    excitation = 0.0  # sum_{j<i} exp(-beta (t_i - t_j))
    previous: float | None = None
    for t in times:
        if previous is not None:
            excitation = math.exp(-beta * (t - previous)) * (1.0 + excitation)
        total += math.log(mu + alpha * excitation)
        previous = t
    compensator = mu * horizon + (alpha / beta) * sum(
        1.0 - math.exp(-beta * (horizon - t)) for t in times
    )
    return total - compensator


def poisson_log_likelihood(events: int, horizon: float, rate: float | None = None) -> float:
    rate = events / horizon if rate is None else rate
    if events == 0:
        return -rate * horizon
    return events * math.log(rate) - rate * horizon


def fit(times: Sequence[float], horizon: float) -> HawkesFit:
    """MLE over (log mu, logit branching, log beta); requires at least 3 events."""
    import numpy as np
    from scipy.optimize import minimize

    ts = sorted(float(t) for t in times)
    if len(ts) < 3 or horizon <= 0 or ts[-1] > horizon or ts[0] < 0:
        raise ValueError("need >= 3 event times within [0, horizon]")

    def unpack(p: np.ndarray) -> tuple[float, float, float]:
        mu = math.exp(p[0])
        branching = MAX_BRANCHING / (1.0 + math.exp(-p[1]))
        beta = math.exp(p[2])
        return mu, branching * beta, beta

    def objective(p: np.ndarray) -> float:
        value = log_likelihood(ts, horizon, *unpack(p))
        return 1e300 if not math.isfinite(value) else -value

    rate = len(ts) / horizon
    best = None
    for b0 in (1.0 / horizon, 0.01, 0.1, 1.0):  # multi-start over the decay scale
        start = np.array([math.log(rate / 2), 0.0, math.log(b0)])
        res = minimize(
            objective,
            start,
            method="Nelder-Mead",
            options={"maxiter": 4000, "xatol": 1e-8, "fatol": 1e-10},
        )
        if best is None or res.fun < best.fun:
            best = res
    assert best is not None
    mu, alpha, beta = unpack(best.x)
    return HawkesFit(mu, alpha, beta, -float(best.fun), len(ts), horizon, bool(best.success))

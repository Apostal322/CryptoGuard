"""Propagation of a seed signal over the interaction graph, plus the simpler baselines.

Heat diffusion on the undirected projection (symmetric, nonnegative ``W``):

    L      = D - W                                  (combinatorial)
    L_sym  = I' - D^(-1/2) W D^(-1/2)               (normalized)
    u(tau) = exp(-tau L) u(0)

``tau`` is a dimensionless diffusion scale, not time on the chain. For an isolated node we
use Chung's convention: its row of ``L_sym`` is zero (``I'`` has a 0 on that diagonal), so
it keeps its own signal and leaks nothing, exactly as with the combinatorial Laplacian.

Invariants (tested): ``exp(-tau L)`` has nonnegative entries for both definitions (``-L`` is
Metzler), so nonnegative seeds give nonnegative outputs. For ``L``, total mass and constant
vectors are preserved; for ``L_sym`` the preserved vector is ``D^(1/2) 1``, not the constant.

Baselines on the same graph: direct-neighbour indicator, hop distance, degree-normalized
neighbour aggregation, and personalized PageRank on the **directed** graph walked against
edge direction ("who caused or paid into the flagged address"), which keeps the direction
the symmetric projection discards.

None of these outputs is a probability of fraud. They rank addresses by how closely the
observed data links them to the seeds.
"""

from __future__ import annotations

import itertools
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptoguard.analytics.graph import DEFAULT_WEIGHTS, EdgeKind, WalletGraph

if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray
    from scipy.sparse import csr_matrix

    Vector = NDArray[np.float64]

NEGATIVE_TOLERANCE = 1e-10


def laplacian(a: csr_matrix, *, normalized: bool) -> csr_matrix:
    import numpy as np
    from scipy.sparse import csr_matrix, diags

    asymmetry = csr_matrix(a - a.T)
    asymmetry.eliminate_zeros()
    if asymmetry.nnz:
        raise ValueError("the Laplacian needs a symmetric adjacency matrix")
    if a.nnz and a.data.min() < 0:
        raise ValueError("adjacency weights must be nonnegative")
    degree = np.asarray(a.sum(axis=1)).ravel()
    if not normalized:
        return csr_matrix(diags(degree) - a)
    nonzero = degree > 0
    inv_sqrt = np.zeros_like(degree)
    inv_sqrt[nonzero] = 1.0 / np.sqrt(degree[nonzero])
    scale = diags(inv_sqrt)
    eye = diags(nonzero.astype(float))  # Chung: 0 on the diagonal of isolated nodes
    return csr_matrix(eye - scale @ a @ scale)


def heat_kernel(a: csr_matrix, u0: Vector, tau: float, *, normalized: bool = True) -> Vector:
    """``exp(-tau L) u0`` without forming the dense exponential (Al-Mohy and Higham)."""
    import numpy as np
    from scipy.sparse.linalg import expm_multiply

    if tau < 0:
        raise ValueError("tau must be nonnegative")
    if a.shape[0] == 0:
        return np.zeros(0)
    if tau == 0:
        return np.array(u0, dtype=float)
    out = np.asarray(expm_multiply(-tau * laplacian(a, normalized=normalized), u0), dtype=float)
    return _checked(out)


def _checked(out: Vector) -> Vector:
    import numpy as np

    if not np.all(np.isfinite(out)):
        raise FloatingPointError("non-finite propagation output")
    if out.size and out.min() < -NEGATIVE_TOLERANCE:
        raise FloatingPointError(f"negative propagation output {out.min():.3e}")
    return np.clip(out, 0.0, None)  # remove round-off below zero


def personalized_pagerank(
    a_directed: csr_matrix,
    u0: Vector,
    *,
    damping: float = 0.85,
    reverse: bool = True,
    tol: float = 1e-12,
    max_iter: int = 500,
) -> tuple[Vector, int]:
    """Random walk with restart to the seeds; ``reverse`` walks edges backwards.

    Dangling nodes (no usable out-edge) send their mass back to the seeds. Converges
    geometrically with rate ``damping``; returns the scores and the iteration count.
    """
    import numpy as np
    from scipy.sparse import diags

    n = a_directed.shape[0]
    if n == 0:
        return np.zeros(0), 0
    if not 0 < damping < 1:
        raise ValueError("damping must be in (0, 1)")
    total = float(np.sum(u0))
    if total <= 0:
        return np.zeros(n), 0
    restart = np.asarray(u0, dtype=float) / total
    m = a_directed.T.tocsr() if reverse else a_directed
    out_weight = np.asarray(m.sum(axis=1)).ravel()
    dangling = out_weight == 0
    inv = np.zeros(n)
    inv[~dangling] = 1.0 / out_weight[~dangling]
    transition_t = (diags(inv) @ m).T.tocsr()  # column-stochastic on non-dangling columns
    x = restart.copy()
    for iteration in range(1, max_iter + 1):
        nxt = damping * (transition_t @ x + x[dangling].sum() * restart) + (1 - damping) * restart
        if np.abs(nxt - x).sum() < tol:
            return _checked(nxt), iteration
        x = nxt
    return _checked(x), max_iter


def hop_distances(a: csr_matrix, seeds: Sequence[int], *, max_hops: int = 6) -> list[int | None]:
    """Unweighted BFS distance to the nearest seed; None beyond ``max_hops`` or unreachable."""
    dist: list[int | None] = [None] * a.shape[0]
    queue: deque[int] = deque()
    for s in seeds:
        dist[s] = 0
        queue.append(s)
    indptr, indices = a.indptr, a.indices
    while queue:
        node = queue.popleft()
        d = dist[node]
        assert d is not None
        if d >= max_hops:
            continue
        for nb in indices[indptr[node] : indptr[node + 1]]:
            if dist[nb] is None:
                dist[nb] = d + 1
                queue.append(int(nb))
    return dist


def neighbour_aggregation(a: csr_matrix, u0: Vector) -> Vector:
    """Degree-normalized sum of the neighbours' seed values (one propagation step)."""
    import numpy as np

    degree = np.asarray(a.sum(axis=1)).ravel()
    agg = np.asarray(a @ u0, dtype=float).ravel()
    out = np.zeros_like(agg)
    nz = degree > 0
    out[nz] = agg[nz] / degree[nz]
    return out


# --- Explainable output -------------------------------------------------------------------


@dataclass(frozen=True)
class Seed:
    """An address flagged at or before the cutoff, with where the flag came from."""

    address: str
    source: str  # e.g. "finding CG-POI-001 at block 19788642"
    block: int


@dataclass(frozen=True)
class PathStep:
    source: str
    target: str
    kind: EdgeKind
    events: int
    example_transaction: str | None
    example_block: int | None


@dataclass(frozen=True)
class RelatedAddress:
    address: str
    roles: tuple[str, ...]
    hops: int
    nearest_seed: str
    path: tuple[PathStep, ...]
    scores: Mapping[str, float]  # method -> score (heat at each tau, ppr, neighbour)


@dataclass(frozen=True)
class PropagationResult:
    status: str  # "ok" | "no_seeds" | "skipped"
    seeds: tuple[Seed, ...]
    related: tuple[RelatedAddress, ...]
    nodes: int
    edges: int
    parameters: Mapping[str, object]
    notes: tuple[str, ...]


def _path(
    graph: WalletGraph, a: csr_matrix, nodes: list[str], start: int, seeds: set[int]
) -> tuple[int, list[int]] | None:
    """Shortest path (as node indices) from ``start`` to the nearest seed."""
    prev: dict[int, int] = {start: -1}
    queue: deque[int] = deque([start])
    while queue:
        node = queue.popleft()
        if node in seeds:
            path = [node]
            while prev[path[-1]] != -1:
                path.append(prev[path[-1]])
            return node, path[::-1]
        for nb in a.indices[a.indptr[node] : a.indptr[node + 1]]:
            if int(nb) not in prev:
                prev[int(nb)] = node
                queue.append(int(nb))
    return None


def _step(graph: WalletGraph, x: str, y: str) -> PathStep:
    for kind in ("caused", "transfer", "native_transfer", "token_use"):
        for src, dst in ((x, y), (y, x)):
            agg = graph.edges.get((src, dst, kind))
            if agg is not None:
                block, tx = agg.samples[0] if agg.samples else (None, None)
                return PathStep(src, dst, agg.kind, agg.count, tx, block)
    raise KeyError((x, y))


def propagate(
    graph: WalletGraph,
    seeds: Sequence[Seed],
    *,
    taus: Sequence[float] = (0.5, 1.0, 2.0),
    weights: Mapping[EdgeKind, float] = DEFAULT_WEIGHTS,
    max_hops: int = 4,
    max_nodes: int = 5_000,
    top_k: int = 20,
) -> PropagationResult:
    """Score every address linked to a seed; explain each by its shortest path to a seed."""
    import numpy as np

    params: dict[str, object] = {
        "taus": list(taus),
        "weights": dict(weights),
        "laplacian": "normalized (Chung convention for isolated nodes)",
        "ppr_damping": 0.85,
        "ppr_direction": "reverse (towards causes and payers)",
        "max_hops": max_hops,
        "wallet_node": "excluded (every counterparty is adjacent to it by construction)",
    }
    a, nodes = graph.matrix(weights=weights, exclude_wallet=True)
    edges = int(a.nnz // 2)
    if len(nodes) > max_nodes:
        return PropagationResult(
            "skipped",
            tuple(seeds),
            (),
            len(nodes),
            edges,
            params,
            (f"{len(nodes)} nodes exceed the {max_nodes}-node budget; propagation skipped.",),
        )
    index = {n: i for i, n in enumerate(nodes)}
    present = [s for s in seeds if s.address in index]
    if not present:
        return PropagationResult(
            "no_seeds",
            tuple(seeds),
            (),
            len(nodes),
            edges,
            params,
            ("No flagged address is part of the observed graph at this cutoff.",),
        )
    u0 = np.zeros(len(nodes))
    for s in present:
        u0[index[s.address]] = 1.0
    u0 /= u0.sum()
    seed_idx = sorted({index[s.address] for s in present})
    heat = {tau: heat_kernel(a, u0, tau) for tau in taus}
    directed, _ = graph.matrix(weights=weights, directed=True, exclude_wallet=True)
    ppr, iterations = personalized_pagerank(directed, u0)
    params["ppr_iterations"] = iterations
    neighbour = neighbour_aggregation(a, u0)
    hops = hop_distances(a, seed_idx, max_hops=max_hops)

    related: list[RelatedAddress] = []
    seed_set = set(seed_idx)
    for i, address in enumerate(nodes):
        h = hops[i]
        if i in seed_set or h is None:
            continue
        found = _path(graph, a, nodes, i, seed_set)
        if found is None:
            continue
        nearest, path = found
        related.append(
            RelatedAddress(
                address=address,
                roles=tuple(sorted(graph.roles.get(address, ()))),
                hops=h,
                nearest_seed=nodes[nearest],
                path=tuple(_step(graph, nodes[x], nodes[y]) for x, y in itertools.pairwise(path)),
                scores={
                    **{f"heat_tau_{tau:g}": float(v[i]) for tau, v in heat.items()},
                    "ppr_reverse": float(ppr[i]),
                    "neighbour": float(neighbour[i]),
                },
            )
        )
    primary = f"heat_tau_{taus[len(taus) // 2]:g}"
    related.sort(key=lambda r: (-r.scores[primary], r.hops, r.address))
    return PropagationResult(
        "ok",
        tuple(present),
        tuple(related[:top_k]),
        len(nodes),
        edges,
        params,
        (
            "Scores rank how closely observed transactions link an address to a flagged one; "
            "they are not probabilities and do not show that the address is malicious.",
        ),
    )

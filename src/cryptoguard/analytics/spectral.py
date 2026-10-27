"""Structural features of the interaction graph, spectral and plain.

Plain features (the baselines): node, edge, counterparty and event counts and the maximum
degree. Spectral features come from the normalized Laplacian ``L_sym`` of the undirected
projection (wallet node excluded, see ``analytics.graph``), whose eigenvalues lie in [0, 2]
whatever the graph's size:

- ``components``: multiplicity of the eigenvalue 0;
- ``algebraic_connectivity``: the second-smallest eigenvalue of the largest component;
- ``lambda_max``: the largest eigenvalue (2 exactly when some component is bipartite);
- the empirical spectral distribution (ESD), used to compare two graphs.

Comparing graphs whose node sets differ: coefficients in two different eigenbases are not
comparable, so we never compare eigenvectors. We compare the two ESDs with the 1-Wasserstein
distance, which needs no node alignment and is bounded by 2 regardless of graph size.

Eigenvalues are computed densely and only up to ``dense_limit`` nodes (O(n^3) time, O(n^2)
memory: 1,500 nodes is ~18 MB). Larger graphs are reported as skipped, never approximated
silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptoguard.analytics.diffusion import laplacian
from cryptoguard.analytics.graph import WalletGraph

if TYPE_CHECKING:
    import numpy as np
    from numpy.typing import NDArray
    from scipy.sparse import csr_matrix

ZERO_TOLERANCE = 1e-9
DENSE_LIMIT = 1_500


@dataclass(frozen=True)
class StructuralFeatures:
    nodes: int
    edges: int
    counterparties: int
    events: int
    max_degree: int
    spectral_status: str  # "ok" | "empty" | "skipped"
    components: int | None = None
    algebraic_connectivity: float | None = None
    lambda_max: float | None = None
    eigenvalues: tuple[float, ...] = ()


def normalized_spectrum(a: csr_matrix) -> NDArray[np.float64]:
    import numpy as np

    lap = laplacian(a, normalized=True).toarray()
    values = np.linalg.eigvalsh(lap)
    if not np.all(np.isfinite(values)):
        raise FloatingPointError("non-finite eigenvalues")
    # Chung's convention gives isolated nodes eigenvalue 0 as their own component.
    return np.clip(values, 0.0, 2.0)


def _largest_component_gap(a: csr_matrix) -> float | None:
    from scipy.sparse.csgraph import connected_components

    count, labels = connected_components(a, directed=False)
    if a.shape[0] < 2:
        return None
    sizes = [(int((labels == c).sum()), c) for c in range(count)]
    size, label = max(sizes)
    if size < 2:
        return None
    members = (labels == label).nonzero()[0]
    sub = a[members][:, members]
    values = normalized_spectrum(sub)
    return float(values[1])


def structural_features(
    graph: WalletGraph, *, dense_limit: int = DENSE_LIMIT
) -> StructuralFeatures:
    a, nodes = graph.matrix(exclude_wallet=True)
    stats = graph.degree_stats(exclude_wallet=True)
    events = sum(e.count for e in graph.edges.values() if e.kind in ("transfer", "native_transfer"))

    def features(status: str, **spectral: Any) -> StructuralFeatures:
        return StructuralFeatures(
            nodes=len(nodes),
            edges=int(a.nnz // 2),
            counterparties=stats["counterparties"],
            events=events,
            max_degree=stats["max_degree"],
            spectral_status=status,
            **spectral,
        )

    if not nodes:
        return features("empty")
    if len(nodes) > dense_limit:
        return features("skipped")
    values = normalized_spectrum(a)
    return features(
        "ok",
        components=int((values < ZERO_TOLERANCE).sum()),
        algebraic_connectivity=_largest_component_gap(a),
        lambda_max=float(values[-1]),
        eigenvalues=tuple(float(v) for v in values),
    )


def spectral_distance(x: tuple[float, ...], y: tuple[float, ...]) -> float | None:
    """1-Wasserstein distance between two empirical spectral distributions on [0, 2]."""
    if not x or not y:
        return None
    from scipy.stats import wasserstein_distance

    return float(wasserstein_distance(x, y))


def smoothness(a: csr_matrix, u: NDArray[np.float64], *, normalized: bool = True) -> float:
    """``u^T L u`` (for the combinatorial L this is 1/2 sum_ij W_ij (u_i - u_j)^2)."""
    import numpy as np

    lap = laplacian(a, normalized=normalized)
    return float(np.asarray(u) @ (lap @ np.asarray(u)))


def structural_change(prev: StructuralFeatures, cur: StructuralFeatures) -> dict[str, float | None]:
    """Changes between two windows: plain baselines first, then the spectral comparison."""
    return {
        "nodes": float(cur.nodes - prev.nodes),
        "edges": float(cur.edges - prev.edges),
        "counterparties": float(cur.counterparties - prev.counterparties),
        "events": float(cur.events - prev.events),
        "max_degree": float(cur.max_degree - prev.max_degree),
        "spectral_distance": spectral_distance(prev.eigenvalues, cur.eigenvalues),
        "algebraic_connectivity": (
            cur.algebraic_connectivity - prev.algebraic_connectivity
            if cur.algebraic_connectivity is not None and prev.algebraic_connectivity is not None
            else None
        ),
    }

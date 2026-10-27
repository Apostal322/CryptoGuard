"""Mathematical correctness of the propagation primitives on small, solvable graphs."""

from __future__ import annotations

import math

import pytest

np = pytest.importorskip("numpy")
sparse = pytest.importorskip("scipy.sparse")
linalg = pytest.importorskip("scipy.linalg")

from cryptoguard.analytics.diffusion import (  # noqa: E402
    heat_kernel,
    hop_distances,
    laplacian,
    neighbour_aggregation,
    personalized_pagerank,
)


def sym(edges: list[tuple[int, int, float]], n: int):  # type: ignore[no-untyped-def]
    rows = [i for i, _, _ in edges] + [j for _, j, _ in edges]
    cols = [j for _, j, _ in edges] + [i for i, _, _ in edges]
    vals = [w for _, _, w in edges] * 2
    return sparse.csr_matrix((vals, (rows, cols)), shape=(n, n))


PATH4 = sym([(0, 1, 1.0), (1, 2, 1.0), (2, 3, 2.0)], 4)
WITH_ISOLATED = sym([(0, 1, 1.0), (1, 2, 1.0)], 4)  # node 3 isolated
TWO_COMPONENTS = sym([(0, 1, 1.0), (2, 3, 1.0)], 4)


def test_zero_scale_is_identity() -> None:
    u0 = np.array([0.2, 0.0, 0.5, 0.3])
    for normalized in (True, False):
        assert np.allclose(heat_kernel(PATH4, u0, 0.0, normalized=normalized), u0)


def test_two_node_graph_matches_closed_form() -> None:
    # Combinatorial L = [[1,-1],[-1,1]], eigenvalues 0 and 2:
    # exp(-tL) e0 = ((1 + e^{-2t}) / 2, (1 - e^{-2t}) / 2).
    a = sym([(0, 1, 1.0)], 2)
    for t in (0.1, 0.7, 3.0):
        out = heat_kernel(a, np.array([1.0, 0.0]), t, normalized=False)
        e = math.exp(-2 * t)
        assert np.allclose(out, [(1 + e) / 2, (1 - e) / 2], atol=1e-12)


@pytest.mark.parametrize("normalized", [True, False])
@pytest.mark.parametrize("graph", [PATH4, WITH_ISOLATED, TWO_COMPONENTS])
def test_sparse_matches_dense_reference(graph, normalized: bool) -> None:  # type: ignore[no-untyped-def]
    u0 = np.array([1.0, 0.0, 0.0, 0.5])
    lap = laplacian(graph, normalized=normalized).toarray()
    for t in (0.3, 1.0, 4.0):
        assert np.allclose(
            heat_kernel(graph, u0, t, normalized=normalized),
            linalg.expm(-t * lap) @ u0,
            atol=1e-10,
        )


def test_combinatorial_conserves_mass_and_constants() -> None:
    u0 = np.array([1.0, 0.0, 0.0, 0.0])
    for t in (0.5, 2.0, 10.0):
        assert heat_kernel(PATH4, u0, t, normalized=False).sum() == pytest.approx(1.0)
        assert np.allclose(heat_kernel(PATH4, np.ones(4), t, normalized=False), 1.0)


def test_normalized_preserves_sqrt_degree_not_constants() -> None:
    degree = np.asarray(PATH4.sum(axis=1)).ravel()
    v = np.sqrt(degree)
    assert np.allclose(heat_kernel(PATH4, v, 1.5, normalized=True), v)
    assert not np.allclose(heat_kernel(PATH4, np.ones(4), 1.5, normalized=True), 1.0)


def test_isolated_node_keeps_its_signal_and_receives_none() -> None:
    lap = laplacian(WITH_ISOLATED, normalized=True).toarray()
    assert np.allclose(lap[3], 0.0)  # Chung convention
    out = heat_kernel(WITH_ISOLATED, np.array([1.0, 0.0, 0.0, 0.7]), 2.0)
    assert out[3] == pytest.approx(0.7)
    out2 = heat_kernel(WITH_ISOLATED, np.array([1.0, 0.0, 0.0, 0.0]), 2.0)
    assert out2[3] == 0.0


def test_disconnected_component_receives_nothing() -> None:
    out = heat_kernel(TWO_COMPONENTS, np.array([1.0, 0.0, 0.0, 0.0]), 5.0, normalized=False)
    assert out[2] == 0.0
    assert out[3] == 0.0
    assert out[0] + out[1] == pytest.approx(1.0)


def test_nonnegative_inputs_give_nonnegative_outputs() -> None:
    rng = np.random.default_rng(0)
    for _ in range(20):
        n = 12
        dense = rng.random((n, n)) * (rng.random((n, n)) < 0.2)
        a = sparse.csr_matrix(np.triu(dense, 1) + np.triu(dense, 1).T)
        u0 = rng.random(n)
        for normalized in (True, False):
            assert heat_kernel(a, u0, 1.0, normalized=normalized).min() >= 0.0


def test_laplacian_rejects_asymmetric_and_negative() -> None:
    with pytest.raises(ValueError, match="symmetric"):
        laplacian(sparse.csr_matrix(np.array([[0.0, 1.0], [0.0, 0.0]])), normalized=False)
    with pytest.raises(ValueError, match="nonnegative"):
        laplacian(sym([(0, 1, -1.0)], 2), normalized=False)


def test_deterministic() -> None:
    u0 = np.array([0.0, 1.0, 0.0, 0.0])
    first = heat_kernel(PATH4, u0, 1.3)
    assert all(np.array_equal(first, heat_kernel(PATH4, u0, 1.3)) for _ in range(5))


def test_empty_graph() -> None:
    empty = sparse.csr_matrix((0, 0))
    assert heat_kernel(empty, np.zeros(0), 1.0).size == 0
    assert personalized_pagerank(empty, np.zeros(0))[0].size == 0


def test_hop_distances_bounded() -> None:
    assert hop_distances(PATH4, [0], max_hops=6) == [0, 1, 2, 3]
    assert hop_distances(PATH4, [0], max_hops=2) == [0, 1, 2, None]
    assert hop_distances(TWO_COMPONENTS, [0]) == [0, 1, None, None]


def test_neighbour_aggregation_is_degree_normalized() -> None:
    out = neighbour_aggregation(PATH4, np.array([1.0, 0.0, 0.0, 0.0]))
    assert out.tolist() == [0.0, 0.5, 0.0, 0.0]


def test_ppr_sums_to_one_and_respects_direction() -> None:
    # 0 -> 1 -> 2 ; seed at 2. Walking backwards reaches 1 then 0; forwards reaches nothing.
    directed = sparse.csr_matrix(([1.0, 1.0], ([0, 1], [1, 2])), shape=(3, 3))
    u0 = np.array([0.0, 0.0, 1.0])
    back, iterations = personalized_pagerank(directed, u0, reverse=True)
    assert back.sum() == pytest.approx(1.0)
    assert back[1] > back[0] > 0
    assert iterations < 500
    forward, _ = personalized_pagerank(directed, u0, reverse=False)
    assert forward[0] == 0.0
    assert forward[1] == 0.0
    assert forward.sum() == pytest.approx(1.0)

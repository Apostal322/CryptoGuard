"""Graph construction, propagation output, structural features and temporal statistics."""

from __future__ import annotations

import math
import random

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("scipy")

from cryptoguard.analytics.diffusion import Seed, propagate  # noqa: E402
from cryptoguard.analytics.graph import GraphScope, build_graph  # noqa: E402
from cryptoguard.analytics.hawkes import fit, log_likelihood, poisson_log_likelihood  # noqa: E402
from cryptoguard.analytics.observations import BlockRange, ObservationSet  # noqa: E402
from cryptoguard.analytics.spectral import (  # noqa: E402
    normalized_spectrum,
    smoothness,
    spectral_distance,
    structural_change,
    structural_features,
)
from cryptoguard.analytics.temporal import (  # noqa: E402
    activity_bins,
    detect_bursts,
    ewma_scores,
    robust_scores,
)
from cryptoguard.blockchain.erc20 import TransferEvent  # noqa: E402
from cryptoguard.core.address import to_checksum_address  # noqa: E402
from cryptoguard.detectors.poisoning import NativeSend  # noqa: E402


def addr(n: int) -> str:
    return to_checksum_address(f"0x{n:040x}")


WALLET = addr(0xAAAA)
TOKEN = addr(0x70CE)
FAKE = addr(0xFA4E)
_log = iter(range(10**6))


def tr(
    sender: str,
    recipient: str,
    block: int,
    value: int = 1,
    *,
    token: str = TOKEN,
    signer: str | None = None,
    tx: str | None = None,
    log: int | None = None,
) -> TransferEvent:
    i = next(_log)
    return TransferEvent(
        token=token,
        sender=sender,
        recipient=recipient,
        value=value,
        block_number=block,
        block_hash="0x" + "11" * 32,
        transaction_hash=tx or f"0x{i:064x}",
        transaction_index=0,
        log_index=i if log is None else log,
        tx_sender=signer,
    )


def obs(
    transfers: list[TransferEvent],
    cutoff: int = 10_000,
    natives: list[NativeSend] | None = None,
    cover_from: int = 0,
) -> ObservationSet:
    return ObservationSet.build(
        chain_id=1,
        wallet=WALLET,
        cutoff_block=cutoff,
        transfers=transfers,
        native_sends=natives or [],
        transfer_ranges=[BlockRange(cover_from, cutoff)],
        wallet_tx_ranges=[BlockRange(cover_from, cutoff)],
    )


# --- observations and graph ---------------------------------------------------------------


def test_duplicate_observations_count_once_and_cutoff_hides_future() -> None:
    t = tr(WALLET, addr(1), 100, signer=WALLET)
    later = tr(addr(2), WALLET, 600)
    o = obs([t, t, later], cutoff=500)
    assert o.duplicates_dropped == 1
    assert [e.block_number for e in o.transfers] == [100]
    assert o.coverage.transfers == (BlockRange(0, 500),)
    with pytest.raises(ValueError, match="forward"):
        o.at(600)


def test_edges_keep_direction_type_and_evidence() -> None:
    attacker = addr(0xBAD)
    lookalike = addr(0x1001)
    o = obs(
        [
            tr(WALLET, addr(1), 10, signer=WALLET),
            tr(WALLET, lookalike, 20, value=0, signer=attacker),
            tr(lookalike, WALLET, 21, token=FAKE),
        ],
        natives=[NativeSend(addr(3), 5, 30, "0x" + "ab" * 32, 0)],
    )
    g = build_graph(o)
    kinds = {(s, d, k) for s, d, k in g.edges}
    assert (WALLET, lookalike, "transfer") in kinds
    assert (lookalike, WALLET, "transfer") in kinds
    assert (attacker, lookalike, "caused") in kinds
    assert (WALLET, addr(3), "native_transfer") in kinds
    assert (lookalike, FAKE, "token_use") in kinds
    assert g.edges[(WALLET, lookalike, "transfer")].zero_value == 1
    assert "signer" in g.roles[attacker]
    assert "token" in g.roles[FAKE]
    assert g.nodes == sorted(g.nodes)  # deterministic order


def test_directed_matrix_differs_from_projection() -> None:
    g = build_graph(obs([tr(addr(1), addr(2), 5), tr(WALLET, addr(1), 6, signer=WALLET)]))
    directed, nodes = g.matrix(directed=True, exclude_wallet=True)
    sym, _ = g.matrix(directed=False, exclude_wallet=True)
    assert (directed != directed.T).nnz > 0
    assert (sym != sym.T).nnz == 0
    assert WALLET not in nodes


def test_scope_limits_truncate_and_report() -> None:
    g = build_graph(
        obs([tr(addr(i), WALLET, i, token=addr(0x5000 + i)) for i in range(1, 50)]),
        GraphScope(max_nodes=10),
    )
    assert len(g.nodes) == 10
    assert WALLET in g.nodes
    assert g.truncated_nodes == 1 + 49 + 49 - 10  # wallet, 49 senders, 49 tokens
    assert all(s in g.nodes and d in g.nodes for s, d, _ in g.edges)


# --- propagation ----------------------------------------------------------------------------


def _poisoning_graph() -> ObservationSet:
    attacker = addr(0xBAD)
    return obs(
        [
            tr(WALLET, addr(0x1000), 10, value=5, signer=WALLET),  # real payee
            tr(WALLET, addr(0x1001), 20, value=0, signer=attacker),  # lookalike 1 (flagged)
            tr(WALLET, addr(0x2001), 21, value=0, signer=attacker),  # lookalike 2, same signer
            tr(addr(0x3000), WALLET, 30, value=7),  # unrelated sender
        ]
    )


def test_propagation_links_addresses_sharing_a_signer_with_a_seed() -> None:
    g = build_graph(_poisoning_graph())
    result = propagate(g, [Seed(addr(0x1001), "finding CG-POI-001", 20)])
    assert result.status == "ok"
    related = {r.address: r for r in result.related}
    assert related[addr(0xBAD)].hops == 1
    assert related[addr(0x2001)].hops == 2
    assert [s.kind for s in related[addr(0x2001)].path] == ["caused", "caused"]
    # The unrelated sender only shares the (popular) token contract.
    unrelated = related.get(addr(0x3000))
    assert (
        unrelated is None
        or unrelated.scores["heat_tau_1"] < related[addr(0x2001)].scores["heat_tau_1"]
    )
    assert all(v >= 0 for r in result.related for v in r.scores.values())


def test_propagation_without_seeds_in_graph_says_so() -> None:
    g = build_graph(_poisoning_graph())
    assert propagate(g, [Seed(addr(0x9999), "x", 1)]).status == "no_seeds"
    assert propagate(g, [Seed(addr(0x1001), "x", 1)], max_nodes=2).status == "skipped"


def test_wallet_node_would_connect_everything_in_two_hops() -> None:
    # Why the wallet is excluded: with it, every counterparty is <= 2 hops from every other.
    from cryptoguard.analytics.diffusion import hop_distances

    g = build_graph(_poisoning_graph())
    with_wallet, nodes = g.matrix(exclude_wallet=False, weights={"transfer": 1.0})
    d = hop_distances(with_wallet, [nodes.index(addr(0x1001))])
    assert d[nodes.index(addr(0x3000))] == 2


# --- spectral -------------------------------------------------------------------------------


def test_spectrum_of_known_graphs() -> None:
    from scipy.sparse import csr_matrix

    # Complete graph K4: normalized eigenvalues 0 and 4/3 (x3).
    k4 = csr_matrix(np.ones((4, 4)) - np.eye(4))
    assert np.allclose(normalized_spectrum(k4), [0, 4 / 3, 4 / 3, 4 / 3])
    # Path on 3 nodes (bipartite): 0, 1, 2.
    p3 = csr_matrix(np.array([[0, 1, 0], [1, 0, 1], [0, 1, 0]], dtype=float))
    assert np.allclose(normalized_spectrum(p3), [0, 1, 2])
    # Relabelling nodes does not change the spectrum.
    perm = [2, 0, 1]
    assert np.allclose(normalized_spectrum(p3[perm][:, perm]), normalized_spectrum(p3))


def test_structural_features_handle_degenerate_graphs() -> None:
    empty = structural_features(build_graph(obs([])))
    assert empty.spectral_status == "empty"
    assert empty.nodes == 0
    one = structural_features(build_graph(obs([tr(addr(1), WALLET, 5)])))
    assert one.spectral_status == "ok"
    assert one.components == 1
    big = structural_features(
        build_graph(obs([tr(addr(i), WALLET, i) for i in range(1, 30)])), dense_limit=5
    )
    assert big.spectral_status == "skipped"
    assert big.nodes > 5


def test_spectral_distance_is_size_normalized_and_bounded() -> None:
    a = (0.0, 1.0, 1.0, 2.0)
    assert spectral_distance(a, a) == 0.0
    assert spectral_distance(a, a * 10) == pytest.approx(0.0)  # same distribution, 10x nodes
    assert 0 <= (spectral_distance((0.0,), (2.0,)) or 0) <= 2
    assert spectral_distance((), a) is None


def test_smoothness_identity() -> None:
    from scipy.sparse import csr_matrix

    w = csr_matrix(np.array([[0, 2, 0], [2, 0, 1], [0, 1, 0]], dtype=float))
    u = np.array([1.0, 0.0, 3.0])
    expected = 0.5 * sum(w[i, j] * (u[i] - u[j]) ** 2 for i in range(3) for j in range(3))
    assert smoothness(w, u, normalized=False) == pytest.approx(expected)


def test_structural_change_reports_baselines_and_spectral() -> None:
    small = structural_features(build_graph(obs([tr(addr(1), WALLET, 5)])))
    larger = structural_features(build_graph(obs([tr(addr(i), WALLET, i) for i in range(1, 6)])))
    change = structural_change(small, larger)
    assert change["counterparties"] == 4
    assert change["spectral_distance"] is not None


# --- temporal -------------------------------------------------------------------------------


def _regular(n_bins: int, per_bin: int, bin_blocks: int = 100) -> list[TransferEvent]:
    return [
        tr(addr(1 + k % 3), WALLET, b * bin_blocks + k)
        for b in range(n_bins)
        for k in range(per_bin)
    ]


def test_constant_rate_produces_no_anomaly() -> None:
    o = obs(_regular(40, 2), cutoff=3_999)
    found, status = detect_bursts(o, bin_blocks=100, series=("transfers",))
    assert found == []
    assert status["scored"] > 0


def test_artificial_burst_is_flagged_with_supporting_transactions() -> None:
    events = _regular(40, 1)
    burst = [tr(addr(0x500 + i), WALLET, 3_950 + i, value=0) for i in range(8)]
    o = obs(events + burst, cutoff=3_999)
    found, _ = detect_bursts(o, bin_blocks=100)
    series = {a.series for a in found}
    assert {"zero_value", "unsolicited_incoming", "new_counterparties"} <= series
    zero = next(a for a in found if a.series == "zero_value")
    assert zero.from_block == 3_900
    assert zero.observed == 8
    assert len(zero.transactions) == 8


def test_short_history_is_reported_not_scored() -> None:
    o = obs(_regular(5, 1), cutoff=499)
    found, status = detect_bursts(o, bin_blocks=100)
    assert found == []
    assert status["scored"] == 0
    assert status["insufficient_history"] > 0


def test_uncovered_bins_are_missing_not_zero() -> None:
    events = _regular(40, 3)
    o = ObservationSet.build(
        chain_id=1,
        wallet=WALLET,
        cutoff_block=3_999,
        transfers=events,
        native_sends=[],
        transfer_ranges=[BlockRange(0, 1_999), BlockRange(3_000, 3_999)],
        wallet_tx_ranges=[BlockRange(0, 3_999)],
    )
    bins = activity_bins(o, bin_blocks=100)
    gap = [b for b in bins if 2_000 <= b.from_block < 3_000]
    assert gap
    assert not any(b.observed for b in gap)
    scores = robust_scores(bins, "transfers")
    assert all(s.status == "missing" for s in scores if 2_000 <= s.from_block < 3_000)
    # The missing stretch does not drag the baseline down: the bins after it are not anomalous.
    assert all((s.score or 0) < 1 for s in scores if s.status == "scored")


def test_out_of_order_ingestion_gives_the_same_bins() -> None:
    events = _regular(20, 2)
    shuffled = events[:]
    random.Random(1).shuffle(shuffled)
    a = activity_bins(obs(events, cutoff=1_999), bin_blocks=100)
    b = activity_bins(obs(shuffled, cutoff=1_999), bin_blocks=100)
    assert [x.counts for x in a] == [x.counts for x in b]


def test_baseline_uses_only_past_bins() -> None:
    events = _regular(30, 1) + [tr(addr(9), WALLET, 2_950 + i) for i in range(20)]
    full = robust_scores(activity_bins(obs(events, cutoff=2_999), bin_blocks=100), "transfers")
    early = robust_scores(activity_bins(obs(events, cutoff=2_899), bin_blocks=100), "transfers")
    # The burst in the last bin cannot change any earlier bin's score.
    assert [s.score for s in full[:-1]][-len(early) :] == [s.score for s in early]


def test_ewma_baseline_shapes() -> None:
    bins = activity_bins(obs(_regular(30, 1), cutoff=2_999), bin_blocks=100)
    out = ewma_scores(bins, "transfers")
    assert len(out) == len(bins)
    assert out[0] is None
    assert out[-1] is not None


# --- Hawkes --------------------------------------------------------------------------------


def test_hawkes_likelihood_reduces_to_poisson_without_excitation() -> None:
    times = [1.0, 5.0, 9.0]
    assert log_likelihood(times, 10.0, 0.3, 0.0, 1.0) == pytest.approx(
        poisson_log_likelihood(3, 10.0, rate=0.3)
    )
    assert log_likelihood(times, 10.0, -1.0, 0.1, 1.0) == -math.inf


def _simulate(mu: float, alpha: float, beta: float, horizon: float, seed: int) -> list[float]:
    rng = random.Random(seed)  # Ogata thinning
    t, events = 0.0, []
    while True:
        bound = mu + sum(alpha * math.exp(-beta * (t - s)) for s in events) + alpha
        t += rng.expovariate(bound)
        if t >= horizon:
            return events
        lam = mu + sum(alpha * math.exp(-beta * (t - s)) for s in events)
        if rng.random() * bound <= lam:
            events.append(t)


def test_hawkes_fit_recovers_parameters_and_respects_stationarity() -> None:
    times = _simulate(0.5, 0.6, 1.2, 600.0, seed=3)
    f = fit(times, 600.0)
    assert f.branching_ratio < 1
    assert 0.3 < f.branching_ratio < 0.7  # true value 0.5
    assert f.log_likelihood > poisson_log_likelihood(len(times), 600.0)
    with pytest.raises(ValueError, match="3 event times"):
        fit([1.0], 10.0)

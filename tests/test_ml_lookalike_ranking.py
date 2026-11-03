"""Lookalike prioritization (Phase 12.1): eligibility, point-in-time features, typed graph
edges, missingness, metrics and inference. Synthetic rows only."""

from __future__ import annotations

import itertools
import statistics
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import lookalike_ranking as lr
from cryptoguard.ml.tsuchiya_archive import COUNTERFEIT, INTENDED, PAYOFF, TINY, ZERO

V = "0x" + "a" * 40  # victim
R = "0x1234" + "0" * 32 + "abcd"  # the recipient the victim pays
L1 = "0x1234" + "f" * 32 + "abcd"  # imitates R (4 + 4)
L2 = "0x12" + "e" * 36 + "cd"  # weak (2 + 2): fails the detector's thresholds
L3 = "0x1234" + "e" * 31 + "babcd"  # imitates R (4 + 5)
OTHER = "0x" + "b" * 40  # another victim
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE = "0x" + "c" * 40

_line = itertools.count(1)


def row(
    block: int,
    sender: str,
    receiver: str,
    flags: int,
    *,
    tx: str | None = None,
    token: str = USDT,
    siv: bool | None = None,
    intended: str | None = None,
) -> lr.Row:
    n = next(_line)
    return lr.Row(
        n, block, tx or f"0x{n:064x}", token, sender, receiver, siv, None, flags, intended
    )


def base_rows() -> list[lr.Row]:
    return [
        row(100, V, R, INTENDED, siv=True),
        row(200, V, R, INTENDED, siv=True),
        row(210, L1, V, ZERO, siv=False, intended=R),
        row(220, L2, V, TINY, siv=False, intended=R),
        row(230, L1, V, ZERO, siv=False, intended=R),
        row(300, V, L1, PAYOFF, siv=True),
    ]


def episode(rows: list[lr.Row] | None = None) -> lr.Episode:
    ep = lr.episode_from_rows(V, rows if rows is not None else base_rows())
    assert isinstance(ep, lr.Episode), ep
    return ep


# --- eligibility -------------------------------------------------------------------------


def test_episode_uses_first_payoff_and_excludes_same_block() -> None:
    rows = [*base_rows(), row(300, L3, V, ZERO, siv=False), row(500, V, L2, PAYOFF, siv=True)]
    ep = episode(rows)
    assert (ep.payoff_block, ep.paid) == (300, L1)
    assert ep.candidates == (L1, L2)  # L3 planted in the payoff block: order unknown
    assert ep.same_block_rows == 1
    assert {r.receiver for r in ep.victim_out} == {R}


@pytest.mark.parametrize(
    ("rows", "reason"),
    [
        ([row(210, L1, V, ZERO, siv=False)], "no_confirmed_payoff_row"),
        ([row(210, L1, V, ZERO, siv=False), row(300, V, L1, PAYOFF, siv=True)], "single_candidate"),
        (
            [row(210, L2, V, ZERO, siv=False), row(300, V, L1, PAYOFF, siv=True)],
            "paid_lookalike_planted_no_earlier_transfer",
        ),
        (
            [
                row(210, L1, V, ZERO),
                row(220, L2, V, ZERO),
                row(300, V, L1, PAYOFF),
                row(300, V, L2, PAYOFF),
            ],
            "several_lookalikes_paid_in_payoff_block",
        ),
    ],
)
def test_ineligible_reasons(rows: list[lr.Row], reason: str) -> None:
    assert lr.episode_from_rows(V, rows) == reason


def test_spoofed_transfer_from_counts_as_planting() -> None:
    rows = [
        row(100, V, R, INTENDED),
        row(210, V, L1, ZERO),
        row(220, L2, V, ZERO),
        row(300, V, L1, PAYOFF),
    ]
    assert episode(rows).candidates == (L1, L2)


# --- features ------------------------------------------------------------------------------


def test_feature_values_and_missingness() -> None:
    f = lr.candidate_features(episode(), lr.View(), None, None)
    assert f is not None
    assert f[L1]["B0"] == 8.0
    assert f[L2]["B0"] == 0.0  # observed, no reference: zero
    assert f[L1]["B3"] == 2.0
    assert f[L2]["B3"] == 0.0
    assert f[L1]["T3"] == 1.0
    assert f[L2]["T3"] is None  # no reference: not observed
    assert f[L1]["B1"] == 8.0
    assert f[L2]["B1"] == 4.0
    assert f[L1]["B2"] == 1.0
    assert f[L2]["B2"] == 3.0
    assert f[L1]["T0"] == -(299 - 230)
    assert f[L1]["T1"] == 2.0
    assert f[L1]["G1"] is None
    assert f[L1]["NC"] is None  # no graph, no token index


def test_missing_history_is_not_zero_and_methods_abstain() -> None:
    rows = [r for r in base_rows() if not r.flags & INTENDED]
    f = lr.candidate_features(episode(rows), lr.View(), None, None)
    assert f is not None
    assert all(v["B0"] is None and v["B3"] is None for v in f.values())
    assert lr.single("B0")(f) is None
    assert lr.top1(lr.single("B0")(f), L1, 2) == 0.5  # abstention scores exactly at random


def test_future_rows_do_not_change_features() -> None:
    ep = episode()
    graph = lr.memory_graph([row(150, L1, OTHER, ZERO, siv=False)])
    before = lr.candidate_features(ep, lr.View(), graph, lr.TokenIndex.build([ep]))
    future = [
        row(400, L2, V, ZERO, siv=False),
        row(301, V, R, INTENDED, siv=True),
        row(350, L1, OTHER, ZERO, siv=False),
        row(360, OTHER, L1, PAYOFF, siv=True),
    ]
    ep2 = episode([*base_rows(), *future])
    graph2 = lr.memory_graph([row(150, L1, OTHER, ZERO, siv=False), *future])
    after = lr.candidate_features(ep2, lr.View(), graph2, lr.TokenIndex.build([ep2]))
    assert before == after


def test_lag_moves_cutoff_and_can_make_episode_unevaluable() -> None:
    ep = episode()
    assert lr.candidate_features(ep, lr.View(lag=85), None, None) is None  # c=215: only L1
    f = lr.candidate_features(ep, lr.View(lag=75), None, None)  # c=225
    assert f is not None
    assert f[L1]["T1"] == 1.0


def test_victim_drop_is_seeded_and_deterministic() -> None:
    ep = episode()
    a = lr.candidate_features(ep, lr.View(victim_drop=0.5, seed=3), None, None)
    b = lr.candidate_features(ep, lr.View(victim_drop=0.5, seed=3), None, None)
    assert a == b
    full = lr.candidate_features(ep, lr.View(victim_drop=1.0), None, None)
    assert full is not None
    assert full[L1]["B0"] is None


# --- typed graph -----------------------------------------------------------------------


def test_graph_counts_reuse_payoffs_and_batches_before_cutoff_only() -> None:
    tx = "0x" + "9" * 64
    rows = [
        row(150, L1, OTHER, ZERO, siv=False),
        row(150, L1, OTHER, ZERO, siv=False),  # duplicate edge, other line
        row(160, OTHER, L1, PAYOFF, siv=True),
        row(210, L1, V, ZERO, tx=tx, siv=False),
        row(210, L3, "0x" + "d" * 40, ZERO, tx=tx, siv=False),
        row(900, L1, "0x" + "e" * 40, ZERO, siv=False),  # after the cutoff
        row(155, L1, "0x" + "f" * 40, ZERO, siv=None),  # victim side unknown: skipped
    ]
    g = lr.memory_graph(rows)
    assert g.prior_victims(L1, 299) == {OTHER, V}
    assert g.prior_payers(L1, 299) == {OTHER}
    assert g.tx_victims(tx, 299) == {V, "0x" + "d" * 40}
    assert g.prior_victims(L1, 149) == set()
    eprows = [
        *base_rows()[:2],
        row(210, L1, V, ZERO, tx=tx, siv=False),
        row(220, L2, V, TINY, siv=False),
        row(300, V, L1, PAYOFF, siv=True),
    ]
    f = lr.candidate_features(episode(eprows), lr.View(), g, None)
    assert f is not None
    assert f[L1]["G1"] == 1.0
    assert f[L1]["G2"] == 1.0
    assert f[L1]["G3"] == 2.0
    assert f[L2]["G1"] == 0.0
    assert f[L2]["G3"] is None


def test_shared_public_token_links_nothing() -> None:
    rows = [
        row(150, L1, OTHER, TINY, siv=False, token=USDT),
        row(150, L2, "0x" + "d" * 40, TINY, siv=False, token=USDT),
    ]
    g = lr.memory_graph(rows)
    assert g.prior_victims(L2, 299) == {"0x" + "d" * 40}  # USDT is not a node
    assert g.prior_victims(L1, 299) == {OTHER}


def test_self_loops_and_cycles_are_safe() -> None:
    rows = [
        row(10, L1, L1, ZERO, siv=True),
        row(11, L1, L3, ZERO, siv=False),
        row(12, L3, L1, ZERO, siv=False),
    ]
    g = lr.memory_graph(rows)
    assert g.prior_victims(L1, 100) == {L3}
    assert g.prior_victims(L3, 100) == {L1}
    assert g.prior_victims("0x" + "7" * 40, 100) == set()  # isolated node


def test_protected_wallet_rows_never_become_graph_edges() -> None:
    tx = "0x" + "9" * 64
    rows = [
        row(150, L1, OTHER, ZERO, tx=tx, siv=False),
        row(150, L1, "0x" + "d" * 40, ZERO, tx=tx, siv=False),
        row(160, OTHER, L1, PAYOFF, siv=True),
    ]
    g = lr.memory_graph(rows, exclude=frozenset({OTHER}))
    assert g.prior_victims(L1, 299) == {"0x" + "d" * 40}
    assert g.prior_payers(L1, 299) == set()
    assert g.tx_victims(tx, 299) == {"0x" + "d" * 40}


def test_protected_overlap_is_direct_or_through_a_linkage_group() -> None:
    e1 = episode()  # candidates L1, L2
    e2 = episode(
        [
            row(100, V, R, INTENDED, siv=True),
            row(210, L1, V, ZERO, siv=False, intended=R),  # shares L1 with e1
            row(220, L3, V, ZERO, siv=False, intended=R),
            row(300, V, L1, PAYOFF, siv=True),
        ]
    )
    e3 = episode(
        [
            row(100, V, R, INTENDED, siv=True),
            row(210, "0x" + "5" * 40, V, ZERO, siv=False),
            row(220, "0x" + "6" * 40, V, ZERO, siv=False),
            row(300, V, "0x" + "5" * 40, PAYOFF, siv=True),
        ]
    )
    assert lr.protected_overlap([e1, e2, e3], frozenset({L2}), frozenset()) == [
        True,
        True,  # campaign overlap: linked to e1 through L1
        False,
    ]
    tx = e3.plantings[0].tx
    assert lr.protected_overlap([e1, e2, e3], frozenset(), frozenset({tx})) == [
        False,
        False,
        True,
    ]


def test_preloaded_graph_equals_the_lazy_index_on_random_rows() -> None:
    import random

    rng = random.Random(7)
    addrs = [f"0x{i:040x}" for i in range(1, 13)]
    txs = [f"0x{i:064x}" for i in range(1, 9)]
    flags = (ZERO, TINY, COUNTERFEIT, PAYOFF, INTENDED, ZERO | PAYOFF)
    rows = [
        row(
            rng.randrange(100, 400),
            rng.choice(addrs),
            rng.choice(addrs),
            rng.choice(flags),
            tx=rng.choice(txs),
            siv=rng.choice((True, False, None)),
        )
        for _ in range(600)
    ]
    rows += rows[:20]  # exact duplicates
    exclude = frozenset(addrs[:2])
    edges = lr.preload_graph(rows, addrs, txs, exclude)
    for keep_row, keep_edge in (
        (None, None),
        (lr.graph_keep(0.5, 3), lr.graph_keep_edge(0.5, 3)),
        (lambda r: r.block <= 250, lambda b, _l: b <= 250),
    ):
        by_addr: dict[str, list[lr.Row]] = {}
        by_tx: dict[str, list[lr.Row]] = {}
        for r in rows:
            for a in {r.sender, r.receiver}:
                by_addr.setdefault(a, []).append(r)
            by_tx.setdefault(r.tx, []).append(r)
        lazy = lr.GraphIndex(
            lambda a, m=by_addr: m.get(a, []),
            lambda t, m=by_tx: m.get(t, []),
            keep=keep_row,
            exclude=exclude,
        )
        pre = edges.index(keep_edge)
        for cutoff in (150, 300, 399):
            for since in (None, 200):
                for a in addrs:
                    assert pre.prior_victims(a, cutoff, since) == lazy.prior_victims(
                        a, cutoff, since
                    )
                    assert pre.prior_payers(a, cutoff, since) == lazy.prior_payers(a, cutoff, since)
            for tx in txs:
                assert pre.tx_victims(tx, cutoff) == lazy.tx_victims(tx, cutoff)
    with pytest.raises(KeyError):
        edges.index().prior_victims("0x" + "9" * 40, 300)


def test_token_index_negative_control() -> None:
    e1 = episode()
    e2 = replace(e1, victim=OTHER)
    tokens = lr.TokenIndex.build([e1, e2])
    assert tokens.victims(USDT, 299, exclude=V) == 1
    assert tokens.victims(FAKE, 299, exclude=V) == 0


# --- methods and metrics ---------------------------------------------------------------


def _brute_mrr(scores: dict[str, float], paid: str) -> float:
    vals = []
    for perm in itertools.permutations(scores):
        order = sorted(perm, key=lambda c: -scores[c])  # stable: ties in random order
        vals.append(1 / (order.index(paid) + 1))
    return statistics.fmean(vals)


@pytest.mark.parametrize(
    "scores",
    [
        {"a": 1.0, "b": 1.0, "c": 0.0},
        {"a": 0.0, "b": 2.0, "c": 2.0, "d": 2.0},
        {"a": 3.0, "b": 2.0, "c": 1.0},
    ],
)
def test_mrr_equals_brute_force_tie_average(scores: dict[str, float]) -> None:
    for paid in scores:
        assert lr.mrr(scores, paid, len(scores)) == pytest.approx(_brute_mrr(scores, paid))


def test_top1_ties_and_random() -> None:
    assert lr.top1({"a": 1, "b": 1, "c": 0}, "a", 3) == 0.5
    assert lr.top1({"a": 1, "b": 1, "c": 0}, "c", 3) == 0.0
    assert lr.top1(None, "a", 4) == 0.25
    assert lr.mrr(None, "a", 3) == pytest.approx((1 + 1 / 2 + 1 / 3) / 3)


def test_normalized_ranks_and_hybrid_skip_abstaining_components() -> None:
    assert lr.normalized_ranks({"a": 1, "b": 1, "c": 5}) == {"a": 0.25, "b": 0.25, "c": 1.0}
    feats: dict[str, dict[str, lr.Value]] = {"x": {"A": 1.0, "B": None}, "y": {"A": 2.0, "B": 0.0}}
    assert lr.hybrid(("A", "B"))(feats) == {"x": 0.0, "y": 1.0}
    assert lr.hybrid(("B",))(feats) is None


# --- groups, split and inference -------------------------------------------------------


def _eps(n: int) -> list[lr.Episode]:
    out = []
    for i in range(n):
        v = f"0x{i + 1:040x}"
        a, b = f"0x{1000 + i:040x}", f"0x{2000 + i // 2:040x}"  # b shared by pairs
        rows = [
            row(10 * i + 1, a, v, ZERO),
            row(10 * i + 2, b, v, ZERO),
            row(10 * i + 5, v, a, PAYOFF),
        ]
        ep = lr.episode_from_rows(v, rows)
        assert isinstance(ep, lr.Episode)
        out.append(ep)
    return out


def test_groups_link_shared_lookalikes_and_split_keeps_groups_whole() -> None:
    eps = _eps(10)
    g = lr.groups(eps)
    assert len(set(g)) == 5
    assert all(g[2 * i] == g[2 * i + 1] for i in range(5))
    split = lr.temporal_split(eps, g, test_share=0.4)
    assert split.count("test") == 4
    assert split[-1] == "test"
    assert split[0] == "dev"
    for grp in set(g):
        assert len({s for s, x in zip(split, g, strict=True) if x == grp}) == 1


def test_paired_is_deterministic_and_null_for_zero_differences() -> None:
    d, g = [0.0] * 20, list(range(20))
    out = lr.paired(d, g, n_perm=500, n_boot=200)
    assert out["mean"] == 0.0
    assert out["p"] == 1.0
    assert out["groups"] == 20
    d2 = [1.0] * 30
    a = lr.paired(d2, list(range(30)), n_perm=999, n_boot=200)
    assert a == lr.paired(d2, list(range(30)), n_perm=999, n_boot=200)
    assert a["p"] < 0.01
    assert a["ci95"] == [1.0, 1.0]


def test_paired_counts_groups_not_episodes() -> None:
    out = lr.paired([1.0, 1.0, 1.0, -1.0], [0, 0, 0, 1], n_perm=500, n_boot=200)
    assert out["groups"] == 2
    assert out["episodes"] == 4
    assert out["p"] > 0.2  # two clusters cannot be significant


def test_holm_and_decision() -> None:
    adj = lr.holm({"a": 0.01, "b": 0.02, "c": 0.04})
    assert adj == pytest.approx({"a": 0.03, "b": 0.04, "c": 0.04})
    assert lr.decision({"mean": 0.1, "ci95": [0.05, 0.15]}, 0.01) == "supported"
    assert lr.decision({"mean": -0.1, "ci95": [-0.15, -0.05]}, 0.01) == "reversed"
    assert lr.decision({"mean": 0.01, "ci95": [-0.02, 0.03]}, 0.5) == "null"
    assert lr.decision({"mean": 0.03, "ci95": [-0.02, 0.09]}, 0.2) == "inconclusive"


def test_counterfeit_flag_wins_over_tiny_in_semantics() -> None:
    rows = [
        row(100, V, R, INTENDED),
        row(210, L1, V, TINY | COUNTERFEIT, token=FAKE),
        row(220, L2, V, TINY),
        row(300, V, L1, PAYOFF),
    ]
    f = lr.candidate_features(episode(rows), lr.View(), None, None)
    assert f is not None
    assert f[L1]["B2"] == 2.0
    assert f[L2]["B2"] == 3.0


# --- end-to-end smoke run on a synthetic data directory -------------------------------


def _synthetic_dir(tmp: Path, n: int = 30) -> Path:
    import json
    import sqlite3

    from cryptoguard.ml.tsuchiya_archive import _DDL, build_targets

    d = tmp / "poisoning"
    (d / lr.RESEARCH_DIR).mkdir(parents=True)
    rows: list[tuple[Any, ...]] = []
    victims, packets = [], []
    lookalikes: set[str] = set()
    planting_txs: set[str] = set()
    line = 0

    def add(
        block: int,
        tx: str,
        sender: str,
        receiver: str,
        siv: bool,
        flags: int,
        intended: str | None,
        value: float = 0.0,
    ) -> None:
        nonlocal line
        line += 1
        rows.append(
            (
                line,
                block,
                tx,
                USDT,
                sender,
                receiver,
                int(siv),
                value,
                0.0,
                flags,
                intended,
                None,
                None,
            )
        )

    for i in range(n):
        v = f"0x{i + 1:040x}"
        ref = f"0x{0xABC000 + i:06x}" + "0" * 30 + f"{i:04x}"
        good = ref[:8] + "f" * 30 + ref[-4:]
        rival = ref[:5] + "e" * 33 + ref[-4:]
        b = 1_000_000 + 10_000 * i
        victims.append(v)
        add(b, f"0x{line:064x}", v, ref, True, INTENDED, None, 5e9)
        # the paid lookalike plants later in half the episodes, earlier in the rest
        late, early = (good, rival) if i % 2 else (rival, good)
        lookalikes |= {good, rival}
        planting_txs |= {f"0x{line:064x}", f"0x{line + 1:064x}"}
        add(b + 100, f"0x{line:064x}", early, v, False, ZERO, ref)
        add(b + 200, f"0x{line:064x}", late, v, False, TINY, ref, 1000.0)
        add(b + 300, f"0x{line:064x}", v, good, True, PAYOFF, None, 4e9)
        packets.append(
            {
                "victim": v,
                "observation_block": b + 200,
                "planting_tx": f"0x{line - 2:064x}",
                "lookalike": late,
                "subtype": "dust",
            }
        )
    manifest = build_targets({"candidate_lookalikes": lookalikes, "planting_txs": planting_txs})
    (d / lr.RESEARCH_DIR / "graph_context_targets.json").write_text(json.dumps(manifest))
    summary = json.dumps({"target_manifest_sha256": manifest["sha256"]})
    for name in ("archive_subset.sqlite", f"{lr.RESEARCH_DIR}/{lr.GRAPH_DB}"):
        con = sqlite3.connect(d / name)
        con.executescript(_DDL)
        con.executemany("insert into transfers values (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        con.execute("insert into meta values ('summary', ?)", (summary,))
        con.commit()
        con.close()
    groups = {"payoff_victims": victims, "incident_victims": [], "payoff_lookalikes": []}
    (d / "archive_targets.json").write_text(json.dumps({"version": 1, "groups": groups}))
    (d / "review_packets_payoff_linked.jsonl").write_text(
        "".join(json.dumps(p) + "\n" for p in packets)
    )
    return d


def test_study_runs_end_to_end_on_synthetic_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptoguard.ml import lookalike_study as ls

    d = _synthetic_dir(tmp_path)
    protected = "0x" + f"{1:040x}"
    monkeypatch.setattr(lr, "protected_wallets", lambda _d: frozenset({protected}))
    # Episode i = 3 (victim 4): its paid lookalike is a frozen item's address under review.
    v3 = 3
    ref3 = f"0x{0xABC000 + v3:06x}" + "0" * 30 + f"{v3:04x}"
    under_review = ref3[:8] + "f" * 30 + ref3[-4:]
    monkeypatch.setattr(
        lr, "protected_entities", lambda _d: (frozenset({protected, under_review}), frozenset())
    )
    report = ls.run(d)
    assert report["coverage_symmetry"]["symmetric"] is True
    assert report["coverage_symmetry"]["paid"]["candidates"] == 29
    assert report["coverage_symmetry"]["rival"]["old_subset_targeted_share"] == 0.0
    assert report["protected_overlap"]["episodes_linked"] == 1
    assert set(report["primary_without_protected_overlap"]) == set(ls.PRIMARY)
    assert report["episodes"] == 29
    assert report["exclusions"] == {"protected_review_wallet": 1}
    assert report["controls"]["future_rows_cut_graph_mismatches"].startswith("0/")
    assert set(report["primary"]) == set(ls.PRIMARY)
    for v in report["primary"].values():
        assert v["decision"] in {"supported", "reversed", "null", "inconclusive"}
        assert 0 < v["p_holm"] <= 1
    assert report["split"]["test"]["episodes"] >= 0.4 * 29
    # The paid lookalike is always the most similar one: B1 must find it every time.
    assert report["methods"]["B1"]["all"]["top1"] == 1.0
    # Recency is right in exactly the episodes where the paid one planted last: odd i in
    # 1..29 (victim 0 is protected), 15 of 29.
    assert report["methods"]["T0"]["all"]["top1"] == pytest.approx(15 / 29, abs=1e-4)
    assert report["methods"]["random"]["all"]["top1"] == 0.5
    assert report["resources"]["rpc_requests"] == 0
    assert report["resources"]["graph_mode"] == "preloaded"
    # Exactness: the Phase 12.1 lazy lookups give the same report.
    lazy = ls.run(d, lazy_graph=True)
    assert ls.comparable(lazy) == ls.comparable(report)
    gap = report["recency_gap_posthoc"]
    assert gap["paid_gap_blocks"]["max"] == 199.0  # (b + 299) - (b + 100), by design
    assert gap["paid_gap_over_30d"]["episodes"] == 0


def test_recency_validation_runs_end_to_end_on_synthetic_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptoguard.ml import recency_validation as rv

    d = _synthetic_dir(tmp_path)
    protected = "0x" + f"{1:040x}"
    monkeypatch.setattr(lr, "protected_wallets", lambda _d: frozenset({protected}))
    monkeypatch.setattr(lr, "protected_entities", lambda _d: (frozenset({protected}), frozenset()))
    report = rv.run(d)
    assert report["episodes"] == 29
    # Both lookalikes plant after the victim's intended transfer, so the symmetric rule keeps
    # every candidate and H1 sees exactly the full sets.
    assert report["manipulation_check"]["paid"]["SR_any_true_share"] == 1.0
    h1 = report["H1_symmetric_confirmation"]
    assert h1["episodes"] == 29
    assert h1["T0_top1"] == report["R_all"]["T0_top1"]
    assert h1["attenuation"] == 0.0
    assert h1["decision"] in {"survives", "explained_or_null", "inconclusive"}
    # Exact duplicates and same-block reordering cannot move recency.
    e11 = report["E11_history_perturbations"]
    assert e11["duplicate_rows"]["T0_top1"] == e11["primary_T0_top1"]
    assert e11["reorder_within_block"]["T0_top1"] == e11["primary_T0_top1"]
    assert report["E1_within_episode_permutation_top1"] == pytest.approx(0.5, abs=0.05)
    bg = report["E14_background"]
    assert bg["windows_warning_set_preserved"] == bg["windows"]
    assert report["resources"]["rpc_requests"] == 0

"""Phase 11.5: candidate-generator audit, hard-negative categories, contamination screen,
typed grouping, matching and the evaluation contract.

Synthetic fixtures only. Nothing here measures fraud-detection accuracy.
"""

from __future__ import annotations

import random

import pytest

from cryptoguard.ml import candidates as cand
from cryptoguard.ml import contamination as ct
from cryptoguard.ml import evaluation as ev
from cryptoguard.ml import grouping as gp
from cryptoguard.ml import hard_negatives as hn
from cryptoguard.ml.events import PoisoningEvent
from cryptoguard.ml.history import events_from_fixture
from cryptoguard.ml.matching import MatchingError, Unit, cem, smd
from tests.unit.test_ml_poisoning import (
    FAKE,
    FRIEND,
    LOOKALIKE,
    STRANGER,
    USDT,
    WALLET,
    eth_tx,
    fixture,
    transfer,
)

ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"  # on the public-infrastructure list
OTHER = "0x" + "44" * 20

# --- generator audit -------------------------------------------------------------------------


def methods_at(fx, block: int) -> set[str]:
    return {m for c in cand.generate(fx) if c.event.planting_block == block for m in c.methods}


def test_legitimate_looking_similarity_is_a_candidate_not_a_label() -> None:
    """A genuine-token, ordinary-value transfer from a lookalike fires only lookalike_in:
    the generator flags shape, not intent."""
    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 100, tx_sender=WALLET, idx=1),
            transfer(900, LOOKALIKE, WALLET, 5_000_000_000, idx=1),
        ],
        [],
    )
    assert methods_at(fx, 900) == {"lookalike_in"}


def test_repeated_and_unknown_counterparties() -> None:
    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 100, tx_sender=WALLET, idx=1),
            transfer(600, FRIEND, WALLET, 5_000_000_000, idx=1),  # the real friend
            transfer(700, STRANGER, WALLET, 5_000_000_000, idx=1),
        ],
        [],
    )
    assert methods_at(fx, 600) == set()  # exact earlier counterparty: not a lookalike
    assert methods_at(fx, 700) == set()  # unrelated stranger: no rule fires


def test_unverified_signer_is_not_a_chosen_counterparty() -> None:
    """candidates/2: an outgoing transfer with an unknown signer (possibly a spoof) does
    not become the 'imitated' counterparty."""
    fx = fixture(
        [
            transfer(500, WALLET, LOOKALIKE, 0, tx_sender=None, idx=1),
            transfer(900, FRIEND, WALLET, 5_000_000_000, idx=1),
        ],
        [],
        transfer_scan_complete=False,
    )
    assert methods_at(fx, 900) == set()
    signed = fixture(
        [
            transfer(500, WALLET, LOOKALIKE, 1, tx_sender=WALLET, idx=1),
            transfer(900, FRIEND, WALLET, 5_000_000_000, idx=1),
        ],
        [],
    )
    assert methods_at(signed, 900) == {"lookalike_in"}


def test_router_pull_is_a_spoofed_out_candidate() -> None:
    """A legitimate transferFrom by an approved spender looks like a spoofed transfer: the
    rule's documented breadth (category E), never a label."""
    fx = fixture([transfer(800, WALLET, OTHER, 10**9, tx_sender=ROUTER, idx=1)], [])
    assert methods_at(fx, 800) == {"spoofed_out"}


def test_duplicate_logs_in_one_transaction_get_distinct_identities() -> None:
    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 1, tx_sender=WALLET, idx=1),
            transfer(900, LOOKALIKE, WALLET, 0, idx=1, log=1),
            transfer(900, LOOKALIKE, WALLET, 0, token=FAKE, idx=1, log=2),
        ],
        [],
    )
    ids = [c.event.victim_event_id for c in cand.generate(fx)]
    assert len(ids) == len(set(ids)) == 2


def test_failed_payments_still_count_as_chosen_and_are_documented() -> None:
    """A reverted ETH send still appears in the wallet's history, so its destination is a
    plausible copy source."""
    fx = fixture(
        [transfer(900, LOOKALIKE, WALLET, 0, idx=1)], [eth_tx(500, FRIEND, 10**18, succeeded=False)]
    )
    assert "lookalike_in" in methods_at(fx, 900)


def _brute_force(fx) -> list[tuple[str, tuple[str, ...], tuple[int, int] | None]]:
    events, _ = events_from_fixture(fx)
    out = []
    wallet = fx.wallet.lower()
    for t in sorted(fx.transfers, key=lambda t: (t.block_number, t.transaction_index, t.log_index)):
        incoming, outgoing = t.recipient.lower() == wallet, t.sender.lower() == wallet
        if not (incoming or outgoing):
            continue
        pos = (t.block_number, t.transaction_index, t.log_index)
        chosen = cand._chosen_before(events, pos)
        party = (t.sender if incoming else t.recipient).lower()
        match = max(
            ((k, m) for k in chosen if (m := cand.similar(party, k))),
            key=lambda km: (sum(km[1]), km[1][1], km[0]),
            default=None,
        )
        methods = cand.transfer_methods(
            incoming=incoming,
            outgoing=outgoing,
            value=int(t.value),
            token=t.token.lower(),
            wallet_signed=None if t.tx_sender is None else t.tx_sender.lower() == wallet,
            matched=match is not None,
        )
        if methods:
            out.append((t.transaction_hash, tuple(methods), match[1] if match else None))
    return out


def test_single_pass_generator_equals_the_per_transfer_definition() -> None:
    rng = random.Random(7)
    parties = [FRIEND, LOOKALIKE, STRANGER, OTHER, "0xd29" + "9" * 33 + "d7d5"]
    for _ in range(30):
        ts = []
        for i in range(25):
            block = rng.randrange(100, 2_000)
            if rng.random() < 0.4:
                ts.append(
                    transfer(
                        block,
                        WALLET,
                        rng.choice(parties),
                        rng.choice([0, 5, 10**9]),
                        tx_sender=rng.choice([WALLET, None, STRANGER]),
                        idx=i,
                    )
                )
            else:
                ts.append(
                    transfer(
                        block,
                        rng.choice(parties),
                        WALLET,
                        rng.choice([0, 5, 10**9]),
                        token=rng.choice([USDT, FAKE]),
                        idx=i,
                    )
                )
        fx = fixture(ts, [eth_tx(rng.randrange(100, 2_000), FRIEND, 1, idx=99)])
        got = [(c.event.planting_tx, c.methods, c.best_match) for c in cand.generate(fx)]
        assert got == _brute_force(fx)


# --- categories ------------------------------------------------------------------------------


def test_categories_are_structural_and_multi_label() -> None:
    cats = hn.categories(
        similarity=(3, 4),
        threshold=6,
        token_trusted=True,
        value_usd=None,
        methods=("lookalike_in",),
        signer=None,
        token=USDT,
        coverage="partial",
        first_time=True,
        receipt_known=True,
        value_base_units=5e9,
    )
    assert set(cats) == {
        "A_similarity_ordinary_value",
        "B_first_time_counterparty",
        "G_incomplete_observation",
        "H_near_threshold",
    }
    dust = hn.categories(
        similarity=None,
        threshold=6,
        token_trusted=True,
        value_usd=0.5,
        methods=("dust_in",),
        signer=ROUTER,
        token=USDT,
        coverage="complete",
        first_time=False,
        receipt_known=True,
        value_base_units=500,
    )
    assert "C_low_value" in dust
    assert "F_shared_infrastructure" in dust
    assert "A_similarity_ordinary_value" not in dust


def test_every_pool_candidate_is_unlabeled() -> None:
    rows = [
        {
            "line": 7,
            "block": 17_000_000,
            "tx": "0x" + "ab" * 32,
            "token": USDT,
            "sender": LOOKALIKE,
            "receiver": WALLET,
            "sender_is_victim": False,
            "value": 1e7,
            "value_usd": 10.0,
            "flags": 64,
            "intended": FRIEND,
            "first_digits": 4,
            "last_digits": 4,
        }
    ]
    (c,) = hn.archive_candidates(rows)
    assert c.label_status == "unlabeled_candidate"
    assert c.event.victim == WALLET
    assert c.event.lookalike == LOOKALIKE
    assert c.event.imitated == FRIEND
    assert "A_similarity_ordinary_value" in c.categories
    assert "G_incomplete_observation" in c.categories  # no wallet history in the archive


# --- contamination ---------------------------------------------------------------------------


def known() -> ct.KnownIndex:
    ix = ct.KnownIndex(coverage=[ct.Coverage("archive", 0, 10_000)])
    return ix.extend(
        [
            ct.KnownAttack("archive", WALLET, LOOKALIKE, "0xt1", FRIEND),
            ct.KnownAttack("archive", OTHER, "0x" + "55" * 20, "0xt2", None, token=FAKE),
            ct.KnownAttack("unconfirmed", None, "0x" + "66" * 20, None),
        ]
    )


@pytest.mark.parametrize(
    ("kw", "level", "status"),
    [
        ({"lookalike": LOOKALIKE, "tx": "0xt1"}, "exact_event", "known_positive_overlap"),
        (
            {"victim": STRANGER, "lookalike": STRANGER, "tx": "0xt1"},
            "exact_tx",
            "known_positive_overlap",
        ),
        ({"lookalike": LOOKALIKE, "tx": "0xnew"}, "victim_lookalike", "known_positive_overlap"),
        (
            {"victim": STRANGER, "lookalike": "0x" + "55" * 20},
            "shared_infrastructure",
            "known_positive_overlap",
        ),
        (
            {"victim": STRANGER, "lookalike": STRANGER, "token": FAKE},
            "shared_infrastructure",
            "known_positive_overlap",
        ),
        (
            {"lookalike": "0x" + "77" * 20, "imitated": FRIEND},
            "related_campaign",
            "potential_positive_overlap",
        ),
        ({"lookalike": "0xd296" + "0" * 32 + "d7d5"}, "weak_similarity", "no_known_overlap"),
        (
            {"lookalike": "0xd296" + "0" * 32 + "d7d5", "block": 99_999},
            "weak_similarity",
            "insufficient_information",
        ),
        ({"victim": STRANGER, "lookalike": STRANGER}, "none", "no_known_overlap"),
        (
            {"victim": STRANGER, "lookalike": STRANGER, "block": 99_999},
            "none",
            "insufficient_information",
        ),
    ],
)
def test_screen_levels_and_statuses(kw: dict, level: str, status: str) -> None:
    args = {
        "victim": WALLET,
        "lookalike": STRANGER,
        "tx": "0xother",
        "block": 500,
        "imitated": None,
        "token": None,
        **kw,
    }
    got = ct.screen(index=known(), **args)
    assert (got.level, got.status) == (level, status)


def test_a_common_token_is_not_attack_infrastructure() -> None:
    """Sharing USDT with a known attack is not an overlap: trusted tokens are never passed
    as counterfeit infrastructure."""
    ix = known()
    got = ct.screen(
        victim=STRANGER, lookalike=STRANGER, tx="0xz", block=5, imitated=None, token=None, index=ix
    )
    assert got.status == "no_known_overlap"


def test_conflicting_sources_are_all_recorded() -> None:
    ix = known().extend([ct.KnownAttack("poison-hunter", WALLET, LOOKALIKE, "0xt1")])
    got = ct.screen(
        victim=WALLET, lookalike=LOOKALIKE, tx="0xt1", block=1, imitated=None, token=None, index=ix
    )
    assert got.sources == ("archive", "poison-hunter")


# --- typed grouping --------------------------------------------------------------------------


def ev_(
    n: int,
    *,
    victim: str,
    look: str,
    signer: str | None = None,
    token: str = USDT,
    imitated: str | None = None,
    tx: str | None = None,
) -> PoisoningEvent:
    return PoisoningEvent(
        chain_id=1,
        victim=victim,
        lookalike=look,
        imitated=imitated,
        planting_tx=tx or "0x" + f"{n:064x}",
        planting_block=100 + n,
        planting_tx_index=0,
        planting_log_index=n,
        observation_timestamp=None,
        subtype="fake_token",
        tx_signer=signer,
        log_contract=token,
        token_contract=None,
        candidate_method="t",
    )


def a(n: int) -> str:
    return "0x" + f"{n:040x}"


def same_group(events: list[PoisoningEvent], policy: gp.GroupingPolicy | None = None) -> bool:
    g = gp.typed_groups(events, policy).group
    return len({g[e.victim_event_id] for e in events}) == 1


def test_typed_grouping_follows_the_threat_model() -> None:
    usdt = [ev_(1, victim=a(1), look=a(11)), ev_(2, victim=a(2), look=a(12))]
    assert not same_group(usdt)  # two unrelated wallets that both use USDT
    signer = [
        ev_(3, victim=a(3), look=a(13), signer=a(99)),
        ev_(4, victim=a(4), look=a(14), signer=a(99)),
    ]
    assert same_group(signer)  # one planting signer, two victims
    router = [
        ev_(5, victim=a(5), look=a(15), signer=ROUTER),
        ev_(6, victim=a(6), look=a(16), signer=ROUTER),
    ]
    assert not same_group(router)  # a public router signs for everyone
    fake = [
        ev_(7, victim=a(7), look=a(17), token=FAKE),
        ev_(8, victim=a(8), look=a(18), token=FAKE),
    ]
    assert same_group(fake)  # a counterfeit token contract, whatever its degree
    repeat = [ev_(9, victim=a(9), look=a(19)), ev_(10, victim=a(10), look=a(19))]
    assert same_group(repeat)  # a repeated lookalike
    imitated = [
        ev_(11, victim=a(21), look=a(31), imitated=a(77)),
        ev_(12, victim=a(22), look=a(32), imitated=a(77)),
    ]
    assert same_group(imitated)  # the same imitated recipient
    unknown = [
        ev_(13, victim=a(23), look=a(33), token=a(500)),
        ev_(14, victim=a(24), look=a(34), token=USDT),
    ]
    assert not same_group(unknown)  # unknown contracts do not link to common tokens
    batch = [
        ev_(15, victim=a(25), look=a(35), tx="0x" + "bb" * 32),
        ev_(16, victim=a(26), look=a(36), tx="0x" + "bb" * 32),
    ]
    assert same_group(batch)  # a multi-victim planting transaction


def test_verified_infrastructure_links_and_exclusions_apply() -> None:
    pair = [
        ev_(1, victim=a(1), look=a(11), signer=ROUTER),
        ev_(2, victim=a(2), look=a(12), signer=ROUTER),
    ]
    assert same_group(pair, gp.GroupingPolicy(verified_infra=frozenset({ROUTER})))
    same_wallet = [ev_(3, victim=a(3), look=a(13)), ev_(4, victim=a(3), look=a(14))]
    assert same_group(same_wallet)
    assert not same_group(same_wallet, gp.GroupingPolicy(exclude=frozenset({"shared_victim"})))
    stats = gp.typed_groups(pair)
    assert stats.edges_ignored["shared_token_contract"] == 2


# --- matching --------------------------------------------------------------------------------


def U(i: str, **cov: object) -> Unit:
    return Unit(i, cov, {"x": float(len(i))})


def test_exact_match_no_match_and_explicit_unmatched() -> None:
    pos = [U("p1", year=2023, bin="a"), U("p2", year=2024, bin="b")]
    cands = [U("c1", year=2023, bin="a"), U("c2", year=2022, bin="a")]
    r = cem(pos, cands, keys=["year", "bin"])
    assert r["pairs"] == [("p1", "c1")]
    assert r["unmatched_positives"] == ["p2"]  # temporal mismatch is not forced
    assert r["unmatched_candidates"] == ["c2"]
    assert r["candidates_without_support"] == 1


def test_one_to_many_is_deterministic_and_missing_is_its_own_level() -> None:
    pos = [U("p1", bin=None)]
    cands = [U(f"c{i}", bin=None) for i in range(5)] + [U("c9", bin="a")]
    a1 = cem(pos, cands, keys=["bin"], ratio=3)
    a2 = cem(pos, list(reversed(cands)), keys=["bin"], ratio=3)
    assert a1["pairs"] == a2["pairs"]
    assert len(a1["pairs"]) == 3
    assert "c9" not in {c for _, c in a1["pairs"]}  # a missing value never matches a present one


def test_matching_refuses_outcome_covariates_and_duplicate_ids() -> None:
    with pytest.raises(MatchingError, match="post-cutoff"):
        cem([U("p")], [U("c")], keys=["later_payment"])
    with pytest.raises(MatchingError, match="repeat"):
        cem([U("x")], [U("x")], keys=[])
    assert smd([1.0, 2.0], [1.0, 2.0]) == 0.0
    assert smd([1.0], [2.0, 3.0]) is None  # insufficient support


# --- evaluation contract -----------------------------------------------------------------------


def example(
    i: int, tier: str | None, score: float | None, *, split: str = "test", weight: float = 1.0
) -> ev.BenchmarkExample:
    return ev.BenchmarkExample(
        event_id=f"{i:016x}",
        group_id=f"g{i}",
        split=split,
        observation=ev.Observation(
            chain_id=1,
            wallet=a(i),
            candidate_address=a(100 + i),
            transaction="0x" + f"{i:064x}",
            block=i,
            observation_cutoff="after tx",
            source_manifest="m",
        ),
        generation=ev.Generation(
            candidate_version="candidates/2", methods=("lookalike_in",), eligible=True
        ),
        source_label=ev.SourceLabel(source=None, status="unlabeled_candidate"),
        human_label=None
        if tier is None
        else ev.HumanLabel(tier=tier, provenance=("h",), reviewers=2),
        prediction=None if score is None else ev.Prediction(model="m", score=score),
        weight=weight,
    )


def test_unlabeled_and_weak_are_never_negatives() -> None:
    data = [
        example(1, "verified_attempt", 0.9),
        example(2, "weak_attempt", 0.1),
        example(3, None, 0.2),
        example(4, "unknown", 0.3),
    ]
    with pytest.raises(ev.MetricRefused, match="no verified_legitimate"):
        ev.evaluate(data, threshold=0.5)


def test_metrics_on_reviewed_examples_name_their_exclusions() -> None:
    data = [
        example(1, "verified_attempt", 0.9),
        example(2, "verified_attempt", 0.4),
        example(3, "verified_legitimate", 0.6),
        example(4, "verified_legitimate", 0.1),
        example(5, None, 0.95),
        example(6, "conflicting", 0.5),
    ]
    r = ev.evaluate(data, threshold=0.5, fpr_budget=0.0, review_capacity=2)
    assert r["precision"] == 0.5
    assert r["recall"] == 0.5
    assert r["fpr"] == 0.5
    assert r["roc_auc"] == 0.75
    assert r["average_precision"] == pytest.approx((1 / 1 + 2 / 3) / 2)
    assert r["recall_at_fpr_budget"]["recall"] == 0.5
    assert r["excluded"]["unreviewed_or_unverified"] == 2
    assert r["labels"]["no_review:unlabeled_candidate"] == 1


def test_contract_refuses_outcomes_in_features_and_unflagged_missing() -> None:
    with pytest.raises(ValueError, match="outcome"):
        ev.Features(feature_version="f", values={"later_payoff_usd": 1.0})
    with pytest.raises(ValueError, match="missing"):
        ev.Features(feature_version="f", values={"prior_payments": None})
    ok = ev.Features(
        feature_version="f", values={"prior_payments": None}, missing=("prior_payments",)
    )
    assert ok.values["prior_payments"] is None  # missing stays missing, never 0


def test_split_report_finds_entity_leakage() -> None:
    e1 = ev_(1, victim=a(1), look=a(11))
    e2 = ev_(2, victim=a(1), look=a(12))  # same wallet in another split
    data = [example(1, None, None, split="train"), example(2, None, None, split="test")]
    events = {data[0].event_id: e1, data[1].event_id: e2}
    r = ev.split_report(data, events)
    assert r["valid"] is False
    assert r["overlap"]["train/test"]["entities"] >= 1


def test_operational_measures_are_labelled_for_what_they_are() -> None:
    r = ev.alerts_per_1000_wallet_days(8, 27, reviewed=False, representative=False)
    assert r["per_1000_wallet_days"] == pytest.approx(296.3, abs=0.1)
    assert "not false alerts" in r["measure"]
    h = ev.precision_under_prevalence(0.9, 0.01, 0.001)
    assert h["scenario"] == "hypothetical"
    with pytest.raises(ev.MetricRefused):
        ev.precision_under_prevalence(1.2, 0.0, 0.1)
    with pytest.raises(ev.MetricRefused, match="no known attempts"):
        ev.candidate_recall([], ["x"])


# --- inventory and separability diagnostics ----------------------------------------------------


def test_inventory_hashes_files_and_never_guesses_provenance(tmp_path) -> None:
    from cryptoguard.ml.inventory import inventory

    (tmp_path / "data/external/tsuchiya2025").mkdir(parents=True)
    (tmp_path / "data/external/tsuchiya2025/x.csv").write_text("h\n1\n2\n", encoding="utf-8")
    (tmp_path / "data/mystery").mkdir(parents=True)
    (tmp_path / "data/mystery/y.bin").write_bytes(b"\x00")
    rows = {r["path"]: r for r in inventory(tmp_path)["files"]}
    known = rows["data/external/tsuchiya2025/x.csv"]
    assert known["records"] == 2
    assert known["licence"] == "CC BY-NC-ND 4.0"
    assert len(known["sha256"]) == 64
    assert rows["data/mystery/y.bin"]["source"] == "unregistered"


def test_separability_auc_is_direction_free() -> None:
    from cryptoguard.ml.hn_study import univariate_auc

    assert univariate_auc([5.0, 6.0], [1.0, 2.0]) == 1.0
    assert univariate_auc([1.0, 2.0], [5.0, 6.0]) == 1.0
    assert univariate_auc([1.0, 2.0], [1.0, 2.0]) == 0.5
    assert univariate_auc([], [1.0]) is None

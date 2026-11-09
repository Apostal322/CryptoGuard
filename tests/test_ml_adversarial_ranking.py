"""Protocol 12.7: research candidate selection under adversarial pressure. Synthetic only;
each expectation follows from a selector's definition, never from a measured outcome."""

from __future__ import annotations

import json
import math
import random
from dataclasses import replace

import pytest

from cryptoguard.detectors.poisoning import PoisoningConfig
from cryptoguard.ml import adversarial_benchmark as ab
from cryptoguard.ml import adversarial_ranking as ar
from cryptoguard.ml import candidate_evidence as ce
from cryptoguard.ml import reliability_study as rs
from cryptoguard.replay.engine import Visibility, detector_outputs

END = rs.END


def _groups(family: str, m: int) -> tuple[list[ce.CandidateGroup], ab.Scenario]:
    sc = ab.scenario(family, m)
    return list(ce.build(sc.fixture, cutoff=END).groups), sc


def _rank(ordered: list[ce.CandidateGroup], look: str) -> int:
    return next(i + 1 for i, g in enumerate(ordered) if g.lookalike == look)


ALL = [ar.Selector(m, seed=3) for m in ar.METHODS] + [
    ar.Selector("P1", lam=math.inf),
    ar.Selector("P1", tie="recency"),
    ar.Selector("P1", nosim=True),
    ar.Selector("P1", nomech=True),
]


# --- provable properties ----------------------------------------------------------------------


@pytest.mark.parametrize("sel", ALL, ids=lambda s: s.label)
def test_every_selector_is_a_permutation_and_input_order_invariant(sel: ar.Selector) -> None:
    groups, _ = _groups("F9_mixed_mechanisms", 60)
    out = ar.order(groups, sel)
    assert sorted(g.identity for g in out) == sorted(g.identity for g in groups)
    assert len({g.identity for g in out}) == len(out)  # no duplicates
    shuffled = list(groups)
    random.Random(1).shuffle(shuffled)
    assert [g.identity for g in ar.order(shuffled, sel)] == [g.identity for g in out]


def test_p1_reads_no_time_no_support_level_and_no_missing_list() -> None:
    groups, _ = _groups("F7_recent_decoys_other_references", 40)
    base = [g.lookalike for g in ar.order(groups, ar.Selector("P1"))]
    rng = random.Random(5)
    pos = [(g.first_position, g.last_position) for g in groups]
    rng.shuffle(pos)
    moved = [
        replace(g, first_position=f, last_position=lp, level="partially_supported", missing=("x",))
        for g, (f, lp) in zip(groups, pos, strict=True)
    ]
    assert [g.lookalike for g in ar.order(moved, ar.Selector("P1"))] == base


def test_determinism_and_seed_dependence() -> None:
    groups, _ = _groups("F6_equal_similarity_same_reference", 50)
    a = [g.lookalike for g in ar.order(groups, ar.Selector("P1", seed=1))]
    assert a == [g.lookalike for g in ar.order(groups, ar.Selector("P1", seed=1))]
    assert a != [g.lookalike for g in ar.order(groups, ar.Selector("P1", seed=2))]  # 51 ties


@pytest.mark.parametrize("m", [0, 5, 50, 400])
@pytest.mark.parametrize("lam", [2.0, 4.0, 8.0, math.inf])
def test_displacement_bound_holds_and_does_not_grow_with_decoys(m: int, lam: float) -> None:
    groups, sc = _groups("F7_recent_decoys_other_references", m)
    ordered = ar.order(groups, ar.Selector("P1", lam=lam))
    first = next(i + 1 for i, g in enumerate(ordered) if ce.bucket_of(g) == sc.target_ref)
    bound = ar.displacement_bound(groups, sc.target_ref, lam)
    assert bound is not None
    assert first <= bound
    # 4 other buckets with equal best bits: each contributes at most floor(0 / lam) + 1 = 1
    assert bound <= 1 + min(m, 4)


def test_bound_is_none_without_a_discount() -> None:
    groups, sc = _groups("F7_recent_decoys_other_references", 5)
    assert ar.displacement_bound(groups, sc.target_ref, 0.0) is None
    assert ar.displacement_bound(groups, "0xnot-a-bucket", 4.0) is None


# --- baseline behaviour from the definitions --------------------------------------------------


def test_recent_equal_decoys_bury_the_target_under_b0_but_not_p1() -> None:
    groups, sc = _groups("F7_recent_decoys_other_references", 50)
    t = sc.relevant[0]
    assert _rank(ar.order(groups, ar.Selector("B0")), t) == 51  # recency breaks the tie
    assert _rank(ar.order(groups, ar.Selector("B1")), t) == 51
    assert _rank(ar.order(groups, ar.Selector("P1")), t) <= 5  # one per other bucket at most


def test_weaker_decoys_never_displace_a_stronger_target() -> None:
    for fam in ("F1_native_dust_flood", "F2_fake_token_flood", "F3_zero_value_flood"):
        groups, sc = _groups(fam, 200)
        t = sc.relevant[0]
        assert _rank(ar.order(groups, ar.Selector("B0")), t) == 1
        assert _rank(ar.order(groups, ar.Selector("P1")), t) == 1
        assert _rank(ar.order(groups, ar.Selector("B1")), t) == len(groups)  # oldest


def test_identifiability_equal_candidates_in_one_bucket() -> None:
    groups, sc = _groups("F6_equal_similarity_same_reference", 30)
    t = sc.relevant[0]
    assert _rank(ar.order(groups, ar.Selector("B0")), t) == 31  # the oldest of 31 equals
    ranks = {_rank(ar.order(groups, ar.Selector("P1", seed=s)), t) for s in range(10)}
    assert len(ranks) > 1  # a keyed hash spreads it; no seed-free guarantee exists


def test_repetition_collapses_into_one_group() -> None:
    groups, sc = _groups("F4_repetition_one_address", 300)
    assert len(groups) == 2  # one target, one repeated decoy
    assert _rank(ar.order(groups, ar.Selector("P1")), sc.relevant[0]) == 2  # 5+5 beats 4+4


def test_reference_buckets_are_bounded_by_the_victims_payments() -> None:
    groups, _ = _groups("F5_distinct_equal_lookalikes", 500)
    refs = {ce.bucket_of(g) for g in groups if g.references}
    assert len(refs) <= 5


def test_relevant_candidates_exist_in_every_family() -> None:
    for fam in ab.FAMILIES:
        groups, sc = _groups(fam, 10)
        looks = {g.lookalike for g in groups}
        assert all(r in looks for r in sc.relevant), fam


def test_unrelated_strangers_create_only_unreferenced_groups() -> None:
    groups, sc = _groups("F15_one_among_unrelated", 200)
    referenced = [g for g in groups if g.references]
    assert [g.lookalike for g in referenced] == list(sc.relevant)


# --- preservation and the summary contract ----------------------------------------------------


def test_selected_result_keeps_every_group_and_reports_its_order() -> None:
    sc = ab.scenario("F16_several_relevant_compete", 120)
    res = ce.build(sc.fixture, cutoff=END)
    sel = ar.Selector("P1")
    out = ar.select(res, sel)
    assert sorted(g.identity for g in out.groups) == sorted(g.identity for g in res.groups)
    s = ce.summarize(out, 5)
    assert (s["order"], s["order_config"]) == ("P1[lam=4]", ar.config_hash(sel))
    assert s["total_groups"] == len(res.groups)
    assert s["hidden_count"] == len(res.groups) - 5
    assert all(i["bucket_size"] >= 1 for i in s["top"])
    assert ce.digest(out) != ce.digest(res)  # the order is part of the fingerprint
    seen, offset = [i["identity"] for i in s["top"]], s["next_offset"]
    while offset is not None:
        pg = ce.page(out, offset=offset, limit=50, expect_digest=s["result_digest"])
        assert pg["order"] == "P1[lam=4]"
        seen += [i["identity"] for i in pg["items"]]
        offset = pg["next_offset"]
    assert seen == [g.identity for g in out.groups]  # every relevant one is reachable


def test_default_summary_is_unchanged_for_the_default_order() -> None:
    sc = ab.scenario("F1_native_dust_flood", 10)
    s = ce.summarize(ce.build(sc.fixture, cutoff=END), 3)
    assert s["order"] == "affix_then_recency"
    assert s["order_config"] is None
    assert "not a risk score" in s["order_note"]


def test_config_hash_is_stable_and_distinguishes_configs() -> None:
    a = ar.config_hash(ar.Selector("P1"))
    assert a == ar.config_hash(ar.Selector("P1"))
    assert a != ar.config_hash(ar.Selector("P1", lam=8.0))
    assert len(a) == 16
    assert ar.config_hash(ar.Selector("P1", lam=math.inf))  # serializable at infinity
    with pytest.raises(ValueError, match="unknown method"):
        ar.Selector("nope")
    with pytest.raises(ValueError, match="unknown tie"):
        ar.Selector("P1", tie="newest")


# --- historical correctness -------------------------------------------------------------------


def test_events_after_the_cutoff_never_change_the_selection() -> None:
    sc = ab.scenario("F7_recent_decoys_other_references", 20)
    later = [
        (rs.lookalike(5_000 + i, prefix=5, suffix=5, ref=rs.REF), 1, 9_500 + i, True)
        for i in range(30)
    ]
    fx = sc.fixture.model_copy(
        update={
            "native_inbound": list(sc.fixture.native_inbound)
            + [r for r in rs.wallet_fixture(native=later).native_inbound]
        }
    )
    a = ar.order(list(ce.build(sc.fixture, cutoff=END).groups), ar.Selector("P1"))
    b = ar.order(list(ce.build(fx, cutoff=END).groups), ar.Selector("P1"))
    assert [g.identity for g in a] == [g.identity for g in b]


def test_duplicated_ingestion_does_not_add_candidates() -> None:
    sc = ab.scenario("F5_distinct_equal_lookalikes", 30)
    dup = sc.fixture.model_copy(update={"native_inbound": list(sc.fixture.native_inbound) * 2})
    assert len(ce.build(dup, cutoff=END).groups) == len(ce.build(sc.fixture, cutoff=END).groups)


def test_unknown_evidence_is_kept_not_turned_benign() -> None:
    for fam in ("F11_missing_receipt", "F12_partial_history", "F10_unknown_signer"):
        sc = ab.scenario(fam, 10)
        res = ar.select(ce.build(sc.fixture, cutoff=END), ar.Selector("P1"))
        g = next(g for g in res.groups if g.lookalike == sc.relevant[0])
        assert g.missing  # still listed as missing
        assert g.level in ce.LEVELS


# --- metrics and scientific integrity ---------------------------------------------------------


def test_metric_denominators() -> None:
    assert ab._exposure([1, 7, None], 5) == pytest.approx(1 / 3)
    assert ab._exposure([2, 3, 4], 3) == pytest.approx(2 / 3)
    cost = ab.attack_cost("F6_equal_similarity_same_reference", 10)
    assert cost is not None
    assert cost["log2_key_trials"] == pytest.approx(math.log2(10) + 32, abs=0.01)
    assert ab.attack_cost("F4_repetition_one_address", 1_000)["addresses"] == 1  # type: ignore[index]
    assert ab.attack_cost("F1_native_dust_flood", 0) is None


def test_grid_cell_reports_every_method_and_no_bound_violation() -> None:
    cell = ab.run_cell(ab.scenario("F16_several_relevant_compete", 30), seeds=(0, 1))
    assert set(ab.selectors(0)) <= set(cell["methods"])
    assert cell["bound_violations"] == {}
    assert all(cell["relevant_found"])
    for meth in cell["methods"].values():
        assert all(0.0 <= v <= 1.0 for v in meth["exposure"].values())


def test_ltr_vector_marks_missing_similarity() -> None:
    v = ab._vec({"B0": None, "T0": -100.0, "T1": 2.0}, ("S", "R", "N"))
    assert v[:2] == [0.0, 1.0]
    assert v[2] == pytest.approx(-math.log1p(100.0))


def test_production_detector_is_untouched() -> None:
    sc = ab.scenario("F9_mixed_mechanisms", 20)
    full = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS
    before = detector_outputs(sc.fixture, 9_000, full, PoisoningConfig())
    ar.select(ce.build(sc.fixture, cutoff=END), ar.Selector("P1"))
    assert detector_outputs(sc.fixture, 9_000, full, PoisoningConfig()) == before


def test_summary_size_stays_bounded_with_selection() -> None:
    small = ce.summarize(
        ar.select(
            ce.build(ab.scenario("F5_distinct_equal_lookalikes", 20).fixture, cutoff=END),
            ar.Selector("P1"),
        ),
        10,
    )
    big = ce.summarize(
        ar.select(
            ce.build(ab.scenario("F5_distinct_equal_lookalikes", 2_000).fixture, cutoff=END),
            ar.Selector("P1"),
        ),
        10,
    )
    assert abs(len(json.dumps(big)) - len(json.dumps(small))) < 200


def test_registered_p1_ties_favour_flooded_buckets_and_p1b_does_not() -> None:
    """P1 breaks ties between bucket leaders by the member's hash; a flooded bucket's
    leader is the minimum of many hashes, so a lone target loses every tie. P1b hashes the
    bucket instead, which is independent of how many decoys a bucket holds."""
    groups, sc = _groups("F7_recent_decoys_other_references", 200)
    t = sc.relevant[0]
    registered = [_rank(ar.order(groups, ar.Selector("P1", seed=s)), t) for s in range(40)]
    fixed = [
        _rank(ar.order(groups, ar.Selector("P1", seed=s, bucket_tie=True)), t) for s in range(40)
    ]
    # Each flooded leader is the minimum of 50 hashes, so the lone target trails all four
    # with probability (50/51)^4, about 0.92 (expected about 37 of 40). With bucket hashes
    # every position among the five leaders is equally likely (expected 8 of 40 at rank 5).
    assert registered.count(5) >= 30
    assert fixed.count(5) <= 20
    assert len(set(fixed)) >= 4
    assert max(fixed) <= 5  # still within the five bucket leaders
    assert ar.Selector("P1", bucket_tie=True).label == "P1b[lam=4]"
    assert ar.config_hash(ar.Selector("P1", bucket_tie=True)) != ar.config_hash(ar.Selector("P1"))

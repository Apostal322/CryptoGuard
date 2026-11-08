"""Protocol 12.5: proxy task, exploratory ranking, candidate features and the shadow ranking.
Expected values are written from each case's definition. Synthetic data only."""

from __future__ import annotations

import json
import math

import pytest

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_features as cf
from cryptoguard.ml import candidate_research as cr
from tests.test_ml_candidate_discovery import (
    ATTACKER,
    END,
    FAKE_TOKEN,
    LOOK_2,
    LOOK_NATIVE,
    LOOK_TOKEN,
    SHORT,
    VICTIM,
    fixture,
    native_in,
    transfer,
)

V = "0x" + "1" * 40
L1, L2, L3 = ("0x" + c * 40 for c in "abc")
ZERO, TINY, COUNTERFEIT = 1 << 1, 1 << 2, 1 << 3


def ep(
    plantings: list[tuple[int, int, str, str, int]],
    *,
    paid: str = L1,
    split: str = "dev",
    group: int = 0,
) -> cr.CachedEpisode:
    return cr.CachedEpisode(
        V,
        10_000,
        paid,
        group,
        split,
        tuple(cr.Planting(b, line, "0xt", s, r, f) for b, line, s, r, f in plantings),
    )


# --- RQ8 proxy rows ------------------------------------------------------------------------


def test_proxy_rows_use_only_strictly_earlier_blocks() -> None:
    e = ep(
        [
            (100, 1, V, L1, ZERO),  # spoofed_out
            (100, 2, L2, V, ZERO),  # zero_in, same block: never an input to block 100
            (110, 1, L3, V, TINY),  # tiny_in
            (110, 2, L2, V, COUNTERFEIT),  # counterfeit_in
            (120, 1, L1, V, ZERO),  # zero_in
        ]
    )
    rows = cr.proxy_rows([e])
    assert [(r.target, r.prefix) for r in rows] == [
        ("tiny_in", ("spoofed_out", "zero_in")),
        ("counterfeit_in", ("spoofed_out", "zero_in")),  # same prefix: 110 order unknown
        ("zero_in", ("spoofed_out", "zero_in", "tiny_in", "counterfeit_in")),
    ]
    f = dict(zip(cr.FEATURE_NAMES, rows[0].features, strict=True))
    assert (f["count_spoofed_out"], f["last_zero_in"], f["distinct_lookalikes"]) == (1, 1, 2)
    assert f["log_blocks_since_last"] == pytest.approx(math.log1p(10))


def test_baselines_are_normalized_and_markov_follows_transitions() -> None:
    train = cr.proxy_rows(
        [ep([(1, 1, V, L1, ZERO), (2, 1, V, L1, ZERO), (3, 1, V, L1, ZERO)], group=1)]
    )
    probs = cr.baseline_probs(train, train)
    for name in ("global", "victim_prefix", "markov"):
        for p in probs[name]:
            assert sum(p.values()) == pytest.approx(1.0)
    # both training rows go spoofed_out -> spoofed_out: (2 + 1) / (2 + 5)
    assert probs["markov"][0]["spoofed_out"] == pytest.approx(3 / 7)


def test_logistic_refuses_single_class_and_is_deterministic() -> None:
    one = cr.proxy_rows([ep([(1, 1, V, L1, ZERO), (2, 1, V, L1, ZERO)])])
    with pytest.raises(ValueError, match="single-class"):
        cr.logistic_probs(one, one)
    mixed = cr.proxy_rows(
        [ep([(1, 1, V, L1, ZERO), (2, 1, L2, V, TINY), (3, 1, V, L1, ZERO), (4, 1, L2, V, TINY)])]
    )
    assert cr.logistic_probs(mixed, mixed) == cr.logistic_probs(mixed, mixed)


def test_log_loss_macro_f1_and_bootstrap() -> None:
    rows = cr.proxy_rows([ep([(1, 1, V, L1, ZERO), (2, 1, L2, V, TINY), (3, 1, V, L1, ZERO)])])
    assert [r.target for r in rows] == ["tiny_in", "spoofed_out"]
    certain = [{c: float(c == r.target) for c in cr.CLASSES} for r in rows]
    assert cr.log_losses(certain, rows) == [0.0, 0.0]
    assert cr.macro_f1(certain, rows)["macro_f1"] == 1.0
    b = cr.group_bootstrap_diff([1.0, 3.0], [0.0, 1.0], [0, 1], draws=200)
    assert b["mean_diff"] == 1.5
    assert b["ci_low"] <= 1.5 <= b["ci_high"]
    assert cr.group_bootstrap_diff([1.0, 3.0], [0.0, 1.0], [0, 1], draws=200) == b


def test_proxy_task_needs_both_splits() -> None:
    with pytest.raises(ValueError, match="development and test"):
        cr.proxy_task([ep([(1, 1, V, L1, ZERO), (2, 1, L2, V, TINY)], split="dev")])


# --- RQ2 and H3a ---------------------------------------------------------------------------


def test_top1_averages_ties() -> None:
    assert cr.top1({"a": (1.0,), "b": (1.0,), "c": (0.0,)}, "a") == 0.5
    assert cr.top1({"a": (1.0,), "b": (2.0,)}, "a") == 0.0


def test_semantic_channel_on_a_constructed_dev_set() -> None:
    # recency favours L2 (inbound, latest); the channel rule favours L1 (spoofed, paid)
    e = ep([(10, 1, V, L1, ZERO), (20, 1, L2, V, TINY)], paid=L1)
    held_out = ep([(10, 1, V, L1, ZERO), (20, 1, L2, V, TINY)], paid=L1, split="test", group=9)
    res = cr.semantic_channel([e, held_out])
    assert (res["episodes"], res["T0_top1"], res["B5_top1"]) == (1, 0.0, 1.0)
    assert res["latest_planting_spoofed_share"] == {"paid": 1.0, "rivals": 0.0}


def test_mad_normalized_recency_ranks_exactly_like_recency() -> None:
    e = ep([(10, 1, V, L1, ZERO), (15, 1, L2, V, TINY), (40, 1, L3, V, ZERO)])
    flat = ep([(10, 1, V, L1, ZERO), (10, 2, L2, V, TINY)])
    assert cr.mad_recency_equivalence([e, flat]) == {
        "episodes_same_order": 1,
        "differ": 0,
        "mad_zero_undefined": 1,
    }


# --- candidate features and the shadow ranking ----------------------------------------------


def scenario(**kw: object) -> object:
    """Legitimate reference (REF at 1100), native dust from LOOK_NATIVE (1200), a fake-token
    lookalike LOOK_TOKEN (1300), an ordinary unrelated 5 ETH payment in from SHORT (1250)."""
    return fixture(
        [transfer(LOOK_TOKEN, VICTIM, 10**18, block=1300, signer=ATTACKER, token=FAKE_TOKEN)],
        native=[
            native_in(LOOK_NATIVE, 10**12, block=1200),
            native_in(SHORT, 5 * 10**18, block=1250),
        ],
        **kw,  # type: ignore[arg-type]
    )


def test_end_to_end_original_and_extended_pathways() -> None:
    fx = scenario()
    c0 = cd.discover(fx, cutoff=END, variant="C0")
    c1 = cd.discover(fx, cutoff=END, variant="C1")
    c2 = cd.discover(fx, cutoff=END, variant="C2")
    assert c0.lookalikes == {LOOK_TOKEN}  # the native channel is invisible to C0
    assert c1.lookalikes == c2.lookalikes == {LOOK_TOKEN, LOOK_NATIVE}  # SHORT: no lookalike
    assert c2.abstain is None
    ranked = cf.rank(fx, END)
    assert [r.lookalike for r in ranked] == [LOOK_TOKEN, LOOK_NATIVE]  # B4: latest first
    assert ranked[0].baseline_ranks["B3"] == 2.0  # LOOK_TOKEN affix 4+4 < LOOK_NATIVE 5+5
    assert all("not a probability" in r.explanation for r in ranked)
    native = next(c for c in c2.candidates if c.lookalike == LOOK_NATIVE)
    f = cf.candidate_features(fx, native, END)
    assert f["signer_role"] == cf.FeatureValue("lookalike_itself", "observed")
    assert f["receipt_status"] == cf.FeatureValue(1.0, "observed")
    assert f["emitter_reviewed"].status == "not_applicable"
    assert f["reference_paid_before"] == cf.FeatureValue(1.0, "observed")
    blob = json.dumps(cf.serialize(ranked), default=str)
    assert json.loads(blob)[0]["version"] == cf.RANKING_VERSION
    partial = scenario(complete=False)
    assert "insufficient history" in str(cd.discover(partial, cutoff=END, variant="C2").abstain)
    pf = cf.candidate_features(partial, native, END)
    assert pf["matched_references"].status == "unknown"  # not a zero


def test_missing_observations_are_unknown_never_zero() -> None:
    fx = scenario()
    tok = next(c for c in cd.discover(fx, cutoff=END, variant="C2").candidates if c.kind == "erc20")
    f = cf.candidate_features(fx, tok, END)
    assert f["signer_reuse_in_window"].status == "zero_observed"  # signer known, no reuse
    unknown_signer = fx.model_copy(  # type: ignore[attr-defined]
        update={"transfers": [t.model_copy(update={"tx_sender": None}) for t in fx.transfers]}  # type: ignore[attr-defined]
    )
    g = cf.candidate_features(unknown_signer, tok, END)
    assert g["signer_reuse_in_window"] == cf.FeatureValue(None, "unknown")


def test_features_are_point_in_time() -> None:
    fx = scenario()
    cut = (1350, 0)
    later = fixture(
        [
            transfer(LOOK_TOKEN, VICTIM, 10**18, block=1300, signer=ATTACKER, token=FAKE_TOKEN),
            transfer(LOOK_2, VICTIM, 0, block=1500, signer=ATTACKER),  # a later planting
            transfer(VICTIM, LOOK_NATIVE, 9 * 10**6, block=1600, signer=VICTIM),  # the payoff
            transfer(LOOK_TOKEN, VICTIM, 0, block=1700, signer=ATTACKER, log=4),  # signer link
        ],
        native=[
            native_in(LOOK_NATIVE, 10**12, block=1200),
            native_in(SHORT, 5 * 10**18, block=1250),
            native_in(LOOK_NATIVE, 7, block=1800),
        ],
    )
    a = {c.lookalike: c for c in cd.discover(fx, cutoff=cut, variant="C2").candidates}
    b = {c.lookalike: c for c in cd.discover(later, cutoff=cut, variant="C2").candidates}
    assert a == b
    for look, cand in a.items():
        assert cf.candidate_features(fx, cand, cut) == cf.candidate_features(later, b[look], cut)
    assert cf.serialize(cf.rank(fx, cut)) == cf.serialize(cf.rank(later, cut))


def test_feature_schema_is_stable() -> None:
    fx = scenario()
    c = cd.discover(fx, cutoff=END, variant="C2").candidates[0]
    assert sorted(cf.candidate_features(fx, c, END)) == sorted(
        [
            "affix_prefix",
            "affix_suffix",
            "matched_references",
            "reference_paid_before",
            "blocks_since_reference_payment",
            "kind",
            "channel",
            "zero_value",
            "signer_role",
            "emitter_reviewed",
            "receipt_status",
            "first_seen_block",
            "last_seen_block",
            "events",
            "events_last_day",
            "median_interarrival",
            "signer_reuse_in_window",
            "coverage_erc20_transfer_logs",
            "coverage_native_inbound_external",
            "coverage_erc20_outgoing_signers",
        ]
    )


def test_flood_is_bounded_by_distinct_lookalikes() -> None:
    fx = cr.flood_fixture(2_000, 100)
    cut = (8_001, 0)
    assert len(cd.discover(fx, cutoff=cut, variant="C1").candidates) == 2_100
    assert len(cd.discover(fx, cutoff=cut, variant="C2").candidates) == 100
    assert len(cf.rank(fx, cut)) == 100


def test_robustness_transforms_never_add_candidates() -> None:
    fx = scenario()
    res = cr.robustness(fx, END)
    assert res["base"] == sorted([LOOK_TOKEN, LOOK_NATIVE])
    for t in cr.TRANSFORMS:
        assert res[t]["added"] == 0, t
    assert res["no_native"]["removed"] == 1  # LOOK_NATIVE is no longer observable
    assert "native_inbound_external" in res["no_native"]["not_complete"]
    assert res["no_reference_history"]["abstain"] is not None

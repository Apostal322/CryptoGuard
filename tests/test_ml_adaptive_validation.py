"""Protocol 12.7.1: generator neutrality, frozen selectors, metrics, the bounded attacker and
the counterexample search. Every expectation follows from a definition; none reads a primary
outcome."""

from __future__ import annotations

import math
from dataclasses import replace

import pytest

from cryptoguard.ml import adaptive_validation as av
from cryptoguard.ml import adversarial_ranking as ar
from cryptoguard.ml import candidate_evidence as ce


def _specs(family: str, m: int, g: int | None = None) -> list[av.Spec]:
    return [
        s for s in av.specs() if s.family == family and s.m == m and (g is None or s.groups == g)
    ]


# --- the design --------------------------------------------------------------------------


def test_design_is_the_registered_grid() -> None:
    sp = av.specs()
    assert len(sp) == len(av.FAMILIES) * len(av.G_GRID) * sum(av.SEEDS_PER_M.values()) == 7_200
    assert len({s.key for s in sp}) == len(sp)  # unique scenario identifiers
    for fam in av.FAMILIES:  # every template sees every age relation
        for g in av.G_GRID:
            ages = {s.age for s in sp if s.family == fam and s.groups == g and s.m == 100}
            assert ages == set(av.AGE_RELATIONS)


def test_generation_is_reproducible_and_seed_specific() -> None:
    a, b = _specs("F4_equal_uniform", 10, 5)[:2]
    assert av.scenario_hash(av.generate(a)) == av.scenario_hash(av.generate(a))
    assert av.scenario_hash(av.generate(a)) != av.scenario_hash(av.generate(b))


def test_frozen_selectors_are_verified() -> None:
    info = av.verify_frozen()
    assert info["config_hashes"] == av.FROZEN_CONFIG_HASHES
    assert ar.config_hash(av.FROZEN_SELECTORS["B8_P1b"]) == "8b3795e363aad678"
    assert ar.config_hash(replace(av.FROZEN_SELECTORS["B8_P1b"], lam=5.0)) != "8b3795e363aad678"


# --- neutrality ----------------------------------------------------------------------------


def _diags(family: str, m: int = 10) -> list[dict]:
    return [av.diagnostics(av.generate(s)) for s in _specs(family, m)]


def test_target_address_and_list_position_carry_no_signal() -> None:
    ds = _diags("F4_equal_uniform") + _diags("F2_equal_other_groups")
    assert abs(sum(d["address_pct"] for d in ds) / len(ds) - 0.5) < 0.08
    assert abs(sum(d["list_pct"] for d in ds) / len(ds) - 0.5) < 0.08


def test_target_age_is_balanced_across_relations() -> None:
    ds = _diags("F4_equal_uniform", 100)
    oldest = sum(d["oldest"] for d in ds) / len(ds)
    newest = sum(d["newest"] for d in ds) / len(ds)
    assert abs(oldest - newest) < 0.08
    assert abs(sum(d["age_pct"] for d in ds) / len(ds) - 0.5) < 0.08


def test_mechanism_is_unique_only_where_the_relation_says_so() -> None:
    for s in _specs("F4_equal_uniform", 100)[:40]:
        d = av.diagnostics(av.generate(s))
        if s.mech in ("same", "majority_same"):
            assert not d["mech_unique"]
        if s.mech == "target_unique":
            assert d["mech_unique"]


def test_target_reference_is_not_systematically_first_or_largest() -> None:
    ds = [av.diagnostics(av.generate(s)) for s in _specs("F4_equal_uniform", 100, 5)]
    pcts = [d["ref_sorted_pct"] for d in ds if d["ref_sorted_pct"] is not None]
    assert 0.3 < sum(pcts) / len(pcts) < 0.7
    assert sum(d["largest_group"] for d in ds) / len(ds) < 0.6


# --- family semantics ----------------------------------------------------------------------


def _target_group(sc: av.Scenario, i: int = 0) -> ce.CandidateGroup:
    return next(g for g in sc.groups if g.lookalike == sc.relevant[i])


def test_equal_similarity_families() -> None:
    sc = av.generate(_specs("F3_equal_own_group", 100, 5)[0])
    tg = _target_group(sc)
    decoys = [g for g in sc.groups if g.lookalike in sc.attacker]
    assert all(ar.bits(g) == ar.bits(tg) for g in decoys)
    assert all(ce.bucket_of(g) == ce.bucket_of(tg) for g in decoys)


def test_stronger_and_weaker_targets() -> None:
    for fam, cmp in (
        ("F1_target_stronger", lambda d, t: d < t),
        ("F5_target_weaker", lambda d, t: d > t),
    ):
        sc = av.generate(_specs(fam, 100, 5)[0])
        tb = ar.bits(_target_group(sc))
        assert all(cmp(ar.bits(g), tb) for g in sc.groups if g.lookalike in sc.attacker), fam


def test_same_total_split_keeps_the_total_and_changes_the_split() -> None:
    sc = av.generate(_specs("F7_same_total_split", 100, 5)[0])
    tg = _target_group(sc)
    t_split = tg.references[0][1:]
    decoys = [g for g in sc.groups if g.lookalike in sc.attacker]
    assert all(ar.bits(g) == ar.bits(tg) for g in decoys)
    assert any(g.references[0][1:] != t_split for g in decoys)


def test_reference_overlap_decoys_land_in_one_overlapping_pair() -> None:
    """Decoys are designed against one reference of an overlapping pair (3+3 shared). A
    decoy that ties both is assigned by the pipeline's label-independent rule, so decoys land
    in at most two buckets, and two buckets are always an overlapping pair."""
    for s in _specs("F8_reference_overlap", 10, 5)[:8]:
        sc = av.generate(s)
        buckets = {ce.bucket_of(g) for g in sc.groups if g.lookalike in sc.attacker}
        assert 1 <= len(buckets) <= 2
        if len(buckets) == 2:
            a, b = sorted(buckets)
            assert a[2:5] == b[2:5]
            assert a[-3:] == b[-3:]


def test_several_relevant_and_equal_leaders() -> None:
    sc = av.generate(_specs("F9_several_relevant", 10, 5)[0])
    assert len(sc.relevant) == 3
    assert len({ce.bucket_of(_target_group(sc, i)) for i in range(3)}) == 3
    sc = av.generate(_specs("F10_equal_leaders", 10, 5)[0])
    tb = ar.bits(_target_group(sc))
    leaders: dict[str, int] = {}
    for g in sc.groups:
        if g.references:
            leaders[ce.bucket_of(g)] = max(leaders.get(ce.bucket_of(g), 0), ar.bits(g))
    assert set(leaders.values()) <= {tb, 36, 32, 28, 24}  # background may exceed; leaders tie
    assert sum(1 for v in leaders.values() if v == tb) >= 2


def test_null_family_target_is_an_ordinary_candidate() -> None:
    ds = _diags("F6_exchangeable_null", 100)
    assert abs(sum(d["age_pct"] for d in ds) / len(ds) - 0.5) < 0.1


def test_groups_carry_no_oracle() -> None:
    sc = av.generate(_specs("F4_equal_uniform", 10, 5)[0])
    fields = set(ce.CandidateGroup.__dataclass_fields__)
    assert not any("target" in f or "relevant" in f or "oracle" in f for f in fields)
    assert all(g.evidence for g in sc.groups)  # every candidate keeps its record


# --- metrics -------------------------------------------------------------------------------


def test_exposure_and_score() -> None:
    assert av._exposure([1, 4, 60], 3) == pytest.approx(1 / 3)
    row = {"r": [1], "b": [1]}
    assert av.score(row) == 1.0
    row = {"r": [4], "b": [1]}
    assert av.score(row) == pytest.approx(4 / 6)  # exposed at K = 5, 10, 20, 50 (of 6)
    assert av.score(row, "b") == 1.0


def _row(fam: str, g: int, m: int, a: int, b: int) -> dict:
    return {
        "family": fam,
        "G": g,
        "m": m,
        "age": "target_random",
        "mech": "mixed_independent",
        "methods": {"A": {"r": [a], "b": [a]}, "B": {"r": [b], "b": [b]}},
    }


def test_paired_uses_equal_template_and_family_weights() -> None:
    f1, f2 = av.PRIMARY_FAMILIES[:2]
    rows = [_row(f1, 1, 0, 1, 100)] * 9 + [_row(f1, 2, 0, 100, 100)] + [_row(f2, 1, 0, 100, 100)]
    out = av.paired(rows, "A", "B", n_boot=50)
    # f1: template (1,0) diff 1.0 (9 rows), template (2,0) diff 0 -> family 0.5; f2: 0
    assert out["per_family"][f1] == pytest.approx(0.5)
    assert out["mean"] == pytest.approx(0.25)
    assert out["templates"] == 3
    assert out["scenarios"] == 11


def test_control_family_is_excluded_from_the_primary_estimate() -> None:
    rows = [
        _row("F6_exchangeable_null", 1, 0, 1, 100),
        _row(av.PRIMARY_FAMILIES[0], 1, 0, 100, 100),
    ]
    assert av.paired(rows, "A", "B", n_boot=10)["mean"] == 0.0


def test_evaluate_reports_every_method_and_a_permutation() -> None:
    sc = av.generate(_specs("F16" if False else "F9_several_relevant", 10, 5)[0])
    ev = av.evaluate(sc)
    assert set(ev["methods"]) == set(av.METHODS)
    for row in ev["methods"].values():
        assert len(row["r"]) == 3
        assert all(1 <= r <= len(sc.groups) for r in row["r"])
        assert all(b <= r for b, r in zip(row["b"], row["r"], strict=True))


# --- the attacker and counterexamples ------------------------------------------------------


def test_attacker_only_adds_and_respects_budget() -> None:
    base, target, refs, tier = av.victim(1)
    snapshot = list(base)
    for att in av.ATTACKS[:12]:
        pop, info = av.attack_population(base, target, refs, tier, att, 100, av._rng("t", att))
        assert base == snapshot  # existing records untouched
        assert pop[: len(base)] == base
        assert info["decoys"] <= min(av.ATTACK_CAP, int(100 * 16.0 ** (-att.delta)))
        assert all(g.lookalike not in {r.lower() for r in refs} for g in pop)


def test_attacker_cannot_go_below_the_similarity_rule() -> None:
    base, target, refs, _ = av.victim(0)
    pop, info = av.attack_population(
        base, target, refs, 6, av.Attack(-1, "own", "newer", False), 10, av._rng("x")
    )
    assert pop == base
    assert "illegal" in info


def test_grinding_only_keeps_hash_winners() -> None:
    base, target, refs, tier = av.victim(2)
    pop, info = av.attack_population(
        base, target, refs, tier, av.Attack(0, "own", "newer", True), 200, av._rng("g")
    )
    th = ar.keyed(av.PUBLIC_SEED, target)
    added = pop[len(base) :]
    assert all(ar.keyed(av.PUBLIC_SEED, g.lookalike) < th for g in added)
    assert info["generated"] == 200 >= info["decoys"]


def test_counterexample_search_terminates_and_shrinks() -> None:
    out = av.counterexamples(trials=300)
    assert out["trials"] == 300
    assert out["invariant_breaks"] == {"bound": 0, "weaker_decoy_moves_bucket_leader": 0}
    for name, cx in out["found"].items():
        if name == "multi_reference_assignment":
            continue
        assert sum(c["is_target"] for c in cx["candidates"]) == 1


def test_fidelity_against_the_real_pipeline() -> None:
    assert av.fidelity(4)["mismatched"] == 0


def test_lambda_infinity_selector_is_pure_rotation() -> None:
    sel = av.FROZEN_SELECTORS["NC_group_rotation"]
    assert math.isinf(sel.lam)
    assert sel.nosim

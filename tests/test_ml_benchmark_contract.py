"""Protocol 12.8: label ontology, case and collector contracts, the blind flow, metric
denominators, the failure taxonomy, splits, sample-size planning and repository safety.
Synthetic only; every expectation follows from a definition in the protocol."""

from __future__ import annotations

import inspect
import json
import subprocess
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from cryptoguard.ml import benchmark_contract as bc
from cryptoguard.ml import benchmark_eval as be
from cryptoguard.ml import benchmark_readiness as br
from cryptoguard.ml import candidate_evidence as ce
from cryptoguard.ml import power, repo_safety
from cryptoguard.ml import reliability_study as rs

W, REF, USDT, FAKE = rs.WALLET, rs.REF, rs.USDT, rs.FAKE
NATIVE = rs.lookalike(1, prefix=4, suffix=4)  # the paid lookalike (native dust)
FAKE_TOKEN = rs.lookalike(2)  # 3+3, fake-token transfer in
SPOOF = rs.lookalike(3, prefix=5, suffix=5)  # zero-value spoofed transfer out
DISTRACTORS = [rs.lookalike(10 + i) for i in range(8)]
HARM_BLOCK = 5_000
DAY = date(2026, 11, 10)


def window(*, paid: str = NATIVE, plant: bool = True, extra_native: list | None = None):
    native = [(d, 1, 2_300 + i, True) for i, d in enumerate(DISTRACTORS)]
    if plant:
        native.append((NATIVE, 1, 2_000, True))
    native.append((rs.lookalike(99, prefix=5, suffix=5), 1, 6_000, True))  # after the cutoff
    native += extra_native or []
    return rs.wallet_fixture(
        transfers=[
            (FAKE_TOKEN, W, 10**18, 2_100, None, FAKE, 0),
            (W, SPOOF, 0, 2_200, rs.ATTACKER, USDT, 0),
        ],
        native=native,
        wallet_txs=[(paid, 10**18, HARM_BLOCK)],  # the harmful payment itself
    )


def case(fx, case_id: str = "syn-1", **kw) -> bc.BenchmarkCase:
    base = dict(
        case_id=case_id, chain_id=1, victim=fx.wallet, from_block=fx.from_block,
        to_block=fx.to_block, cutoff=(HARM_BLOCK, 0), cutoff_rule="strictly before the harm block",
        observation_schema="observation/2",
        source=bc.CaseSource(publisher="synthetic", url="synthetic://oracle"),
        cluster_id=case_id, population="synthetic",
    )  # fmt: skip
    return bc.BenchmarkCase(**(base | kw))


def label(dimension: str, value: str, *, kinds=("synthetic_oracle",), subject: str = NATIVE, **kw):
    base = dict(
        label_id=f"{dimension}:{value}", subject=subject, dimension=dimension, value=value,
        evidence=tuple(bc.EvidenceRef(kind=k, ref="0x" + "ab" * 32) for k in kinds),
        source="oracle", determined_at=DAY, method="by construction", confidence="supported",
        cutoff_relation="post_cutoff_outcome",
    )  # fmt: skip
    return bc.Label(**(base | kw))


def outcome(fx, case_id: str = "syn-1", paid: str = NATIVE, **kw) -> bc.Outcome:
    harm = fx.wallet_transactions[-1].transaction_hash
    base = dict(
        case_id=case_id, verified=True, paid_address=paid, intended_recipient=REF, harm_tx=harm,
        harm_block=HARM_BLOCK,
        labels=(
            label("outcome", "paid_to_candidate", kinds=("chain_transaction", "synthetic_oracle"),
                  subject=paid),
            label("mechanism", "native_dust", subject=paid, cutoff_relation="forensic"),
        ),
    )  # fmt: skip
    return bc.Outcome(**(base | kw))


def run(fx, c, o) -> dict:
    return be.run_case(c, fx, be.OutcomeVault({c.case_id: o} if o else {}), be.Ledger(None))


# --- the controlled end-to-end benchmark ----------------------------------------------------


def test_end_to_end_blind_benchmark() -> None:
    fx = window()
    c, o = case(fx), outcome(fx)
    assert bc.status(bc.case_quality(c, fx, o)) == "valid_with_limitations"  # coverage gaps
    pred = be.predict(c, fx)
    vault, ledger = be.OutcomeVault({c.case_id: o}), be.Ledger(None)
    with pytest.raises(be.UnblindingError):
        vault.open(pred)  # the outcome cannot be read before the prediction is sealed
    vault.seal(pred)
    r = ledger.record(pred, be.score(c, pred, vault.open(pred), fx))
    assert len(pred.candidates) == 11  # 8 distractors + native + fake token + spoof
    assert rs.lookalike(99, prefix=5, suffix=5) not in pred.candidates  # planted after the cutoff
    assert (r["T1_observed"], r["T2_generated"]) == (True, True)
    assert r["T3_rank"]["B0"] == 2  # the 5+5 spoof ranks first, the 4+4 paid address second
    assert r["T4_exposed"]["B0"] == {"1": False, "3": True, "5": True, "10": True}
    assert r["T5_mechanism_identified"] is True
    assert r["failure"] == "exposed"
    assert r["fidelity"]["records"] == r["fidelity"]["resolved_pre_cutoff"] == 11
    assert pred.coverage["internal_value_transfers"] != "complete"  # incomplete coverage
    assert not bc.mechanism_eligibility(pred.coverage)["all_mechanisms"]["eligible"]
    # every candidate and record stays reachable
    res = ce.build(fx, cutoff=c.cutoff)
    assert {g.lookalike for g in res.groups} == set(pred.candidates)
    assert ce.page(res, offset=10, limit=5)["items"][0]["rank"] == 11


def test_prediction_cannot_see_an_outcome() -> None:
    assert list(inspect.signature(be.predict).parameters) == ["case", "fixture"]
    fx = window()
    a = be.predict(case(fx), fx)
    b = be.predict(case(fx), fx)
    assert a.digest == b.digest  # deterministic, identical inputs
    assert "paid" not in " ".join(bc.BenchmarkCase.model_fields)
    assert set(bc.CollectorRequest.model_fields) == {
        "chain_id", "wallet", "from_block", "to_block", "observation", "max_requests"
    }  # fmt: skip
    with pytest.raises(ValidationError):
        bc.CollectorRequest(chain_id=1, wallet=W, from_block=1, to_block=2, observation=2,
                            max_requests=10, paid_address=NATIVE)  # fmt: skip


def test_missing_candidate_counts_as_a_miss_end_to_end() -> None:
    fx1 = window()
    hit = run(fx1, case(fx1), outcome(fx1))
    fx2 = window(plant=False)  # the paid address never planted before the cutoff
    c2 = case(fx2, "syn-2")
    miss = run(fx2, c2, outcome(fx2, "syn-2"))
    assert miss["failure"] == "not_observed_in_complete_stream"
    assert miss["T2_generated"] is False
    m = be.aggregate([hit, miss])
    assert m["conditional_topk"]["B0"][10] == {"value": 1.0, "numerator": 1, "denominator": 1}
    assert m["end_to_end_topk"]["B0"][10] == {"value": 0.5, "numerator": 1, "denominator": 2}
    assert m["candidate_recall"]["denominator"] == 2
    assert m["mrr_on_generated"]["B0"] == {"value": 0.5, "denominator": 1}
    assert m["failures"] == {"exposed": 1, "not_observed_in_complete_stream": 1}


def test_unsupported_observation_is_not_a_ranking_failure() -> None:
    fx = br.degrade(window(), "native")
    c = case(fx)
    r = run(fx, c, outcome(fx))
    assert r["failure"] == "observation_unsupported"
    assert r["mechanism_eligible"] is False
    assert r["T1_assessable"] is False
    m = be.aggregate([r])
    assert m["end_to_end_topk"]["B0"][10]["denominator"] == 0  # not a detection-benchmark case
    assert m["end_to_end_topk_all_verified"]["B0"][10] == {
        "value": 0.0, "numerator": 0, "denominator": 1,
    }  # fmt: skip


@pytest.mark.parametrize(
    ("what", "expected"),
    [("first_half", "observation_partial"), ("receipts", "exposed"), ("signer_lookups", "exposed")],
)
def test_degradations(what: str, expected: str) -> None:
    base = window()
    fx = br.degrade(base, what)
    assert run(fx, case(fx), outcome(fx))["failure"] == expected
    assert len(base.native_inbound) == 10  # the original recording is never modified


def test_failure_taxonomy_branches() -> None:
    stranger = "0x" + "9d" * 20  # sends dust but resembles no recipient
    fx = window(paid=stranger, plant=False, extra_native=[(stranger, 1, 2_050, True)])
    r = run(fx, case(fx), outcome(fx, paid=stranger))
    assert (r["T1_observed"], r["failure"]) == (True, "candidate_not_generated")
    fx = window()
    r = run(fx, case(fx), outcome(fx, intended_recipient="0x" + "77" * 20))
    assert r["failure"] == "incorrect_reference_matching"
    weak = rs.lookalike(500)  # 3+3, buried under 12 stronger lookalikes
    strong = [(rs.lookalike(600 + i, prefix=4, suffix=4), 1, 2_400 + i, True) for i in range(12)]
    fx = window(paid=weak, plant=False, extra_native=[(weak, 1, 2_050, True), *strong])
    r = run(fx, case(fx), outcome(fx, paid=weak))
    assert r["T2_generated"] is True
    assert r["T3_rank"]["B0"] > 10
    assert r["failure"] == "ranked_below_k"  # reachable only through pagination
    assert run(fx, case(fx), None)["failure"] == "outcome_not_verified"
    bad = outcome(fx, labels=(label("legitimacy", "confirmed_malicious",
                                    kinds=("chain_transaction",)),))  # fmt: skip
    assert run(fx, case(fx), bad)["failure"] == "label_uncertain"


def test_empty_candidate_set_and_same_block_cutoff() -> None:
    fx = rs.wallet_fixture(wallet_txs=[(NATIVE, 10**18, HARM_BLOCK)])
    r = run(fx, case(fx), outcome(fx))
    assert (r["candidates"], r["T2_generated"]) == (0, False)
    assert be.aggregate([r])["burden"]["candidates_per_window_mean"] == 0
    # a planting in the harmful block is not usable: within-block order is not assumed
    fx = window(plant=False, extra_native=[(NATIVE, 1, HARM_BLOCK, True)])
    assert run(fx, case(fx), outcome(fx))["T1_observed"] is False


# --- ledger and vault -----------------------------------------------------------------------


def test_ledger_scores_once_and_refuses_a_different_rerun(tmp_path: Path) -> None:
    fx = window()
    c, o = case(fx), outcome(fx)
    path = tmp_path / "ledger.jsonl"
    first = be.run_case(c, fx, be.OutcomeVault({c.case_id: o}), be.Ledger(path))
    again = be.run_case(c, fx, be.OutcomeVault({c.case_id: o}), be.Ledger(path))
    assert again == first  # the same prediction returns the stored result
    changed = window(extra_native=[(rs.lookalike(700), 1, 2_900, True)])
    ledger = be.Ledger(path)
    with pytest.raises(be.RerunError):
        be.run_case(c, changed, be.OutcomeVault({c.case_id: o}), ledger)
    assert len(be.Ledger(path).refused) == 1  # the attempt is on record
    assert len(be.Ledger(path).entries) == 1


def test_vault_refuses_a_second_prediction() -> None:
    fx = window()
    c = case(fx)
    vault = be.OutcomeVault({})
    vault.seal(be.predict(c, fx))
    other = window(extra_native=[(rs.lookalike(701), 1, 2_901, True)])
    with pytest.raises(be.RerunError):
        vault.seal(be.predict(c, other))


# --- labels ---------------------------------------------------------------------------------


def test_label_rules() -> None:
    assert bc.label_problems(label("outcome", "paid_to_candidate"), synthetic_case=True) == [
        "paid_to_candidate needs a chain_transaction reference"
    ]
    assert bc.label_problems(label("mechanism", "native_dust", kinds=()), synthetic_case=True)
    legit = label("legitimacy", "confirmed_legitimate", kinds=("chain_transaction",))
    assert any("absence is not evidence" in p for p in bc.label_problems(legit))
    reviewed = label("legitimacy", "confirmed_legitimate", kinds=("reviewer_decision",))
    assert any("reviewer id" in p for p in bc.label_problems(reviewed))
    assert (
        bc.label_problems(
            label(
                "legitimacy", "confirmed_legitimate", kinds=("reviewer_decision",), reviewer_id="r1"
            )
        )
        == []
    )
    malicious = label("legitimacy", "confirmed_malicious", kinds=("chain_transaction", "receipt"))
    assert any("on-chain event alone" in p for p in bc.label_problems(malicious))
    assert any(
        "synthetic_oracle" in p for p in bc.label_problems(label("mechanism", "native_dust"))
    )  # an oracle label on a real case
    unknown = label("legitimacy", "unreviewed", kinds=(), confidence="verified")
    assert bc.label_problems(unknown) == ["a non-asserting value cannot be verified"]
    leak = label("outcome", "paid_to_candidate", kinds=("chain_transaction",),
                 cutoff_relation="pre_cutoff_observable")  # fmt: skip
    assert any("never be a pre-cutoff model input" in p for p in bc.label_problems(leak))
    assert not bc.model_input_allowed(leak)
    assert bc.model_input_allowed(
        label("mechanism", "native_dust", cutoff_relation="pre_cutoff_observable")
    )
    old = label("mechanism", "unknown", kinds=(), schema_version="benchmark-labels/0")
    assert any("incompatible" in p for p in bc.label_problems(old))


def test_invalid_category_and_conflicts() -> None:
    with pytest.raises(ValidationError, match="invalid category"):
        label("legitimacy", "benign")
    with pytest.raises(ValidationError, match="invalid dimension"):
        label("fraud", "unknown")
    a = label("mechanism", "native_dust")
    b = label("mechanism", "fake_token")
    assert len(bc.label_conflicts([a, b])) == 1
    assert bc.label_conflicts([a, label("mechanism", "unknown", kinds=())]) == []


def test_unknown_is_never_a_negative() -> None:
    labels = [
        label("legitimacy", "unreviewed", kinds=(), subject="0x" + "01" * 20),
        label("legitimacy", "ambiguous", kinds=(), subject="0x" + "02" * 20),
        label("legitimacy", "insufficient_evidence", kinds=(), subject="0x" + "03" * 20),
    ]
    assert be.false_positive_rate(labels, flagged=["0x" + "01" * 20])["status"] == "blocked"
    ok = label("legitimacy", "confirmed_legitimate", kinds=("reviewer_decision",),
               reviewer_id="r1", subject="0x" + "04" * 20)  # fmt: skip
    r = be.false_positive_rate([*labels, ok], flagged=["0x" + "01" * 20, "0x" + "04" * 20])
    assert (r["numerator"], r["denominator"]) == (1, 1)  # only the verified negative counts


# --- data quality and independence ----------------------------------------------------------


def codes(issues) -> set[str]:
    return {i.code for i in issues}


def test_case_quality_rules() -> None:
    fx = window()
    c, o = case(fx), outcome(fx)
    assert "incomplete_categories" in codes(bc.case_quality(c, fx, o))
    assert bc.status(bc.case_quality(c, fx, o, duplicate=True)) == "invalid"
    assert bc.status(bc.case_quality(c, fx, o, protected=True)) == "not_evaluable"
    assert "outcome_not_verified" in codes(bc.case_quality(c, fx, None))
    no_tx = outcome(fx, harm_tx=None)
    assert "missing_transaction_hash" in codes(bc.case_quality(c, fx, no_tx))
    late = case(fx, cutoff=(HARM_BLOCK + 1, 0))
    assert "cutoff_after_harm_block" in codes(bc.case_quality(late, fx, o))
    planted_tx = fx.native_inbound[0].transaction_hash
    assert "future_information_leak" in codes(
        bc.case_quality(c, fx, outcome(fx, harm_tx=planted_tx))
    )
    assert "chain_mismatch" in codes(bc.case_quality(case(fx, chain_id=10), fx, o))
    assert "wallet_mismatch" in codes(bc.case_quality(case(fx, victim="0x" + "ee" * 20), fx, o))
    assert "invalid_address" in codes(bc.case_quality(case(fx, victim="0x123"), fx, o))
    dup = fx.model_copy(update={"native_inbound": fx.native_inbound * 2})
    assert "duplicate_records" in codes(bc.case_quality(c, dup, o))
    unread = br.degrade(fx, "receipts")
    assert "missing_receipts" in codes(bc.case_quality(c, unread, o))
    assert "no_recording" in codes(bc.case_quality(c, None, o))
    old = case(fx, schema_version="benchmark-case/0")
    assert "incompatible_artifact_version" in codes(bc.case_quality(old, fx, o))
    conflicted = outcome(fx, labels=(label("mechanism", "native_dust"),
                                     label("mechanism", "fake_token")))  # fmt: skip
    assert "conflicting_labels" in codes(bc.case_quality(c, fx, conflicted))


def test_independence_reasons() -> None:
    fx = window()
    c, o = case(fx, population="independent_candidate"), outcome(fx)
    assert bc.independence(c, o, bc.DevelopmentIndex()) == []
    dev = bc.index_from_fixtures([fx], clusters=["syn-1"], protected=[NATIVE])
    reasons = bc.independence(c, o, dev)
    assert "victim already used in development" in reasons
    assert "attack cluster already used in development" in reasons
    assert "paid address already seen in a development artifact" in reasons
    assert "paid address in a frozen review cohort" in reasons
    untraceable = case(fx, source=bc.CaseSource(publisher="rumour", url=""))
    assert "no traceable source" in bc.independence(untraceable, o, bc.DevelopmentIndex())
    assert "declared development" in bc.independence(
        case(fx, population="development"), o, bc.DevelopmentIndex()
    )


def test_coverage_matrix_and_mechanism_eligibility() -> None:
    cov = bc.coverage_matrix(window())
    e = bc.mechanism_eligibility(cov)
    assert e["native_dust"]["eligible"]
    assert e["spoofed_transfer"]["eligible"]
    assert e["all_mechanisms"]["state"] == "unsupported"
    assert "internal_value_transfers" in e["all_mechanisms"]["missing"]
    gone = bc.mechanism_eligibility(bc.coverage_matrix(br.degrade(window(), "native")))
    assert gone["native_dust"] == {
        "state": "unsupported", "eligible": False, "missing": ["native_inbound_external"],
    }  # fmt: skip
    half = bc.mechanism_eligibility(bc.coverage_matrix(br.degrade(window(), "first_half")))
    assert half["fake_token"]["state"] == "partial"


# --- splits and leakage ---------------------------------------------------------------------


def test_groups_keep_related_cases_together() -> None:
    fx = window()
    cases = [
        case(fx, "a", cutoff=(4_000, 0)),
        case(fx, "b", cutoff=(4_500, 0)),  # the same victim
        case(fx, "c", victim="0x" + "11" * 20, cluster_id="a"),  # the same campaign
        case(fx, "d", victim="0x" + "22" * 20, cutoff=(4_900, 0)),
        case(fx, "e", victim="0x" + "33" * 20),
    ]
    outs = {"d": outcome(fx, "d"), "e": outcome(fx, "e")}  # d and e share the paid address
    grp = be.groups(cases, outs)
    assert grp["a"] == grp["b"] == grp["c"]
    assert grp["d"] == grp["e"] != grp["a"]
    split = be.chronological_split(cases, grp, test_share=0.4)
    assert be.split_leakage(split, grp) == []
    assert be.split_leakage({**split, "b": "test" if split["a"] == "dev" else "dev"}, grp)
    folds = be.leave_one_group_out(grp)
    assert len(folds) == 2
    assert all(not be.split_leakage(f, grp) for f in folds)
    assert be.split_feasibility(2)["leave_one_group_out"] is False


def test_leakage_audit_blocks_confirmatory_claims_for_development_cases() -> None:
    fx = window()
    c = case(fx)
    req = bc.collector_request(c, max_requests=100)
    audit = be.leakage_audit(c, fx, be.predict(c, fx), req, protected=False, dev_reasons=())
    assert audit["confirmatory_allowed"] is True
    dev = be.leakage_audit(c, fx, be.predict(c, fx), req, protected=True, dev_reasons=("used",))
    assert dev["confirmatory_allowed"] is False
    assert dev["checks"]["no_post_cutoff_evidence"] is True


# --- sample-size planning -------------------------------------------------------------------


def test_sign_test_power_and_planning() -> None:
    assert power.sign_test_power(4, 1.0)["critical"] is None  # 4 of 4: p = 0.0625 > 0.05
    assert power.sign_test_power(5, 1.0) == {
        "n_discordant": 5, "critical": 5, "size": 0.03125, "power": 1.0,
    }  # fmt: skip
    assert power.sign_test_power(0, 0.9)["power"] == 0.0  # identical predictions decide nothing
    need = [power.discordant_needed(p) for p in (0.7, 0.8, 0.9)]
    assert all(n is not None for n in need)
    assert need[0] > need[1] > need[2]  # a larger effect needs fewer discordant incidents
    assert power.discordant_needed(0.5) is None
    plan = power.incidents_needed(0.8, 0.25, eligible_rate=0.5, deff=1.5)
    d = plan["discordant_needed"]
    assert plan["eligible_needed"] == -(-d * 1.5 // 0.25)
    assert plan["screened_needed"] == 2 * plan["eligible_needed"]
    with pytest.raises(ValueError, match="discordance"):
        power.incidents_needed(0.8, 0.0)


# --- public-repository safety ---------------------------------------------------------------


def test_secret_scan_reports_names_and_counts_only(tmp_path: Path) -> None:
    token = "gh" + "p_" + "A" * 36  # built at run time: never a literal in the repository
    assert repo_safety.scan_text(f"x = '{token}'") == {"github_token": 1}
    assert repo_safety.scan_text("token = '0x" + "ab" * 20 + "'") == {}  # an address is no secret
    repo = tmp_path / "repo"
    (repo / "data").mkdir(parents=True)
    (repo / "data" / "raw.jsonl").write_text("{}", encoding="utf-8")
    (repo / "notes.txt").write_text(f"key {token}", encoding="utf-8")
    (repo / "unblinding_key.jsonl").write_text("{}", encoding="utf-8")
    try:
        subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=60)  # noqa: S603, S607
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, timeout=60)  # noqa: S603, S607
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git is not available")
    out = repo_safety.scan(repo)
    assert out["clean"] is False
    assert out["secret_pattern_files"] == {"notes.txt": {"github_token": 1}}
    assert out["restricted_paths_tracked"] == ["data/raw.jsonl"]
    assert out["sensitive_names"] == ["unblinding_key.jsonl"]
    assert token not in json.dumps(out)  # the value itself is never reported


def test_this_repository_is_clean() -> None:
    out = repo_safety.scan(Path(__file__).resolve().parent.parent)
    if not out["available"]:
        pytest.skip("not a git checkout")
    assert out["secret_pattern_files"] == {}
    assert out["restricted_paths_tracked"] == []
    assert out["sensitive_names"] == []
    assert out["oversized_files"] == []
    assert out["local_user_paths"] == {}


def test_baseline_registry_does_not_prefer_p1b() -> None:
    p1b = next(r for r in be.REGISTRY if r["id"] == "P1b")
    assert "failed" in p1b["status"]
    assert "not preferred" in p1b["status"]
    assert be.PRIMARY_METHOD == "B0"

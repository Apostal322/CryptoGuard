"""Agreement statistics, replacements, the unblinding gate and the pre-specified analysis.

All reviewer decisions are synthetic software inputs; no real label is created.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import unblind as ub
from cryptoguard.ml.agreement import BINARY, agreement
from cryptoguard.ml.annotation import (
    AdjudicationRecord,
    AnnotationError,
    ReviewerStore,
    load_submission,
)
from cryptoguard.ml.review_server import REPLACEMENT_SHEET, ReviewApp
from tests.review_fixtures import INSUFFICIENT_FIELDS, fields, frozen

# --- agreement -----------------------------------------------------------------------------


def labels(pairs: list[tuple[str, str]]) -> tuple[dict[str, str], dict[str, str]]:
    return ({str(i): a for i, (a, _) in enumerate(pairs)},
            {str(i): b for i, (_, b) in enumerate(pairs)})  # fmt: skip


def test_kappa_and_ac1_match_hand_computation() -> None:
    # 2x2 table [[20, 5], [10, 15]]: po = 0.7, pe = 0.5, kappa = 0.4.
    pairs = (
        [("attempt", "attempt")] * 20
        + [("attempt", "not_attempt")] * 5
        + [("not_attempt", "attempt")] * 10
        + [("not_attempt", "not_attempt")] * 15
    )
    a, b = labels(pairs)
    r = agreement(a, b, BINARY)
    assert r["observed_agreement"] == pytest.approx(0.7)
    assert r["cohen_kappa"] == pytest.approx(0.4)
    # AC1: pi = (0.55, 0.45), pe = 2 * 0.55 * 0.45 / 1 = 0.495.
    assert r["gwet_ac1"] == pytest.approx((0.7 - 0.495) / (1 - 0.495))
    assert r["confusion"]["not_attempt"]["attempt"] == 10
    assert r["disagreements"] == 15


def test_kappa_is_undefined_not_zero_when_both_use_one_category() -> None:
    a, b = labels([("attempt", "attempt")] * 6)
    r = agreement(a, b, BINARY)
    assert r["cohen_kappa"] is None
    assert "single" in r["kappa_note"]
    assert r["gwet_ac1"] == pytest.approx(1.0)
    empty = agreement({}, {}, BINARY)
    assert empty["cohen_kappa"] is None
    assert empty["observed_agreement"] is None


def test_unpaired_items_and_foreign_labels_are_reported() -> None:
    r = agreement({"1": "attempt", "2": "attempt"}, {"1": "attempt"}, BINARY)
    assert r["unpaired"] == {"only_a": 1, "only_b": 0}
    assert r["paired_items"] == 1
    with pytest.raises(ValueError, match="outside"):
        agreement({"1": "benign"}, {"1": "attempt"}, BINARY)


# --- workflow helpers --------------------------------------------------------------------------


def review(pkg: Path, decide: Any) -> Path:
    """Save one synthetic decision per item through the store, then finalize."""
    app = ReviewApp(pkg)
    with app.store:
        for it in app.state()["items"]:
            app.store.save(fields(it["item"], it["victim_event_id"], decide(it["item"])))
        app.finalize()
    return pkg / "annotations" / "submission.json"


def attempt(_: int) -> dict[str, Any]:
    from tests.review_fixtures import ATTEMPT_FIELDS

    return ATTEMPT_FIELDS


@pytest.fixture
def study(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    _, sample, manifest = frozen(tmp_path, monkeypatch)
    work = tmp_path / "work"
    pkgs = {r: ub.make_package(sample, work, r, tmp_path / f"pkg-{r}") for r in ("A", "B")}
    return {"sample": sample, "work": work, "pkgs": pkgs, "manifest": manifest, "tmp": tmp_path}


# --- gate --------------------------------------------------------------------------------------


def test_gate_refuses_before_two_finalized_reviewers(study: dict[str, Any]) -> None:
    a = review(study["pkgs"]["A"], attempt)
    with pytest.raises(ub.UnblindingRefused, match="two finalized"):
        ub.unblind(study["sample"], study["work"], [a])
    with pytest.raises(ub.UnblindingRefused, match="submitted twice"):
        ub.unblind(study["sample"], study["work"], [a, a])
    missing = study["tmp"] / "pkg-B" / "annotations" / "submission.json"
    with pytest.raises(ub.UnblindingRefused):
        ub.unblind(study["sample"], study["work"], [a, missing])
    assert not (study["work"] / ub.ACCESS_LOG).exists()  # the key was never opened


def test_gate_refuses_incomplete_or_edited_submissions(study: dict[str, Any]) -> None:
    a = review(study["pkgs"]["A"], attempt)
    app = ReviewApp(study["pkgs"]["B"])
    with app.store:
        it = app.state()["items"][0]
        app.store.save(fields(it["item"], it["victim_event_id"]))
    with pytest.raises(AnnotationError, match="no decision"), app.store:
        app.finalize()
    b = review(study["pkgs"]["B"], attempt)
    body = json.loads(b.read_text(encoding="utf-8"))
    body["decisions"][0]["decision"] = "insufficient_evidence"
    b.write_text(json.dumps(body), encoding="utf-8")
    with pytest.raises(ub.UnblindingRefused, match="edited"):
        ub.unblind(study["sample"], study["work"], [a, b])


def test_gate_refuses_a_modified_key(study: dict[str, Any]) -> None:
    a = review(study["pkgs"]["A"], attempt)
    b = review(study["pkgs"]["B"], attempt)
    key = study["sample"] / rs.KEY
    key.write_bytes(key.read_bytes().replace(b"tsuchiya-payoff:confirmed", b"x", 1))
    with pytest.raises(ub.UnblindingRefused, match="unblinding_key"):
        ub.unblind(study["sample"], study["work"], [a, b])


def test_unblinding_reports_agreement_estimates_and_source_comparison(
    study: dict[str, Any],
) -> None:
    a = review(study["pkgs"]["A"], attempt)
    b = review(study["pkgs"]["B"], lambda i: INSUFFICIENT_FIELDS if i % 6 == 0 else attempt(i))
    report = ub.unblind(study["sample"], study["work"], [a, b])
    n = len(study["manifest"]["selected"])
    disagree = n // 6
    assert report["items_reviewed_by_all"] == n
    primary = report["primary_all_reviewers_attempt"]["overall"]
    lenient = report["sensitivity_any_reviewer_attempt"]["overall"]
    assert primary["positives"] == n - disagree
    assert lenient["positives"] == n
    assert primary["estimate"] < lenient["estimate"] == 1.0
    assert report["agreement"]["binary"]["disagreements"] == disagree
    lo, hi = report["primary_all_reviewers_attempt"]["attempt_level_bounds"]
    assert lo <= primary["estimate"] <= hi
    cats = report["source_comparison"]["categories"]
    assert cats == {"full_agreement": n - disagree, "insufficient_evidence": disagree}
    log = (study["work"] / ub.ACCESS_LOG).read_text(encoding="utf-8").splitlines()
    assert json.loads(log[-1])["purpose"] == "unblind"
    rows = (study["work"] / "unblinded_items.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == n  # row-level table stays in the git-ignored work directory
    assert "0x" not in json.dumps(report)  # the aggregate report carries no addresses


def test_adjudication_is_separate_and_by_a_third_person(study: dict[str, Any]) -> None:
    a = review(study["pkgs"]["A"], attempt)
    b = review(study["pkgs"]["B"], lambda i: INSUFFICIENT_FIELDS if i == 1 else attempt(i))
    sub_b = load_submission(b)
    item1 = next(x for x in sub_b.decisions if x.item == 1).victim_event_id
    rec = {
        "victim_event_id": item1,
        "reviewer_decisions": {"A": "confirmed_poisoning_attempt", "B": "insufficient_evidence"},
        "final_decision": "likely_poisoning_attempt",
        "rationale": "Counterparty found in the earlier history.",
        "additional_evidence_used": True,
        "saw_source_labels": False,
        "adjudicated_at": "2026-11-03T00:00:00+00:00",
    }
    path = study["tmp"] / "adj.jsonl"
    path.write_text(AdjudicationRecord(adjudicator="A", **rec).model_dump_json(), encoding="utf-8")
    with pytest.raises(ub.UnblindingRefused, match="one of the reviewers"):
        ub.unblind(study["sample"], study["work"], [a, b], path)
    path.write_text(AdjudicationRecord(adjudicator="C", **rec).model_dump_json(), encoding="utf-8")
    report = ub.unblind(study["sample"], study["work"], [a, b], path)
    primary = report["primary_all_reviewers_attempt"]["overall"]["positives"]
    adjudicated = report["secondary_adjudicated"]["overall"]["positives"]
    assert adjudicated == primary + 1  # the original disagreement still counts in primary


# --- replacements ------------------------------------------------------------------------------


def test_replacement_takes_the_next_reserve_and_reaches_packages_blinded(
    study: dict[str, Any],
) -> None:
    m = study["manifest"]
    first = m["selected"][0]
    rec = ub.record_replacement(
        study["sample"],
        study["work"],
        original_event_id=first["victim_event_id"],
        reason="transaction_not_found",
        evidence="No explorer or archive node returns the transaction.",
        exposed=["A"],
        recorded_by="maintainer",
    )
    assert rec.replacement_event_id == m["reserves"][first["stratum"]][0]
    assert rec.replacement_item == len(m["selected"]) + 1
    pkg = ub.make_package(study["sample"], study["work"], "C", study["tmp"] / "pkg-C")
    line = (pkg / REPLACEMENT_SHEET).read_text(encoding="utf-8")
    assert first["stratum"].split("|")[0] not in line  # no stratum or subtype in the package
    state = ReviewApp(pkg).state()
    ids = {i["victim_event_id"] for i in state["items"]}
    assert rec.replacement_event_id in ids
    assert first["victim_event_id"] not in ids
    with pytest.raises(AnnotationError, match="not an active"):
        ub.record_replacement(
            study["sample"],
            study["work"],
            original_event_id=first["victim_event_id"],
            reason="transaction_not_found",
            evidence="Replacing it a second time must fail.",
            exposed=[],
            recorded_by="maintainer",
        )


def test_replaced_originals_are_nonresponse_in_the_sensitivity_bounds(
    study: dict[str, Any],
) -> None:
    first = study["manifest"]["selected"][0]
    ub.record_replacement(
        study["sample"],
        study["work"],
        original_event_id=first["victim_event_id"],
        reason="chain_data_unavailable",
        evidence="The block is not served by any reachable source.",
        exposed=[],
        recorded_by="maintainer",
    )
    pkgs = {r: ub.make_package(study["sample"], study["work"], r, study["tmp"] / f"r-{r}")
            for r in ("A", "B")}  # fmt: skip
    subs = [review(pkgs[r], attempt) for r in ("A", "B")]
    report = ub.unblind(study["sample"], study["work"], subs)
    sens = report["replacement_sensitivity"]["overall"]
    assert sens["missing"] == 1
    lo, hi = sens["bounds_missing_as_false_true"]
    assert lo < hi == 1.0
    assert report["replacements"][0]["reason"] == "chain_data_unavailable"


def test_out_of_order_replacements_are_rejected(study: dict[str, Any]) -> None:
    from cryptoguard.ml.annotation import ReplacementRecord, validate_replacements

    m = study["manifest"]
    first = m["selected"][0]
    reserves = m["reserves"][first["stratum"]]
    rec = ReplacementRecord(
        original_event_id=first["victim_event_id"],
        original_item=1,
        replacement_event_id=reserves[1],  # skips the first reserve
        replacement_item=99,
        sheet_line={"victim_event_id": reserves[1]},
        stratum=first["stratum"],
        reserve_position=1,
        reason="transaction_not_found",
        inaccessibility_evidence="not retrievable anywhere",
        reviewers_exposed_to_original=(),
        recorded_by="m",
        recorded_at="t",
    )
    problems = validate_replacements(m, [rec])
    assert any("next reserve" in p for p in problems)


def test_reviewer_store_rejects_items_outside_the_package(study: dict[str, Any]) -> None:
    s = ReviewerStore(study["tmp"] / "x", "A", {1: "00000000000000aa"})
    with s, pytest.raises(AnnotationError, match="unknown item"):
        s.save(fields(2, "00000000000000bb"))

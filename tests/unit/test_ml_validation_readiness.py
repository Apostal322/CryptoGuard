"""Phase 11.6: evidence packets, training cohort, amendment-2 submissions, label policy,
experiment specification, power planning and leakage guards.

Synthetic data only; no reviewer decision here is real.
"""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import evidence as ev
from cryptoguard.ml import experiment_spec as spec
from cryptoguard.ml import label_policy as lp
from cryptoguard.ml import power, training
from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import unblind as ub
from cryptoguard.ml.annotation import Annotation, AnnotationError
from cryptoguard.ml.evaluation import Features
from cryptoguard.ml.review_server import PackageError, ReviewApp
from cryptoguard.ml.submissions import agreement_report, check_submission
from tests.review_fixtures import ATTEMPT_FIELDS, INSUFFICIENT_FIELDS, fields, frozen
from tests.unit.test_ml_poisoning import FRIEND, LOOKALIKE, WALLET, fixture, transfer

STRANGER = "0x" + "3c" * 20
TOKEN = "0xdac17f958d2ee523a2206206994597c13d831ec7"

# --- evidence packets ------------------------------------------------------------------------


def archive_db(path: Path, rows: list[tuple[Any, ...]]) -> Path:
    con = sqlite3.connect(path)
    con.execute(
        "create table transfers (line integer primary key, block integer, tx text, token text, "
        "sender text, receiver text, sender_is_victim integer, value real, value_usd real, "
        "flags integer, intended text, first_digits integer, last_digits integer)"
    )
    con.executemany("insert into transfers values (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.commit()
    con.close()
    return path


def arow(
    line: int,
    block: int,
    tx: str,
    s: str,
    r: str,
    value: float = 1.0,
    *,
    flags: int = 1,
    intended: str | None = None,
) -> tuple[Any, ...]:
    return (line, block, tx, TOKEN, s, r, 0, value, 1.0, flags, intended, 4, 4)


ITEM = {
    "item": 1,
    "victim_event_id": "00000000000000a1",
    "wallet": WALLET,
    "address_under_review": LOOKALIKE,
    "transaction": "0xplant",
    "block": 1_000,
}


def base_rows() -> list[tuple[Any, ...]]:
    return [
        arow(1, 500, "0xa", WALLET, FRIEND, 100.0),  # the wallet pays its friend
        arow(2, 900, "0xb", LOOKALIKE, STRANGER, 0.0, flags=8),  # address elsewhere, earlier
        arow(3, 1_000, "0xplant", LOOKALIKE, WALLET, 0.0, flags=2, intended=FRIEND),
    ]


def build(tmp: Path, rows: list[tuple[Any, ...]], name: str = "a.sqlite") -> list[dict]:
    return ev.build([ITEM], archive_dbs=[archive_db(tmp / name, rows)], fixtures=[])


def test_packet_contents_and_no_source_labels(tmp_path: Path) -> None:
    (p,) = build(tmp_path, base_rows())
    assert [r["transaction"] for r in p["candidate_event"]] == ["0xplant"]
    assert p["wallet_history"]["rows_before_cutoff"] == 1
    assert p["graph_context"] == {
        "earlier_rows_of_address_with_other_wallets": 1,
        "distinct_other_wallets": 1,
    }
    assert "source_selected_rows_only" in p["coverage"]["statuses"]
    assert "unknown_signer" in p["coverage"]["statuses"]  # the archive records no signer
    text = json.dumps(p)
    for word in ("flags", "intended", "payoff", "categor"):
        assert word not in text
    assert FRIEND in text  # the friend appears only as an observed counterparty


def test_future_rows_labels_and_payoffs_never_change_a_packet(tmp_path: Path) -> None:
    """Metamorphic: rows at or after the cutoff block, a later payoff and any change to the
    source's flags or intended column leave the packet unchanged."""
    before = build(tmp_path, base_rows(), "a.sqlite")
    rows = [
        *base_rows(),
        arow(5, 1_500, "0xpay", WALLET, LOOKALIKE, 5_000.0, flags=16),  # later payoff
        arow(6, 2_000, "0xlater", LOOKALIKE, STRANGER, 0.0, flags=2),
    ]
    relabelled = [(*r[:9], 999, STRANGER, *r[11:]) for r in rows]
    assert build(tmp_path, rows, "b.sqlite") == before
    assert build(tmp_path, relabelled, "c.sqlite") == before


def test_inconsistent_cutoff_fails_and_missing_tx_is_reported(tmp_path: Path) -> None:
    rows = [r if r[0] != 3 else arow(3, 1_001, "0xplant", LOOKALIKE, WALLET) for r in base_rows()]
    with pytest.raises(ev.EvidenceError, match="cutoff"):
        build(tmp_path, rows)
    (p,) = build(tmp_path, base_rows()[:2], "d.sqlite")
    assert p["candidate_event"] == []
    assert "missing_transaction_details" in p["coverage"]["statuses"]
    assert p["transaction_semantics"]["zero_value"] is None  # unknown, never False


def test_recorded_window_uses_exact_order_and_signers() -> None:
    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 1, tx_sender=WALLET, idx=1),
            transfer(1_000, WALLET, FRIEND, 2, tx_sender=WALLET, idx=1),  # same block, earlier
            transfer(1_000, LOOKALIKE, WALLET, 0, idx=3),
            transfer(1_000, WALLET, FRIEND, 3, tx_sender=WALLET, idx=9),
        ],
        [],
    )
    plant = next(t for t in fx.transfers if t.sender == LOOKALIKE)
    item = {**ITEM, "transaction": plant.transaction_hash, "block": 1_000}
    (p,) = ev.build([item], archive_dbs=[], fixtures=[fx])
    assert p["wallet_history"]["rows_before_cutoff"] == 2  # idx 1 in-block counts, idx 9 not
    assert "complete_for_declared_scope" in p["coverage"]["statuses"]
    assert "unknown_signer" in p["coverage"]["statuses"]  # incoming log: signer not recorded
    assert p["graph_context"] is None


def test_packets_are_deterministic_and_history_is_bounded(tmp_path: Path) -> None:
    rows = [arow(10 + i, 100 + i, f"0x{i:x}", WALLET, FRIEND) for i in range(80)] + base_rows()[2:]
    a = build(tmp_path, rows, "e.sqlite")
    b = build(tmp_path, list(reversed(rows)), "f.sqlite")
    assert a == b
    assert len(a[0]["wallet_history"]["shown"]) == ev.MAX_HISTORY
    assert a[0]["wallet_history"]["rows_before_cutoff"] == 80


# --- training cohort ------------------------------------------------------------------------


def test_training_package_is_synthetic_deterministic_and_served(tmp_path: Path) -> None:
    pkg = training.make_package("A", tmp_path / "train")
    assert training.build() == training.build()
    state = ReviewApp(pkg).state()
    assert len(state["items"]) == 10
    assert all(i["description"].startswith("TRAINING") for i in state["items"])
    assert all("evidence" in i for i in state["items"])
    assert (pkg / training.NOTES).exists()
    assert training.sheet_sha256() not in {h[rs.SHEET] for h in rs.COHORTS.values()}


def test_training_submissions_can_never_be_unblinded(tmp_path: Path, monkeypatch) -> None:
    _, sample, _ = frozen(tmp_path, monkeypatch)
    with pytest.raises(KeyError):
        ub.preflight(sample, tmp_path / "w", [], cohort=training.TRAINING_VERSION)


def test_unregistered_or_tampered_evidence_is_refused(tmp_path: Path) -> None:
    pkg = training.make_package("A", tmp_path / "train")
    packets = pkg / ev.PACKETS
    packets.write_bytes(packets.read_bytes().replace(b'"block": 2000', b'"block": 1999', 1))
    with pytest.raises(PackageError, match="registered evidence"):
        ReviewApp(pkg)


def test_sessions_expire(tmp_path: Path) -> None:
    from cryptoguard.ml.review_server import make_handler  # noqa: F401 - imported for coverage

    app = ReviewApp(training.make_package("A", tmp_path / "t"), session_ttl_seconds=0)
    import threading
    import urllib.error
    import urllib.request

    from cryptoguard.ml.review_server import serve

    with app.store:
        httpd, url = serve(app)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        req = urllib.request.Request(  # noqa: S310 - loopback test
            url.split("/#")[0] + "/api/state", headers={"X-Review-Token": app.token}
        )
        try:
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(req, timeout=10)  # noqa: S310 - loopback test
            assert err.value.code == 403
        finally:
            httpd.shutdown()
            httpd.server_close()


# --- amendment 2 -----------------------------------------------------------------------------


def make(**over: Any) -> Annotation:
    return Annotation.model_validate(
        {**fields(1, "00000000000000a1"), "reviewer": "A", "revision": 1, "saved_at": "t", **over}
    )


def test_amendment_two_requires_exposure_and_reasons() -> None:
    make()
    with pytest.raises(ValueError, match="saw_later_victim_payment"):
        make(saw_later_victim_payment=None)
    with pytest.raises(ValueError, match="reason code"):
        make(reason_codes=[])
    with pytest.raises(ValueError, match="evidence references"):
        make(evidence_refs=["etherscan.io/tx/abc"])
    make(evidence_refs=["0x" + "ab" * 32, FRIEND])
    old = make(
        protocol="review-protocol/1+amendment-1",
        used_offline_evidence=None,
        saw_later_victim_payment=None,
        third_party_label_influenced=None,
        reason_codes=[],
    )
    assert old.protocol.endswith("amendment-1")  # earlier records stay loadable


# --- submission checks -------------------------------------------------------------------------


def _finalize(pkg: Path, decide) -> Path:
    app = ReviewApp(pkg)
    with app.store:
        for it in app.state()["items"]:
            app.store.save(fields(it["item"], it["victim_event_id"], decide(it["item"])))
        app.finalize()
    return pkg / "annotations" / "submission.json"


def _rehash(path: Path, body: dict[str, Any]) -> None:
    from cryptoguard.ml.annotation import _canonical, _sha

    body.pop("content_sha256", None)
    body["content_sha256"] = _sha(_canonical(body))
    path.write_text(json.dumps(body), encoding="utf-8")


def test_submission_checks_report_every_problem(tmp_path: Path, monkeypatch) -> None:
    _, sample, _ = frozen(tmp_path, monkeypatch)
    pkg = ub.make_package(sample, tmp_path / "w", "A", tmp_path / "pa")
    sub = _finalize(pkg, lambda i: ATTEMPT_FIELDS)
    assert check_submission(sub, sample, cohort=rs.SAMPLE_VERSION) == []
    assert check_submission(tmp_path / "nope.json", sample, cohort=rs.SAMPLE_VERSION)
    original = json.loads(sub.read_text(encoding="utf-8"))
    edited = tmp_path / "edited.json"

    def problems_after(change) -> str:
        body = json.loads(json.dumps(original))
        change(body)
        _rehash(edited, body)
        return " | ".join(check_submission(edited, sample, cohort=rs.SAMPLE_VERSION))

    def other_reviewer(b: dict) -> None:
        b["decisions"][1]["reviewer"] = "B"

    def repeat(b: dict) -> None:
        b["decisions"].append(b["decisions"][0])

    def drop(b: dict) -> None:
        b["decisions"].pop()

    def stale(b: dict) -> None:
        b["protocol"] = "review-protocol/1+amendment-1"

    assert "another reviewer" in problems_after(other_reviewer)
    assert "repeated" in problems_after(repeat)
    assert "without a decision" in problems_after(drop)
    assert "stale protocol" in problems_after(stale)
    edited.write_text("{broken", encoding="utf-8")
    assert check_submission(edited, sample, cohort=rs.SAMPLE_VERSION)


def test_agreement_report_needs_two_valid_distinct_reviewers(tmp_path: Path, monkeypatch) -> None:
    _, sample, m = frozen(tmp_path, monkeypatch)
    a = _finalize(
        ub.make_package(sample, tmp_path / "w", "A", tmp_path / "pa"), lambda i: ATTEMPT_FIELDS
    )
    b = _finalize(
        ub.make_package(sample, tmp_path / "w", "B", tmp_path / "pb"),
        lambda i: INSUFFICIENT_FIELDS if i <= 6 else ATTEMPT_FIELDS,
    )
    with pytest.raises(AnnotationError, match="distinct"):
        agreement_report([a], sample, cohort=rs.SAMPLE_VERSION)
    r = agreement_report([a, b], sample, cohort=rs.SAMPLE_VERSION)
    assert r["binary"]["disagreements"] == 6
    assert r["per_reviewer"]["B"]["insufficient_rate"] == pytest.approx(6 / len(m["selected"]))
    assert "consistency" in r["note"]


# --- label policy, experiment spec, power -----------------------------------------------------


@pytest.mark.parametrize(
    ("decisions", "status"),
    [
        (["confirmed_poisoning_attempt"] * 2, "reviewed_attack"),
        (["confirmed_legitimate_interaction"] * 2, "reviewed_legitimate"),
        (["confirmed_poisoning_attempt", "likely_poisoning_attempt"], "likely_attack"),
        (["confirmed_poisoning_attempt", "insufficient_evidence"], "unknown"),
        (["confirmed_poisoning_attempt", "confirmed_legitimate_interaction"], "conflicting"),
        (["likely_poisoning_attempt", "conflicting_evidence"], "conflicting"),
        (["confirmed_poisoning_attempt"], "unknown"),  # one reviewer is not enough
    ],
)
def test_label_policy(decisions: list[str], status: str) -> None:
    assert lp.resolve(decisions) == status


def test_strict_benchmark_counts_every_exclusion() -> None:
    r = lp.strict_benchmark(
        {
            "a": ["confirmed_poisoning_attempt"] * 2,
            "b": ["confirmed_legitimate_interaction"] * 2,
            "c": ["likely_poisoning_attempt"] * 2,
            "d": ["insufficient_evidence"] * 2,
        }
    )
    assert (r["eligible"], r["positives"], r["negatives"]) == (2, 1, 1)
    assert r["excluded"] == {"likely_attack": 1, "unknown": 1}


def test_spec_feature_groups_exist_and_are_clean() -> None:
    from cryptoguard.ml import candidates as cand
    from cryptoguard.ml.history import events_from_fixture

    fx = fixture(
        [
            transfer(500, WALLET, FRIEND, 1, tx_sender=WALLET, idx=1),
            transfer(900, LOOKALIKE, WALLET, 0, idx=2),
        ],
        [],
    )
    events, cov = events_from_fixture(fx)
    row = cand.event_features(cand.generate(fx)[0], events, cov).as_model_row()
    for name, cols in spec.FEATURE_GROUPS.items():
        assert set(cols) <= set(row), name
    assert spec.forbidden_columns(spec.FEATURE_GROUPS["combined"]) == []
    assert spec.forbidden_columns(("source_id", "x")) == ["source_id"]


def test_spec_stays_inactive_without_enough_reviewed_labels() -> None:
    few = {f"p{i}": 1 for i in range(10)} | {f"n{i}": 0 for i in range(40)}
    r = spec.activation_check(few, {})
    assert r["active"] is False
    assert any("reviewed_attack" in u for u in r["unmet"])
    one_group = {f"p{i}": 1 for i in range(30)} | {f"n{i}": 0 for i in range(30)}
    r = spec.activation_check(one_group, dict.fromkeys(one_group, "g"))
    assert r["active"] is False  # 60 labels from a single campaign are not 60 observations


def test_power_matches_the_closed_form_and_clustering_multiplies() -> None:
    # Zero observed false positives: the Wilson upper bound is z^2 / (n + z^2).
    z2 = 1.959963984540054**2
    for target in (0.10, 0.05, 0.01):
        assert power.negatives_needed(target, 0.0) == math.floor(z2 * (1 - target) / target) + 1
    assert power.design_effect(5, 0.25) == pytest.approx(2.0)
    row = next(r for r in power.plan_table() if r["target_fpr"] == 0.05 and r["assumed_true_fpr"])
    assert row["negatives_deff_2.0"] == 2 * row["negatives_iid"]
    with pytest.raises(ValueError, match="need"):
        power.negatives_needed(0.05, 0.06)


def test_contract_refuses_source_identifiers_as_features() -> None:
    for bad in ("source_dataset", "cohort_id", "row_index", "frame"):
        with pytest.raises(ValueError, match="outcome"):
            Features(feature_version="f", values={bad: 1.0})


def test_both_frozen_cohorts_are_one_protected_holdout(tmp_path: Path, monkeypatch) -> None:
    from cryptoguard.ml.benchmark import (
        HoldoutLeakError,
        check_training_events,
        holdout_from_sheets,
    )
    from tests.unit.test_ml_benchmark import event

    _, sample, _ = frozen(tmp_path, monkeypatch)
    sheet2 = tmp_path / "s2.jsonl"
    sheet2.write_text(
        json.dumps(
            {
                "schema_version": "review-sheet/2",
                "item": 1,
                "victim_event_id": "f" * 16,
                "wallet": STRANGER,
                "address_under_review": FRIEND,
                "transaction": "0x" + "cd" * 32,
                "block": 5,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    h = holdout_from_sheets([sample / rs.SHEET, sheet2])
    with pytest.raises(HoldoutLeakError):
        check_training_events([event(1, victim=STRANGER)], h)


# --- candidate generator audit (Phase 11.6 additions) ------------------------------------------


def test_generator_orders_several_transactions_in_one_block() -> None:
    """A payment earlier in the same block makes FRIEND a chosen counterparty for a
    lookalike later in that block, but not for one earlier in it."""
    from cryptoguard.ml import candidates as cand

    fx = fixture(
        [
            transfer(900, LOOKALIKE, WALLET, 0, idx=1),
            transfer(900, WALLET, FRIEND, 5, tx_sender=WALLET, idx=2),
            transfer(900, LOOKALIKE, WALLET, 0, idx=3, log=1),
        ],
        [],
    )
    by_idx = {c.event.planting_tx_index: set(c.methods) for c in cand.generate(fx)}
    assert by_idx[1] == {"zero_value_in"}
    assert by_idx[3] == {"zero_value_in", "lookalike_in"}


def test_a_duplicated_input_record_is_counted_not_hidden() -> None:
    from cryptoguard.ml import candidates as cand

    t = transfer(900, LOOKALIKE, WALLET, 0, idx=1)
    _, stats = cand.generate_with_stats(fixture([t, t], []))
    assert stats.candidates == 2
    assert stats.duplicate_identities == 1

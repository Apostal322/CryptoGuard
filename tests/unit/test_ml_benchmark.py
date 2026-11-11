"""Benchmark readiness and protection of the reviewed holdout (Phase 11.4).

Synthetic events only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptoguard.ml import benchmark as bm
from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.events import PoisoningEvent, quality_gates
from cryptoguard.ml.review import DECISION_TIER
from tests.review_fixtures import addr, frozen


def event(n: int, *, victim: str | None = None, tx: str | None = None) -> PoisoningEvent:
    return PoisoningEvent(
        chain_id=1,
        victim=victim or addr(70_000 + n),
        lookalike=addr(80_000 + n),
        imitated=addr(90_000 + n),
        planting_tx=tx or "0x" + f"{900_000 + n:064x}",
        planting_block=17_000_000 + n,
        planting_tx_index=None,
        planting_log_index=None,
        observation_timestamp=None,
        subtype="fake_token",
        tx_signer=None,
        log_contract=None,
        token_contract=None,
        candidate_method="synthetic",
    )


@pytest.fixture
def holdout(tmp_path: Path, monkeypatch) -> bm.Holdout:
    _, sample, _ = frozen(tmp_path, monkeypatch)
    return bm.holdout_from_sheet(sample / rs.SHEET)


def test_training_data_touching_the_holdout_is_refused(holdout: bm.Holdout, tmp_path) -> None:
    sheet = rs.read_sheet(tmp_path / "sample" / rs.SHEET)
    clean = [event(i) for i in range(5)]
    bm.check_training_events(clean, holdout)
    same_wallet = event(99, victim=sheet[0]["wallet"].upper().replace("0X", "0x"))
    same_tx = event(98, tx=sheet[1]["transaction"])
    for bad in (same_wallet, same_tx):
        with pytest.raises(bm.HoldoutLeakError, match="overlap"):
            bm.check_training_events([*clean, bad], holdout)


def test_development_use_is_recorded_and_fails_the_holdout_criterion(
    holdout: bm.Holdout, tmp_path: Path
) -> None:
    state = tmp_path / "holdout_state.json"
    ready = bm.readiness([event(1)], {}, holdout, license_ok=False, candidate_recall_measured=False)
    assert next(c for c in ready if c["criterion"].startswith("9"))["passed"] is True
    bm.mark_development(holdout, state, "detector retuned after reading review errors", "t")
    again = bm.holdout_from_sheet(tmp_path / "sample" / rs.SHEET, state)
    assert again.status == "development"
    ready = bm.readiness([event(1)], {}, again, license_ok=False, candidate_recall_measured=False)
    assert next(c for c in ready if c["criterion"].startswith("9"))["passed"] is False
    assert json.loads(state.read_text())["history"][0]["reason"].startswith("detector")


def test_current_state_is_not_a_benchmark(holdout: bm.Holdout) -> None:
    """With no verified labels the label, negative and protocol criteria fail."""
    events = [event(i) for i in range(10)]
    labels = {e.victim_event_id: "weak_attempt" for e in events}
    ready = {c["criterion"][:2].strip(): c["passed"] for c in bm.readiness(
        events, labels, holdout, license_ok=False, candidate_recall_measured=False)}  # fmt: skip
    assert ready["3"] is False
    assert ready["4"] is False
    assert ready["10"] is False
    assert bm.component_versions()["evaluation_protocol"] is None


def test_unknown_and_insufficient_are_never_negatives() -> None:
    assert DECISION_TIER["insufficient_evidence"] == "unknown"
    assert DECISION_TIER["conflicting_evidence"] == "conflicting"
    events = [event(i) for i in range(40)]
    labels = {e.victim_event_id: "unknown" for e in events}
    gate = next(g for g in quality_gates(events, labels, license_ok=False)
                if g.gate == "B_label_validity")  # fmt: skip
    assert "verified negatives 0" in gate.detail


def test_manifest_pins_components_and_changes_with_labels() -> None:
    events = [event(i) for i in range(3)]
    a = bm.benchmark_manifest(events, {events[0].victim_event_id: "weak_attempt"})
    b = bm.benchmark_manifest(events, {events[0].victim_event_id: "verified_attempt"})
    assert a["sha256"] != b["sha256"]
    assert a["components"]["task"] == "poisoning-attempt/1"
    assert a["components"]["human_labels"].startswith("review-sample/1+review-protocol/1")

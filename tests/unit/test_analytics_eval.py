"""The analytics evaluation must not see the harmful block or anything after it."""

from __future__ import annotations

import pytest

pytest.importorskip("scipy")

from cryptoguard.replay.analytics_eval import Subject, evaluate_subject
from cryptoguard.replay.models import RecordedTransfer, load_cases

CASE = "usdt-50m-poisoning-2025-12-19"


def _subject(fixture):  # type: ignore[no-untyped-def]
    case = next(c for c in load_cases() if c.manifest.case_id == CASE)
    return Subject(
        CASE, "positive", fixture, case.manifest.harm.block_number, case.manifest.harm.recipient
    )


def _fixture():  # type: ignore[no-untyped-def]
    case = next(c for c in load_cases() if c.manifest.case_id == CASE)
    assert case.fixture is not None
    return case.fixture, case.manifest.harm.block_number


def _summary(result):  # type: ignore[no-untyped-def]
    return {
        m: (r.alerts, r.alert_blocks, r.on_target, r.lead_blocks) for m, r in result.methods.items()
    }


def test_data_at_the_harm_block_cannot_change_any_method() -> None:
    fixture, harm = _fixture()
    baseline = evaluate_subject(_subject(fixture))
    noisy = fixture.model_copy(deep=True)
    for i in range(50):  # a burst at the harmful block itself
        noisy.transfers.append(
            RecordedTransfer(
                token=fixture.transfers[0].token,
                sender=f"0x{0xBEEF00 + i:040x}",
                recipient=fixture.wallet,
                value="0",
                block_number=harm,
                block_hash="0x" + "00" * 32,
                transaction_hash=f"0x{0xF00 + i:064x}",
                transaction_index=0,
                log_index=900 + i,
                tx_sender=None,
            )
        )
    assert _summary(evaluate_subject(_subject(noisy))) == _summary(baseline)


def test_existing_detector_result_matches_the_replay_engine() -> None:
    fixture, harm = _fixture()
    result = evaluate_subject(_subject(fixture))
    a = result.methods["A_existing"]
    assert a.on_target
    assert a.lead_blocks == 113  # the replay engine's lead for this case (EVALUATION.md)
    assert result.onset_block is not None
    assert result.onset_block < harm

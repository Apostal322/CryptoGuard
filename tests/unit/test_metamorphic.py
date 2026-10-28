"""Metamorphic point-in-time tests on the real replay fixtures.

Each test changes the input in a way that must not matter (future data, labels, unrelated
events, record order, a second run) and checks the semantic output is identical.
"""

from __future__ import annotations

import random

import pytest

from cryptoguard.analytics.observations import BlockRange, ObservationSet
from cryptoguard.detectors.poisoning import PoisoningConfig
from cryptoguard.replay.engine import Visibility, detector_outputs, replay
from cryptoguard.replay.models import RecordedTransfer, ReplayFixture, load_cases

CASES = ["wbtc-1155-poisoning-2024-05-03", "usdt-50m-poisoning-2025-12-19"]
# Full replays of the 340-transfer WBTC fixture take ~13 s each, so these use smaller real cases.
REPLAY_CASES = ["usdt-50m-poisoning-2025-12-19", "eth-140-poisoning-2025-08-14"]
CONFIG = PoisoningConfig()


def _case(case_id: str):  # type: ignore[no-untyped-def]
    case = next(c for c in load_cases() if c.manifest.case_id == case_id)
    assert case.fixture is not None
    return case


def _semantic(fixture: ReplayFixture, cutoff: int) -> list[tuple[object, ...]]:
    cases, _ = detector_outputs(fixture, cutoff, Visibility.ERC20_PLUS_WALLET_TRANSACTIONS, CONFIG)
    return sorted(
        (
            c.suspect,
            c.reference,
            c.rule_id,
            c.severity,
            c.confidence,
            tuple(s.code for s in c.signals),
            tuple(s.transaction_hash for s in c.signals),
        )
        for c in cases
    )


def _checkpoints(fixture: ReplayFixture, harm: int) -> list[int]:
    blocks = sorted({t.block_number for t in fixture.transfers if t.block_number < harm})
    return blocks[:: max(1, len(blocks) // 12)]


def _future_burst(fixture: ReplayFixture, after: int, n: int = 40) -> ReplayFixture:
    out = fixture.model_copy(deep=True)
    out.to_block = after + 10_000
    for i in range(n):  # a later poisoning wave and payments, all after ``after``
        out.transfers.append(
            RecordedTransfer(
                token=fixture.transfers[0].token,
                sender=fixture.wallet,
                recipient=f"0x{0xD9A1000000 + i:040x}",
                value=str(i),
                block_number=after + 1 + i,
                block_hash="0x" + "ab" * 32,
                transaction_hash=f"0x{0xF000 + i:064x}",
                transaction_index=0,
                log_index=i,
                tx_sender=fixture.wallet if i % 2 else None,
            )
        )
    return out


@pytest.mark.parametrize("case_id", CASES)
def test_future_transactions_do_not_change_earlier_outputs(case_id: str) -> None:
    case = _case(case_id)
    harm = case.manifest.harm.block_number
    noisy = _future_burst(case.fixture, harm)
    for cutoff in _checkpoints(case.fixture, harm):
        assert _semantic(noisy, cutoff) == _semantic(case.fixture, cutoff)


@pytest.mark.parametrize("case_id", REPLAY_CASES)
def test_ground_truth_labels_do_not_change_detection(case_id: str) -> None:
    import inspect

    assert "manifest" not in inspect.signature(detector_outputs).parameters
    case = _case(case_id)
    relabelled = case.manifest.model_copy(deep=True)
    relabelled.harm.recipient = "0x" + "77" * 20  # a different "attacker", never a suspect
    relabelled.intended_recipient = None
    a, b = replay(case.manifest, case.fixture), replay(relabelled, case.fixture)
    for va, vb in zip(a.results, b.results, strict=True):
        # Scoring moves (the label moved); the warned addresses before the harm do not.
        warned_a = va.other_addresses_flagged_before_harm + (va.first_warning is not None)
        warned_b = vb.other_addresses_flagged_before_harm + (vb.first_warning is not None)
        assert warned_a == warned_b
        assert va.checkpoints_evaluated == vb.checkpoints_evaluated
        assert vb.first_warning is None


@pytest.mark.parametrize("case_id", CASES)
def test_unrelated_events_do_not_alter_existing_evidence(case_id: str) -> None:
    case = _case(case_id)
    harm = case.manifest.harm.block_number
    noisy = case.fixture.model_copy(deep=True)
    for i in range(30):  # ordinary payments to unrelated, dissimilar addresses
        block = case.fixture.from_block + 50 + i * 97
        noisy.transfers.append(
            RecordedTransfer(
                token=case.fixture.transfers[0].token,
                sender=f"0x{0x1234500000 + i:040x}",
                recipient=case.fixture.wallet,
                value="1000",
                block_number=block,
                block_hash="0x" + "cd" * 32,
                transaction_hash=f"0x{0xE000 + i:064x}",
                transaction_index=0,
                log_index=900 + i,
                tx_sender=None,
            )
        )
    before = _semantic(case.fixture, harm - 1)
    after = _semantic(noisy, harm - 1)
    assert before == after


@pytest.mark.parametrize("case_id", CASES)
def test_record_order_does_not_matter(case_id: str) -> None:
    case = _case(case_id)
    shuffled = case.fixture.model_copy(deep=True)
    random.Random(7).shuffle(shuffled.transfers)
    random.Random(8).shuffle(shuffled.wallet_transactions)
    harm = case.manifest.harm.block_number
    for cutoff in _checkpoints(case.fixture, harm):
        assert _semantic(shuffled, cutoff) == _semantic(case.fixture, cutoff)


@pytest.mark.parametrize("case_id", REPLAY_CASES)
def test_replaying_twice_gives_the_same_semantic_result(case_id: str) -> None:
    case = _case(case_id)

    def semantic(r):  # type: ignore[no-untyped-def]
        return [
            (
                v.visibility,
                v.outcome,
                v.first_warning,
                v.lead_time_blocks,
                v.at_harm_block,
                v.other_addresses_flagged_before_harm,
                v.checkpoints_evaluated,
            )
            for v in r.results
        ]

    first, second = replay(case.manifest, case.fixture), replay(case.manifest, case.fixture)
    assert semantic(first) == semantic(second)
    assert first.fixture_sha256 == second.fixture_sha256
    assert [c.model_dump() for c in first.leakage_checks] == [
        c.model_dump() for c in second.leakage_checks
    ]


def test_analytics_observations_ignore_input_order_and_duplicates() -> None:
    case = _case(CASES[0])
    events = [t.as_event() for t in case.fixture.transfers]
    shuffled = events[:]
    random.Random(3).shuffle(shuffled)

    def build(evs):  # type: ignore[no-untyped-def]
        return ObservationSet.build(
            chain_id=1,
            wallet=case.fixture.wallet,
            cutoff_block=case.fixture.to_block,
            transfers=evs,
            native_sends=[],
            transfer_ranges=[BlockRange(0, case.fixture.to_block)],
            wallet_tx_ranges=[BlockRange(0, case.fixture.to_block)],
        )

    assert build(events).transfers == build(shuffled + shuffled[:20]).transfers

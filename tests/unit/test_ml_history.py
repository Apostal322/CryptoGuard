"""Wallet-history features: point in time, zero versus unknown, reverted payments, lookalikes."""

from __future__ import annotations

import random

from cryptoguard.ml.history import Coverage, WalletEvent, history_features

FRIEND = "0xd296222fb44f5ec8d9600a8c91ed70ed5657d7d5"
LOOKALIKE = "0xd296261b103d698c272887274f38d7ea8097d7d5"  # same first and last 5 hex characters
STRANGER = "0x" + "3c" * 20
FULL = Coverage(from_block=100, to_block=10_000, complete=True)


def pay(block: int, to: str, *, idx: int = 0, succeeded: bool | None = True) -> WalletEvent:
    return WalletEvent(block, idx, -1, "out", to, 10**18, wallet_signed=True, succeeded=succeeded)


def plant_in(block: int, sender: str) -> WalletEvent:
    return WalletEvent(block, 0, 3, "in", sender, 0)


def spoof_out(block: int, to: str) -> WalletEvent:
    return WalletEvent(block, 0, 4, "out", to, 0, wallet_signed=False)


def features(events: list[WalletEvent], to: str, block: int = 5_000, **kw: object):  # type: ignore[no-untyped-def]
    return history_features(
        events,
        kw.pop("coverage", FULL),
        recipient=to,
        block=block,  # type: ignore[arg-type]
        tx_index=kw.pop("tx_index", 5),
        **kw,
    )  # type: ignore[arg-type]


def test_empty_complete_history_gives_real_zeros() -> None:
    f = features([], FRIEND)
    assert f.history_status == "available"
    assert f.prior_payments_to_recipient == 0
    assert f.distinct_prior_recipients == 0
    assert f.recipient_lookalike_of_known is False
    assert f.blocks_since_first_interaction is None  # never interacted: no duration


def test_unavailable_and_partial_history_are_not_zero() -> None:
    none = features([pay(200, FRIEND)], FRIEND, coverage=None)
    assert none.history_status == "unavailable"
    assert none.prior_payments_to_recipient is None
    gap = features([pay(200, FRIEND)], FRIEND, coverage=Coverage(100, 4_000, complete=True))
    assert gap.history_status == "partial"  # scan stops before the payment's block
    assert gap.prior_payments_to_recipient is None
    incomplete = features([pay(200, FRIEND)], FRIEND, coverage=Coverage(100, 9_000, complete=False))
    assert incomplete.history_status == "partial"
    starts_later = features([], FRIEND, coverage=Coverage(6_000, 9_000, complete=True))
    assert starts_later.history_status == "unavailable"
    row, zero_row = gap.as_model_row(), features([], FRIEND).as_model_row()
    assert row["history_partial"] == 1.0
    assert row["prior_payments_to_recipient"] == -1.0
    assert zero_row["prior_payments_to_recipient"] == 0.0  # zero and unknown stay distinct


def test_one_and_several_prior_payments() -> None:
    once = features([pay(1_000, FRIEND)], FRIEND)
    assert once.prior_payments_to_recipient == 1
    assert once.blocks_since_first_interaction == 4_000
    many = features([pay(1_000, FRIEND), pay(2_000, FRIEND), pay(3_000, STRANGER)], FRIEND)
    assert many.prior_payments_to_recipient == 2
    assert many.blocks_since_last_interaction == 3_000
    assert many.distinct_prior_recipients == 2


def test_new_recipient_that_imitates_a_known_one() -> None:
    events = [pay(1_000, FRIEND), plant_in(1_500, LOOKALIKE), spoof_out(1_600, LOOKALIKE)]
    f = features(events, LOOKALIKE)
    assert f.prior_payments_to_recipient == 0
    assert f.recipient_lookalike_of_known is True
    assert f.recipient_max_affix_to_known == 10
    assert f.unsolicited_events_with_recipient == 2  # one planted in, one spoofed out
    assert f.lookalike_plantings_observed == 2
    honest = features(events, FRIEND)
    assert honest.recipient_lookalike_of_known is False


def test_reverted_payment_identifies_a_counterparty_but_is_not_a_payment() -> None:
    f = features([pay(1_000, FRIEND, succeeded=False)], FRIEND)
    assert f.prior_payments_to_recipient == 0
    assert f.distinct_prior_recipients == 1
    lookalike = features([pay(1_000, FRIEND, succeeded=False)], LOOKALIKE)
    assert lookalike.recipient_lookalike_of_known is True


def test_unknown_receipt_counts_as_executed_like_the_detector() -> None:
    assert features([pay(1_000, FRIEND, succeeded=None)], FRIEND).prior_payments_to_recipient == 1


def test_recent_new_recipient_share() -> None:
    events = [pay(1_000 + i, f"0x{i:040x}") for i in range(1, 6)] + [
        pay(2_000, "0x" + "0" * 39 + "1")
    ]
    f = features(events, FRIEND)
    assert f.recent_new_recipient_share == 5 / 6  # six payments, the last to a known address


def test_future_events_never_change_earlier_features() -> None:
    """Metamorphic: adding events after the boundary changes nothing."""
    past = [pay(1_000, FRIEND), plant_in(1_500, LOOKALIKE)]
    future = [pay(6_000, LOOKALIKE), pay(5_000, LOOKALIKE, idx=9), plant_in(7_000, STRANGER)]
    assert features(past + future, LOOKALIKE) == features(past, LOOKALIKE)


def test_event_order_does_not_matter() -> None:
    events = [
        pay(1_000, FRIEND),
        pay(2_000, STRANGER),
        plant_in(1_500, LOOKALIKE),
        pay(3_000, FRIEND, succeeded=False),
    ]
    shuffled = events[:]
    random.Random(0).shuffle(shuffled)
    assert features(shuffled, LOOKALIKE) == features(events, LOOKALIKE)


def test_same_block_ordering_depends_on_the_boundary() -> None:
    same_block = [pay(5_000, FRIEND, idx=2)]
    pre_signing = features(same_block, FRIEND, tx_index=5, boundary="pre_signing")
    pre_execution = features(same_block, FRIEND, tx_index=5, boundary="pre_execution")
    assert pre_signing.prior_payments_to_recipient == 0  # same block: not yet known
    assert pre_execution.prior_payments_to_recipient == 1  # executed before it in the block
    later_in_block = features(
        [pay(5_000, FRIEND, idx=7)], FRIEND, tx_index=5, boundary="pre_execution"
    )
    assert later_in_block.prior_payments_to_recipient == 0


def test_pre_execution_needs_coverage_of_the_payment_block() -> None:
    cov = Coverage(100, 4_999, complete=True)
    assert features([], FRIEND, coverage=cov, boundary="pre_signing").history_status == "available"
    assert features([], FRIEND, coverage=cov, boundary="pre_execution").history_status == "partial"


def test_address_casing_is_irrelevant() -> None:
    upper = [pay(1_000, FRIEND.upper().replace("0X", "0x"))]
    assert features(upper, FRIEND).prior_payments_to_recipient == 1


def test_replay_fixture_adapter_respects_coverage() -> None:
    from cryptoguard.ml.history import events_from_fixture
    from cryptoguard.replay.models import load_cases

    case = next(c for c in load_cases() if c.fixture is not None)
    events, coverage = events_from_fixture(case.fixture)
    assert coverage.from_block == case.fixture.from_block
    assert events
    assert all(e.direction in ("in", "out") for e in events)

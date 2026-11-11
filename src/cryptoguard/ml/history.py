"""Point-in-time wallet-history features for one outgoing payment (pure Python).

The Phase 11 transaction classifier sees a transaction in isolation, and its main blind spot
is a plain token transfer: by shape alone, a payment to a poisoned lookalike and an ordinary
payment look the same. What separates them is the wallet's own history: has it paid this
address before, and does the address imitate one it has paid? These features answer that,
from events strictly before an explicit observation boundary.

Data contract:

- **Input**: canonical wallet events (``WalletEvent``: direction, counterparty, position) and
  a ``Coverage`` stating which blocks were observed and whether the scan was complete. Reorg
  handling belongs to the caller: CryptoGuard's stored history is rebased on reorgs, replay
  fixtures are recorded at confirmed blocks.
- **Boundary**: ``pre_signing`` sees blocks before the payment's block only; ``pre_execution``
  also sees earlier transactions in the same block (what executed before it).
- **Zero versus unknown**: every count is ``None`` when the history is unavailable for the
  boundary, and ``history_status`` says why. A wallet with no events in a complete window
  gets real zeros. ``as_model_row`` encodes ``None`` as -1 next to explicit indicators, so
  the two states never collapse.
- **Reverted payments**: identify a counterparty the wallet chose (they count for
  "known counterparties" and lookalike checks) but never as a completed payment.
- **Cost**: O(n) in the number of events for one query.

These features are infrastructure: no independently labelled dataset with wallet histories
exists here, so no accuracy is claimed (see ML_GENERALIZATION_AUDIT.md).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from cryptoguard.detectors.poisoning import PoisoningConfig, affix_match, is_lookalike

Boundary = Literal["pre_signing", "pre_execution"]
Status = Literal["available", "partial", "unavailable"]
RECENT_PAYMENTS = 20
HISTORY_FEATURE_VERSION = "wallet-history/1"


@dataclass(frozen=True)
class WalletEvent:
    block: int
    tx_index: int
    log_index: int  # -1 for a transaction's own value (moves before its logs)
    direction: Literal["out", "in"]
    counterparty: str
    value: int
    wallet_signed: bool | None = None  # outgoing only: did the wallet sign it?
    succeeded: bool | None = None  # None = unknown (treated as executed)

    @property
    def position(self) -> tuple[int, int, int]:
        return (self.block, self.tx_index, self.log_index)


@dataclass(frozen=True)
class Coverage:
    from_block: int  # first block whose events were scanned
    to_block: int  # last block scanned (inclusive)
    complete: bool  # every relevant event in [from_block, to_block] was observed


@dataclass(frozen=True)
class HistoryFeatures:
    history_status: Status
    observed_from_block: int | None
    prior_payments_to_recipient: int | None
    prior_interactions_with_recipient: int | None
    blocks_since_first_interaction: int | None
    blocks_since_last_interaction: int | None
    distinct_prior_recipients: int | None
    recent_new_recipient_share: float | None
    recipient_lookalike_of_known: bool | None
    recipient_max_affix_to_known: int | None
    unsolicited_events_with_recipient: int | None
    lookalike_plantings_observed: int | None

    def as_model_row(self) -> dict[str, float]:
        """Numeric row: ``None`` -> -1, with indicator columns that keep zero and unknown apart."""
        row: dict[str, float] = {
            "history_available": float(self.history_status == "available"),
            "history_partial": float(self.history_status == "partial"),
        }
        for key, value in asdict(self).items():
            if key in ("history_status", "observed_from_block"):
                continue
            row[key] = -1.0 if value is None else float(value)
        return row


def _unavailable(status: Status = "unavailable") -> HistoryFeatures:
    return HistoryFeatures(status, None, None, None, None, None, None, None, None, None, None, None)


def _unsolicited(e: WalletEvent) -> bool:
    """A planting-shaped event: a zero-value transfer in, or a transfer out of the wallet that
    the wallet did not sign (the spoofed ``transferFrom`` used in address poisoning)."""
    return (e.direction == "in" and not e.value) or (
        e.direction == "out" and e.wallet_signed is False
    )


def _visible(event: WalletEvent, block: int, tx_index: int, boundary: Boundary) -> bool:
    if boundary == "pre_signing":
        return event.block < block
    return (event.block, event.tx_index) < (block, tx_index)


def history_features(
    events: list[WalletEvent],
    coverage: Coverage | None,
    *,
    recipient: str,
    block: int,
    tx_index: int,
    boundary: Boundary = "pre_signing",
    config: PoisoningConfig | None = None,
) -> HistoryFeatures:
    """Features for a payment to ``recipient`` at (``block``, ``tx_index``)."""
    config = config or PoisoningConfig()
    if coverage is None or coverage.from_block > block:
        return _unavailable()
    last_needed = block - 1 if boundary == "pre_signing" else block
    status: Status = (
        "available" if coverage.complete and coverage.to_block >= last_needed else "partial"
    )
    if status == "partial":
        # Counts would silently undercount; only say what is known to exist.
        return _unavailable("partial")
    recipient = recipient.lower()
    seen = sorted(
        (e for e in events if _visible(e, block, tx_index, boundary)), key=lambda e: e.position
    )

    paid: dict[str, int] = {}
    chosen: set[str] = set()  # counterparties the wallet itself picked (incl. reverted sends)
    first_block: int | None = None
    last_block: int | None = None
    interactions = 0
    unsolicited_with_recipient = 0
    new_flags: list[bool] = []
    for e in seen:
        party = e.counterparty.lower()
        if party == recipient:
            interactions += 1
            first_block = e.block if first_block is None else first_block
            last_block = e.block
            unsolicited_with_recipient += _unsolicited(e)
        if e.direction == "out" and e.wallet_signed is not False:
            new_flags.append(party not in chosen)
            chosen.add(party)
            if e.succeeded is not False:
                paid[party] = paid.get(party, 0) + 1

    known = chosen - {recipient}
    affixes = [sum(affix_match(recipient, k)) for k in known]
    lookalike = any(is_lookalike(recipient, k, config) for k in known)
    plantings = sum(
        1
        for e in seen
        if _unsolicited(e)
        and any(is_lookalike(e.counterparty, k, config) for k in chosen - {e.counterparty.lower()})
    )
    recent = new_flags[-RECENT_PAYMENTS:]
    return HistoryFeatures(
        history_status="available",
        observed_from_block=coverage.from_block,
        prior_payments_to_recipient=paid.get(recipient, 0),
        prior_interactions_with_recipient=interactions,
        blocks_since_first_interaction=None if first_block is None else block - first_block,
        blocks_since_last_interaction=None if last_block is None else block - last_block,
        distinct_prior_recipients=len(chosen),
        recent_new_recipient_share=(sum(recent) / len(recent)) if recent else None,
        recipient_lookalike_of_known=lookalike,
        recipient_max_affix_to_known=max(affixes, default=0),
        unsolicited_events_with_recipient=unsolicited_with_recipient,
        lookalike_plantings_observed=plantings,
    )


def events_from_fixture(fixture: object) -> tuple[list[WalletEvent], Coverage]:
    """Adapter: a recorded replay fixture (``replay.models.ReplayFixture``) as wallet events.
    Token transfers in both directions plus the wallet's own ETH-carrying transactions."""
    from cryptoguard.replay.models import ReplayFixture

    assert isinstance(fixture, ReplayFixture)
    wallet = fixture.wallet.lower()
    events: list[WalletEvent] = []
    for t in fixture.transfers:
        if t.sender.lower() == wallet:
            signer = None if t.tx_sender is None else t.tx_sender.lower() == wallet
            events.append(
                WalletEvent(
                    t.block_number,
                    t.transaction_index,
                    t.log_index,
                    "out",
                    t.recipient,
                    int(t.value),
                    wallet_signed=signer,
                )
            )
        elif t.recipient.lower() == wallet:
            events.append(
                WalletEvent(
                    t.block_number, t.transaction_index, t.log_index, "in", t.sender, int(t.value)
                )
            )
    for tx in fixture.wallet_transactions:
        if tx.to and int(tx.value):
            events.append(
                WalletEvent(
                    tx.block_number,
                    tx.transaction_index,
                    -1,
                    "out",
                    tx.to,
                    int(tx.value),
                    wallet_signed=True,
                    succeeded=tx.succeeded,
                )
            )
    complete = fixture.transfer_scan_complete and fixture.sender_lookups_skipped == 0
    return events, Coverage(fixture.from_block, fixture.to_block, complete)

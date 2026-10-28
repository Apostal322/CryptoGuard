"""Canonical poisoning attempts: one record per planting event, per victim.

An attempt is derived from the existing address-poisoning detector, never instead of it: a
planting event qualifies only if the detector, run on the victim's observations at the
cutoff, reports the counterparty as a lookalike (CG-POI-001/002/003) and the event is one of
its planting signals.

What each address field means (they are frequently different on Ethereum):

- ``signer``: the transaction's ``tx.from``, read from the chain (``eth_getTransaction``).
  It paid for the transaction. ``None`` = not looked up (e.g. incoming transfers).
- ``log_from`` / ``log_to``: the addresses *inside the emitted Transfer log*. A contract can
  emit any values it likes, so these prove only that the log exists.
- ``contract``: the contract that emitted the log (the "token").
- ``asset_movement`` is always ``"unverified"``: a Transfer log is not evidence that real
  value moved (fake tokens emit logs without balances; zero-value transfers move nothing).

The identity is deterministic: keccak(chain | tx hash | log index | victim | lookalike), so
re-ingesting the same log never yields a second attempt.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from cryptoguard.analytics.observations import ObservationSet
from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.core.hashing import keccak256
from cryptoguard.detectors.poisoning import (
    DETECTOR_ID,
    DETECTOR_VERSION,
    NATIVE_ASSET,
    PoisoningConfig,
    detect_poisoning,
)

ATTEMPT_MODEL_VERSION = "poisoning-attempt/1"

EventType = Literal[
    "spoofed_outgoing_transfer",  # Transfer "from" the victim in a tx the victim did not sign
    "zero_value_transfer",  # zero-value Transfer between victim and lookalike, not victim-signed
    "unsolicited_incoming_transfer",  # Transfer from the lookalike before the victim paid it
]
PLANTING_SIGNALS: frozenset[str] = frozenset(
    {"spoofed_outgoing_transfer", "zero_value_transfer", "unsolicited_incoming_transfer"}
)
Source = Literal["wallet_scan", "expansion"]


@dataclass(frozen=True, order=True)
class PoisoningAttempt:
    block_number: int
    transaction_index: int
    log_index: int
    attempt_id: str
    chain_id: int
    victim: str
    lookalike: str
    imitated: str | None  # the address the lookalike resembles (a payee of the victim)
    imitated_confirmed: bool  # the victim itself signed the payment to ``imitated``
    event_type: EventType
    transaction_hash: str
    block_hash: str
    contract: str  # emitting contract; NATIVE_ASSET never occurs for planting events
    log_from: str
    log_to: str
    value: int
    signer: str | None
    rule_id: str  # the victim-level rule at extraction time (CG-POI-001/002/003)
    source: Source
    detector: str = f"{DETECTOR_ID}/{DETECTOR_VERSION}"
    asset_movement: Literal["unverified"] = "unverified"


def attempt_id(chain_id: int, tx_hash: str, log_index: int, victim: str, lookalike: str) -> str:
    material = f"{chain_id}|{tx_hash.lower()}|{log_index}|{victim.lower()}|{lookalike.lower()}"
    return "0x" + keccak256(material.encode()).hex()


def _event_type(event: TransferEvent, victim: str) -> EventType | None:
    outgoing = event.sender == victim
    if outgoing and event.tx_sender == victim:
        return None  # the victim's own action is never a planting event
    if event.value == 0:
        return "zero_value_transfer"
    if outgoing:
        return "spoofed_outgoing_transfer" if event.tx_sender is not None else None
    return "unsolicited_incoming_transfer"


def extract_attempts(
    observations: ObservationSet,
    *,
    wallet_is_plain_eoa: bool | None,
    config: PoisoningConfig | None = None,
    source: Source = "wallet_scan",
) -> list[PoisoningAttempt]:
    """Planting events of every lookalike the detector reports for this wallet, at the
    observation set's cutoff (later data was already removed by ``ObservationSet``)."""
    wallet = observations.wallet
    events = observations.all_events()
    cases = detect_poisoning(
        wallet,
        list(observations.transfers),
        chain_id=observations.chain_id,
        wallet_is_plain_eoa=wallet_is_plain_eoa,
        config=config,
        native_sends=list(observations.native_sends),
    )
    out: list[PoisoningAttempt] = []
    for case in cases:
        planted = {s.transaction_hash for s in case.signals if s.code in PLANTING_SIGNALS}
        for e in events:
            if e.transaction_hash not in planted or e.token == NATIVE_ASSET:
                continue
            if case.suspect not in (e.sender, e.recipient):
                continue
            kind = _event_type(e, wallet)
            if kind is None:
                continue
            # A smart account's legitimate transfers are relayer-signed: only plain EOAs make
            # a foreign signer meaningful (the detector applies the same rule).
            if kind == "spoofed_outgoing_transfer" and wallet_is_plain_eoa is not True:
                continue
            out.append(
                PoisoningAttempt(
                    block_number=e.block_number,
                    transaction_index=e.transaction_index,
                    log_index=e.log_index,
                    attempt_id=attempt_id(
                        observations.chain_id, e.transaction_hash, e.log_index, wallet, case.suspect
                    ),
                    chain_id=observations.chain_id,
                    victim=wallet,
                    lookalike=case.suspect,
                    imitated=case.reference,
                    imitated_confirmed=case.reference_confirmed,
                    event_type=kind,
                    transaction_hash=e.transaction_hash,
                    block_hash=e.block_hash,
                    contract=e.token,
                    log_from=e.sender,
                    log_to=e.recipient,
                    value=e.value,
                    signer=e.tx_sender if e.sender == wallet else None,
                    rule_id=case.rule_id,
                    source=source,
                )
            )
    return dedupe(out)


def dedupe(attempts: Iterable[PoisoningAttempt]) -> list[PoisoningAttempt]:
    """One record per attempt id, in chain order (first occurrence wins)."""
    seen: dict[str, PoisoningAttempt] = {}
    for a in sorted(attempts):
        seen.setdefault(a.attempt_id, a)
    return sorted(seen.values())


def at_cutoff(attempts: Sequence[PoisoningAttempt], cutoff_block: int) -> list[PoisoningAttempt]:
    return [a for a in attempts if a.block_number <= cutoff_block]

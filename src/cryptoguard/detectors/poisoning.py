"""Address-poisoning detection (detector ``address-poisoning`` 1.0.0).

Attack pattern: after a wallet sends to address R, an attacker generates a vanity address C
sharing R's first and last characters (what wallets display) and plants C in the wallet's
history, e.g. with a zero-value ``transferFrom(wallet, C, 0)`` (which many tokens allow
without an allowance), a fake-token Transfer, or a dust transfer from C. The victim later
copies C from history and sends funds to the attacker.

Method (explainable, no ML):

1. **References** are recipients of the wallet's nonzero outgoing transfers that the wallet
   itself signed (``tx.from == wallet``). For smart accounts or EIP-7702-delegated wallets a
   relayer may sign, so an unknown/foreign signer leaves a reference *unconfirmed* instead
   of marking it spoofed.
2. **Similarity** compares the full 40-hex-character bodies: common prefix and suffix
   lengths. A pair matches only above configurable thresholds. A shared prefix made only of
   zeros (vanity-zero contracts are common) needs a longer suffix to count.
3. **Context signals** on the lookalike: zero-value transfers with the wallet, outgoing
   transfers the wallet did not sign, unsolicited incoming transfers, appearance soon after
   the reference was used, and the wallet itself sending to the lookalike.
4. Similarity alone is informational; similarity plus context is elevated risk; a
   wallet-signed send to the lookalike after the reference was used is possible-loss evidence.

Excluded: the wallet itself, the zero and common burn addresses, and curated known contracts.
Only ERC-20 Transfer logs are visible; native-ETH poisoning transfers are not.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.erc20 import LogPosition, TransferEvent
from cryptoguard.core.address import ZERO_ADDRESS, to_checksum_address
from cryptoguard.core.known_contracts import lookup_known_contract
from cryptoguard.detectors.base import DetectionContext
from cryptoguard.risk.rules import (
    Confidence,
    EvidenceRef,
    FindingCandidate,
    RuleEvaluation,
    Severity,
    make_candidate,
)

DETECTOR_ID = "address-poisoning"
DETECTOR_VERSION = "1.0.0"
BURN_ADDRESSES = frozenset(
    {ZERO_ADDRESS, to_checksum_address("0x000000000000000000000000000000000000dead")}
)
RECOMMENDED_ACTION = (
    "Never copy a recipient from transaction history. Before sending, compare the FULL address "
    "character by character with a trusted source (your address book, or the recipient over a "
    "separate channel). CryptoGuard never needs your keys or seed phrase."
)


@dataclass(frozen=True)
class PoisoningConfig:
    min_prefix: int = 2
    min_suffix: int = 2
    min_affix_total: int = 7
    zero_prefix_min_suffix: int = 4
    reaction_window_blocks: int = 50_400  # about one week of 12-second blocks


class PoisoningSignal(BaseModel):
    code: str
    description: str
    transaction_hash: str | None
    block_number: int | None


class PoisoningCase(BaseModel):
    suspect: str
    reference: str
    reference_confirmed: bool
    reference_first_used_block: int
    prefix_match: int
    suffix_match: int
    displayed_as: str
    random_match_odds: str
    signals: list[PoisoningSignal]
    rule_id: str
    severity: Severity
    confidence: Confidence
    explanation: str
    recommended_action: str
    first_seen_block: int


def affix_match(a: str, b: str) -> tuple[int, int]:
    """Common leading and trailing hex characters of two addresses (case-insensitive)."""
    x, y = a[2:].lower(), b[2:].lower()
    prefix = 0
    while prefix < 40 and x[prefix] == y[prefix]:
        prefix += 1
    suffix = 0
    while suffix < 40 - prefix and x[39 - suffix] == y[39 - suffix]:
        suffix += 1
    return prefix, suffix


def is_lookalike(a: str, b: str, config: PoisoningConfig) -> tuple[int, int] | None:
    if a.lower() == b.lower():
        return None
    prefix, suffix = affix_match(a, b)
    if prefix < config.min_prefix or suffix < config.min_suffix:
        return None
    if prefix + suffix < config.min_affix_total:
        return None
    if set(a[2 : 2 + prefix]) <= {"0"} and suffix < config.zero_prefix_min_suffix:
        return None  # shared run of zeros: common among vanity contracts
    return prefix, suffix


def _display(address: str, prefix: int, suffix: int) -> str:
    shown_prefix, shown_suffix = max(prefix, 4), max(suffix, 4)
    return f"{address[: 2 + shown_prefix]}…{address[-shown_suffix:]}"


@dataclass(frozen=True)
class _Signer:
    """Who caused an outgoing transfer: True = the wallet, False = someone else, None = unknown."""

    plain_eoa: bool | None

    def wallet_signed(self, event: TransferEvent, wallet: str) -> bool | None:
        if event.tx_sender is None:
            return None
        if event.tx_sender == wallet:
            return True
        # A smart account or delegated EOA can be driven by a relayer's transaction.
        return False if self.plain_eoa else None


def _event_signal(code: str, description: str, event: TransferEvent) -> PoisoningSignal:
    return PoisoningSignal(
        code=code,
        description=description,
        transaction_hash=event.transaction_hash,
        block_number=event.block_number,
    )


def detect_poisoning(
    wallet: str,
    transfers: Sequence[TransferEvent],
    *,
    chain_id: int,
    wallet_is_plain_eoa: bool | None,
    config: PoisoningConfig | None = None,
) -> list[PoisoningCase]:
    config = config or PoisoningConfig()
    wallet = to_checksum_address(wallet)
    signer = _Signer(wallet_is_plain_eoa)
    ordered = sorted(transfers, key=lambda e: e.position)

    # 1. References: first nonzero outgoing send to each recipient, confirmed if wallet-signed.
    references: dict[str, tuple[TransferEvent, bool]] = {}
    for e in ordered:
        if e.sender != wallet or e.value == 0 or e.recipient in BURN_ADDRESSES | {wallet}:
            continue
        signed = signer.wallet_signed(e, wallet)
        if signed is False:
            continue  # spoofed: not a reference
        first, confirmed = references.get(e.recipient, (e, False))
        references[e.recipient] = (first, confirmed or signed is True)

    # 2. Counterparties and their transfers with the wallet.
    by_party: dict[str, list[TransferEvent]] = defaultdict(list)
    for e in ordered:
        other = e.recipient if e.sender == wallet else e.sender
        if other == wallet or other in BURN_ADDRESSES:
            continue
        if lookup_known_contract(chain_id, other) is not None:
            continue
        by_party[other].append(e)

    cases: list[PoisoningCase] = []
    for suspect in sorted(by_party):
        events = by_party[suspect]
        best: tuple[int, str, tuple[int, int]] | None = None
        for reference in sorted(references):
            match = is_lookalike(suspect, reference, config)
            if match is None:
                continue
            first_ref = references[reference][0].position
            if suspect in references and references[suspect][0].position < first_ref:
                continue  # the suspect was in use first: it is the original, not the copy
            score = match[0] + match[1]
            if best is None or score > best[0]:
                best = (score, reference, match)
        if best is None:
            continue
        _, reference, (prefix, suffix) = best
        case = _assess(
            wallet,
            suspect,
            reference,
            references[reference],
            prefix,
            suffix,
            events,
            signer,
            config,
        )
        if case is not None:
            cases.append(case)
    return cases


def _assess(
    wallet: str,
    suspect: str,
    reference: str,
    ref_info: tuple[TransferEvent, bool],
    prefix: int,
    suffix: int,
    events: list[TransferEvent],
    signer: _Signer,
    config: PoisoningConfig,
) -> PoisoningCase | None:
    ref_event, ref_confirmed = ref_info
    ref_pos: LogPosition = ref_event.position
    signals: list[PoisoningSignal] = []
    context_before: list[LogPosition] = []
    wallet_sends: list[TransferEvent] = []
    unconfirmed_sends: list[TransferEvent] = []
    first_signed_send: LogPosition | None = None

    for e in events:
        outgoing = e.sender == wallet
        signed = signer.wallet_signed(e, wallet) if outgoing else None
        if e.value == 0:
            signals.append(
                _event_signal(
                    "zero_value_transfer",
                    f"Zero-value {'outgoing' if outgoing else 'incoming'} transfer of token "
                    f"{e.token} between the wallet and the lookalike"
                    + (
                        f", in a transaction signed by {e.tx_sender}, not by the wallet"
                        if outgoing and signed is False
                        else ""
                    )
                    + ".",
                    e,
                )
            )
            context_before.append(e.position)
        elif outgoing and signed is False:
            signals.append(
                _event_signal(
                    "spoofed_outgoing_transfer",
                    f"Transfer of {e.value} base units of {e.token} 'from' the wallet to the "
                    f"lookalike in a transaction signed by {e.tx_sender}, not by the wallet.",
                    e,
                )
            )
            context_before.append(e.position)
        elif not outgoing and (first_signed_send is None or e.position < first_signed_send):
            signals.append(
                _event_signal(
                    "unsolicited_incoming_transfer",
                    f"Incoming {e.value} base units of {e.token} from the lookalike before the "
                    "wallet ever sent to it.",
                    e,
                )
            )
            context_before.append(e.position)
        elif outgoing and signed is True:
            if first_signed_send is None:
                first_signed_send = e.position
            if e.position > ref_pos:
                wallet_sends.append(e)
        elif outgoing and signed is None and e.position > ref_pos:
            unconfirmed_sends.append(e)

    first_seen = events[0]
    if (
        first_seen.position > ref_pos
        and first_seen.block_number - ref_event.block_number <= config.reaction_window_blocks
    ):
        signals.append(
            _event_signal(
                "appeared_soon_after_reference_use",
                f"First appeared {first_seen.block_number - ref_event.block_number} blocks "
                f"after the wallet first sent to {reference}.",
                first_seen,
            )
        )
    for e in unconfirmed_sends:
        signals.append(
            _event_signal(
                "unverified_outgoing_to_lookalike",
                "Nonzero outgoing transfer to the lookalike whose signer could not be verified.",
                e,
            )
        )

    odds = 16 ** (prefix + suffix)
    displayed = _display(suspect, prefix, suffix)
    similarity = (
        f"{suspect} shares its first {prefix} and last {suffix} hex characters with "
        f"{reference}, an address the wallet "
        + ("sent to (signed by the wallet)" if ref_confirmed else "appears to have sent to")
        + f" at block {ref_event.block_number}. Both display similarly (e.g. {displayed}). A "
        f"random address matches this closely with probability about 1 in {odds:,}."
    )

    if wallet_sends:
        loss = wallet_sends[0]
        prior_context = any(p < loss.position for p in context_before)
        rule_id = "CG-POI-003"
        severity = Severity.CRITICAL_EVIDENCE if prior_context else Severity.ELEVATED_RISK
        confidence = Confidence.MEDIUM if prior_context else Confidence.LOW
        signals.append(
            _event_signal(
                "wallet_sent_to_lookalike",
                f"The wallet signed a transfer of {loss.value} base units of {loss.token} to the "
                "lookalike.",
                loss,
            )
        )
        tail = (
            " Poisoning activity preceded this send, which matches the address-poisoning loss "
            "pattern. Verify whether the recipient was intended."
            if prior_context
            else " No poisoning step is visible in ERC-20 history (it may have been a native ETH "
            "transfer, which is not indexed); the recipient may also be intended."
        )
        explanation = similarity + tail
    elif context_before:
        rule_id = "CG-POI-001"
        severity = Severity.ELEVATED_RISK
        strong = {"zero_value_transfer", "spoofed_outgoing_transfer"}
        confidence = (
            Confidence.HIGH if any(s.code in strong for s in signals) else Confidence.MEDIUM
        )
        explanation = similarity + (
            " The lookalike was planted with poisoning-style transfers; this is a warning, not "
            "proof of fraud."
        )
    else:
        rule_id = "CG-POI-002"
        severity = Severity.INFORMATIONAL
        confidence = Confidence.LOW
        explanation = similarity + " No other poisoning context was observed."

    return PoisoningCase(
        suspect=suspect,
        reference=reference,
        reference_confirmed=ref_confirmed,
        reference_first_used_block=ref_event.block_number,
        prefix_match=prefix,
        suffix_match=suffix,
        displayed_as=displayed,
        random_match_odds=f"1 in {odds:,}",
        signals=sorted(signals, key=lambda s: (s.block_number or 0, s.code)),
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        explanation=explanation,
        recommended_action=RECOMMENDED_ACTION,
        first_seen_block=first_seen.block_number,
    )


def to_candidate(case: PoisoningCase, *, chain_id: int, wallet: str) -> FindingCandidate:
    return make_candidate(
        case.rule_id,
        chain_id=chain_id,
        wallet=wallet,
        subject=f"poisoning:{case.suspect}",
        severity=case.severity,
        confidence=case.confidence,
        title=f"Possible address poisoning: {case.displayed_as} imitates {case.reference}",
        explanation=f"{case.explanation} {case.recommended_action}",
        evidence=[
            EvidenceRef(
                kind="transfer_event",
                description=f"{s.code}: {s.description}",
                block_number=s.block_number or case.first_seen_block,
                transaction_hash=s.transaction_hash,
            )
            for s in case.signals[:10]
        ],
    )


class PoisoningDetector:
    detector_id = DETECTOR_ID
    version = DETECTOR_VERSION

    def __init__(self, config: PoisoningConfig | None = None) -> None:
        self.config = config or PoisoningConfig()

    def analyze(self, context: DetectionContext) -> RuleEvaluation:
        plain = context.state.account.code_kind is CodeKind.NO_CODE
        cases = detect_poisoning(
            context.wallet,
            context.transfers,
            chain_id=context.chain_id,
            wallet_is_plain_eoa=plain,
            config=self.config,
        )
        return RuleEvaluation(
            candidates=[
                to_candidate(c, chain_id=context.chain_id, wallet=context.wallet) for c in cases
            ]
        )

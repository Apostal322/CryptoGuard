"""Address-poisoning detector: representative attacks and benign look-alike situations."""

from __future__ import annotations

import random

import pytest

from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.hashing import keccak256
from cryptoguard.detectors.poisoning import (
    PoisoningCase,
    PoisoningConfig,
    affix_match,
    detect_poisoning,
    is_lookalike,
    to_candidate,
)
from cryptoguard.risk.rules import Confidence, Severity

WALLET = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
FAKE_TOKEN = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
DEAD = "0x000000000000000000000000000000000000dEaD"


def addr(body: str) -> str:
    assert len(body) == 40, body
    return to_checksum_address("0x" + body)


REAL = addr("a1b2c3" + "1" * 28 + "d4e5f6")  # the friend the wallet actually pays
FAKE = addr("a1b2c" + "9" * 30 + "4e5f6")  # attacker's vanity copy: first 5 / last 5 match
ATTACKER_SIGNER = addr("7" * 40)


def tx(block: int, index: int) -> str:
    return "0x" + keccak256(f"{block}:{index}".encode()).hex()


def transfer(
    sender: str,
    recipient: str,
    value: int,
    block: int,
    *,
    signer: str | None,
    token: str = TOKEN,
    index: int = 0,
) -> TransferEvent:
    return TransferEvent(
        token=token,
        sender=sender,
        recipient=recipient,
        value=value,
        block_number=block,
        block_hash="0x" + keccak256(f"block:{block}".encode()).hex(),
        transaction_hash=tx(block, index),
        transaction_index=0,
        log_index=index,
        tx_sender=signer,
    )


def pay_friend(block: int = 100) -> TransferEvent:
    return transfer(WALLET, REAL, 100, block, signer=WALLET)


def detect(transfers: list[TransferEvent], **kwargs: object) -> list[PoisoningCase]:
    return detect_poisoning(
        WALLET,
        transfers,
        chain_id=1,
        wallet_is_plain_eoa=kwargs.pop("plain", True),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def codes(case: PoisoningCase) -> set[str]:
    return {s.code for s in case.signals}


# -- similarity ------------------------------------------------------------------------------


def test_affix_match_uses_full_addresses() -> None:
    assert affix_match(REAL, FAKE) == (5, 5)
    assert affix_match(REAL, REAL.lower()) == (40, 0)
    # Same first 4 / last 4 as displayed by wallets, but the full comparison sees more.
    assert affix_match(addr("abcd" + "0" * 32 + "1234"), addr("abcd" + "f" * 32 + "1234")) == (4, 4)


def test_lookalike_thresholds_are_configurable() -> None:
    assert is_lookalike(FAKE, REAL, PoisoningConfig()) == (5, 5)
    assert is_lookalike(FAKE, REAL, PoisoningConfig(min_affix_total=11)) is None
    assert is_lookalike(REAL, REAL.lower(), PoisoningConfig()) is None  # identical, not a copy
    three_three = addr("a1b" + "9" * 34 + "5f6")
    assert is_lookalike(three_three, REAL, PoisoningConfig()) is None  # 6 chars: coincidence


# -- representative attacks ------------------------------------------------------------------


def test_zero_value_transfer_from_poisoner() -> None:
    [case] = detect([pay_friend(), transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER)])
    assert (case.rule_id, case.severity, case.confidence) == (
        "CG-POI-001",
        Severity.ELEVATED_RISK,
        Confidence.HIGH,
    )
    assert (case.suspect, case.reference) == (FAKE, REAL)
    assert (case.prefix_match, case.suffix_match) == (5, 5)
    assert case.random_match_odds == f"1 in {16**10:,}"
    assert codes(case) == {"zero_value_transfer", "appeared_soon_after_reference_use"}
    zero = next(s for s in case.signals if s.code == "zero_value_transfer")
    assert ATTACKER_SIGNER in zero.description
    assert zero.transaction_hash == tx(110, 0)
    assert "seed phrase" in case.recommended_action
    assert "private key" not in case.recommended_action.lower().replace("never needs", "")


def test_unsolicited_dust_from_lookalike() -> None:
    [case] = detect([pay_friend(), transfer(FAKE, WALLET, 1, 105, signer=FAKE)])
    assert case.rule_id == "CG-POI-001"
    assert case.confidence is Confidence.MEDIUM
    assert "unsolicited_incoming_transfer" in codes(case)


def test_fake_token_spoofed_outgoing_transfer() -> None:
    spoof = transfer(WALLET, FAKE, 500, 120, signer=ATTACKER_SIGNER, token=FAKE_TOKEN)
    [case] = detect([pay_friend(), spoof])
    assert case.rule_id == "CG-POI-001"
    assert case.confidence is Confidence.HIGH
    assert "spoofed_outgoing_transfer" in codes(case)
    assert FAKE not in {c.reference for c in detect([pay_friend(), spoof])}  # never a reference


def test_victim_sent_funds_to_lookalike() -> None:
    [case] = detect(
        [
            pay_friend(),
            transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
            transfer(WALLET, FAKE, 10_000, 130, signer=WALLET),
        ]
    )
    assert (case.rule_id, case.severity, case.confidence) == (
        "CG-POI-003",
        Severity.CRITICAL_EVIDENCE,
        Confidence.MEDIUM,
    )
    assert "wallet_sent_to_lookalike" in codes(case)


def test_send_to_lookalike_without_visible_poisoning_is_lower_confidence() -> None:
    [case] = detect([pay_friend(), transfer(WALLET, FAKE, 10_000, 130, signer=WALLET)])
    assert (case.rule_id, case.severity, case.confidence) == (
        "CG-POI-003",
        Severity.ELEVATED_RISK,
        Confidence.LOW,
    )
    assert "native ETH" in case.explanation


def test_similarity_without_context_is_informational() -> None:
    [case] = detect([pay_friend(), transfer(WALLET, FAKE, 5, 130, signer=None)])  # signer unknown
    assert (case.rule_id, case.severity, case.confidence) == (
        "CG-POI-002",
        Severity.INFORMATIONAL,
        Confidence.LOW,
    )
    assert "unverified_outgoing_to_lookalike" in codes(case)


def test_candidate_carries_evidence_and_stable_fingerprint() -> None:
    [case] = detect([pay_friend(), transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER)])
    a = to_candidate(case, chain_id=1, wallet=WALLET)
    b = to_candidate(case, chain_id=1, wallet=WALLET)
    assert a.fingerprint == b.fingerprint
    assert a.subject == f"poisoning:{FAKE}"
    assert all(e.kind == "transfer_event" for e in a.evidence)
    assert any(e.transaction_hash == tx(110, 0) for e in a.evidence)


# -- false-positive prevention ---------------------------------------------------------------


def test_legitimate_repeated_recipient() -> None:
    assert detect([pay_friend(100 + i) for i in range(10)]) == []


def test_coincidental_small_similarity() -> None:
    near = addr("a1b" + "9" * 34 + "5f6")  # 3 + 3 characters
    assert detect([pay_friend(), transfer(WALLET, near, 0, 110, signer=ATTACKER_SIGNER)]) == []


def test_benign_zero_value_transfer_from_unrelated_address() -> None:
    unrelated = addr("0123456789" * 4)
    assert detect([pay_friend(), transfer(unrelated, WALLET, 0, 110, signer=unrelated)]) == []


def test_known_contract_is_never_a_suspect() -> None:
    ref = addr("000000000022" + "1" * 23 + "78ba3")  # crafted to resemble Permit2
    assert is_lookalike(PERMIT2, ref, PoisoningConfig()) is not None
    events = [
        transfer(WALLET, ref, 5, 100, signer=WALLET),
        transfer(PERMIT2, WALLET, 0, 110, signer=WALLET),
    ]
    assert detect(events) == []


def test_burn_and_zero_addresses_are_excluded() -> None:
    dead_like = addr("0000000000000000000000000000000000" + "11dead")
    events = [
        transfer(WALLET, DEAD, 5, 100, signer=WALLET),
        transfer(dead_like, WALLET, 0, 110, signer=dead_like),
    ]
    assert detect(events) == []


def test_self_transfers_are_ignored() -> None:
    assert detect([transfer(WALLET, WALLET, 5, 100, signer=WALLET)]) == []


def test_unrelated_token_spam() -> None:
    rng = random.Random(7)
    spam = [
        transfer(
            addr(f"{rng.getrandbits(160):040x}"),
            WALLET,
            1,
            110 + i,
            signer=None,
            token=FAKE_TOKEN,
            index=i,
        )
        for i in range(200)
    ]
    assert detect([pay_friend(), *spam]) == []


@pytest.mark.parametrize(("suffix", "expected"), [("ab", 0), ("abcd", 1)])
def test_shared_zero_prefix_needs_a_longer_suffix(suffix: str, expected: int) -> None:
    ref = addr("00000000" + "1" * (32 - len(suffix)) + suffix)
    other = addr("00000000" + "9" * (32 - len(suffix)) + suffix)
    events = [
        transfer(WALLET, ref, 5, 100, signer=WALLET),
        transfer(WALLET, other, 0, 110, signer=ATTACKER_SIGNER),
    ]
    assert len(detect(events)) == expected


def test_smart_account_relayer_is_not_treated_as_spoofing() -> None:
    relayer = addr("8" * 40)
    events = [
        transfer(WALLET, REAL, 100, 100, signer=relayer),  # relayed but genuine
        transfer(WALLET, FAKE, 50, 120, signer=relayer),
    ]
    [case] = detect(events, plain=False)
    assert "spoofed_outgoing_transfer" not in codes(case)
    assert case.rule_id == "CG-POI-002"
    assert case.reference_confirmed is False
    # The same history from a plain EOA *is* spoofing.
    assert detect(events, plain=True) == []  # REAL is then spoofed too, so no reference


def test_original_address_is_not_flagged_as_copy() -> None:
    events = [
        transfer(WALLET, FAKE, 100, 50, signer=WALLET),  # used first: the original
        transfer(WALLET, REAL, 100, 100, signer=WALLET),
    ]
    [case] = detect(events)
    assert case.suspect == REAL  # the later one is compared against the earlier
    assert case.severity is not Severity.CRITICAL_EVIDENCE


def test_detection_is_order_independent() -> None:
    events = [
        pay_friend(),
        transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER),
        transfer(FAKE, WALLET, 1, 111, signer=FAKE),
    ]
    shuffled = list(reversed(events))
    assert detect(events) == detect(shuffled)

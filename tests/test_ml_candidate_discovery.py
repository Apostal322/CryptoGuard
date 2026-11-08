"""Protocol 12.4, population P1: synthetic mechanism cases A-L for shadow candidate
discovery. Every expected output is written out by hand from the case's definition, not
computed by the code under test. Synthetic: software correctness only, never a rate."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.replay.models import (
    RecordedNativeInbound,
    RecordedTransaction,
    RecordedTransfer,
    ReplayFixture,
    UnattributedInbound,
)
from cryptoguard.replay.observation import (
    OBSERVATION_V2,
    CategoryCoverage,
    ObservationCoverage,
    legacy_coverage,
)

VICTIM = "0x" + "c" * 40
REF = "0xabcde" + "1" * 30 + "54321"  # the recipient the victim paid
LOOK_NATIVE = "0xabcde" + "9" * 30 + "54321"  # prefix 5 + suffix 5 with REF
LOOK_TOKEN = "0xabcd" + "8" * 32 + "4321"  # prefix 4 + suffix 4 with REF
LOOK_2 = "0xabc" + "7" * 33 + "4321"  # prefix 3 + suffix 4
SHORT = "0xab" + "6" * 36 + "21"  # prefix 2 + suffix 2: below MIN_AFFIX 6
ATTACKER = "0x" + "a1" * 20
OTHER_SIGNER = "0x" + "b2" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # reviewed stablecoin
FAKE_TOKEN = "0x" + "f" * 40  # any unreviewed contract; its symbol is never consulted


def _tx(n: int) -> str:
    return "0x" + f"{n:064x}"


def transfer(
    sender: str,
    recipient: str,
    value: int,
    *,
    block: int,
    signer: str | None,
    token: str = USDT,
    tx: int = 0,
    tx_index: int = 0,
    log: int = 0,
) -> RecordedTransfer:
    return RecordedTransfer(
        token=token,
        sender=sender,
        recipient=recipient,
        value=str(value),
        block_number=block,
        block_hash=_tx(block),
        transaction_hash=_tx(tx or block * 10 + log),
        transaction_index=tx_index,
        log_index=log,
        tx_sender=signer,
    )


def native_in(
    sender: str,
    value: int,
    *,
    block: int,
    succeeded: bool | None = True,
    tx_index: int = 0,
    tx: int = 0,
) -> RecordedNativeInbound:
    return RecordedNativeInbound(
        transaction_hash=_tx(tx or block * 10 + 7),
        block_number=block,
        transaction_index=tx_index,
        sender=sender,
        value=str(value),
        succeeded=succeeded,
    )


def full_coverage(**override: str) -> ObservationCoverage:
    """observation/2 coverage: every collectable category complete, by construction."""
    cats = {
        k: CategoryCoverage(status="complete")
        for k in (
            "erc20_transfer_logs",
            "erc20_outgoing_signers",
            "erc721_transfer_logs",
            "malformed_transfer_logs",
            "wallet_signed_transactions",
            "native_inbound_external",
            "native_inbound_unattributed",
        )
    }
    cats["erc1155_transfer_logs"] = CategoryCoverage(status="not_collected")
    cats["native_inbound_zero_value"] = CategoryCoverage(status="partial")
    cats["internal_value_transfers"] = CategoryCoverage(status="unsupported")
    for k, v in override.items():
        cats[k] = CategoryCoverage(status=v)  # type: ignore[arg-type]
    return ObservationCoverage(schema_version=OBSERVATION_V2, categories=cats)


def fixture(
    transfers: list[RecordedTransfer] | None = None,
    *,
    native: list[RecordedNativeInbound] | None = None,
    unattributed: list[UnattributedInbound] | None = None,
    v2: bool = True,
    reference: bool = True,
    complete: bool = True,
    wallet: str = VICTIM,
    **coverage: str,
) -> ReplayFixture:
    ref = [transfer(wallet, REF, 1_000_000, block=1100, signer=wallet, log=1)] if reference else []
    return ReplayFixture(
        case_id="synthetic",
        chain_id=1,
        wallet=wallet,
        from_block=1000,
        to_block=2000,
        recorded_at=datetime(2026, 11, 4, tzinfo=UTC),
        recorded_with="synthetic",
        rpc_requests=0,
        transfer_scan_complete=complete,
        sender_lookups_skipped=0,
        method=["synthetic"],
        wallet_code_hex={"1000": "0x", "1999": "0x"},
        block_timestamps={},
        transfers=ref + (transfers or []),
        wallet_transactions=[],
        observation=(
            full_coverage(**({} if complete else {"erc20_transfer_logs": "partial"}), **coverage)
            if v2
            else None
        ),
        native_inbound=(native or []) if v2 else None,
        unattributed_inbound=(unattributed or []) if v2 else None,
        nft_transfers=[] if v2 else None,
    )


END = (2001, 0)  # cutoff after the whole window


def found(fx: ReplayFixture, variant: cd.Variant = "C1", cutoff: tuple[int, int] = END) -> Any:
    return cd.discover(fx, cutoff=cutoff, variant=variant)


# --- Case A: native ETH dust poisoning -----------------------------------------------------


def test_case_a_native_dust_is_invisible_to_c0_and_found_by_c1_only_after_planting() -> None:
    fx = fixture(native=[native_in(LOOK_NATIVE, 1_000, block=1200)])
    assert found(fx, "C0").lookalikes == set()
    [c] = found(fx).candidates
    assert (c.lookalike, c.imitated, c.methods, c.kind) == (
        LOOK_NATIVE,
        REF,
        ("lookalike_in",),
        "native",
    )
    assert c.affix == (5, 5)
    assert found(fx, cutoff=(1200, 0)).lookalikes == set()  # not yet observable


# --- Case B: spoofed transferFrom ---------------------------------------------------------


def test_case_b_spoofed_transfer_is_flagged_and_never_becomes_a_reference() -> None:
    fx = fixture([transfer(VICTIM, LOOK_TOKEN, 0, block=1300, signer=ATTACKER)])
    for variant in ("C0", "C1"):
        [c] = found(fx, variant).candidates  # type: ignore[arg-type]
        assert (c.lookalike, "spoofed_out" in c.methods) == (LOOK_TOKEN, True)
    screen = cd.screen_payment(fx, recipient=LOOK_TOKEN, cutoff=END)
    assert (screen.flagged, screen.imitated) == (True, REF)  # not "a reference the wallet chose"


# --- Case C: fake-token planting ----------------------------------------------------------


def test_case_c_fake_token_is_untrusted_by_contract_not_by_symbol() -> None:
    fx = fixture(
        [transfer(LOOK_TOKEN, VICTIM, 5 * 10**18, block=1300, signer=ATTACKER, token=FAKE_TOKEN)]
    )
    [c] = found(fx).candidates
    assert c.methods == ("lookalike_in", "untrusted_token_in")


# --- Case D: zero-value token transfer ----------------------------------------------------


def test_case_d_zero_value_transfer_from_a_lookalike() -> None:
    fx = fixture([transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER)])
    [c0] = found(fx, "C0").candidates
    [c1] = found(fx).candidates
    assert c0.methods == c1.methods == ("zero_value_in", "lookalike_in")


# --- Case E: missing history --------------------------------------------------------------


def test_case_e_missing_history_abstains_instead_of_claiming_no_references() -> None:
    fx = fixture(
        [transfer(LOOK_TOKEN, VICTIM, 5 * 10**6, block=1300, signer=ATTACKER)], reference=False
    )
    res = found(fx, "C2")
    assert res.lookalikes == set()
    assert res.abstain is not None
    assert "not evidence of no earlier recipients" in res.abstain
    assert cd.screen_payment(fx, recipient=LOOK_TOKEN, cutoff=END).flagged is None
    partial = fixture(complete=False)
    assert found(partial, "C2").abstain is not None
    assert "insufficient history" in str(found(partial, "C2").abstain)
    assert cd.screen_payment(partial, recipient=LOOK_TOKEN, cutoff=END).flagged is None


# --- Case F: multiple lookalikes ----------------------------------------------------------


def test_case_f_competing_lookalikes_keep_their_identity_and_order() -> None:
    fx = fixture(
        [
            transfer(LOOK_2, VICTIM, 0, block=1250, signer=OTHER_SIGNER),
            transfer(LOOK_TOKEN, VICTIM, 0, block=1200, signer=ATTACKER),
        ]
    )
    res = found(fx)
    assert [c.lookalike for c in res.candidates] == [LOOK_TOKEN, LOOK_2]  # chain order
    assert {c.imitated for c in res.candidates} == {REF}


# --- Case G: reverted transaction ---------------------------------------------------------


def test_case_g_reverted_native_transfer_is_not_evidence() -> None:
    fx = fixture(native=[native_in(LOOK_NATIVE, 1_000, block=1200, succeeded=False)])
    assert found(fx).lookalikes == set()


# --- Case H: contract-mediated value ------------------------------------------------------


def test_case_h_unattributed_inbound_is_reported_but_names_no_one() -> None:
    fx = fixture(unattributed=[UnattributedInbound(block_number=1400, value="5")])
    res = found(fx)
    assert res.candidates == []
    assert res.unattributed_inbound_blocks == [1400]
    assert res.coverage["internal_value_transfers"] == "unsupported"


# --- Case I: same-block ordering ----------------------------------------------------------


def test_case_i_a_later_transaction_in_the_cutoff_block_is_not_seen() -> None:
    fx = fixture(
        [
            transfer(LOOK_TOKEN, VICTIM, 0, block=1500, signer=ATTACKER, tx_index=7),
            transfer(LOOK_2, VICTIM, 0, block=1500, signer=ATTACKER, tx_index=3, log=2),
        ]
    )
    assert found(fx, cutoff=(1500, 5)).lookalikes == {LOOK_2}
    assert found(fx, cutoff=(1500, 0)).lookalikes == set()


# --- Case J: public token contract reuse --------------------------------------------------


def test_case_j_a_shared_token_contract_links_nothing_a_shared_signer_does() -> None:
    w2 = "0x" + "d" * 40

    def one(wallet: str, signer: str) -> tuple[str, ReplayFixture, Any]:
        fx = fixture([transfer(LOOK_TOKEN, wallet, 0, block=1300, signer=signer)], wallet=wallet)
        return wallet, fx, found(fx)

    assert cd.signer_links([one(VICTIM, ATTACKER), one(w2, OTHER_SIGNER)]) == []
    assert cd.signer_links([one(VICTIM, ATTACKER), one(w2, ATTACKER)]) == [(VICTIM, w2, ATTACKER)]


# --- Case K: no poisoning -----------------------------------------------------------------


def test_case_k_a_short_shared_affix_is_not_a_candidate() -> None:
    fx = fixture(native=[native_in(SHORT, 5 * 10**18, block=1200)])
    assert found(fx).candidates == []
    assert cd.screen_payment(fx, recipient=SHORT, cutoff=END).flagged is False


# --- Case L: duplicate ingestion ----------------------------------------------------------


def test_case_l_the_same_event_from_two_sources_counts_once() -> None:
    dup = native_in(LOOK_NATIVE, 1_000, block=1200)
    fx = fixture(native=[dup, dup])
    assert len(found(fx).candidates) == 1
    log = transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER)
    assert len(cd.observations(fixture([log, log]))) == 2  # the reference and one planting


# --- completeness and point-in-time invariants --------------------------------------------


def test_legacy_fixtures_declare_native_and_nft_as_not_collected() -> None:
    cov = legacy_coverage(fixture(v2=False))
    assert cov.status("erc20_transfer_logs") == "complete"
    assert cov.status("native_inbound_external") == "not_collected"
    assert cov.status("erc721_transfer_logs") == "not_collected"
    assert cov.status("internal_value_transfers") == "unsupported"
    assert cov.status("not a category") == "unknown"


def test_scoped_history_never_reports_unobserved_inbound_as_zero() -> None:
    legacy = cd.scoped_history(fixture(v2=False), recipient=LOOK_TOKEN, block=1900, tx_index=0)
    assert legacy["prior_interactions_with_recipient"] is None  # /1 would say 0
    assert legacy["inbound_scope_complete"] is False
    assert legacy["distinct_prior_recipients"] == 1  # outgoing scope is complete
    v2 = cd.scoped_history(fixture(), recipient=LOOK_TOKEN, block=1900, tx_index=0)
    assert v2["prior_interactions_with_recipient"] == 0  # a real zero in the declared scope
    assert v2["inbound_scope"] == cd.INBOUND_SCOPE


def test_later_events_do_not_change_discovery_at_an_earlier_cutoff() -> None:
    base = [transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER)]
    later = [
        transfer(LOOK_2, VICTIM, 0, block=1700, signer=ATTACKER),  # a later planting
        transfer(VICTIM, LOOK_TOKEN, 9 * 10**6, block=1800, signer=VICTIM),  # the theft
    ]
    cut = (1600, 0)
    a = found(fixture(base), cutoff=cut)
    b = found(fixture(base + later, native=[native_in(LOOK_NATIVE, 5, block=1650)]), cutoff=cut)
    assert a.candidates == b.candidates


def test_record_order_does_not_change_the_output() -> None:
    rows = [
        transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER),
        transfer(LOOK_2, VICTIM, 0, block=1250, signer=OTHER_SIGNER),
    ]
    assert found(fixture(rows)).candidates == found(fixture(rows[::-1])).candidates


def test_c1_on_a_legacy_fixture_equals_c0() -> None:
    fx = fixture(
        [
            transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER),
            transfer(VICTIM, LOOK_2, 0, block=1400, signer=ATTACKER),
        ],
        v2=False,
    )
    assert cd.compare(found(fx, "C0"), found(fx, "C1")) == {
        "added": [],
        "removed": [],
        "kept": sorted([LOOK_TOKEN, LOOK_2]),
    }


@pytest.mark.parametrize("variant", ["C0", "C1", "C2"])
def test_discovery_takes_no_outcome_input(variant: cd.Variant) -> None:
    import inspect

    params = set(inspect.signature(cd.discover).parameters)
    assert params == {"fixture", "cutoff", "variant"}  # no victim label, no theft recipient
    assert found(fixture(), variant).version == cd.DISCOVERY_VERSION


def test_a_reverted_own_send_still_counts_as_a_reference() -> None:
    fx = fixture(reference=False).model_copy(
        update={
            "wallet_transactions": [
                RecordedTransaction(
                    transaction_hash=_tx(1),
                    block_number=1100,
                    transaction_index=0,
                    nonce=0,
                    to=REF,
                    value=str(10**18),
                    succeeded=False,
                )
            ]
        }
    )
    assert cd.screen_payment(fx, recipient=LOOK_NATIVE, cutoff=END).flagged is True


def test_frozen_items_are_caught_in_every_observed_class() -> None:
    from cryptoguard.ml.observation_study import touches_frozen_any

    clean = fixture(native=[native_in(LOOK_NATIVE, 1, block=1200)])
    assert not touches_frozen_any(clean, (frozenset({SHORT}), frozenset()))
    assert touches_frozen_any(clean, (frozenset({LOOK_NATIVE}), frozenset()))  # native sender
    paid = fixture(reference=False).model_copy(
        update={
            "wallet_transactions": [
                RecordedTransaction(
                    transaction_hash=_tx(9),
                    block_number=1100,
                    transaction_index=0,
                    nonce=0,
                    to=SHORT,
                    value="1",
                )
            ]
        }
    )
    assert touches_frozen_any(paid, (frozenset({SHORT}), frozenset()))  # native recipient


def test_zero_value_native_floods_cannot_become_unrestricted_warnings() -> None:
    """Anyone can send a wallet 0 ETH. C1 (coverage measurement, C0's rules unchanged)
    lists each such event; C2 (warning-facing) keeps only native senders that imitate one of
    the wallet's own references, one candidate per lookalike; the production detector reads
    no native inbound at all."""
    from cryptoguard.detectors.poisoning import PoisoningConfig
    from cryptoguard.replay.engine import Visibility, detector_outputs

    strangers = [
        native_in("0x" + f"{i:040x}", 0, block=1200 + i % 700, tx=10_000 + i) for i in range(1000)
    ]
    lookalike = [native_in(LOOK_NATIVE, 0, block=1300 + i, tx=20_000 + i) for i in range(3)]
    fx = fixture(native=strangers + lookalike)
    c1 = found(fx, "C1")
    assert len(c1.candidates) == 1003  # listed, never weighted: a volume measurement
    c2 = found(fx, "C2")
    [only] = c2.candidates
    assert (only.lookalike, only.imitated, only.events) == (LOOK_NATIVE, REF, 3)
    assert only.position == (1300, 0, -1)  # the earliest evidence is kept
    full = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS
    cfg = PoisoningConfig()
    legacy = fx.model_copy(update={"native_inbound": None, "observation": None})
    assert detector_outputs(fx, 2000, full, cfg) == detector_outputs(legacy, 2000, full, cfg)


def test_c2_keeps_one_candidate_per_lookalike_across_classes() -> None:
    fx = fixture(
        [
            transfer(LOOK_TOKEN, VICTIM, 0, block=1300, signer=ATTACKER),
            transfer(LOOK_TOKEN, VICTIM, 0, block=1310, signer=ATTACKER, log=3),
        ],
        native=[native_in(LOOK_TOKEN, 0, block=1320)],
    )
    assert len(found(fx, "C1").candidates) == 3
    [c] = found(fx, "C2").candidates
    assert (c.lookalike, c.events, c.position[0]) == (LOOK_TOKEN, 3, 1300)
    assert c.methods == ("zero_value_in", "lookalike_in")

from __future__ import annotations

import inspect
from datetime import UTC, date, datetime

import pytest

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.replay.engine import Visibility, detector_outputs, replay
from cryptoguard.replay.models import (
    EvaluationWindow,
    HarmfulTransaction,
    IncidentManifest,
    RecordedTransaction,
    RecordedTransfer,
    ReplayFixture,
    SourceRef,
    load_cases,
)
from cryptoguard.replay.record import record_fixture
from cryptoguard.replay.report import render_markdown
from tests.fakenode import FakeNode
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET, transfer

HARM = 130


def manifest(**overrides: object) -> IncidentManifest:
    base: dict[str, object] = {
        "case_id": "synthetic",
        "title": "Synthetic poisoning",
        "category": "address_poisoning",
        "chain_id": 1,
        "summary": "Test case.",
        "first_public_report": date(2026, 1, 1),
        "public_sources": [
            SourceRef(
                publisher="test",
                title="t",
                url="https://example.org",
                accessed=date(2026, 1, 1),
                used_for="test",
            )
        ],
        "victim": WALLET,
        "intended_recipient": REAL,
        "harm": HarmfulTransaction(
            transaction_hash="0x" + "ab" * 32,
            block_number=HARM,
            recipient=FAKE,
            token=TOKEN,
            value_base_units="1000",
            description="test",
        ),
        "evaluation": EvaluationWindow(from_block=90, to_block=HARM, rationale="test"),
        "onchain_verification": [],
        "ground_truth_limitations": [],
    }
    base.update(overrides)
    return IncidentManifest.model_validate(base)


def fixture(transfers, wallet_txs=(), to_block: int = HARM) -> ReplayFixture:  # type: ignore[no-untyped-def]
    blocks = {t.block_number for t in transfers} | {t.block_number for t in wallet_txs} | {HARM}
    return ReplayFixture(
        case_id="synthetic",
        chain_id=1,
        wallet=WALLET,
        from_block=90,
        to_block=to_block,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        recorded_with="test",
        rpc_requests=0,
        transfer_scan_complete=True,
        sender_lookups_skipped=0,
        method=[],
        wallet_code_hex={"90": "0x", str(HARM - 1): "0x"},
        block_timestamps={str(b): 1_700_000_000 + b * 12 for b in blocks},
        transfers=[RecordedTransfer.from_event(t) for t in transfers],
        wallet_transactions=list(wallet_txs),
    )


def native(to: str, block: int, value: int = 10**16) -> RecordedTransaction:
    return RecordedTransaction(
        transaction_hash="0x" + f"{block:064x}",
        block_number=block,
        transaction_index=0,
        nonce=block,
        to=to,
        value=str(value),
    )


POISON = transfer(WALLET, FAKE, 0, 110, signer=ATTACKER_SIGNER)
THEFT = transfer(WALLET, FAKE, 1000, HARM, signer=WALLET)


def outcome(result, visibility: Visibility):  # type: ignore[no-untyped-def]
    return next(v for v in result.results if v.visibility is visibility)


def test_early_warning_with_lead_time() -> None:
    result = replay(
        manifest(), fixture([transfer(WALLET, REAL, 5, 100, signer=WALLET), POISON, THEFT])
    )
    erc20 = outcome(result, Visibility.ERC20_ONLY)
    assert erc20.outcome == "early_warning"
    assert erc20.first_warning is not None
    assert erc20.first_warning.block_number == 110
    assert erc20.first_warning.rule_id == "CG-POI-001"
    assert (erc20.lead_time_blocks, erc20.lead_time_seconds) == (20, 240)
    assert erc20.at_harm_block is not None
    assert erc20.at_harm_block.rule_id == "CG-POI-003"
    assert all(c.passed for c in result.leakage_checks)
    assert result.rpc_requests_during_replay == 0


def test_native_reference_needs_wallet_transaction_visibility() -> None:
    # Mirrors the WBTC case: the wallet paid the real address in native ETH.
    result = replay(manifest(), fixture([POISON, THEFT], wallet_txs=[native(REAL, 100)]))
    assert outcome(result, Visibility.ERC20_ONLY).outcome == "not_detected"
    with_txs = outcome(result, Visibility.ERC20_PLUS_WALLET_TRANSACTIONS)
    assert with_txs.outcome == "early_warning"
    assert with_txs.first_warning is not None
    assert with_txs.first_warning.block_number == 110


def test_post_incident_only_is_not_an_early_warning() -> None:
    result = replay(manifest(), fixture([transfer(WALLET, REAL, 5, 100, signer=WALLET), THEFT]))
    erc20 = outcome(result, Visibility.ERC20_ONLY)
    assert erc20.outcome == "post_incident_only"
    assert erc20.first_warning is None
    assert erc20.lead_time_blocks is None
    assert "not an early" in erc20.explanation


def test_detector_never_sees_data_after_the_cutoff() -> None:
    fx = fixture([transfer(WALLET, REAL, 5, 100, signer=WALLET), POISON, THEFT])
    for cutoff in (100, 109, 110, 129):
        _, newest = detector_outputs(fx, cutoff, Visibility.ERC20_ONLY, _config())
        assert newest <= cutoff
    early, _ = detector_outputs(fx, 109, Visibility.ERC20_ONLY, _config())
    assert early == []  # the poison at block 110 is not visible at 109


def test_ground_truth_is_not_a_detector_input() -> None:
    assert "manifest" not in inspect.signature(detector_outputs).parameters
    fx = fixture([transfer(WALLET, REAL, 5, 100, signer=WALLET), POISON, THEFT])
    honest = replay(manifest(), fx)
    # Pointing the label at a different address changes the score, not the detector's output.
    relabelled = replay(manifest(harm=manifest().harm.model_copy(update={"recipient": REAL})), fx)
    assert outcome(honest, Visibility.ERC20_ONLY).outcome == "early_warning"
    assert outcome(relabelled, Visibility.ERC20_ONLY).outcome == "not_detected"
    assert outcome(relabelled, Visibility.ERC20_ONLY).other_addresses_flagged_before_harm == 1


def test_fixture_with_post_harm_data_fails_the_leakage_check() -> None:
    late = transfer(WALLET, REAL, 5, HARM + 5, signer=WALLET)
    result = replay(manifest(), fixture([POISON, THEFT, late], to_block=HARM + 5))
    check = next(c for c in result.leakage_checks if c.check == "fixture_ends_at_harm_block")
    assert not check.passed


def test_replay_is_deterministic_and_report_uses_real_numbers() -> None:
    fx = fixture([transfer(WALLET, REAL, 5, 100, signer=WALLET), POISON, THEFT])
    a, b = replay(manifest(), fx), replay(manifest(), fx)
    volatile = {"runtime_ms", "peak_memory_kib"}
    assert a.model_dump(exclude=volatile) == b.model_dump(exclude=volatile)
    report = render_markdown([a], generated_at=datetime(2026, 1, 1, tzinfo=UTC))
    assert fx.sha256() in report
    assert "Early warning" in report
    assert "20 blocks (~4 min)" in report
    assert "PASS `inputs_bounded_by_cutoff`" in report


def test_mismatched_case_is_rejected() -> None:
    with pytest.raises(ValueError, match="different cases"):
        replay(manifest(case_id="other"), fixture([POISON]))


def test_packaged_manifest_is_valid() -> None:
    cases = {c.manifest.case_id: c for c in load_cases()}
    case = cases["wbtc-1155-poisoning-2024-05-03"]
    assert case.manifest.harm.block_number == case.manifest.evaluation.to_block
    assert case.manifest.public_sources
    if case.fixture is not None:
        assert case.fixture.to_block == case.manifest.harm.block_number


async def test_recorder_finds_every_wallet_transaction(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.add_token(TOKEN)
    node.head = 200
    node.send_native(WALLET, REAL, 10**16, block=100)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=110, signer=ATTACKER_SIGNER)
    theft = node.add_transfer_log(TOKEN, WALLET, FAKE, 1000, block=HARM, signer=WALLET)
    node.send_native(WALLET, TOKEN, 0, block=HARM)  # the theft's own transaction (to the token)
    recorded = await record_fixture(provider, manifest(), chunk_blocks=50)
    assert [t.block_number for t in recorded.wallet_transactions] == [100, HARM]
    assert recorded.wallet_transactions[0].to == REAL
    assert {t.transaction_hash for t in recorded.transfers} >= {theft["transactionHash"]}
    assert recorded.wallet_code_hex == {"90": "0x", str(HARM - 1): "0x"}
    assert str(HARM) in recorded.block_timestamps
    result = replay(manifest(), recorded)
    assert outcome(result, Visibility.ERC20_PLUS_WALLET_TRANSACTIONS).outcome == "early_warning"


def _config():  # type: ignore[no-untyped-def]
    from cryptoguard.detectors.poisoning import PoisoningConfig

    return PoisoningConfig()

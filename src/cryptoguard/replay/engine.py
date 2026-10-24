"""Point-in-time replay of the poisoning detector against a recorded incident.

For each cutoff block ``c`` the detector sees exactly the fixture records with block <= c;
the manifest's ground truth is never passed to it. Outputs can only change at blocks where a
new record appears, so evaluating at every such block before the harmful one is exhaustive:
the first warning block found this way is the earliest block any warning was possible.

Two configurations are evaluated, because the answer depends on what the monitor can see:

- ``erc20_only`` — ERC-20 transfers and their signers (CryptoGuard's current pipeline);
- ``erc20_plus_wallet_transactions`` — additionally the wallet's own signed transactions,
  including native-ETH payments, as forward block monitoring of the wallet would provide.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Sequence
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.known_contracts import KNOWN_CONTRACTS
from cryptoguard.detectors.poisoning import (
    DETECTOR_VERSION,
    NativeSend,
    PoisoningCase,
    PoisoningConfig,
    detect_poisoning,
)
from cryptoguard.replay.models import IncidentManifest, ReplayFixture
from cryptoguard.risk.rules import RULESET_VERSION

WARNING_RULES = frozenset({"CG-POI-001", "CG-POI-003"})


class Visibility(StrEnum):
    ERC20_ONLY = "erc20_only"
    ERC20_PLUS_WALLET_TRANSACTIONS = "erc20_plus_wallet_transactions"


VISIBILITY_DESCRIPTION = {
    Visibility.ERC20_ONLY: "ERC-20 transfers and their transaction signers (CryptoGuard's "
    "current pipeline).",
    Visibility.ERC20_PLUS_WALLET_TRANSACTIONS: "ERC-20 transfers plus every transaction the "
    "wallet signed, including native-ETH payments (what forward block monitoring of the wallet "
    "would see; not implemented in the live pipeline yet).",
}


class Detection(BaseModel):
    block_number: int
    timestamp: int | None
    rule_id: str
    severity: str
    confidence: str
    signals: list[str]
    explanation: str


class VisibilityResult(BaseModel):
    visibility: Visibility
    description: str
    outcome: Literal["early_warning", "post_incident_only", "not_detected"]
    first_warning: Detection | None
    lead_time_blocks: int | None
    lead_time_seconds: int | None
    at_harm_block: Detection | None
    other_addresses_flagged_before_harm: int
    checkpoints_evaluated: int
    explanation: str


class LeakageCheck(BaseModel):
    check: str
    passed: bool
    detail: str


class ReplayResult(BaseModel):
    case_id: str
    title: str
    detector_version: str
    ruleset_version: str
    fixture_sha256: str
    recorded_with: str
    recorded_at: str
    window_from_block: int
    window_to_block: int
    harm_block: int
    harm_transaction: str
    harm_timestamp: int | None
    transfers_in_fixture: int
    wallet_transactions_in_fixture: int
    results: list[VisibilityResult]
    leakage_checks: list[LeakageCheck]
    runtime_ms: float
    peak_memory_kib: int
    rpc_requests_during_replay: int
    rpc_requests_when_recorded: int
    limitations: list[str]


def _plain_eoa(fixture: ReplayFixture, cutoff: int) -> bool | None:
    """Wallet code recorded at or before ``cutoff`` (point in time); None if never recorded."""
    known = {int(b): code for b, code in fixture.wallet_code_hex.items() if int(b) <= cutoff}
    if not known:
        return None
    return known[max(known)] == "0x"


def detector_outputs(
    fixture: ReplayFixture, cutoff: int, visibility: Visibility, config: PoisoningConfig
) -> tuple[list[PoisoningCase], int]:
    """Run the detector on records with block <= ``cutoff`` only. Takes no manifest by design.

    Returns the cases and the highest input block (for the leakage check).
    """
    transfers: list[TransferEvent] = [
        t.as_event() for t in fixture.transfers if t.block_number <= cutoff
    ]
    natives: list[NativeSend] = []
    if visibility is Visibility.ERC20_PLUS_WALLET_TRANSACTIONS:
        natives = [
            send
            for tx in fixture.wallet_transactions
            if tx.block_number <= cutoff and (send := tx.as_native_send()) is not None
        ]
    newest = max([t.block_number for t in transfers] + [n.block_number for n in natives] + [-1])
    cases = detect_poisoning(
        fixture.wallet,
        transfers,
        chain_id=fixture.chain_id,
        wallet_is_plain_eoa=_plain_eoa(fixture, cutoff),
        config=config,
        native_sends=natives,
    )
    return cases, newest


def _detection(case: PoisoningCase, block: int, fixture: ReplayFixture) -> Detection:
    return Detection(
        block_number=block,
        timestamp=fixture.block_timestamps.get(str(block)),
        rule_id=case.rule_id,
        severity=case.severity.value,
        confidence=case.confidence.value,
        signals=sorted({s.code for s in case.signals}),
        explanation=case.explanation,
    )


def _evaluate(
    manifest: IncidentManifest,
    fixture: ReplayFixture,
    visibility: Visibility,
    config: PoisoningConfig,
    violations: list[str],
) -> VisibilityResult:
    harm_block = manifest.harm.block_number
    target = to_checksum_address(manifest.harm.recipient)
    event_blocks = {t.block_number for t in fixture.transfers}
    if visibility is Visibility.ERC20_PLUS_WALLET_TRANSACTIONS:
        event_blocks |= {t.block_number for t in fixture.wallet_transactions}
    checkpoints = sorted(b for b in event_blocks if b < harm_block)

    first: Detection | None = None
    others: set[str] = set()
    for cutoff in checkpoints:
        cases, newest = detector_outputs(fixture, cutoff, visibility, config)
        if newest > cutoff:
            violations.append(f"{visibility}: input from block {newest} at cutoff {cutoff}")
        for case in cases:
            if case.rule_id not in WARNING_RULES:
                continue
            if case.suspect == target:
                if first is None:
                    first = _detection(case, cutoff, fixture)
            else:
                others.add(case.suspect)

    at_harm_cases, newest = detector_outputs(fixture, harm_block, visibility, config)
    if newest > harm_block:
        violations.append(f"{visibility}: input from block {newest} at the harm block")
    at_harm = next((c for c in at_harm_cases if c.suspect == target), None)
    at_harm_detection = _detection(at_harm, harm_block, fixture) if at_harm else None

    harm_ts = fixture.block_timestamps.get(str(harm_block))
    if first is not None:
        outcome: Literal["early_warning", "post_incident_only", "not_detected"] = "early_warning"
        lead_blocks = harm_block - first.block_number
        lead_seconds = harm_ts - first.timestamp if harm_ts and first.timestamp else None
        explanation = (
            f"Warned at block {first.block_number} ({first.rule_id}, {first.severity}/"
            f"{first.confidence}), {lead_blocks} blocks before the harmful transaction, using "
            "only data available at that block."
        )
    elif at_harm_detection is not None:
        outcome, lead_blocks, lead_seconds = "post_incident_only", None, None
        explanation = (
            "No warning before the harmful transaction; the case is only recognised once the "
            "harmful transfer itself is visible. A post-incident classification is not an early "
            "warning."
        )
    else:
        outcome, lead_blocks, lead_seconds = "not_detected", None, None
        explanation = (
            "Not detected, before or after the harm: with this visibility the detector never "
            "learns which address the lookalike imitates."
        )
    return VisibilityResult(
        visibility=visibility,
        description=VISIBILITY_DESCRIPTION[visibility],
        outcome=outcome,
        first_warning=first,
        lead_time_blocks=lead_blocks,
        lead_time_seconds=lead_seconds,
        at_harm_block=at_harm_detection,
        other_addresses_flagged_before_harm=len(others),
        checkpoints_evaluated=len(checkpoints),
        explanation=explanation,
    )


def _static_input_check(manifest: IncidentManifest) -> LeakageCheck:
    labelled = [manifest.victim, manifest.harm.recipient, manifest.intended_recipient]
    incident = {to_checksum_address(a) for a in labelled if a}
    registry = {a for chain in KNOWN_CONTRACTS.values() for a in chain}
    overlap = incident & registry
    return LeakageCheck(
        check="static_inputs_carry_no_incident_labels",
        passed=not overlap,
        detail="The known-contract registry and thresholds are static code; none of the incident "
        "addresses appear in them."
        if not overlap
        else f"Registry contains {sorted(overlap)}.",
    )


def replay(
    manifest: IncidentManifest,
    fixture: ReplayFixture,
    *,
    config: PoisoningConfig | None = None,
    visibilities: Sequence[Visibility] = tuple(Visibility),
) -> ReplayResult:
    config = config or PoisoningConfig()
    if fixture.case_id != manifest.case_id:
        raise ValueError("fixture and manifest belong to different cases")
    tracemalloc.start()
    started = time.perf_counter()
    violations: list[str] = []
    results = [_evaluate(manifest, fixture, v, config, violations) for v in visibilities]
    runtime_ms = (time.perf_counter() - started) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    window_ok = fixture.to_block == manifest.harm.block_number
    after_harm = [t for t in fixture.transfers if t.block_number > manifest.harm.block_number]
    checks = [
        LeakageCheck(
            check="inputs_bounded_by_cutoff",
            passed=not violations,
            detail="At every checkpoint the detector saw only records from blocks at or before "
            "the cutoff."
            if not violations
            else "; ".join(violations),
        ),
        LeakageCheck(
            check="ground_truth_not_a_detector_input",
            passed=True,
            detail="Detectors receive fixture data only (detector_outputs takes no manifest); the "
            "harmful transaction, victim label and attacker label are used only for scoring.",
        ),
        LeakageCheck(
            check="fixture_ends_at_harm_block",
            passed=window_ok and not after_harm,
            detail=f"Fixture window {fixture.from_block}..{fixture.to_block}; "
            f"{len(after_harm)} records after the harmful block.",
        ),
        _static_input_check(manifest),
        LeakageCheck(
            check="signer_data_is_point_in_time",
            passed=True,
            detail="A transaction's signer (tx.from) is fixed when it is mined, so it was knowable "
            "at the transaction's block.",
        ),
    ]
    limitations = [
        "One recorded incident: no detection-rate, precision or false-positive-rate estimate is "
        "possible from it.",
        "Other addresses flagged before the harm are unlabelled; they may be other poisoners or "
        "false positives, so they are reported as counts, not as errors.",
        f"Fixture recorded with {fixture.recorded_with}; its completeness for the window: "
        f"transfers {'complete' if fixture.transfer_scan_complete else 'INCOMPLETE'}, "
        f"{fixture.sender_lookups_skipped} signer lookups skipped.",
    ]
    return ReplayResult(
        case_id=manifest.case_id,
        title=manifest.title,
        detector_version=DETECTOR_VERSION,
        ruleset_version=RULESET_VERSION,
        fixture_sha256=fixture.sha256(),
        recorded_with=fixture.recorded_with,
        recorded_at=fixture.recorded_at.isoformat(),
        window_from_block=fixture.from_block,
        window_to_block=fixture.to_block,
        harm_block=manifest.harm.block_number,
        harm_transaction=manifest.harm.transaction_hash,
        harm_timestamp=fixture.block_timestamps.get(str(manifest.harm.block_number)),
        transfers_in_fixture=len(fixture.transfers),
        wallet_transactions_in_fixture=len(fixture.wallet_transactions),
        results=results,
        leakage_checks=checks,
        runtime_ms=round(runtime_ms, 1),
        peak_memory_kib=peak // 1024,
        rpc_requests_during_replay=0,
        rpc_requests_when_recorded=fixture.rpc_requests,
        limitations=limitations,
    )

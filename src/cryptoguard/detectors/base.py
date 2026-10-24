"""Detector interface and the runner that merges detector outputs.

Detectors are synchronous and pure: all chain I/O happens before, in the services that build
the ``DetectionContext``. That keeps detectors deterministic and replayable on stored data.
They emit candidates only; lifecycle, persistence and presentation happen elsewhere.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from cryptoguard.blockchain.erc20 import TransferEvent

if TYPE_CHECKING:
    from cryptoguard.detectors.poisoning import NativeSend
from cryptoguard.history.state import WalletState
from cryptoguard.risk.rules import RuleEvaluation, evaluate


@dataclass(frozen=True)
class DetectionContext:
    chain_id: int
    wallet: str
    block: int
    state: WalletState
    transfers: Sequence[TransferEvent]
    transfer_coverage: str
    native_sends: Sequence[NativeSend] = ()


class Detector(Protocol):
    detector_id: str
    version: str

    def analyze(self, context: DetectionContext) -> RuleEvaluation: ...


def run_detectors(detectors: Sequence[Detector], context: DetectionContext) -> RuleEvaluation:
    merged = RuleEvaluation(candidates=[])
    seen: set[str] = set()
    for detector in detectors:
        result = detector.analyze(context)
        for candidate in result.candidates:
            if candidate.fingerprint not in seen:
                seen.add(candidate.fingerprint)
                merged.candidates.append(candidate)
        merged.unverifiable_subjects |= result.unverifiable_subjects
    merged.candidates.sort(key=lambda c: c.fingerprint)
    return merged


class StateRulesDetector:
    """The Phase 3 state rules (approvals, delegation, account code)."""

    detector_id = "state-rules"
    version = "1.0.0"

    def analyze(self, context: DetectionContext) -> RuleEvaluation:
        return evaluate(
            context.state, chain_id=context.chain_id, wallet=context.wallet, block=context.block
        )

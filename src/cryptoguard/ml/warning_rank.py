"""Experimental recency ordering of production poisoning warnings (``poisoning-warning-rank/1``).

Research only (protocol ``docs/ml/protocol-12.2.md``). It takes the cases the production
detector already produced and returns a display order for an experimental view. It never:
- adds, removes, merges or re-tiers a warning;
- changes a case object;
- emits a probability.

Ordering:
1. Severity tier, as production assigns it.
2. Within a tier, the recency of the warning's latest *planting* signal at or before the
   cutoff: a zero-value transfer, a spoofed outgoing transfer or an unsolicited incoming
   transfer. The wallet's own sends never count.
3. Ties break by prefix+suffix descending, then by address. That is deterministic for
   display only; the research metric keeps them tied.

A warning with no planting signal at or before the cutoff has no recency basis. It is placed
after its tier's warnings that have one, in baseline order, and is marked
``no_recency_basis``.

Phase 12.1 found that recency put the paid lookalike first among *source-flagged* candidates
in a payoff-conditioned archive. That is a retrospective ranking result, not a fraud
probability and not a validated warning policy.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from cryptoguard.detectors.poisoning import PoisoningCase
from cryptoguard.risk.rules import Severity

RANK_VERSION = "poisoning-warning-rank/1"
TASK = "poisoning-warning-rank/1"
PLANTING_SIGNALS = frozenset(
    {"zero_value_transfer", "spoofed_outgoing_transfer", "unsolicited_incoming_transfer"}
)
TIER = {
    Severity.CRITICAL_EVIDENCE: 4,
    Severity.ELEVATED_RISK: 3,
    Severity.REVIEW_RECOMMENDED: 2,
    Severity.INFORMATIONAL: 1,
    Severity.UNKNOWN: 0,
}

Basis = Literal["latest_planting_signal", "no_recency_basis"]


@dataclass(frozen=True)
class RankedWarning:
    rank: int  # 1-based display position in the experimental view
    suspect: str
    rule_id: str
    severity: str
    similarity: int  # prefix + suffix, as production computed it
    basis: Basis
    basis_block: int | None
    basis_transaction: str | None
    blocks_before_cutoff: int | None
    cutoff_block: int
    algorithm: str
    explanation: str


def planting_basis(case: PoisoningCase, cutoff: int) -> tuple[int, str | None] | None:
    """The block (and transaction) of the case's latest planting signal at or before
    ``cutoff``; ``None`` when it has none."""
    best: tuple[int, str | None] | None = None
    for s in case.signals:
        if s.code not in PLANTING_SIGNALS or s.block_number is None or s.block_number > cutoff:
            continue
        if best is None or s.block_number > best[0]:
            best = (s.block_number, s.transaction_hash)
    return best


def baseline_score(case: PoisoningCase) -> tuple[int, int]:
    """OP0: severity tier, then prefix+suffix."""
    return TIER.get(case.severity, 0), case.prefix_match + case.suffix_match


def recency_score(case: PoisoningCase, cutoff: int) -> tuple[int, int, int]:
    """OP1: severity tier, then (has a basis, basis block); without a basis, prefix+suffix
    keeps the baseline order behind the warnings that have one."""
    tier, similarity = baseline_score(case)
    basis = planting_basis(case, cutoff)
    return (tier, 1, basis[0]) if basis is not None else (tier, 0, similarity)


def rank_warnings(cases: Sequence[PoisoningCase], cutoff: int) -> list[RankedWarning]:
    """Every case, in the experimental order. The output always holds the same warnings as
    the input."""
    keyed = sorted(
        cases,
        key=lambda c: (
            recency_score(c, cutoff),
            c.prefix_match + c.suffix_match,
            # Address ascending as the final tie-break: negate via sort on a reversed key.
            tuple(-ord(ch) for ch in c.suspect.lower()),
        ),
        reverse=True,
    )
    out: list[RankedWarning] = []
    for i, c in enumerate(keyed, start=1):
        basis = planting_basis(c, cutoff)
        if basis is None:
            explanation = (
                "No planting signal at or before the cutoff: kept in baseline order within "
                "its severity tier."
            )
        else:
            explanation = (
                f"Within severity {c.severity.value}, ordered by its latest planting signal at "
                f"block {basis[0]} ({cutoff - basis[0]} blocks before cutoff {cutoff}), "
                f"against {len(cases) - 1} other warning(s). Ordering only: not a probability."
            )
        out.append(
            RankedWarning(
                rank=i,
                suspect=c.suspect,
                rule_id=c.rule_id,
                severity=c.severity.value,
                similarity=c.prefix_match + c.suffix_match,
                basis="no_recency_basis" if basis is None else "latest_planting_signal",
                basis_block=None if basis is None else basis[0],
                basis_transaction=None if basis is None else basis[1],
                blocks_before_cutoff=None if basis is None else cutoff - basis[0],
                cutoff_block=cutoff,
                algorithm=RANK_VERSION,
                explanation=explanation,
            )
        )
    return out

"""Phase 12.2: the symmetric confirmation rule, the experimental warning ranking and its
safety invariants, and the decision rules. Synthetic rows and packaged fixtures only."""

from __future__ import annotations

import itertools

import pytest

from cryptoguard.detectors.poisoning import PoisoningCase, PoisoningSignal
from cryptoguard.ml import lookalike_ranking as lr
from cryptoguard.ml import recency_validation as rv
from cryptoguard.ml import warning_rank as wr
from cryptoguard.ml.tsuchiya_archive import INTENDED, PAYOFF, TINY, ZERO
from cryptoguard.risk.rules import Confidence, Severity

V = "0x" + "a" * 40
R = "0x1234" + "0" * 32 + "abcd"
L1 = "0x1234" + "f" * 32 + "abcd"
L2 = "0x1234" + "e" * 32 + "abcd"
L3 = "0x1234" + "d" * 32 + "abcd"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
_line = itertools.count(1)


def row(block: int, sender: str, receiver: str, flags: int, intended: str | None = None) -> lr.Row:
    n = next(_line)
    siv = sender == V
    return lr.Row(n, block, f"0x{n:064x}", USDT, sender, receiver, siv, None, flags, intended)


def episode(rows: list[lr.Row]) -> lr.Episode:
    ep = lr.episode_from_rows(V, rows)
    assert isinstance(ep, lr.Episode), ep
    return ep


# --- the symmetric confirmation rule -----------------------------------------------------


def test_confirmation_rule_needs_a_planting_strictly_after_an_intended_transfer() -> None:
    ep = episode(
        [
            row(100, V, R, INTENDED),
            row(150, L1, V, ZERO, intended=R),  # after the intended row: confirmable
            row(90, L2, V, TINY, intended=R),  # before it: not confirmable
            row(100, L3, V, ZERO, intended=R),  # same block: order unknown, not counted
            row(160, "0x" + "5" * 40, V, ZERO),  # no intended address: not evaluable
            row(300, V, L1, PAYOFF),
        ]
    )
    sr = rv.confirmation_rule(ep, 299)
    assert sr[L1] == (True, True)
    assert sr[L2] == (False, False)
    assert sr[L3] == (False, False)
    assert sr["0x" + "5" * 40] == (None, None)


def test_confirmation_rule_latest_variant_uses_the_latest_intended_row() -> None:
    ep = episode(
        [
            row(100, V, R, INTENDED),
            row(150, L1, V, ZERO, intended=R),
            row(200, V, R, INTENDED),  # a later intended row: L1's planting is now older
            row(210, L2, V, ZERO, intended=R),
            row(300, V, L2, PAYOFF),
        ]
    )
    sr = rv.confirmation_rule(ep, 299)
    assert sr[L1] == (True, False)
    assert sr[L2] == (True, True)
    # Rows after the cutoff never count.
    assert rv.confirmation_rule(ep, 199)[L1] == (True, True)


# --- the experimental warning ranking ----------------------------------------------------


def case(
    suspect: str,
    severity: Severity,
    signals: list[tuple[str, int | None]],
    prefix: int = 4,
    suffix: int = 4,
) -> PoisoningCase:
    return PoisoningCase(
        suspect=suspect,
        reference=R,
        reference_confirmed=True,
        reference_first_used_block=1,
        prefix_match=prefix,
        suffix_match=suffix,
        displayed_as="x",
        random_match_odds="1",
        signals=[
            PoisoningSignal(code=c, description="", transaction_hash=None, block_number=b)
            for c, b in signals
        ],
        rule_id="poisoning",
        severity=severity,
        confidence=Confidence.MEDIUM,
        explanation="",
        recommended_action="",
        first_seen_block=1,
    )


def test_ranking_keeps_every_warning_and_never_lowers_a_severity_tier() -> None:
    old_critical = case(L1, Severity.CRITICAL_EVIDENCE, [("zero_value_transfer", 10)])
    recent_review = case(L2, Severity.REVIEW_RECOMMENDED, [("zero_value_transfer", 99)])
    no_basis = case(L3, Severity.CRITICAL_EVIDENCE, [("sent_to_lookalike", 50)])
    cases = [recent_review, no_basis, old_critical]
    before = [c.model_dump() for c in cases]
    ranked = wr.rank_warnings(cases, cutoff=100)
    assert sorted(r.suspect for r in ranked) == sorted(c.suspect for c in cases)
    assert [r.suspect for r in ranked] == [L1, L3, L2]  # tier first; no basis after basis
    assert ranked[1].basis == "no_recency_basis"
    assert ranked[0].blocks_before_cutoff == 90
    assert "not a probability" in ranked[0].explanation
    assert [c.model_dump() for c in cases] == before  # inputs untouched


def test_own_sends_and_signals_after_the_cutoff_are_not_a_basis() -> None:
    c = case(L1, Severity.ELEVATED_RISK, [("sent_to_lookalike", 90), ("zero_value_transfer", 120)])
    assert wr.planting_basis(c, 100) is None
    c2 = case(
        L1,
        Severity.ELEVATED_RISK,
        [("unsolicited_incoming_transfer", 40), ("spoofed_outgoing_transfer", 70)],
    )
    assert wr.planting_basis(c2, 100) == (70, None)
    assert (
        wr.planting_basis(case(L1, Severity.ELEVATED_RISK, [("zero_value_transfer", None)]), 100)
        is None
    )


def test_ties_break_deterministically_by_similarity_then_address() -> None:
    a = case(L2, Severity.ELEVATED_RISK, [("zero_value_transfer", 50)], prefix=4, suffix=4)
    b = case(L1, Severity.ELEVATED_RISK, [("zero_value_transfer", 50)], prefix=4, suffix=4)
    c = case(L3, Severity.ELEVATED_RISK, [("zero_value_transfer", 50)], prefix=5, suffix=5)
    for order in itertools.permutations([a, b, c]):
        assert [r.suspect for r in wr.rank_warnings(list(order), 100)] == [L3, L2, L1]


def test_research_metric_keeps_ties_and_resolves_single_blocks() -> None:
    a = case(L1, Severity.ELEVATED_RISK, [("zero_value_transfer", 20_000_000)])
    b = case(L2, Severity.ELEVATED_RISK, [("zero_value_transfer", 20_000_001)])
    op0, op1 = rv._op_top1([a, b], L2.lower(), 20_000_005)
    assert op0 == 0.5  # same tier and similarity: tied
    assert op1 == 1.0  # one block more recent: exact, no float rounding


def test_ranking_of_recorded_incident_ignores_rows_after_the_cutoff() -> None:
    from cryptoguard.detectors.poisoning import PoisoningConfig
    from cryptoguard.replay.engine import Visibility, detector_outputs
    from cryptoguard.replay.models import load_cases

    fx = next(c for c in load_cases() if c.fixture is not None)
    assert fx.fixture is not None
    cut = fx.manifest.harm.block_number - 1
    full = fx.fixture
    trimmed = full.model_copy(
        update={"transfers": [t for t in full.transfers if t.block_number <= cut]}
    )
    vis, cfg = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS, PoisoningConfig()
    a = wr.rank_warnings(detector_outputs(full, cut, vis, cfg)[0], cut)
    b = wr.rank_warnings(detector_outputs(trimmed, cut, vis, cfg)[0], cut)
    assert a == b
    assert len(a) >= 2


# --- production replay on archive rows, decisions, helpers -------------------------------


def test_production_detector_runs_on_archive_rows_before_the_cutoff_only() -> None:
    ep = episode(
        [
            row(100, V, R, INTENDED),
            row(150, L1, V, ZERO, intended=R),
            row(160, L3, V, ZERO, intended=R),
            row(300, V, L1, PAYOFF),
        ]
    )
    suspects = {c.suspect.lower() for c in rv.production_cases(ep, 299)}
    assert {L1, L3} <= suspects
    early = {c.suspect.lower() for c in rv.production_cases(ep, 155)}
    assert L1 in early
    assert L3 not in early  # planted at 160, after this cutoff


@pytest.mark.parametrize(
    ("mean", "ci", "p", "expected"),
    [
        (0.2, (0.1, 0.3), 0.001, "survives"),
        (0.01, (-0.03, 0.04), 0.5, "explained_or_null"),
        (-0.1, (-0.2, 0.02), 0.01, "explained_or_null"),
        (0.04, (0.01, 0.07), 0.01, "inconclusive"),
        (0.2, (0.1, 0.3), 0.2, "inconclusive"),
    ],
)
def test_phase_12_2_decision_rule(
    mean: float, ci: tuple[float, float], p: float, expected: str
) -> None:
    assert rv._decision({"mean": mean, "ci95": list(ci)}, p) == expected


def test_spearman_and_bins() -> None:
    assert rv._spearman([1, 2, 3], [3, 2, 1]) == pytest.approx(-1.0)
    assert rv._spearman([1, 1, 1], [1, 2, 3]) is None
    assert rv._agebin(299) == "a_under_1h"
    assert rv._agebin(7 * lr.DAY) == "d_over_7d"
    assert rv._kbin(2) == "2"

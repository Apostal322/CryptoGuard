"""Benchmark label policy for ``poisoning-attempt/1`` (Phase 11.6).

Seven statuses stay distinct and are never collapsed automatically:

- ``external_source_assertion``: a research source calls it an attempt (source data);
- ``reviewed_attack``: every reviewer (2 or more) chose *confirmed poisoning attempt*;
- ``reviewed_legitimate``: every reviewer chose *confirmed legitimate interaction*;
- ``likely_attack``: every reviewer chose confirmed or likely attempt, not all confirmed;
- ``unknown``: not reviewed, or a reviewer found the evidence insufficient;
- ``conflicting``: reviewers disagree across attack and legitimate, or chose conflicting
  evidence;
- ``later_victim_loss``: a payment to the lookalike followed (an outcome, never a feature).

A strict binary benchmark admits only ``reviewed_attack`` (1) and ``reviewed_legitimate``
(0). Everything else is excluded *and counted*. Reviewed labels are evidence-based
judgments, not proof of intent. An adjudicated label is a separate, secondary layer and
never replaces the reviewers' own.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Literal

POLICY_VERSION = "label-policy/1"
Status = Literal[
    "external_source_assertion",
    "reviewed_attack",
    "reviewed_legitimate",
    "likely_attack",
    "unknown",
    "conflicting",
    "later_victim_loss",
]
ATTACKISH = frozenset({"confirmed_poisoning_attempt", "likely_poisoning_attempt"})
MIN_REVIEWERS = 2


def resolve(decisions: Sequence[str]) -> Status:
    """Status from the reviewers' own decisions (adjudication is handled separately)."""
    if len(decisions) < MIN_REVIEWERS:
        return "unknown"
    s = set(decisions)
    if "conflicting_evidence" in s:
        return "conflicting"
    if s & ATTACKISH and "confirmed_legitimate_interaction" in s:
        return "conflicting"
    if "insufficient_evidence" in s:
        return "unknown"
    if s == {"confirmed_poisoning_attempt"}:
        return "reviewed_attack"
    if s == {"confirmed_legitimate_interaction"}:
        return "reviewed_legitimate"
    if s <= ATTACKISH:
        return "likely_attack"
    return "conflicting"


def binary_target(status: Status) -> int | None:
    return {"reviewed_attack": 1, "reviewed_legitimate": 0}.get(status)


def strict_benchmark(reviews: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    """Eligible labels and the count of every exclusion, for a set of reviewed items."""
    statuses = {e: resolve(d) for e, d in reviews.items()}
    labels = {e: t for e, s in statuses.items() if (t := binary_target(s)) is not None}
    return {
        "policy": POLICY_VERSION,
        "eligible": len(labels),
        "positives": sum(labels.values()),
        "negatives": len(labels) - sum(labels.values()),
        "excluded": dict(Counter(s for e, s in statuses.items() if e not in labels)),
        "labels": labels,
    }

"""Finding lifecycle: new → active → (acknowledged) → resolved / superseded.

``reconcile`` is pure: given the open/closed findings and this snapshot's rule evaluation, it
decides every status transition. The repository applies the result in one transaction.

- A condition seen for the first time is ``new``; seen again it becomes ``active``.
- ``acknowledged`` (set by the user) persists while the condition holds.
- An open finding whose condition is no longer observed is ``resolved`` — unless its subject
  could not be verified at this block, in which case it is left unchanged.
- An open finding from an older ruleset major version is ``superseded``.
- A resolved or superseded condition that reappears is reopened as ``new``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cryptoguard.risk.rules import RULESET_MAJOR, FindingCandidate, RuleEvaluation


class FindingStatus(StrEnum):
    NEW = "new"
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPERSEDED = "superseded"


OPEN_STATUSES = frozenset({FindingStatus.NEW, FindingStatus.ACTIVE, FindingStatus.ACKNOWLEDGED})


@dataclass(frozen=True)
class KnownFinding:
    fingerprint: str
    status: FindingStatus
    ruleset_version: str
    subject: str


@dataclass(frozen=True)
class Transition:
    fingerprint: str
    from_status: FindingStatus | None
    to_status: FindingStatus
    reason: str


@dataclass(frozen=True)
class Reconciliation:
    transitions: list[Transition]
    observed: list[FindingCandidate]  # every candidate: create or refresh last-seen/details
    not_reverified: list[str]  # open fingerprints left unchanged because inputs were unknown


def reconcile(known: dict[str, KnownFinding], evaluation: RuleEvaluation) -> Reconciliation:
    transitions: list[Transition] = []
    seen: set[str] = set()
    for candidate in evaluation.candidates:
        fp = candidate.fingerprint
        seen.add(fp)
        existing = known.get(fp)
        if existing is None:
            transitions.append(Transition(fp, None, FindingStatus.NEW, "Condition first observed."))
        elif existing.status in (FindingStatus.RESOLVED, FindingStatus.SUPERSEDED):
            transitions.append(
                Transition(
                    fp,
                    existing.status,
                    FindingStatus.NEW,
                    "Condition observed again after it ended.",
                )
            )
        elif existing.status is FindingStatus.NEW:
            transitions.append(
                Transition(fp, FindingStatus.NEW, FindingStatus.ACTIVE, "Condition still present.")
            )

    not_reverified: list[str] = []
    for fp in sorted(known):
        existing = known[fp]
        if fp in seen or existing.status not in OPEN_STATUSES:
            continue
        if existing.ruleset_version.split(".")[0] != RULESET_MAJOR:
            transitions.append(
                Transition(
                    fp,
                    existing.status,
                    FindingStatus.SUPERSEDED,
                    f"Replaced by ruleset major version {RULESET_MAJOR}.",
                )
            )
        elif existing.subject in evaluation.unverifiable_subjects:
            not_reverified.append(fp)
        else:
            transitions.append(
                Transition(
                    fp,
                    existing.status,
                    FindingStatus.RESOLVED,
                    "Condition no longer observed at this snapshot's block.",
                )
            )
    return Reconciliation(transitions, list(evaluation.candidates), not_reverified)


class InvalidTransitionError(ValueError):
    pass


def acknowledge(status: FindingStatus) -> FindingStatus:
    if status not in (FindingStatus.NEW, FindingStatus.ACTIVE):
        raise InvalidTransitionError(f"A {status.value} finding cannot be acknowledged.")
    return FindingStatus.ACKNOWLEDGED

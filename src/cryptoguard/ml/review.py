"""Offline label review for candidate poisoning events (no hosted service).

``export_packets`` writes one JSON line per event with the evidence a reviewer needs and
nothing else: no model score is included, so the independent label is not anchored on the
model. ``import_reviews`` validates returned decisions and appends them to a label history;
earlier labels and disagreements are kept, never overwritten (``events.resolve_labels``
turns verified disagreement into ``conflicting``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from cryptoguard.ml.events import LabelRecord, LabelTier, PoisoningEvent

REVIEW_SCHEMA = "poisoning-review/1"

Decision = Literal[
    "confirmed_poisoning_attempt",
    "likely_poisoning_attempt",
    "confirmed_legitimate_interaction",
    "insufficient_evidence",
    "conflicting_evidence",
]
DECISION_TIER: dict[str, LabelTier] = {
    "confirmed_poisoning_attempt": "verified_attempt",
    "likely_poisoning_attempt": "weak_attempt",
    "confirmed_legitimate_interaction": "verified_legitimate",
    "insufficient_evidence": "unknown",
    "conflicting_evidence": "conflicting",
}


class ReviewPacket(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-review/1"] = "poisoning-review/1"
    victim_event_id: str
    victim: str
    lookalike: str
    imitated: str | None
    planting_tx: str
    observation_block: int
    subtype: str
    evidence_summary: str
    coverage_limitations: str
    source_labels: tuple[str, ...]


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-review/1"] = "poisoning-review/1"
    victim_event_id: str
    decision: Decision
    rationale: str
    reviewer: str  # pseudonym
    reviewed_at: str  # ISO timestamp


class ReviewImportError(ValueError):
    pass


def packet(event: PoisoningEvent, source_labels: Sequence[str], evidence: str) -> ReviewPacket:
    limits = {
        "complete": "wallet window fully observed",
        "partial": "wallet history incomplete: unobserved events may exist",
        "unavailable": "no wallet history observed",
    }[event.coverage]
    return ReviewPacket(
        victim_event_id=event.victim_event_id,
        victim=event.victim,
        lookalike=event.lookalike,
        imitated=event.imitated,
        planting_tx=event.planting_tx,
        observation_block=event.planting_block,
        subtype=event.subtype,
        evidence_summary=evidence,
        coverage_limitations=limits,
        source_labels=tuple(source_labels),
    )


def export_packets(packets: Iterable[ReviewPacket], path: Path) -> int:
    lines = [p.model_dump_json() for p in sorted(packets, key=lambda p: p.victim_event_id)]
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8", newline="\n")
    return len(lines)


def import_reviews(
    path: Path, known_events: set[str], history: list[LabelRecord]
) -> list[LabelRecord]:
    """Validate every decision first (all or nothing), then append to ``history``."""
    new: list[LabelRecord] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            d = ReviewDecision.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ReviewImportError(f"{path}: line {i}: {exc}") from None
        if d.victim_event_id not in known_events:
            raise ReviewImportError(f"{path}: line {i}: unknown event {d.victim_event_id}")
        new.append(
            LabelRecord(
                victim_event_id=d.victim_event_id,
                tier=DECISION_TIER[d.decision],
                source=f"review:{d.reviewer}",
                available_at=d.reviewed_at,
                rationale=d.rationale,
            )
        )
    return [*history, *new]

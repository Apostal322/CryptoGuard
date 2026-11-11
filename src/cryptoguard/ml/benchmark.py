"""Benchmark readiness for ``poisoning-attempt/1`` and protection of the review holdout.

- ``benchmark_manifest`` pins every component a result depends on. Its versions are:
  - candidate generation;
  - source and human labels;
  - the feature schema;
  - the split policy;
  - the evaluation protocol.
  A result is comparable only with others that share it.
- ``Holdout`` holds the reviewed sample's events and entities (wallets, lookalikes,
  planting transactions). ``check_training_events`` refuses a training set that touches
  any of them. Once the holdout is used for development, ``mark_development`` records it
  for good. From then on it can no longer be reported as independent evaluation.
- ``readiness`` lists the ten criteria a supervised benchmark must meet. It reuses
  ``events.quality_gates`` for the label and split gates, so the two cannot disagree.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cryptoguard.ml.events import (
    EVENT_SCHEMA_VERSION,
    TASK_ID,
    LabelTier,
    PoisoningEvent,
    quality_gates,
)

BENCHMARK_VERSION = "poisoning-benchmark/0"  # 0: not yet a valid benchmark
SPLIT_POLICY = "grouped-temporal/1"  # events.grouped_temporal_split
EVALUATION_PROTOCOL = None  # undefined until verified negatives exist (gate B)


class HoldoutLeakError(ValueError):
    pass


def component_versions() -> dict[str, str | None]:
    from cryptoguard.ml.annotation import PROTOCOL
    from cryptoguard.ml.candidates import CANDIDATE_VERSION, EVENT_FEATURE_VERSION
    from cryptoguard.ml.reconcile import RECONCILE_VERSION
    from cryptoguard.ml.review_sample import SAMPLE_VERSION
    from cryptoguard.ml.tsuchiya import SOURCE_VERSION
    from cryptoguard.ml.tsuchiya_archive import PARSER_VERSION

    return {
        "task": TASK_ID,
        "event_schema": EVENT_SCHEMA_VERSION,
        "candidate_generation": CANDIDATE_VERSION,
        "feature_schema": EVENT_FEATURE_VERSION,
        "source_labels": f"{PARSER_VERSION}+{SOURCE_VERSION}+{RECONCILE_VERSION}",
        "human_labels": f"{SAMPLE_VERSION}+{PROTOCOL}",
        "split_policy": SPLIT_POLICY,
        "evaluation_protocol": EVALUATION_PROTOCOL,
    }


def benchmark_manifest(
    events: Sequence[PoisoningEvent], labels: Mapping[str, LabelTier]
) -> dict[str, Any]:
    body = {
        "benchmark": BENCHMARK_VERSION,
        "components": component_versions(),
        "events": sorted(e.victim_event_id for e in events),
        "labels": dict(sorted(labels.items())),
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {**body, "events": len(events), "labels": len(labels), "sha256": digest}


@dataclass
class Holdout:
    event_ids: frozenset[str]
    entities: frozenset[str]  # lowercase wallets, lookalikes and planting transactions
    status: Literal["untouched", "development"] = "untouched"
    history: list[dict[str, str]] = field(default_factory=list)


def holdout_from_sheet(sheet: Path, state: Path | None = None) -> Holdout:
    """Build the holdout from the blinded sheet (no key needed). ``state`` is an optional
    JSON file that records development use."""
    from cryptoguard.ml.review_sample import read_sheet

    rows = read_sheet(sheet)
    entities = {
        str(r[k]).lower() for r in rows for k in ("wallet", "address_under_review", "transaction")
    }
    h = Holdout(frozenset(r["victim_event_id"] for r in rows), frozenset(entities))
    if state is not None and state.exists():
        saved = json.loads(state.read_text(encoding="utf-8"))
        h.status, h.history = saved["status"], saved["history"]
    return h


def mark_development(h: Holdout, state: Path, reason: str, when: str) -> None:
    """Irreversible: the reviewed sample has influenced development."""
    h.status = "development"
    h.history.append({"at": when, "reason": reason})
    state.write_text(json.dumps({"status": h.status, "history": h.history}, indent=1) + "\n")


def check_training_events(events: Sequence[PoisoningEvent], h: Holdout) -> None:
    """Refuse training data that shares an event, wallet, lookalike or planting transaction
    with the reviewed holdout (the same entity-level rule as the grouped split)."""
    hits = [
        e.victim_event_id
        for e in events
        if e.victim_event_id in h.event_ids
        or {e.victim.lower(), e.lookalike.lower(), e.planting_tx.lower()} & h.entities
    ]
    if hits:
        raise HoldoutLeakError(
            f"{len(hits)} training event(s) overlap the review holdout, e.g. {hits[:3]}"
        )


def readiness(
    events: Sequence[PoisoningEvent],
    labels: Mapping[str, LabelTier],
    holdout: Holdout,
    *,
    license_ok: bool,
    candidate_recall_measured: bool,
) -> list[dict[str, Any]]:
    """The ten criteria. ``passed`` is None where only a person can judge."""
    gates = {g.gate: g for g in quality_gates(events, dict(labels), license_ok=license_ok)}
    versions = component_versions()
    return [
        {"criterion": "1 prediction unit", "passed": True,
         "detail": f"victim-event at a cutoff ({TASK_ID}, {EVENT_SCHEMA_VERSION})"},
        {"criterion": "2 reliable source labels", "passed": False,
         "detail": "source categories are heuristics (ML_CROSS_DATASET_VALIDATION.md §17)"},
        {"criterion": "3 independent review evidence", "passed": gates["B_label_validity"].passed,
         "detail": gates["B_label_validity"].detail},
        {"criterion": "4 suitable negatives", "passed": gates["B_label_validity"].passed,
         "detail": "verified_legitimate matched candidates (ML_BENCHMARK_READINESS.md §4)"},
        {"criterion": "5 point-in-time features", "passed": True,
         "detail": f"{versions['feature_schema']}: features use data up to the planting only"},
        {"criterion": "6 candidate-generation coverage", "passed": candidate_recall_measured,
         "detail": "needs full wallet histories; reported apart from classifier metrics"},
        {"criterion": "7 entity-aware splitting", "passed": gates["D_split_validity"].passed,
         "detail": gates["D_split_validity"].detail},
        {"criterion": "8 temporal validation", "passed": gates["C_temporal_validity"].passed,
         "detail": gates["C_temporal_validity"].detail},
        {"criterion": "9 untouched final holdout", "passed": holdout.status == "untouched",
         "detail": f"{len(holdout.event_ids)} reviewed items, status {holdout.status}"},
        {"criterion": "10 stable evaluation protocol", "passed": EVALUATION_PROTOCOL is not None,
         "detail": "not defined until 3 and 4 pass"},
    ]  # fmt: skip


def holdout_from_sheets(sheets: list[Path], state: Path | None = None) -> Holdout:
    """Both frozen review cohorts (or any set of sheets) as one protected holdout."""
    parts = [holdout_from_sheet(s) for s in sheets]
    h = Holdout(
        frozenset().union(*(p.event_ids for p in parts)),
        frozenset().union(*(p.entities for p in parts)),
    )
    if state is not None and state.exists():
        saved = json.loads(state.read_text(encoding="utf-8"))
        h.status, h.history = saved["status"], saved["history"]
    return h

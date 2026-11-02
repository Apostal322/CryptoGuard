"""Benchmark data contract and label-aware evaluation for ``poisoning-attempt/1`` (Phase 11.5).

``BenchmarkExample`` keeps seven layers apart:
1. the raw observation;
2. the candidate-generation result;
3. the feature vector;
4. the source label;
5. the human-reviewed label;
6. the later victim outcome;
7. the model prediction.

Features never contain an outcome, label or score field. A missing feature is ``None``,
never 0.

The metrics refuse what the data cannot support.
- Only ``verified_attempt`` (1) and ``verified_legitimate`` (0) count as truth.
- Weak, unknown, conflicting and unlabeled examples are excluded and counted, never
  turned into negatives.
- Precision needs reviewed positives and negatives; a false-positive rate needs reviewed
  negatives.
- Every result names its population, weights and exclusions.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT_VERSION = "benchmark-example/1"
TRUTH = {"verified_attempt": 1, "verified_legitimate": 0}
FORBIDDEN_FEATURE_WORDS = (
    "label",
    "outcome",
    "payoff",
    "loss",
    "score",
    "prediction",
    "paid",
    # source construction, not behaviour (Phase 11.5 separability findings)
    "source",
    "dataset",
    "cohort",
    "frame",
    "row_index",
    "line_number",
    "file",
)
Split = Literal["train", "validation", "test"]


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: int
    wallet: str
    candidate_address: str
    transaction: str
    block: int
    observation_cutoff: str  # e.g. "after tx, before the rest of the block"
    source_manifest: str  # hash of the input data


class Generation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_version: str
    methods: tuple[str, ...]
    eligible: bool
    eligibility_flags: tuple[str, ...] = ()


class Features(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    feature_version: str
    values: dict[str, float | None]
    missing: tuple[str, ...] = ()  # names whose input was unavailable (not zero)

    @model_validator(mode="after")
    def _no_post_cutoff_fields(self) -> Features:
        bad = [k for k in self.values if any(w in k.lower() for w in FORBIDDEN_FEATURE_WORDS)]
        if bad:
            raise ValueError(f"label, outcome or score data in features: {bad}")
        unflagged = [k for k, v in self.values.items() if v is None and k not in self.missing]
        if unflagged:
            raise ValueError(f"missing values must be listed in `missing`: {unflagged}")
        return self


class SourceLabel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str | None
    status: Literal["source_positive", "unlabeled_candidate", "none"]


class HumanLabel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tier: Literal[
        "verified_attempt", "weak_attempt", "verified_legitimate", "unknown", "conflicting"
    ]
    provenance: tuple[str, ...]  # submission content hashes
    reviewers: int = Field(ge=0)


class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    later_loss: bool | None  # never an input; for outcome analyses only


class Prediction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model: str
    score: float


class BenchmarkExample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["benchmark-example/1"] = "benchmark-example/1"
    task: Literal["poisoning-attempt/1"] = "poisoning-attempt/1"
    event_id: str
    group_id: str
    split: Split | None = None
    observation: Observation
    generation: Generation
    features: Features | None = None
    source_label: SourceLabel
    human_label: HumanLabel | None = None
    outcome: Outcome | None = None
    prediction: Prediction | None = None
    weight: float = Field(default=1.0, gt=0)  # inverse inclusion probability

    @model_validator(mode="after")
    def _consistent(self) -> BenchmarkExample:
        if self.split is not None and not self.generation.eligible:
            raise ValueError("an ineligible candidate cannot be assigned to a split")
        return self

    @property
    def truth(self) -> int | None:
        return TRUTH.get(self.human_label.tier) if self.human_label else None


class MetricRefused(ValueError):
    """The labels or population cannot support the requested metric."""


def label_accounting(examples: Sequence[BenchmarkExample]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for e in examples:
        c[e.human_label.tier if e.human_label else f"no_review:{e.source_label.status}"] += 1
    return dict(sorted(c.items()))


def _auc(pos: Sequence[float], neg: Sequence[float]) -> float:
    """Mann-Whitney AUC with ties counted as one half."""
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def _average_precision(scores: Sequence[tuple[float, int, float]]) -> float:
    """Weighted AP: the step-wise precision at each positive, ties broken pessimistically."""
    ranked = sorted(scores, key=lambda s: (-s[0], s[1]))
    tp = fp = ap = 0.0
    total_pos = sum(w for _, y, w in ranked if y == 1)
    for _, y, w in ranked:
        if y == 1:
            tp += w
            ap += w * tp / (tp + fp)
        else:
            fp += w
    return ap / total_pos


def evaluate(
    examples: Sequence[BenchmarkExample],
    *,
    threshold: float,
    fpr_budget: float | None = None,
    review_capacity: int | None = None,
    split: Split = "test",
) -> dict[str, Any]:
    """Metrics on the reviewed, eligible, predicted examples of one split. Raises
    ``MetricRefused`` when the population cannot support them."""
    scope = [e for e in examples if e.split == split]
    if not scope:
        raise MetricRefused(f"no examples assigned to the {split} split")
    usable = [e for e in scope if e.truth is not None and e.prediction is not None]
    excluded = {
        "unreviewed_or_unverified": sum(1 for e in scope if e.truth is None),
        "no_prediction": sum(1 for e in scope if e.truth is not None and e.prediction is None),
    }
    pos = [e for e in usable if e.truth == 1]
    neg = [e for e in usable if e.truth == 0]
    if not neg:
        raise MetricRefused(
            "no verified_legitimate examples: precision, FPR and AUC are undefined; weak, "
            "unknown and unlabeled examples are never negatives"
        )
    if not pos:
        raise MetricRefused("no verified_attempt examples: recall and AP are undefined")

    def w(es: Sequence[BenchmarkExample]) -> float:
        return sum(e.weight for e in es)

    def score(e: BenchmarkExample) -> float:
        assert e.prediction is not None
        return e.prediction.score

    tp = w([e for e in pos if score(e) >= threshold])
    fp = w([e for e in neg if score(e) >= threshold])
    out: dict[str, Any] = {
        "split": split,
        "population": "reviewed candidates in this split; not natural prevalence unless the "
        "sample was drawn to represent it",
        "labels": label_accounting(scope),
        "excluded": excluded,
        "positives": len(pos),
        "negatives": len(neg),
        "weighted": any(e.weight != 1.0 for e in usable),
        "threshold": threshold,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / w(pos),
        "fpr": fp / w(neg),
        "average_precision": _average_precision(
            [(score(e), e.truth or 0, e.weight) for e in usable]
        ),
        "roc_auc": _auc([score(e) for e in pos], [score(e) for e in neg])
        if len(pos) * len(neg) <= 4_000_000
        else None,
    }
    if fpr_budget is not None:
        cuts = sorted({score(e) for e in usable}, reverse=True)
        best = 0.0
        for t in cuts:
            if w([e for e in neg if score(e) >= t]) / w(neg) <= fpr_budget:
                best = max(best, w([e for e in pos if score(e) >= t]) / w(pos))
        out["recall_at_fpr_budget"] = {"budget": fpr_budget, "recall": best}
    if review_capacity is not None:
        top = sorted(usable, key=lambda e: -score(e))[:review_capacity]
        out["precision_at_capacity"] = {
            "capacity": review_capacity,
            "precision": sum(1 for e in top if e.truth == 1) / len(top) if top else None,
        }
    return out


def candidate_recall(
    known_event_ids: Sequence[str], generated_ids: Sequence[str]
) -> dict[str, Any]:
    """Share of known attempts the generator emitted at all, reported apart from classifier
    metrics. A model cannot score what the generator never produced."""
    known = set(known_event_ids)
    if not known:
        raise MetricRefused("no known attempts: candidate recall is undefined")
    hit = known & set(generated_ids)
    return {"known": len(known), "generated": len(hit), "recall": len(hit) / len(known)}


def alerts_per_1000_wallet_days(
    alerts: int, wallet_days: float, *, reviewed: bool, representative: bool
) -> dict[str, Any]:
    if wallet_days <= 0:
        raise MetricRefused("no observed wallet-days")
    kind = "confirmed false alerts" if reviewed else "unlabeled candidate volume (not false alerts)"
    return {
        "per_1000_wallet_days": 1000 * alerts / wallet_days,
        "measure": kind,
        "generalizes": representative,
        "note": None if representative else "convenience sample: not an Ethereum-wide rate",
    }


def precision_under_prevalence(tpr: float, fpr: float, prevalence: float) -> dict[str, Any]:
    """HYPOTHETICAL scenario, not an observed measurement."""
    for name, v in (("tpr", tpr), ("fpr", fpr), ("prevalence", prevalence)):
        if not 0 <= v <= 1 or math.isnan(v):
            raise MetricRefused(f"{name} must be in [0, 1]")
    denom = tpr * prevalence + fpr * (1 - prevalence)
    return {
        "scenario": "hypothetical",
        "tpr": tpr,
        "fpr": fpr,
        "prevalence": prevalence,
        "precision": tpr * prevalence / denom if denom else None,
    }


def split_report(examples: Sequence[BenchmarkExample], events: Mapping[str, Any]) -> dict[str, Any]:
    """Rows, labels, groups and entity overlap per split. ``events`` maps event id to its
    ``PoisoningEvent`` (for the typed-entity overlap check)."""
    from cryptoguard.ml.grouping import overlapping

    by_split: dict[str, list[BenchmarkExample]] = {}
    for e in examples:
        by_split.setdefault(e.split or "unassigned", []).append(e)
    report: dict[str, Any] = {}
    for s, es in sorted(by_split.items()):
        blocks = [e.observation.block for e in es]
        report[s] = {
            "rows": len(es),
            "labels": label_accounting(es),
            "groups": len({e.group_id for e in es}),
            "wallets": len({e.observation.wallet for e in es}),
            "blocks": [min(blocks), max(blocks)],
        }
    names = [s for s in ("train", "validation", "test") if s in by_split]
    leaks = {}
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            shared_groups = {e.group_id for e in by_split[a]} & {e.group_id for e in by_split[b]}
            shared_entities = overlapping(
                [events[e.event_id] for e in by_split[a]], [events[e.event_id] for e in by_split[b]]
            )
            leaks[f"{a}/{b}"] = {"groups": len(shared_groups), "entities": len(shared_entities)}
    report["overlap"] = leaks
    report["valid"] = bool(names) and all(v == {"groups": 0, "entities": 0} for v in leaks.values())
    return report

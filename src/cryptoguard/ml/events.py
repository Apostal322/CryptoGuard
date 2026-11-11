"""Wallet-centric poisoning research data model (task ``poisoning-attempt/1``).

Prediction unit: ``(chain_id, victim, candidate_event_id, observation_cutoff)``. A candidate
event is one suspicious transfer seen by one wallet; the question is whether it is a
poisoning attempt *against that wallet*, judged at the cutoff. Whether the victim later lost
money is a separate outcome, stored apart and never available as a feature.

Identity:

- ``planting_tx_id``: ``chain_id:tx_hash``. One batched transaction can plant many victims.
- ``victim_event_id``: hash of chain, victim, planting tx, lookalike and log index. Rows of a
  source that repeat the same victim-event are duplicates, not independent examples.
- ``group_id``: connected component over victims, lookalikes, planting txs and signers
  (public infrastructure exempt): all events of one campaign stay on one side of a split.

Labels, outcomes and features each carry their own availability block, so a label assigned
in retrospect can be a target but never an input.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.ml.dataset import PUBLIC_INFRASTRUCTURE as _PUBLIC

TASK_ID = "poisoning-attempt/1"
EVENT_SCHEMA_VERSION = "poisoning-event/1"

LabelTier = Literal[
    "verified_attempt",  # independent review confirmed a poisoning attempt
    "verified_legitimate",  # independent review confirmed a legitimate interaction
    "weak_attempt",  # a source pipeline says attempt; not independently reviewed
    "likely_legitimate",  # limited evidence of legitimacy
    "conflicting",
    "unknown",
]
OutcomeStatus = Literal[
    "confirmed_direct_payment",
    "no_direct_payment_observed_with_complete_declared_coverage",
    "partial_coverage",
    "unresolved",
    "not_evaluated",
]
Subtype = Literal["zero_value", "dust", "fake_token", "spoofed_transfer_from", "other", "unknown"]
CoverageStatus = Literal["complete", "partial", "unavailable"]
TRAINABLE_POSITIVE: frozenset[LabelTier] = frozenset({"verified_attempt"})
TRAINABLE_NEGATIVE: frozenset[LabelTier] = frozenset({"verified_legitimate"})


def _norm(address: str | None) -> str | None:
    return None if address is None else address.lower()


class PoisoningEvent(BaseModel):
    """One candidate event against one wallet. Unknown values are ``None``, never guessed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-event/1"] = "poisoning-event/1"
    chain_id: int
    victim: str
    lookalike: str
    imitated: str | None
    planting_tx: str
    planting_block: int
    planting_tx_index: int | None
    planting_log_index: int | None
    observation_timestamp: int | None
    subtype: Subtype
    tx_signer: str | None  # verified signer of the planting transaction
    log_contract: str | None  # contract that emitted the planting log
    token_contract: str | None  # token being imitated, when known
    candidate_method: str  # how the event entered the dataset (source or rule id)
    evidence_refs: tuple[str, ...] = ()
    coverage: CoverageStatus = "unavailable"
    dataset_version: str | None = None

    @property
    def planting_tx_id(self) -> str:
        return f"{self.chain_id}:{self.planting_tx.lower()}"

    @property
    def victim_event_id(self) -> str:
        key = "|".join(
            [
                str(self.chain_id),
                self.victim.lower(),
                self.planting_tx.lower(),
                self.lookalike.lower(),
                "" if self.planting_log_index is None else str(self.planting_log_index),
            ]
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def cutoff(self) -> tuple[int, int]:
        """Scored after the planting transaction executes, before anything later in its block.
        An unknown transaction index means only earlier blocks are visible."""
        return (
            self.planting_block,
            -1 if self.planting_tx_index is None else self.planting_tx_index,
        )


class LabelRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    victim_event_id: str
    tier: LabelTier
    source: str  # e.g. "poison-hunter-sample", "review:<pseudonym>"
    confidence: float | None = Field(default=None, ge=0, le=1)
    available_at: str | None  # when the label became known (ISO date or block); not a feature
    rationale: str | None = None


class OutcomeRecord(BaseModel):
    """What happened to the victim afterwards (secondary target, never a feature)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    victim_event_id: str
    status: OutcomeStatus
    window_from: int | None
    window_to: int | None
    declared_coverage: str
    evidence_refs: tuple[str, ...] = ()


def deduplicate(events: Iterable[PoisoningEvent]) -> tuple[list[PoisoningEvent], int]:
    """Keep the first event per victim-event identity; returns (events, duplicates dropped)."""
    seen: set[str] = set()
    kept: list[PoisoningEvent] = []
    dropped = 0
    for e in events:
        if e.victim_event_id in seen:
            dropped += 1
            continue
        seen.add(e.victim_event_id)
        kept.append(e)
    return kept, dropped


def resolve_labels(labels: Sequence[LabelRecord]) -> dict[str, LabelTier]:
    """One tier per event. Verified labels win over weak ones; verified disagreement is
    ``conflicting``; nothing is overwritten, the input history stays as it is."""
    by_event: dict[str, set[LabelTier]] = defaultdict(set)
    for lab in labels:
        by_event[lab.victim_event_id].add(lab.tier)
    out: dict[str, LabelTier] = {}
    for event_id, tiers in by_event.items():
        verified = tiers & {"verified_attempt", "verified_legitimate"}
        if len(verified) == 2 or "conflicting" in tiers:
            out[event_id] = "conflicting"
        elif verified:
            out[event_id] = (
                "verified_attempt" if "verified_attempt" in verified else "verified_legitimate"
            )
        elif {"weak_attempt", "likely_legitimate"} <= tiers:
            out[event_id] = "conflicting"
        elif "weak_attempt" in tiers:
            out[event_id] = "weak_attempt"
        elif "likely_legitimate" in tiers:
            out[event_id] = "likely_legitimate"
        else:
            out[event_id] = "unknown"
    return out


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.parent[self.find(a)] = self.find(b)


def campaign_groups(
    events: Sequence[PoisoningEvent], exempt: frozenset[str] = frozenset(_PUBLIC)
) -> dict[str, str]:
    """``victim_event_id -> group id``. Events sharing a victim, lookalike, planting tx or
    planting signer are linked; reviewed public infrastructure (routers, token contracts) is
    exempt so it does not merge unrelated campaigns."""
    uf = _UnionFind()
    exempt = frozenset(a.lower() for a in exempt)
    for e in events:
        node = "e:" + e.victim_event_id
        uf.find(node)
        for kind, value in (
            ("v", e.victim),
            ("l", e.lookalike),
            ("t", e.planting_tx_id),
            ("s", e.tx_signer),
        ):
            if value and value.lower() not in exempt:
                uf.union(node, f"{kind}:{value.lower()}")
    roots = {e.victim_event_id: uf.find("e:" + e.victim_event_id) for e in events}
    names = {root: f"g{i:04d}" for i, root in enumerate(sorted(set(roots.values())))}
    return {event_id: names[root] for event_id, root in roots.items()}


def grouped_temporal_split(
    events: Sequence[PoisoningEvent],
    groups: dict[str, str],
    *,
    test_fraction: float = 0.3,
) -> dict[str, Literal["train", "test"]]:
    """Whole groups go to one side; the groups that start latest form the test set, so the
    test set is both later in time and disjoint in campaigns, victims and infrastructure."""
    first: dict[str, int] = {}
    size: Counter[str] = Counter()
    for e in events:
        g = groups[e.victim_event_id]
        first[g] = min(first.get(g, e.planting_block), e.planting_block)
        size[g] += 1
    target = test_fraction * len(events)
    test: set[str] = set()
    taken = 0
    for g in sorted(first, key=lambda g: (-first[g], g)):
        if taken >= target:
            break
        test.add(g)
        taken += size[g]
    return {
        e.victim_event_id: "test" if groups[e.victim_event_id] in test else "train" for e in events
    }


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: str
    passed: bool
    detail: str


def quality_gates(
    events: Sequence[PoisoningEvent],
    labels: dict[str, LabelTier],
    *,
    license_ok: bool,
    min_per_class: int = 30,
) -> list[GateResult]:
    """Dataset acceptance checks run before any training. Failing gates block training."""
    ids = [e.victim_event_id for e in events]
    tiers: Counter[str] = Counter(labels.get(i, "unknown") for i in ids)
    positives = sum(tiers[t] for t in TRAINABLE_POSITIVE)
    negatives = sum(tiers[t] for t in TRAINABLE_NEGATIVE)
    groups = campaign_groups(events)
    pos_groups = {groups[i] for i in ids if labels.get(i) in TRAINABLE_POSITIVE}
    neg_groups = {groups[i] for i in ids if labels.get(i) in TRAINABLE_NEGATIVE}
    return [
        GateResult(
            gate="A_data_validity",
            passed=len(ids) == len(set(ids)) and len(ids) > 0,
            detail=f"{len(ids)} events, {len(ids) - len(set(ids))} duplicate identities",
        ),
        GateResult(
            gate="B_label_validity",
            passed=positives >= min_per_class and negatives >= min_per_class,
            detail=(
                f"verified positives {positives}, verified negatives {negatives} "
                f"(need {min_per_class} each); weak {tiers['weak_attempt']}, "
                f"unknown {tiers['unknown']}, conflicting {tiers['conflicting']}"
            ),
        ),
        GateResult(
            gate="C_temporal_validity",
            passed=all(e.planting_block > 0 for e in events),
            detail="every event has a planting block; cutoff = after the planting transaction",
        ),
        GateResult(
            gate="D_split_validity",
            passed=len(pos_groups) >= 5 and len(neg_groups) >= 5,
            detail=f"{len(pos_groups)} positive and {len(neg_groups)} negative campaign groups",
        ),
        GateResult(
            gate="license",
            passed=license_ok,
            detail="raw rows stay local" if not license_ok else "redistributable",
        ),
    ]


def manifest(events: Sequence[PoisoningEvent], labels: Sequence[LabelRecord]) -> dict[str, object]:
    """Deterministic dataset manifest: content hash over canonical event and label JSON."""
    ev = sorted(e.model_dump_json() for e in events)
    lab = sorted(lab.model_dump_json() for lab in labels)
    digest = hashlib.sha256(json.dumps([ev, lab]).encode()).hexdigest()
    return {
        "task": TASK_ID,
        "event_schema": EVENT_SCHEMA_VERSION,
        "events": len(ev),
        "labels": len(lab),
        "sha256": digest,
    }

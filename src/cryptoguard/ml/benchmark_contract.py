"""Benchmark contracts for real-incident evaluation (protocol 12.8). Research only.

Three things are defined here and nothing is computed on outcomes:

- the **label ontology** (``benchmark-labels/1``): five independent dimensions, each with an
  ``unknown``-type value, and the evidence a label needs before it may assert anything;
- the **case contract** (``benchmark-case/1``): what a collector may know about a case, kept
  apart from the sealed outcome record, plus the collector request type, which cannot carry
  an answer;
- **eligibility**: data-quality issues with severities, per-mechanism observation coverage,
  and independence from every development artifact.

An unknown candidate is never a negative, a wallet without a reported theft is never a
verified benign wallet, and a paid lookalike is an outcome label, not proof that every
earlier event from that address was malicious.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, model_validator

LABELS_VERSION = "benchmark-labels/1"
CASE_VERSION = "benchmark-case/1"

DIMENSIONS: dict[str, tuple[str, ...]] = {
    "mechanism": (
        "native_dust",
        "zero_value_token",
        "fake_token",
        "spoofed_transfer",
        "other",
        "unknown",
    ),
    "provenance": (
        "signer_verified",
        "emitter_verified",
        "receipt_verified",
        "relationship_verified",
        "inferred",
        "unsupported",
        "unknown",
    ),
    "relationship": (
        "exact_address",
        "lookalike_of_recipient",
        "no_recipient_relationship",
        "ambiguous_multiple_references",
        "unknown",
    ),
    "outcome": (
        "paid_to_candidate",
        "paid_to_legitimate_recipient",
        "harmful_transfer",
        "no_verified_outcome",
        "unknown",
    ),
    "legitimacy": (
        "confirmed_malicious",
        "confirmed_legitimate",
        "ambiguous",
        "unreviewed",
        "insufficient_evidence",
    ),
}
NON_ASSERTING = frozenset(
    {"unknown", "unreviewed", "no_verified_outcome", "insufficient_evidence", "ambiguous"}
)
NEEDS_TRANSACTION = frozenset(
    {"paid_to_candidate", "paid_to_legitimate_recipient", "harmful_transfer"}
)
POST_OUTCOME_DIMENSIONS = frozenset({"outcome", "legitimacy"})
EvidenceKind = Literal[
    "chain_transaction",
    "receipt",
    "incident_report",
    "campaign_attribution",
    "reviewer_decision",
    "synthetic_oracle",
]
Confidence = Literal["verified", "supported", "weak", "none"]
CutoffRelation = Literal["pre_cutoff_observable", "post_cutoff_outcome", "forensic"]
Population = Literal["development", "independent_candidate", "synthetic"]
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX = re.compile(r"^0x[0-9a-fA-F]{64}$")


# --- labels ---------------------------------------------------------------------------------


class EvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: EvidenceKind
    ref: str  # a transaction hash, a report URL, a reviewer submission id, an oracle id


class Label(BaseModel):
    """One asserted or explicitly non-asserted fact about a subject, with its evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label_id: str
    schema_version: str = LABELS_VERSION
    subject: str  # an address, a transaction hash or a case id
    dimension: str
    value: str
    evidence: tuple[EvidenceRef, ...] = ()
    source: str
    determined_at: date
    method: str
    reviewer_id: str | None = None
    confidence: Confidence
    ambiguity: str | None = None
    limitations: tuple[str, ...] = ()
    cutoff_relation: CutoffRelation

    @model_validator(mode="after")
    def _category(self) -> Label:
        if self.dimension not in DIMENSIONS:
            raise ValueError(f"invalid dimension {self.dimension!r}")
        if self.value not in DIMENSIONS[self.dimension]:
            raise ValueError(f"invalid category {self.value!r} for {self.dimension}")
        return self


def label_problems(label: Label, *, synthetic_case: bool = False) -> list[str]:
    """Why a label may not be used as stated (protocol 12.8 section 2); empty when valid."""
    out: list[str] = []
    if label.schema_version != LABELS_VERSION:
        out.append(f"incompatible label schema {label.schema_version!r}")
    kinds = {e.kind for e in label.evidence}
    asserting = label.value not in NON_ASSERTING
    if asserting and not label.evidence:
        out.append("an asserting label has no evidence reference")
    if label.value in NEEDS_TRANSACTION and "chain_transaction" not in kinds:
        out.append(f"{label.value} needs a chain_transaction reference")
    if label.value == "confirmed_legitimate" and not kinds & {
        "reviewer_decision",
        "synthetic_oracle",
    }:
        out.append("confirmed_legitimate needs a reviewer decision (absence is not evidence)")
    if label.value == "confirmed_malicious" and kinds and kinds <= {"chain_transaction", "receipt"}:
        out.append("confirmed_malicious cannot rest on an on-chain event alone")
    if "reviewer_decision" in kinds and not label.reviewer_id:
        out.append("a reviewer_decision reference needs a reviewer id")
    if "synthetic_oracle" in kinds and not synthetic_case:
        out.append("a synthetic_oracle reference on a non-synthetic case")
    if not asserting and label.confidence == "verified":
        out.append("a non-asserting value cannot be verified")
    if (
        label.dimension in POST_OUTCOME_DIMENSIONS
        and label.cutoff_relation == "pre_cutoff_observable"
    ):
        out.append(f"a {label.dimension} label can never be a pre-cutoff model input")
    return out


def label_conflicts(labels: Iterable[Label]) -> list[str]:
    """Two asserting labels of one dimension on one subject with different values."""
    seen: dict[tuple[str, str], set[str]] = {}
    for lab in labels:
        if lab.value not in NON_ASSERTING:
            seen.setdefault((lab.subject.lower(), lab.dimension), set()).add(lab.value)
    return [
        f"{dim} of {subject}: {sorted(values)}"
        for (subject, dim), values in sorted(seen.items())
        if len(values) > 1
    ]


def model_input_allowed(label: Label) -> bool:
    """Only pre-cutoff, non-outcome labels may ever reach a generator or a ranker."""
    return (
        label.cutoff_relation == "pre_cutoff_observable"
        and label.dimension not in POST_OUTCOME_DIMENSIONS
    )


# --- cases, outcomes, collector -------------------------------------------------------------


class CaseSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    publisher: str
    url: str
    published: str | None = None


class BenchmarkCase(BaseModel):
    """Everything a collector and a predictor may know. No outcome field exists here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    schema_version: str = CASE_VERSION
    chain_id: int
    victim: str
    from_block: int
    to_block: int
    cutoff: tuple[int, int]  # observations strictly before (block, tx index) are usable
    cutoff_rule: str
    observation_schema: str
    source: CaseSource
    cluster_id: str  # related wallets / transactions of one attack share a cluster
    population: Population
    development_reasons: tuple[str, ...] = ()


class Outcome(BaseModel):
    """The sealed answer. Held by the outcome vault; never passed to a predictor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    verified: bool
    paid_address: str | None = None
    intended_recipient: str | None = None
    harm_tx: str | None = None
    harm_block: int | None = None
    labels: tuple[Label, ...] = ()


class CollectorRequest(BaseModel):
    """The only fields a recorder accepts. Extra fields are refused, so an attacker address,
    a paid address, a harmful transaction or an answer key cannot be handed to it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: int
    wallet: str
    from_block: int
    to_block: int
    observation: Literal[1, 2]
    max_requests: int


def collector_request(
    case: BenchmarkCase, *, max_requests: int, observation: Literal[1, 2] = 2
) -> CollectorRequest:
    return CollectorRequest(
        chain_id=case.chain_id,
        wallet=case.victim,
        from_block=case.from_block,
        to_block=case.to_block,
        observation=observation,
        max_requests=max_requests,
    )


# --- data quality ---------------------------------------------------------------------------

SEVERITIES = ("valid", "valid_with_limitations", "needs_review", "not_evaluable", "invalid")


class Issue(NamedTuple):
    severity: str
    code: str
    detail: str


def status(issues: Sequence[Issue]) -> str:
    """A case's status is its worst issue."""
    return max((i.severity for i in issues), key=SEVERITIES.index, default="valid")


def case_quality(
    case: BenchmarkCase,
    fixture: Any | None,
    outcome: Outcome | None,
    *,
    protected: bool = False,
    duplicate: bool = False,
) -> list[Issue]:
    """Every data-quality issue of one case (protocol 12.8 section 4). Nothing is dropped:
    the caller keeps the case and its issues in the ledger."""
    from cryptoguard.ml import candidate_discovery as cd

    out: list[Issue] = []

    def add(severity: str, code: str, detail: str = "") -> None:
        out.append(Issue(severity, code, detail))

    if case.schema_version != CASE_VERSION:
        add("invalid", "incompatible_artifact_version", case.schema_version)
    if not _ADDR.match(case.victim):
        add("invalid", "invalid_address", "victim")
    if case.from_block > case.to_block:
        add("invalid", "inconsistent_block_order", "window")
    if not case.from_block <= case.cutoff[0] <= case.to_block + 1:
        add("invalid", "window_does_not_cover_cutoff")
    if duplicate:
        add("invalid", "duplicate_case")
    if protected:
        add("not_evaluable", "protected_cohort_overlap", "touches a frozen review cohort")
    if case.population == "development":
        add("valid_with_limitations", "development_case", "; ".join(case.development_reasons))
    # outcome
    synthetic = case.population == "synthetic"
    if outcome is None or not outcome.verified or not outcome.paid_address:
        add("not_evaluable", "outcome_not_verified")
    else:
        if not _ADDR.match(outcome.paid_address):
            add("invalid", "invalid_address", "paid address")
        if outcome.harm_tx is None:
            add("needs_review", "missing_transaction_hash", "harmful transaction")
        elif not _TX.match(outcome.harm_tx):
            add("invalid", "invalid_transaction_hash", "harmful transaction")
        if outcome.harm_block is not None:
            if not case.from_block <= outcome.harm_block <= case.to_block:
                add("invalid", "harm_block_outside_window")
            if case.cutoff > (outcome.harm_block, 0):
                add("invalid", "cutoff_after_harm_block", "future information would be usable")
    if outcome is not None:
        for lab in outcome.labels:
            for p in label_problems(lab, synthetic_case=synthetic):
                add("needs_review", "label_missing_evidence", f"{lab.label_id}: {p}")
        for c in label_conflicts(outcome.labels):
            add("needs_review", "conflicting_labels", c)
    # observations
    if fixture is None:
        add("not_evaluable", "no_recording")
        return out
    if fixture.chain_id != case.chain_id:
        add("invalid", "chain_mismatch")
    if fixture.wallet.lower() != case.victim.lower():
        add("invalid", "wallet_mismatch")
    if (fixture.from_block, fixture.to_block) != (case.from_block, case.to_block):
        add("needs_review", "truncated_or_shifted_window", "recording window differs from the case")
    obs = cd.observations(fixture)
    raw = len(fixture.transfers) + len(fixture.native_inbound or [])
    keys = [(t.transaction_hash.lower(), t.log_index) for t in fixture.transfers] + [
        (n.transaction_hash.lower(), -1) for n in fixture.native_inbound or []
    ]
    if len(set(keys)) != raw:
        add("valid_with_limitations", "duplicate_records", f"{raw - len(set(keys))} duplicates")
    if any(not fixture.from_block <= o.block <= fixture.to_block for o in obs):
        add("invalid", "inconsistent_block_order", "observation outside the window")
    if any(not _TX.match(o.tx_hash) for o in obs):
        add("invalid", "missing_transaction_hash", "observation without a valid hash")
    if outcome is not None and outcome.harm_tx:
        h = outcome.harm_tx.lower()
        if any(o.tx_hash.lower() == h and (o.block, o.tx_index) < case.cutoff for o in obs):
            add("invalid", "future_information_leak", "the outcome transaction precedes the cutoff")
    if getattr(fixture, "sender_lookups_skipped", 0):
        add("valid_with_limitations", "incomplete_signer_lookup")
    if any(n.succeeded is None for n in fixture.native_inbound or []):
        add("valid_with_limitations", "missing_receipts")
    incomplete = sorted(k for k, v in coverage_matrix(fixture).items() if v != "complete")
    if incomplete:
        add("valid_with_limitations", "incomplete_categories", ", ".join(incomplete))
    return out


# --- observation eligibility ----------------------------------------------------------------

# each mechanism: every listed alternative set must have one fully complete option
MECHANISM_REQUIREMENTS: dict[str, tuple[tuple[str, ...], ...]] = {
    "native_dust": (("native_inbound_external",),),
    "zero_value_token": (("erc20_transfer_logs",),),
    "fake_token": (("erc20_transfer_logs",),),
    "spoofed_transfer": (
        ("erc20_transfer_logs",),
        ("erc20_outgoing_signers", "wallet_signed_transactions"),
    ),
}
_ABSENT = frozenset({"unsupported", "not_collected"})


def coverage_matrix(fixture: Any) -> dict[str, str]:
    """Category -> status for one window (derived for ``observation/1`` recordings)."""
    from cryptoguard.replay.observation import CATEGORIES, coverage_of

    cov = coverage_of(fixture)
    return {c: str(cov.status(c)) for c in CATEGORIES}


def mechanism_eligibility(coverage: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """For each mechanism: ``complete`` (assessable), ``partial`` or ``unsupported``, and
    the categories that stop it. ``all_mechanisms`` needs every category complete."""
    out: dict[str, dict[str, Any]] = {}
    for mech, groups in MECHANISM_REQUIREMENTS.items():
        missing: list[str] = []
        worst = "complete"
        for alternatives in groups:
            states = [coverage.get(c, "unknown") for c in alternatives]
            if "complete" in states:
                continue
            missing += list(alternatives)
            state = "unsupported" if all(s in _ABSENT for s in states) else "partial"
            worst = "unsupported" if "unsupported" in (worst, state) else "partial"
        out[mech] = {"state": worst, "eligible": worst == "complete", "missing": missing}
    missing_all = sorted(c for c, s in coverage.items() if s != "complete")
    out["all_mechanisms"] = {
        "state": "complete" if not missing_all else "unsupported",
        "eligible": not missing_all,
        "missing": missing_all,
    }
    return out


# --- independence ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DevelopmentIndex:
    """Identifiers already used in development: an overlap makes a case non-independent."""

    victims: frozenset[str] = frozenset()
    addresses: frozenset[str] = frozenset()  # every counterparty seen in a development artifact
    transactions: frozenset[str] = frozenset()
    clusters: frozenset[str] = frozenset()
    protected: frozenset[str] = frozenset()  # frozen review cohorts (addresses and hashes)
    sources: tuple[str, ...] = field(default=())


def independence(case: BenchmarkCase, outcome: Outcome | None, dev: DevelopmentIndex) -> list[str]:
    """Reasons a case is *not* independent of earlier research; empty when it is."""
    reasons: list[str] = []
    v = case.victim.lower()
    if v in dev.victims:
        reasons.append("victim already used in development")
    if v in dev.protected:
        reasons.append("victim in a frozen review cohort")
    if case.cluster_id in dev.clusters:
        reasons.append("attack cluster already used in development")
    if outcome is not None:
        for name, value in (("paid address", outcome.paid_address), ("harm tx", outcome.harm_tx)):
            if value is None:
                continue
            x = value.lower()
            if x in dev.addresses or x in dev.transactions:
                reasons.append(f"{name} already seen in a development artifact")
            if x in dev.protected:
                reasons.append(f"{name} in a frozen review cohort")
    if not case.source.url:
        reasons.append("no traceable source")
    if case.population == "development":
        reasons.append("declared development")
    return reasons


def index_from_fixtures(
    fixtures: Iterable[Any], *, clusters: Collection[str] = (), protected: Collection[str] = ()
) -> DevelopmentIndex:
    victims: set[str] = set()
    addresses: set[str] = set()
    txs: set[str] = set()
    for fx in fixtures:
        victims.add(fx.wallet.lower())
        for t in fx.transfers:
            addresses.update((t.sender.lower(), t.recipient.lower()))
            txs.add(t.transaction_hash.lower())
        for w in fx.wallet_transactions:
            txs.add(w.transaction_hash.lower())
            if w.to:
                addresses.add(w.to.lower())
        for n in fx.native_inbound or []:
            addresses.add(n.sender.lower())
            txs.add(n.transaction_hash.lower())
    return DevelopmentIndex(
        victims=frozenset(victims),
        addresses=frozenset(addresses - victims),
        transactions=frozenset(txs),
        clusters=frozenset(clusters),
        protected=frozenset(x.lower() for x in protected),
    )

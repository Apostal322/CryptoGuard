"""Independent human annotation of the frozen review sample (``review-protocol/1``,
amendment 1).

- ``Annotation``: one reviewer's structured decision on one item. A strong decision must
  carry the evidence it rests on, and the reviewer's exposure to later or external
  information is recorded, never inferred.
- ``ReviewerStore``: one reviewer's append-only, hash-chained log. Each save rewrites the
  whole file atomically (temporary file, fsync, replace), so a crash leaves the old or the
  new log, never a torn one. A revision appends; nothing is erased.
- ``finalize``: once every item has a decision, the submission is written with a content
  hash, and the store refuses further saves. Changes then need a protocol amendment.
- ``Submission``, ``ReplacementRecord``, ``AdjudicationRecord``: the files the maintainer
  combines in ``unblind``.

The store never reads the unblinding key, and nothing here assigns a label.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from cryptoguard.ml.review import Decision, ReviewDecision

ANNOTATION_SCHEMA = "poisoning-annotation/1"
SUBMISSION_SCHEMA = "poisoning-submission/1"
PROTOCOL = "review-protocol/1+amendment-2"
Protocol = Literal["review-protocol/1+amendment-1", "review-protocol/1+amendment-2"]
LOG = "annotations.log.jsonl"
SUBMISSION = "submission.json"
LOCK = ".lock"
ATTEMPT = frozenset({"confirmed_poisoning_attempt", "likely_poisoning_attempt"})

Evidence = Literal[
    "observed",  # seen and supports the check
    "not_observed",  # looked for, with adequate data, and absent
    "not_available",  # the data needed does not exist or cannot be reached
    "not_loaded",  # not looked at
    "not_applicable",
    "contradictory",  # observations disagree
]
Token = Literal["genuine", "imitation", "unknown", "not_applicable"]
ValueClass = Literal["zero", "dust", "ordinary", "unknown"]
Initiator = Literal["wallet", "third_party", "unknown"]
Exposure = Literal["no", "yes", "unsure"]
Confidence = Literal["high", "medium", "low"]
ReasonCode = Literal[
    "lookalike_of_earlier_counterparty",
    "imitation_token_contract",
    "zero_value_transfer",
    "dust_value",
    "third_party_initiated_transfer",
    "wallet_initiated_transfer",
    "known_relationship",
    "same_owner_evidence",
    "ordinary_payment_pattern",
    "no_earlier_counterparty_found",
    "history_unavailable",
    "contradictory_observations",
    "other",
]
REF = re.compile(r"^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
REVIEWER_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


class AnnotationError(ValueError):
    pass


class StoreCorruptError(AnnotationError):
    """The log or submission fails its hash chain or schema; nothing is repaired."""


class FinalizedError(AnnotationError):
    """The reviewer's submission is finalized; edits need a protocol amendment."""


class Annotation(BaseModel):
    """One decision. ``reviewer``, ``revision`` and ``saved_at`` are set by the store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-annotation/1"] = "poisoning-annotation/1"
    protocol: Protocol = "review-protocol/1+amendment-2"
    item: int = Field(ge=1)
    victim_event_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    reviewer: str
    revision: int = Field(ge=1)
    saved_at: str
    decision: Decision
    confidence: Confidence
    # Protocol §3 checks, in order.
    planting_transfer: Evidence
    prior_counterparty: Evidence
    prior_counterparty_address: str | None = None
    matched_leading: int | None = Field(default=None, ge=0, le=40)
    matched_trailing: int | None = Field(default=None, ge=0, le=40)
    token: Token
    value_class: ValueClass
    initiator: Initiator
    legitimate_explanation: Evidence
    # Exposure (amendment 1): recorded, never inferred.
    used_explorer: bool
    viewed_after_cutoff: Exposure
    saw_external_label: Exposure
    saw_source_or_model_output: bool
    # Amendment 2: required from then on (None only in amendment-1 records).
    used_offline_evidence: bool | None = None
    saw_later_victim_payment: Exposure | None = None
    third_party_label_influenced: Exposure | None = None
    reason_codes: tuple[ReasonCode, ...] = ()
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=20)  # tx hashes, addresses
    rationale: str = Field(min_length=1, max_length=4000)
    notes: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def _evidence_supports_decision(self) -> Annotation:
        problems = evidence_problems(self)
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def to_review_decision(self) -> ReviewDecision:
        """The ``poisoning-review/1`` record that ``review.import_reviews`` accepts."""
        return ReviewDecision(
            victim_event_id=self.victim_event_id,
            decision=self.decision,
            rationale=self.rationale,
            reviewer=self.reviewer,
            reviewed_at=self.saved_at,
        )


def evidence_problems(a: Annotation) -> list[str]:
    """Rules from protocol amendment 1 §4. Missing evidence is never read as negative."""
    out: list[str] = []
    if not REVIEWER_ID.match(a.reviewer):
        out.append("reviewer must be a pseudonym of 1-32 letters, digits, '-' or '_'")
    addr = a.prior_counterparty_address
    if addr is not None and not ADDRESS.match(addr):
        out.append("prior_counterparty_address must be a 0x-prefixed 40-hex address")
    if addr is not None and a.prior_counterparty not in ("observed", "contradictory"):
        out.append(
            "a prior counterparty address needs prior_counterparty observed or contradictory"
        )
    if a.protocol == "review-protocol/1+amendment-2":
        missing = [
            name
            for name in (
                "used_offline_evidence",
                "saw_later_victim_payment",
                "third_party_label_influenced",
            )
            if getattr(a, name) is None
        ]
        if missing:
            out.append(f"amendment 2 requires: {', '.join(missing)}")
        if a.decision in ("confirmed_poisoning_attempt", "confirmed_legitimate_interaction") and (
            not a.reason_codes
        ):
            out.append("a confirmed decision needs at least one reason code")
        bad = [r for r in a.evidence_refs if not REF.match(r)]
        if bad:
            out.append(f"evidence references must be 0x addresses or tx hashes: {bad[:3]}")
    words = len(a.rationale.split())
    d = a.decision
    if d == "confirmed_poisoning_attempt":
        if a.planting_transfer != "observed":
            out.append("confirmed: the planting transfer must be observed")
        if a.prior_counterparty != "observed" or addr is None:
            out.append("confirmed: the imitated earlier counterparty must be observed and given")
        if a.matched_leading is None or a.matched_trailing is None:
            out.append("confirmed: record the matched leading and trailing characters")
        if a.legitimate_explanation not in ("not_observed",):
            out.append("confirmed: a legitimate explanation must have been looked for and absent")
    elif d == "likely_poisoning_attempt":
        if a.planting_transfer != "observed":
            out.append("likely: the planting transfer must be observed")
        if a.legitimate_explanation == "observed":
            out.append("likely: contradicts an observed legitimate explanation")
    elif d == "confirmed_legitimate_interaction":
        if a.legitimate_explanation != "observed":
            out.append("legitimate: the legitimate explanation must be observed")
    elif d == "conflicting_evidence":
        checks = (a.planting_transfer, a.prior_counterparty, a.legitimate_explanation)
        if "contradictory" not in checks:
            out.append("conflicting: mark the contradictory check")
    if d in ("confirmed_poisoning_attempt", "confirmed_legitimate_interaction") and words < 5:
        out.append("a confirmed decision needs a rationale of at least 5 words")
    return out


# --- durable store ------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    """Temporary file, fsync, replace: readers see the old or the new file, never a mix."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ReviewerStore:
    """One reviewer's log in ``root``. Use as a context manager to hold the OS lock, which
    keeps a second server (or a second copy of the app) off the same store."""

    def __init__(self, root: Path, reviewer: str, items: Mapping[int, str]) -> None:
        if not REVIEWER_ID.match(reviewer):
            raise AnnotationError(f"invalid reviewer pseudonym {reviewer!r}")
        self.root, self.reviewer, self.items = root, reviewer, dict(items)
        self._fd: int | None = None
        self.entries: list[dict[str, Any]] = []
        self.root.mkdir(parents=True, exist_ok=True)
        leftover = self.root / (LOG + ".tmp")
        if leftover.exists():  # an interrupted save; the log itself is intact
            leftover.unlink()
        self._load()

    def __enter__(self) -> ReviewerStore:
        from cryptoguard.blockchain.budget import _try_os_lock

        fd = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT)
        if not _try_os_lock(fd):
            os.close(fd)
            raise AnnotationError(f"{self.root}: another review session holds this store")
        self._fd = fd
        return self

    def __exit__(self, *exc: object) -> None:
        from cryptoguard.blockchain.budget import _os_unlock

        if self._fd is not None:
            _os_unlock(self._fd)
            os.close(self._fd)
            self._fd = None

    # Log format: {"seq", "prev", "kind", "record", "sha256"}; sha256 covers the rest.
    def _load(self) -> None:
        path = self.root / LOG
        if not path.exists():
            return
        prev = None
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                entry = json.loads(line)
                body = {k: entry[k] for k in ("seq", "prev", "kind", "record")}
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise StoreCorruptError(f"{path}: line {i}: {exc}") from None
            if entry["sha256"] != _sha(_canonical(body)) or entry["prev"] != prev:
                raise StoreCorruptError(f"{path}: line {i}: hash chain broken")
            if entry["seq"] != i:
                raise StoreCorruptError(f"{path}: line {i}: sequence {entry['seq']}")
            if entry["kind"] == "annotation":
                try:
                    a = Annotation.model_validate(entry["record"])
                except ValidationError as exc:
                    raise StoreCorruptError(f"{path}: line {i}: {exc}") from None
                if a.reviewer != self.reviewer:
                    raise StoreCorruptError(f"{path}: line {i}: reviewer {a.reviewer!r}")
            prev = entry["sha256"]
            self.entries.append(entry)

    def _append(self, kind: str, record: dict[str, Any]) -> None:
        if self._fd is None:
            raise AnnotationError("open the store with `with` before writing")
        body = {
            "seq": len(self.entries) + 1,
            "prev": self.entries[-1]["sha256"] if self.entries else None,
            "kind": kind,
            "record": record,
        }
        entry = {**body, "sha256": _sha(_canonical(body))}
        data = b"".join(_canonical(e) + b"\n" for e in [*self.entries, entry])
        atomic_write(self.root / LOG, data)  # raises before memory changes on a failed write
        self.entries.append(entry)

    @property
    def finalized(self) -> bool:
        return any(e["kind"] == "finalize" for e in self.entries)

    def history(self, item: int) -> list[Annotation]:
        return [
            Annotation.model_validate(e["record"])
            for e in self.entries
            if e["kind"] == "annotation" and e["record"]["item"] == item
        ]

    def latest(self) -> dict[int, Annotation]:
        out: dict[int, Annotation] = {}
        for e in self.entries:
            if e["kind"] == "annotation":
                a = Annotation.model_validate(e["record"])
                out[a.item] = a
        return out

    def save(
        self, fields: Mapping[str, Any], *, expected_revision: int | None = None
    ) -> Annotation:
        """Validate and append. ``expected_revision`` (the revision the client last saw)
        rejects a save based on a stale copy instead of silently overwriting. An identical
        resubmission is a no-op that returns the stored record."""
        if self.finalized:
            raise FinalizedError("submission finalized; edits need a protocol amendment")
        item = fields.get("item")
        if not isinstance(item, int) or item not in self.items:
            raise AnnotationError(f"unknown item {item!r}")
        if fields.get("victim_event_id") != self.items[item]:
            raise AnnotationError(f"item {item}: event id does not match the reviewer sheet")
        prior = self.history(item)
        current = prior[-1].revision if prior else 0
        if expected_revision is not None and expected_revision != current:
            raise AnnotationError(
                f"item {item}: saved revision is {current}, not {expected_revision}; reload"
            )
        record = {
            **{k: v for k, v in fields.items() if k not in ("reviewer", "revision", "saved_at")},
            "reviewer": self.reviewer,
            "revision": current + 1,
            "saved_at": now(),
        }
        try:
            a = Annotation.model_validate(record)
        except ValidationError as exc:
            raise AnnotationError(_messages(exc)) from None
        if prior and _decision_view(prior[-1]) == _decision_view(a):
            return prior[-1]
        self._append("annotation", a.model_dump(mode="json"))
        return a

    def finalize(self, sample: Mapping[str, str]) -> Submission:
        """Write the submission once every item has a decision. ``sample`` holds
        ``selection_sha256`` and ``sheet_sha256`` of the frozen sample."""
        if self.finalized:
            raise FinalizedError("already finalized")
        latest = self.latest()
        missing = sorted(set(self.items) - set(latest))
        if missing:
            raise AnnotationError(f"{len(missing)} item(s) have no decision: {missing[:10]}")
        log_sha = _sha((self.root / LOG).read_bytes())
        body = {
            "schema_version": SUBMISSION_SCHEMA,
            "protocol": PROTOCOL,
            "reviewer": self.reviewer,
            "selection_sha256": sample["selection_sha256"],
            "sheet_sha256": sample["sheet_sha256"],
            "decisions": [latest[i].model_dump(mode="json") for i in sorted(latest)],
            "revisions": sum(1 for e in self.entries if e["kind"] == "annotation"),
            "log_sha256": log_sha,
            "finalized_at": now(),
        }
        sub = Submission.model_validate({**body, "content_sha256": _sha(_canonical(body))})
        self._append("finalize", {"content_sha256": sub.content_sha256, "log_sha256": log_sha})
        atomic_write(self.root / SUBMISSION, sub.model_dump_json(indent=1).encode() + b"\n")
        return sub


def _decision_view(a: Annotation) -> dict[str, Any]:
    return a.model_dump(exclude={"revision", "saved_at"})


def _messages(exc: ValidationError) -> str:
    return "; ".join(
        (".".join(str(p) for p in e["loc"]) + ": " if e["loc"] else "") + e["msg"]
        for e in exc.errors()
    )


# --- submissions, replacements and adjudication -------------------------------------------


class Submission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-submission/1"]
    protocol: Protocol
    reviewer: str
    selection_sha256: str
    sheet_sha256: str
    decisions: tuple[Annotation, ...]
    revisions: int
    log_sha256: str
    finalized_at: str
    content_sha256: str

    def body_sha256(self) -> str:
        body = self.model_dump(mode="json", exclude={"content_sha256"})
        return _sha(_canonical(body))


def load_submission(path: Path) -> Submission:
    try:
        sub = Submission.model_validate_json(path.read_bytes())
    except ValidationError as exc:
        raise StoreCorruptError(f"{path}: {_messages(exc)}") from None
    if sub.body_sha256() != sub.content_sha256:
        raise StoreCorruptError(f"{path}: content hash does not match; the file was edited")
    if any(a.reviewer != sub.reviewer for a in sub.decisions):
        raise StoreCorruptError(f"{path}: a decision belongs to another reviewer")
    items = [a.item for a in sub.decisions]
    if len(set(items)) != len(items):
        raise StoreCorruptError(f"{path}: repeated item")
    return sub


ReplacementReason = Literal[
    "transaction_not_found",  # the planting transaction cannot be retrieved anywhere
    "chain_data_unavailable",  # no explorer or archive can show the block
    "sheet_record_malformed",  # the frozen sheet line cannot be presented
]


class ReplacementRecord(BaseModel):
    """Replacement for technical inaccessibility only; difficulty, disagreement or an
    apparently benign item is a result, never a reason."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-replacement/1"] = "poisoning-replacement/1"
    original_event_id: str
    original_item: int = Field(ge=1)
    replacement_event_id: str
    replacement_item: int = Field(ge=1)  # numbered after the frozen sheet
    sheet_line: dict[str, Any]  # blinded, as ``review_sample.blind`` builds it
    stratum: str  # maintainer-only: never copied into a reviewer package
    reserve_position: int = Field(ge=0)  # index in the stratum's frozen reserve list
    reason: ReplacementReason
    inaccessibility_evidence: str = Field(min_length=10)
    reviewers_exposed_to_original: tuple[str, ...]
    recorded_by: str
    recorded_at: str
    protocol: Protocol = "review-protocol/1+amendment-2"


def validate_replacements(
    manifest: Mapping[str, Any], records: Sequence[ReplacementRecord]
) -> list[str]:
    """Each replacement must replace an active item and take the next unused reserve of its
    stratum, in frozen order. A replacement can itself be replaced, by the same rule."""
    problems: list[str] = []
    active = {r["victim_event_id"]: r["stratum"] for r in manifest["selected"]}
    used: dict[str, int] = {}
    for rec in records:
        s = active.get(rec.original_event_id)
        if s is None:
            problems.append(f"{rec.original_event_id}: not an active sampled item")
            continue
        if rec.stratum != s:
            problems.append(f"{rec.original_event_id}: stratum {rec.stratum} != {s}")
        reserves = manifest["reserves"].get(s, [])
        pos = used.get(s, 0)
        if pos >= len(reserves) or reserves[pos] != rec.replacement_event_id:
            problems.append(f"{rec.original_event_id}: not the next reserve of {s}")
        if rec.reserve_position != pos:
            problems.append(f"{rec.original_event_id}: reserve position {rec.reserve_position}")
        if rec.sheet_line.get("victim_event_id") != rec.replacement_event_id:
            problems.append(f"{rec.original_event_id}: sheet line is for another event")
        del active[rec.original_event_id]
        active[rec.replacement_event_id] = s
        used[s] = pos + 1
    return problems


class AdjudicationRecord(BaseModel):
    """A third, separately recorded decision. It never replaces the two originals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["poisoning-adjudication/1"] = "poisoning-adjudication/1"
    victim_event_id: str
    adjudicator: str
    reviewer_decisions: dict[str, Decision]  # as finalized, by reviewer pseudonym
    final_decision: Decision
    rationale: str = Field(min_length=10)
    additional_evidence_used: bool
    saw_source_labels: bool
    adjudicated_at: str


def read_jsonl[M: BaseModel](path: Path, model: type[M]) -> list[M]:
    out: list[M] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(model.model_validate_json(line))
        except ValidationError as exc:
            raise AnnotationError(f"{path}: line {i}: {_messages(exc)}") from None
    return out


def to_review_decisions(subs: Iterable[Submission]) -> list[ReviewDecision]:
    return [a.to_review_decision() for s in subs for a in s.decisions]

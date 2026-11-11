"""Phase 12.9 reviewer-blinding integrity (protocol 12.9, Part I). Offline only.

Two jobs:

1. **Exposure audit** of the frozen review cohorts. Each item's identifiers come from the
   blinded reviewer sheet only (the unblinding key is hashed for integrity, never parsed).
   They are searched in the public repository at HEAD, in every line ever added to its
   history, and as truncated prefixes. Each match gets the role of the artifact it is in
   (outcome, context or neutral), which sets a deterministic level R0/R1/R2/R3/RU. The
   item's documented provenance gives a separate external level. R4 (confirmed reviewer
   exposure) is never inferred from R3: it comes only from a reviewer's own declaration.

2. **Prospective review workflow**: task payloads built from a whitelist and checked for
   outcome-bearing keys or words, reviewer declarations that are never defaulted, and an
   adjudication-readiness check.

Per-item mappings are written to the git-ignored research directory only. The public
report carries aggregates.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.label_policy import MIN_REVIEWERS

STUDY_VERSION = "review-blinding/1"
TASK_VERSION = "review-task/1"
Level = Literal["R0", "RU", "R1", "R2", "R3", "R4"]
ORDER: dict[str, int] = {"R0": 0, "RU": 1, "R1": 2, "R2": 3, "R3": 4, "R4": 5}
ROLE_LEVEL = {"neutral": "R1", "context": "R2", "outcome": "R3"}
DISPOSITION = {
    "R3": "not eligible for confirmatory blinded evaluation (exploratory or sensitivity only)",
    "R2": "requires qualified blinding; sensitivity stratum",
    "R1": "eligible for an explicitly qualified blinded review",
    "R0": "eligible for an explicitly qualified blinded review",
    "RU": "requires exposure clarification",
}
FREEZE_DATE = "2026-11-02"  # both cohorts (Phase 11.4 and c68d3a4)
PUBLIC_NOT_FOUND = "2026-11-09"  # anonymous API: Not Found
PUBLIC_SEEN = "2026-11-10"  # anonymous API: visibility public
COHORT_DIRS = {
    rs.SAMPLE_VERSION: Path("review_sample"),
    "hard-negative-candidates/1": Path("hard_negative/cohort_v1"),
}
EXTERNAL_LEVEL = {
    "archive_payoff_linked": "R3",  # the public dataset labels the event's payoff victim
    "archive_uncategorized": "R2",  # public dataset, poisoning-attempt context
    "recorded_window": "R0",  # raw chain data alone carries no label
    "unknown": "RU",
}

_HEX = re.compile(r"0x[0-9a-fA-F]{64}|0x[0-9a-fA-F]{40}")
_PARTIAL = re.compile(r"0x([0-9a-fA-F]{8,39})\s*(?:…|\.\.\.)")
_LINE_KEY = re.compile(r'"([A-Za-z_]+)"\s*:\s*"[^"]*0x')
_INCIDENT_DIR = r"(?:src/cryptoguard/replay/cases|docs/ml/incident-benchmark/cases)/[^/]+"
REGISTRY_OUTCOME_KEYS = frozenset({"lookalike", "harm_tx", "planting_tx"})
MANIFEST_OUTCOME_PATHS = frozenset({("harm", "recipient"), ("harm", "transaction_hash")})
MANIFEST_OUTCOME_LINE_KEYS = frozenset({"recipient", "transaction_hash"})  # conservative


# --- artifact roles --------------------------------------------------------------------------


def artifact_kind(path: str) -> str:
    p = path.replace("\\", "/")
    if re.fullmatch(_INCIDENT_DIR + r"/manifest\.json", p):
        return "incident_manifest"
    if re.fullmatch(r"docs/ml/incident-benchmark/[^/]*candidates[^/]*\.json", p):
        return "incident_registry"
    if re.fullmatch(_INCIDENT_DIR + r"/fixture\.json", p):
        return "incident_fixture"
    if p.startswith("src/cryptoguard/replay/campaign_cases/"):
        return "campaign_expansion"
    return "neutral"


DEFAULT_ROLE = {
    "incident_manifest": "context",
    "incident_registry": "context",
    "incident_fixture": "context",
    "campaign_expansion": "context",
    "neutral": "neutral",
}


def _stronger(a: str | None, b: str) -> str:
    rank = {"neutral": 0, "context": 1, "outcome": 2}
    return b if a is None or rank[b] > rank[a] else a


def _walk(obj: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, (*path, str(k)))
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, path)
    elif isinstance(obj, str):
        yield path, obj


def json_roles(kind: str, obj: Any) -> dict[str, str]:
    """Identifier (lower case) -> its strongest role in one parsed artifact."""
    out: dict[str, str] = {}
    for path, text in _walk(obj):
        for m in _HEX.findall(text):
            role = DEFAULT_ROLE[kind]
            if kind == "incident_manifest" and path[-2:] in MANIFEST_OUTCOME_PATHS:
                role = "outcome"
            if (
                kind == "incident_registry"
                and "identifiers" in path
                and path[-1:]
                and (path[-1] in REGISTRY_OUTCOME_KEYS or path[-1].startswith("etherscan_filter"))
            ):
                role = "outcome"
            out[m.lower()] = _stronger(out.get(m.lower()), role)
    return out


def line_role(kind: str, line: str) -> str:
    """Role of an identifier on one added history line (no parse of the whole file)."""
    keys = set(_LINE_KEY.findall(line))
    if kind == "incident_registry" and (
        keys & REGISTRY_OUTCOME_KEYS or any(k.startswith("etherscan_filter") for k in keys)
    ):
        return "outcome"
    if kind == "incident_manifest" and keys & MANIFEST_OUTCOME_LINE_KEYS:
        return "outcome"
    return DEFAULT_ROLE[kind]


# --- git channels ----------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout


@dataclass
class Occurrence:
    path: str
    kind: str
    role: str
    channel: str  # head | history
    first_date: str | None = None


def scan_head(root: Path, idents: frozenset[str]) -> dict[str, list[Occurrence]]:
    out: dict[str, list[Occurrence]] = {}
    listing = _git(root, "ls-files") or ""
    for rel in (f for f in listing.splitlines() if f):
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hit = {m.lower() for m in _HEX.findall(text)} & idents
        if not hit:
            continue
        kind = artifact_kind(rel)
        roles: dict[str, str] = {}
        if kind != "neutral" and rel.endswith(".json"):
            try:
                roles = json_roles(kind, json.loads(text))
            except ValueError:
                roles = {}
        for i in hit:
            out.setdefault(i, []).append(
                Occurrence(rel, kind, roles.get(i, DEFAULT_ROLE[kind]), "head")
            )
    return out


def scan_history(root: Path, idents: frozenset[str]) -> dict[str, dict[str, Occurrence]]:
    """Identifier -> file -> first added occurrence (date and role) across all commits."""
    patch = _git(
        root,
        "log",
        "--all",
        "--reverse",
        "-p",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--date=short",
        "--format=%x1ecommit %ad",
    )
    out: dict[str, dict[str, Occurrence]] = {}
    date: str | None = None
    current: str | None = None
    # split on newlines only: str.splitlines() also breaks at the \x1e record separator
    for line in (patch or "").split("\n"):
        line = line.rstrip("\r")
        if line.startswith("\x1ecommit "):
            date = line.split(" ", 1)[1].strip()
        elif line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and current is not None:
            hit = {m.lower() for m in _HEX.findall(line)} & idents
            if not hit:
                continue
            kind = artifact_kind(current)
            role = line_role(kind, line)
            for i in hit:
                prior = out.setdefault(i, {}).get(current)
                if prior is None:
                    out[i][current] = Occurrence(current, kind, role, "history", date)
                else:
                    prior.role = _stronger(prior.role, role)
    return out


def scan_partial(root: Path, idents: frozenset[str]) -> dict[str, list[str]]:
    """Identifier -> tracked files holding a truncated prefix it extends (ambiguous)."""
    out: dict[str, list[str]] = {}
    listing = _git(root, "ls-files") or ""
    for rel in (f for f in listing.splitlines() if f):
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        prefixes = {"0x" + p.lower() for p in _PARTIAL.findall(text)}
        for pre in prefixes:
            for i in idents:
                if i.startswith(pre) and i != pre:
                    out.setdefault(i, []).append(rel)
    return out


# --- items and levels ------------------------------------------------------------------------


@dataclass
class Item:
    cohort: str
    item: int
    provenance: str
    core: frozenset[str]
    context: frozenset[str]
    sheet_sha256: str


def provenance(row: Mapping[str, Any]) -> str:
    """The item's documented provenance class, from the blinded sheet's own fields."""
    note = str(row.get("coverage_note", ""))
    if row.get("schema_version") == rs.SHEET_SCHEMA and not note:
        return "archive_payoff_linked"  # every review-sample/1 item is payoff-linked
    if note.startswith("No wallet history is included"):
        return "archive_uncategorized"
    if note.startswith("The wallet's transfers in the recorded window"):
        return "recorded_window"
    return "unknown"


def load_items(poisoning_dir: Path) -> list[Item]:
    items: list[Item] = []
    for cohort, rel in COHORT_DIRS.items():
        sheet = poisoning_dir / rel / rs.SHEET
        sha = rs.file_sha256(sheet)
        for r in rs.read_sheet(sheet):
            core = frozenset(
                str(r[k]).lower() for k in ("wallet", "address_under_review", "transaction")
            )
            ctx = frozenset(str(c["counterparty"]).lower() for c in r.get("context", []))
            items.append(Item(cohort, int(r["item"]), provenance(r), core, ctx - core, sha))
    return items


def verify_cohorts(poisoning_dir: Path) -> dict[str, dict[str, str]]:
    """Committed-hash check of every frozen cohort (key bytes hashed, never parsed)."""
    out: dict[str, dict[str, str]] = {}
    for cohort, rel in COHORT_DIRS.items():
        d = poisoning_dir / rel
        rs.verify_frozen(d, cohort=cohort, with_key=True)
        out[cohort] = {n: rs.file_sha256(d / n) for n in (rs.MANIFEST, rs.SHEET, rs.KEY)}
    return out


def max_level(levels: Iterable[str]) -> str:
    return max(levels, key=lambda x: ORDER[x], default="R0")


@dataclass
class Assessment:
    cohort: str
    item: int
    provenance: str
    repo_level: str
    repo_level_core_only: str
    repo_level_campaign_as_outcome: str
    external_level: str
    combined: str
    disposition: str
    occurrences: list[dict[str, Any]] = field(default_factory=list)
    partial_files: int = 0
    identifiers_matched: dict[str, int] = field(default_factory=dict)


def _level(occs: Sequence[Occurrence], partial: bool, *, campaign_outcome: bool = False) -> str:
    if occs:
        roles = [
            "outcome" if campaign_outcome and o.kind == "campaign_expansion" else o.role
            for o in occs
        ]
        return max_level(ROLE_LEVEL[r] for r in roles)
    return "RU" if partial else "R0"


def assess(
    item: Item,
    head: Mapping[str, Sequence[Occurrence]],
    history: Mapping[str, Mapping[str, Occurrence]],
    partial: Mapping[str, Sequence[str]],
) -> Assessment:
    def occurrences(idents: Iterable[str]) -> list[Occurrence]:
        occs: list[Occurrence] = []
        for i in idents:
            at_head = {o.path: o for o in head.get(i, ())}
            hist = history.get(i, {})
            for path, o in at_head.items():
                first = hist[path].first_date if path in hist else None
                occs.append(Occurrence(o.path, o.kind, o.role, "head", first))
            occs += [o for p, o in hist.items() if p not in at_head]
        return occs

    every = item.core | item.context
    occs = occurrences(every)
    core_occs = occurrences(item.core)
    has_partial = any(partial.get(i) for i in every)
    repo = _level(occs, has_partial)
    external = EXTERNAL_LEVEL[item.provenance]
    combined = max_level((repo, external))
    matched = {
        "core": sum(1 for i in item.core if head.get(i) or history.get(i)),
        "context": sum(1 for i in item.context if head.get(i) or history.get(i)),
    }
    return Assessment(
        cohort=item.cohort,
        item=item.item,
        provenance=item.provenance,
        repo_level=repo,
        repo_level_core_only=_level(core_occs, any(partial.get(i) for i in item.core)),
        repo_level_campaign_as_outcome=_level(occs, has_partial, campaign_outcome=True),
        external_level=external,
        combined=combined,
        disposition=DISPOSITION[combined],
        occurrences=[
            {
                "path": o.path,
                "kind": o.kind,
                "role": o.role,
                "channel": o.channel,
                "first_date": o.first_date,
            }
            for o in sorted(occs, key=lambda o: (o.path, o.channel))
        ],
        partial_files=len({f for i in every for f in partial.get(i, ())}),
        identifiers_matched=matched,
    )


def core_overlap_12_8(
    head: Mapping[str, Sequence[Occurrence]], items: Sequence[Item]
) -> dict[str, int]:
    """The Phase 12.8 measure: per tracked file, unique core identifiers; summed."""
    core = {i for it in items for i in it.core}
    per_file: Counter[str] = Counter()
    for i in core:
        for o in head.get(i, ()):
            per_file[o.path] += 1
    return {"files": len(per_file), "identifiers": sum(per_file.values())}


def summarize(assessments: Sequence[Assessment]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cohort in COHORT_DIRS:
        rows = [a for a in assessments if a.cohort == cohort]
        files = {o["path"] for a in rows for o in a.occurrences}
        dates = [o["first_date"] for a in rows for o in a.occurrences if o["first_date"]]
        out[cohort] = {
            "items": len(rows),
            "provenance": dict(Counter(a.provenance for a in rows)),
            "repo_level": dict(Counter(a.repo_level for a in rows)),
            "repo_level_core_identifiers_only": dict(Counter(a.repo_level_core_only for a in rows)),
            "repo_level_if_campaign_expansion_were_outcome": dict(
                Counter(a.repo_level_campaign_as_outcome for a in rows)
            ),
            "external_level": dict(Counter(a.external_level for a in rows)),
            "combined_level": dict(Counter(a.combined for a in rows)),
            "disposition": dict(Counter(a.disposition for a in rows)),
            "items_with_core_match": sum(a.identifiers_matched["core"] > 0 for a in rows),
            "items_with_context_only_match": sum(
                a.identifiers_matched["core"] == 0 and a.identifiers_matched["context"] > 0
                for a in rows
            ),
            "items_with_history_only_match": sum(
                bool(a.occurrences) and all(o["channel"] == "history" for o in a.occurrences)
                for a in rows
            ),
            "items_with_partial_match": sum(a.partial_files > 0 for a in rows),
            "overlapping_files": len(files),
            "overlapping_file_kinds": dict(Counter(artifact_kind(f) for f in files)),
            "first_added": {
                "earliest": min(dates, default=None),
                "latest": max(dates, default=None),
                "before_freeze": sum(d < FREEZE_DATE for d in dates),
                "on_or_after_freeze": sum(d >= FREEZE_DATE for d in dates),
            },
            "confirmatory_eligible_items": sum(ORDER[a.combined] <= ORDER["R1"] for a in rows),
        }
    return out


# --- prospective review workflow -------------------------------------------------------------

Answer = Literal["yes", "no", "unknown"]
PAYLOAD_FIELDS = (
    "item",
    "chain_id",
    "wallet",
    "address_under_review",
    "transaction",
    "block",
    "context",
    "coverage_note",
)
CONTEXT_FIELDS = ("block", "counterparty", "direction", "value")
ALLOWED_KEYS = frozenset(PAYLOAD_FIELDS) | frozenset(CONTEXT_FIELDS)  # values still checked
FORBIDDEN_KEY = re.compile(
    r"(?i)label|status|verdict|outcome|payoff|attack|attribut|score|rank|predict|model|"
    r"decision|review|subtype|source|conclu|cohort|stratum|purpose|victim|lookalike|imitat|"
    r"intended|harm|key|exposure|description|warning"
)
FORBIDDEN_TEXT = re.compile(
    r"(?i)poison|scam|attack|victim|lookalike|look-alike|payoff|malicious|phish|stolen|theft|"
    r"exploit|drain|confirmed|verified|legitimate|benign|hard.?negative|positive|negative|"
    r"suspicious|fraud"
)
GUIDANCE_LEAKS = re.compile(
    r"(?i)payoff|confirmed (?:victim|attack|poison)|known (?:victim|attack|incident)|"
    r"most (?:of these|items|cases)|majority|expected (?:answer|label|result)|ground truth|"
    r"answer key|unblind|cohort|hard.?negative|\bpositives?\b|\bnegatives?\b|source label|"
    r"dataset label|was paid|lost funds|later lost|the model (?:flag|rank|score)"
)


class PayloadLeakError(ValueError):
    """A review payload would carry outcome-bearing information."""


def assert_payload_clean(payload: Any, where: str = "payload") -> None:
    """Raise if a key or a text value could carry a label, a verdict or an attribution.
    The message names the location only, never the value."""
    if isinstance(payload, dict):
        for k, v in payload.items():
            if str(k) not in ALLOWED_KEYS and FORBIDDEN_KEY.search(str(k)):
                raise PayloadLeakError(f"forbidden key at {where}.{k}")
            assert_payload_clean(v, f"{where}.{k}")
    elif isinstance(payload, list):
        for n, v in enumerate(payload):
            assert_payload_clean(v, f"{where}[{n}]")
    elif isinstance(payload, str) and FORBIDDEN_TEXT.search(payload):
        raise PayloadLeakError(f"outcome-bearing wording at {where}")


def task_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """The reviewer-visible payload: whitelisted sheet fields only."""
    out: dict[str, Any] = {}
    for k in PAYLOAD_FIELDS:
        if k not in row:
            continue
        if k == "context":
            out[k] = [{f: c[f] for f in CONTEXT_FIELDS if f in c} for c in row[k]]
        else:
            out[k] = row[k]
    assert_payload_clean(out)
    return out


class ReviewerDeclaration(BaseModel):
    """Given by the reviewer, per task. Nothing here is ever filled in for them."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reviewer_id: str
    task_id: str
    prior_familiarity: Answer
    external_sources_consulted: Answer
    repository_consulted: Answer
    model_output_seen: Answer
    declared_at: str

    @field_validator("reviewer_id")
    @classmethod
    def _rid(cls, v: str) -> str:
        from cryptoguard.ml.annotation import REVIEWER_ID

        if not REVIEWER_ID.match(v):
            raise ValueError("reviewer id must be an opaque code")
        return v


class ReviewTask(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = TASK_VERSION
    task_id: str
    item_version: str  # sheet SHA-256
    evidence_version: str
    evidence_sha256: str
    exposure_level: Level
    payload: dict[str, Any]


def task_id(sheet_sha256: str, item: int) -> str:
    """Opaque: names neither the cohort nor its purpose."""
    return hashlib.sha256(f"cg-12.9-task|{sheet_sha256}|{item}".encode()).hexdigest()[:20]


def build_task(
    row: Mapping[str, Any],
    *,
    sheet_sha256: str,
    evidence_version: str,
    evidence_sha256: str,
    exposure_level: str,
) -> ReviewTask:
    if exposure_level not in ORDER or exposure_level == "R4":
        raise ValueError("a task carries a computed item level; R4 comes only from a reviewer")
    return ReviewTask(
        task_id=task_id(sheet_sha256, int(row["item"])),
        item_version=sheet_sha256,
        evidence_version=evidence_version,
        evidence_sha256=evidence_sha256,
        exposure_level=exposure_level,
        payload=task_payload(row),
    )


def review_exposure(item_level: str, declaration: ReviewerDeclaration | None) -> dict[str, Any]:
    """The exposure of one review. A missing declaration is never defaulted (RU). R4 only
    when the reviewer declares familiarity or a consultation on an outcome-exposed item."""
    if declaration is None:
        return {"level": "RU", "reason": "no declaration", "model_output_seen": None}
    answers = (
        declaration.prior_familiarity,
        declaration.external_sources_consulted,
        declaration.repository_consulted,
    )
    model_seen = declaration.model_output_seen
    if item_level == "R3" and "yes" in answers:
        return {"level": "R4", "reason": "declared on an R3 item", "model_output_seen": model_seen}
    if "unknown" in answers:
        return {"level": "RU", "reason": "declaration incomplete", "model_output_seen": model_seen}
    return {"level": item_level, "reason": "declared", "model_output_seen": model_seen}


@dataclass(frozen=True)
class SubmittedReview:
    reviewer_id: str
    decision: str
    evidence_sha256: str
    declaration: ReviewerDeclaration | None


def adjudication_readiness(task: ReviewTask, reviews: Sequence[SubmittedReview]) -> dict[str, Any]:
    """Two independent decisions on the same evidence, each with a declaration."""
    problems: list[str] = []
    reviewers = {r.reviewer_id for r in reviews}
    if len(reviewers) < MIN_REVIEWERS:
        problems.append(f"fewer than {MIN_REVIEWERS} independent reviewers")
    if len(reviewers) != len(reviews):
        problems.append("a reviewer submitted more than once")
    if any(r.evidence_sha256 != task.evidence_sha256 for r in reviews):
        problems.append("a decision was made on different evidence")
    levels = [review_exposure(task.exposure_level, r.declaration)["level"] for r in reviews]
    if any(r.declaration is None for r in reviews):
        problems.append("a declaration is missing")
    elif any(r.declaration.task_id != task.task_id for r in reviews if r.declaration):
        problems.append("a declaration names another task")
    return {
        "ready": not problems,
        "problems": problems,
        "review_levels": levels,
        "confirmatory": not problems and all(ORDER[x] <= ORDER["R1"] for x in levels),
    }


def guidance_findings(text: str) -> dict[str, int]:
    """Counts of prevalence or source-verdict hints in reviewer guidance (no text)."""
    return dict(Counter(m.group(0).lower() for m in GUIDANCE_LEAKS.finditer(text)))


# --- study ----------------------------------------------------------------------------------


def main(root: Path, poisoning_dir: Path, out: Path, *, history: bool = True) -> dict[str, Any]:
    before = verify_cohorts(poisoning_dir)
    items = load_items(poisoning_dir)
    idents = frozenset(i for it in items for i in it.core | it.context)
    head = scan_head(root, idents)
    hist = scan_history(root, idents) if history else {}
    partial = scan_partial(root, idents)
    rows = [assess(it, head, hist, partial) for it in items]
    after = verify_cohorts(poisoning_dir)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "item_exposure.local.jsonl").open("w", encoding="utf-8") as fh:
        for a in rows:
            fh.write(json.dumps(a.__dict__, sort_keys=True) + "\n")
    kits = sorted((poisoning_dir / "outbox").glob("reviewer-*/*.md"))
    guidance = {
        "files": len(kits),
        "files_with_findings": sum(
            bool(guidance_findings(p.read_text(encoding="utf-8", errors="replace"))) for p in kits
        ),
        "findings": dict(
            sum(
                (
                    Counter(guidance_findings(p.read_text(encoding="utf-8", errors="replace")))
                    for p in kits
                ),
                Counter(),
            )
        ),
    }
    sent = []
    for rec in sorted((poisoning_dir / "outbox").glob("reviewer-*.record.json")):
        sent.append(json.loads(rec.read_text(encoding="utf-8")).get("sent") is not None)
    return {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.9",
        "rpc_requests": 0,
        "cohort_integrity": {
            "unchanged": before == after,
            "verified_against_committed_hashes": sorted(before),
        },
        "identifiers_searched": len(idents),
        "core_overlap_12_8_definition": core_overlap_12_8(head, items),
        "history_scanned": history,
        "cohorts": summarize(rows),
        "reviewer_process": {
            "kits_prepared": len(sent),
            "kits_sent": sum(sent),
            "submission_files_found": sum(
                1 for p in poisoning_dir.rglob("*submission*.json") if p.is_file()
            ),
            "declarations": 0,  # the declaration form is introduced in this phase
        },
        "existing_guidance_check": guidance,
        "timing": {
            "freeze": FREEZE_DATE,
            "public_not_found": PUBLIC_NOT_FOUND,
            "public_seen": PUBLIC_SEEN,
        },
    }

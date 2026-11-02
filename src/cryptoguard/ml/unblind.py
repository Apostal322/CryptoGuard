"""Maintainer side of the review: reviewer packages, replacements, the unblinding gate and
the pre-specified analysis (protocol §7 as amended).

Only this module reads the unblinding key, and only inside ``record_replacement`` (to
build one blinded line) and ``unblind``. ``unblind`` refuses to open the key until:
- the frozen files match their committed hashes;
- at least two distinct reviewers' finalized submissions cover every active item;
- every hash, id and protocol version checks out.
There is no flag to skip the gate. Each opening of the key is appended to an access log.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml import sample_design as sd
from cryptoguard.ml.agreement import BINARY, agreement, binary
from cryptoguard.ml.annotation import (
    ATTEMPT,
    PROTOCOL,
    AdjudicationRecord,
    AnnotationError,
    ReplacementReason,
    ReplacementRecord,
    Submission,
    _canonical,
    atomic_write,
    load_submission,
    now,
    read_jsonl,
    validate_replacements,
)
from cryptoguard.ml.review_server import PACKAGE_INFO, REPLACEMENT_SHEET

UNBLIND_VERSION = "unblind/1"
REPLACEMENTS = "replacements.jsonl"
ACCESS_LOG = "key_access.log.jsonl"
MIN_CELL = 10  # smallest subgroup for which agreement statistics are reported


class UnblindingRefused(AnnotationError):
    """A precondition of the unblinding gate failed; the key was not opened."""


def _log_access(work: Path, purpose: str, detail: Mapping[str, Any]) -> None:
    work.mkdir(parents=True, exist_ok=True)
    path = work / ACCESS_LOG
    line = json.dumps({"at": now(), "purpose": purpose, **detail}, sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)


def record_of(row: Mapping[str, Any]) -> Mapping[str, Any]:
    """The source record in a key line: a review packet (Phase 11.4 sample) or a candidate
    record (later cohorts)."""
    rec: Mapping[str, Any] = row.get("packet") or row["candidate"]
    return rec


def _id(row: Mapping[str, Any]) -> str:
    rec = record_of(row)
    return str(rec.get("victim_event_id") or rec["event_id"])


def _key_rows(sample_dir: Path, wanted: set[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in (sample_dir / rs.KEY).read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if _id(row) in wanted:
            out[_id(row)] = row
    return out


def replacements(work: Path) -> list[ReplacementRecord]:
    path = work / REPLACEMENTS
    return read_jsonl(path, ReplacementRecord) if path.exists() else []


# --- reviewer packages -------------------------------------------------------------------


def make_package(
    sample_dir: Path, work: Path, reviewer: str, out: Path, *, cohort: str = rs.SAMPLE_VERSION
) -> Path:
    """Copy what one reviewer needs and nothing else: the blinded sheet (byte for byte), any
    blinded replacement lines and a small info file. Never the key or the manifest."""
    from cryptoguard.ml.annotation import REVIEWER_ID

    if not REVIEWER_ID.match(reviewer):
        raise AnnotationError(f"invalid reviewer pseudonym {reviewer!r}")
    manifest = rs.verify_frozen(sample_dir, cohort=cohort)
    info_path = out / PACKAGE_INFO
    if info_path.exists():
        existing = json.loads(info_path.read_text(encoding="utf-8"))
        if existing.get("reviewer") != reviewer:
            raise AnnotationError(f"{out} already belongs to reviewer {existing.get('reviewer')}")
    elif out.exists() and any(out.iterdir()):
        raise AnnotationError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sample_dir / rs.SHEET, out / rs.SHEET)
    expected_evidence = rs.COHORTS[cohort].get("evidence")
    if expected_evidence:  # amendment 2: the registered pre-cutoff evidence packets
        from cryptoguard.ml.evidence import PACKETS

        src = work / "evidence" / PACKETS
        if not src.exists() or rs.file_sha256(src) != expected_evidence:
            raise AnnotationError(
                f"{src}: registered evidence packets missing or changed; rebuild with "
                "`cryptoguard ml review build-evidence`"
            )
        shutil.copyfile(src, out / PACKETS)
    recs = replacements(work)
    problems = validate_replacements(manifest, recs)
    if problems:
        raise AnnotationError("; ".join(problems))
    lines = [
        json.dumps({"replaces_item": r.original_item, **r.sheet_line}, sort_keys=True) + "\n"
        for r in recs
    ]
    if lines:
        atomic_write(out / REPLACEMENT_SHEET, "".join(lines).encode())
    info = {
        "reviewer": reviewer,
        "protocol": PROTOCOL,
        "selection_sha256": manifest["selection_sha256"],
        "sheet_sha256": rs.file_sha256(out / rs.SHEET),
    }
    atomic_write(info_path, json.dumps(info, indent=1).encode() + b"\n")
    return out


def record_replacement(
    sample_dir: Path,
    work: Path,
    *,
    original_event_id: str,
    reason: ReplacementReason,
    evidence: str,
    exposed: Sequence[str],
    recorded_by: str,
    cohort: str = rs.SAMPLE_VERSION,
) -> ReplacementRecord:
    """Append the next frozen reserve of the original's stratum. Only for technical
    inaccessibility; the log keeps every replacement with its reason."""
    manifest = rs.verify_frozen(sample_dir, cohort=cohort)
    recs = replacements(work)
    active = {r["victim_event_id"]: r["stratum"] for r in manifest["selected"]}
    items = {r["victim_event_id"]: r["item"] for r in rs.read_sheet(sample_dir / rs.SHEET)}
    used: Counter[str] = Counter()
    for r in recs:
        del active[r.original_event_id]
        active[r.replacement_event_id] = r.stratum
        items[r.replacement_event_id] = r.replacement_item
        used[r.stratum] += 1
    stratum = active.get(original_event_id)
    if stratum is None:
        raise AnnotationError(f"{original_event_id} is not an active sampled item")
    reserves = manifest["reserves"].get(stratum, [])
    pos = used[stratum]
    if pos >= len(reserves):
        raise AnnotationError(f"{stratum}: no reserve left (nonresponse; see protocol §5)")
    new_id = reserves[pos]
    _log_access(work, "replacement sheet line", {"event": new_id})
    row = _key_rows(sample_dir, {new_id})[new_id]
    item = max(items.values()) + 1
    if "packet" in row:
        from cryptoguard.ml.review import ReviewPacket

        line = rs.blind(ReviewPacket.model_validate(row["packet"]), item)
    else:  # later cohorts keep the blinded line in the frozen key's sheet copy
        line = {**row["sheet"], "item": item}
    rec = ReplacementRecord(
        original_event_id=original_event_id,
        original_item=items[original_event_id],
        replacement_event_id=new_id,
        replacement_item=item,
        sheet_line=line,
        stratum=stratum,
        reserve_position=pos,
        reason=reason,
        inaccessibility_evidence=evidence,
        reviewers_exposed_to_original=tuple(exposed),
        recorded_by=recorded_by,
        recorded_at=now(),
    )
    problems = validate_replacements(manifest, [*recs, rec])
    if problems:
        raise AnnotationError("; ".join(problems))
    work.mkdir(parents=True, exist_ok=True)
    with (work / REPLACEMENTS).open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(rec.model_dump_json() + "\n")
    return rec


# --- gate --------------------------------------------------------------------------------


def preflight(
    sample_dir: Path,
    work: Path,
    submission_paths: Sequence[Path],
    adjudication_path: Path | None = None,
    *,
    cohort: str = rs.SAMPLE_VERSION,
) -> dict[str, Any]:
    """Every check that must pass before the key may be opened. Raises
    ``UnblindingRefused`` listing all failures. Never reads the key's contents (only its
    hash)."""
    problems: list[str] = []
    try:
        manifest = rs.verify_frozen(sample_dir, cohort=cohort)
    except rs.ReviewSampleError as exc:
        raise UnblindingRefused(f"frozen sample: {exc}") from None
    recs = replacements(work)
    problems += validate_replacements(manifest, recs)
    active = {r["victim_event_id"] for r in manifest["selected"]}
    for r in recs:
        active.discard(r.original_event_id)
        active.add(r.replacement_event_id)
    subs: list[Submission] = []
    for p in submission_paths:
        try:
            subs.append(load_submission(p))
        except (AnnotationError, OSError) as exc:
            problems.append(str(exc))
    reviewers = [s.reviewer for s in subs]
    if len(set(reviewers)) < 2:
        problems.append("two finalized submissions from distinct reviewers are required")
    if len(set(reviewers)) != len(reviewers):
        problems.append("a reviewer submitted twice")
    for s in subs:
        if s.selection_sha256 != manifest["selection_sha256"]:
            problems.append(f"{s.reviewer}: submission is for another sample")
        if s.sheet_sha256 != rs.COHORTS[cohort][rs.SHEET]:
            problems.append(f"{s.reviewer}: submission is for another reviewer sheet")
        if s.protocol != PROTOCOL:
            problems.append(f"{s.reviewer}: protocol {s.protocol}")
        got = {a.victim_event_id for a in s.decisions}
        if got - active:
            problems.append(f"{s.reviewer}: {len(got - active)} unknown or replaced item(s)")
        if active - got:
            problems.append(f"{s.reviewer}: {len(active - got)} active item(s) without a decision")
    adjudications: list[AdjudicationRecord] = []
    if adjudication_path is not None:
        adjudications = read_jsonl(adjudication_path, AdjudicationRecord)
        decided = {s.reviewer: {a.victim_event_id: a.decision for a in s.decisions} for s in subs}
        seen: set[str] = set()
        for adj in adjudications:
            if adj.victim_event_id in seen:
                problems.append(f"{adj.victim_event_id}: adjudicated twice")
            seen.add(adj.victim_event_id)
            if adj.adjudicator in decided:
                problems.append(f"{adj.victim_event_id}: adjudicator is one of the reviewers")
            originals = {r: d.get(adj.victim_event_id) for r, d in decided.items()}
            if adj.reviewer_decisions != originals:
                problems.append(
                    f"{adj.victim_event_id}: recorded decisions differ from submissions"
                )
            if len(set(originals.values())) < 2:
                problems.append(f"{adj.victim_event_id}: adjudication of an agreed item")
    if problems:
        raise UnblindingRefused("; ".join(problems))
    return {
        "manifest": manifest,
        "submissions": subs,
        "replacements": recs,
        "adjudications": adjudications,
        "active": active,
    }


def unblind(
    sample_dir: Path,
    work: Path,
    submission_paths: Sequence[Path],
    adjudication_path: Path | None = None,
    *,
    cohort: str = rs.SAMPLE_VERSION,
) -> dict[str, Any]:
    """Run the gate, open the key, write the local item table and return the aggregate
    report. Reviewer decisions are never overwritten by source labels."""
    pre = preflight(sample_dir, work, submission_paths, adjudication_path, cohort=cohort)
    active: set[str] = pre["active"]
    subs: list[Submission] = pre["submissions"]
    _log_access(
        work,
        "unblind",
        {
            "reviewers": sorted(s.reviewer for s in subs),
            "submissions": sorted(s.content_sha256 for s in subs),
        },
    )
    key = _key_rows(sample_dir, active)
    report = analyse(pre["manifest"], subs, pre["replacements"], pre["adjudications"], key)
    rows = item_table(subs, pre["adjudications"], key)
    work.mkdir(parents=True, exist_ok=True)
    atomic_write(work / "unblinded_items.jsonl", b"".join(_canonical(r) + b"\n" for r in rows))
    body = json.dumps(report, indent=1, sort_keys=True).encode() + b"\n"
    atomic_write(work / "unblinded_report.json", body)
    return report


# --- analysis ----------------------------------------------------------------------------


def _decisions(subs: Sequence[Submission]) -> dict[str, dict[str, str]]:
    return {s.reviewer: {a.victim_event_id: a.decision for a in s.decisions} for s in subs}


def item_table(
    subs: Sequence[Submission],
    adjudications: Sequence[AdjudicationRecord],
    key: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Row-level, local only (contains addresses): reviewer decisions next to the source."""
    adj = {a.victim_event_id: a for a in adjudications}
    rows = []
    for e in sorted(key):
        packet = record_of(key[e])
        reviews = {s.reviewer: next(a for a in s.decisions if a.victim_event_id == e) for s in subs}
        found = {
            r: a.prior_counterparty_address.lower()
            for r, a in reviews.items()
            if a.prior_counterparty_address
        }
        imitated = (packet.get("imitated") or "").lower()
        rows.append(
            {
                "victim_event_id": e,
                "stratum": key[e]["stratum"],
                "source_subtype": packet.get("subtype"),
                "source_labels": packet.get("source_labels"),
                "frame": packet.get("frame"),
                "categories": packet.get("categories"),
                "screen_status": packet.get("screen_status"),
                "rival_lookalikes": len(packet.get("competing_lookalikes", ())),
                "reviewer_decisions": {r: a.decision for r, a in reviews.items()},
                "reviewer_counterparty_matches_source_imitated": {
                    r: addr == imitated for r, addr in found.items()
                },
                "adjudicated": adj[e].final_decision if e in adj else None,
            }
        )
    return rows


def _source_category(decisions: Sequence[str]) -> str:
    b = {binary(d) for d in decisions}
    if any(d == "insufficient_evidence" for d in decisions):
        return "insufficient_evidence"
    if len(b) > 1:
        return "reviewer_disagreement"
    if b == {"attempt"}:
        both_confirmed = all(d == "confirmed_poisoning_attempt" for d in decisions)
        return "full_agreement" if both_confirmed else "partial_agreement"
    if any(d == "conflicting_evidence" for d in decisions):
        return "unresolved_ambiguity"
    return "source_disagreement"


def analyse(
    manifest: Mapping[str, Any],
    subs: Sequence[Submission],
    recs: Sequence[ReplacementRecord],
    adjudications: Sequence[AdjudicationRecord],
    key: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Pre-specified analysis; aggregate only.

    The primary outcome is an item counted as an attempt only if *every* reviewer marked
    it confirmed or likely (protocol §7). A replaced original is nonresponse in the
    bounds. ``key`` (source information) is needed only for the source comparison."""
    d = sd.design(manifest)
    stratum_of = dict(d.item_cell)
    for r in recs:
        stratum_of[r.replacement_event_id] = r.stratum
    # Replacements take their original's slot in the design (same stratum, frozen order).
    slot = {r.replacement_event_id: r.original_event_id for r in recs}
    while any(v in slot for v in slot.values()):
        slot = {k: slot.get(v, v) for k, v in slot.items()}
    decisions = _decisions(subs)
    reviewers = sorted(decisions)
    items = sorted(set.intersection(*(set(v) for v in decisions.values())))

    def outcome(rule: str, positive: frozenset[str] = ATTEMPT) -> dict[str, bool | None]:
        out: dict[str, bool | None] = dict.fromkeys(d.item_cell)
        for e in items:
            labels = [decisions[r][e] for r in reviewers]
            flags = [x in positive for x in labels]
            out[slot.get(e, e)] = all(flags) if rule == "all" else any(flags)
        return out

    primary, lenient = outcome("all"), outcome("any")
    legitimate = outcome("all", frozenset({"confirmed_legitimate_interaction"}))
    adjudicated = dict(primary)
    for a in adjudications:
        adjudicated[slot.get(a.victim_event_id, a.victim_event_id)] = a.final_decision in ATTEMPT
    subtypes = sorted({c.subtype for c in d.cells.values() if c.selected})

    def block(o: Mapping[str, bool | None]) -> dict[str, Any]:
        overall = sd.estimate(d, o)
        return {
            "overall": overall,
            "attempt_level_bounds": sd.attempt_bounds(
                overall.get("wilson95_design"), d.population, d.queue_packets
            ),
            "by_subtype": {s: sd.estimate(d, o, scope=sd.subtype_scope(s)) for s in subtypes},
        }

    pair = reviewers[:2]
    a_lab = decisions[pair[0]]
    b_lab = decisions[pair[1]]
    agree: dict[str, Any] = {
        "reviewers": pair,
        "five_category": agreement(a_lab, b_lab),
        "binary": agreement(
            {k: binary(v) for k, v in a_lab.items()},
            {k: binary(v) for k, v in b_lab.items()},
            BINARY,
        ),
        "by_subgroup": {},
    }
    for name, member in _subgroups(stratum_of, manifest["design"].get("strata")).items():
        ids = [e for e in items if e in member]
        if len(ids) < MIN_CELL:
            agree["by_subgroup"][name] = {"items": len(ids), "note": f"fewer than {MIN_CELL}"}
            continue
        agree["by_subgroup"][name] = agreement(
            {e: binary(a_lab[e]) for e in ids}, {e: binary(b_lab[e]) for e in ids}, BINARY
        )
    exposure = {
        r: {
            "used_explorer": sum(a.used_explorer for a in s.decisions),
            "viewed_after_cutoff": dict(Counter(a.viewed_after_cutoff for a in s.decisions)),
            "saw_external_label": dict(Counter(a.saw_external_label for a in s.decisions)),
            "saw_source_or_model_output": sum(a.saw_source_or_model_output for a in s.decisions),
        }
        for r, s in zip(reviewers, sorted(subs, key=lambda s: s.reviewer), strict=True)
    }
    # Exploratory (protocol amendment 1 §6): attempt decisions by whether the reviewer saw
    # activity after the cutoff. Not a causal comparison.
    exposure_comparison = {
        s.reviewer: {
            seen: {
                "items": sum(1 for a in s.decisions if a.viewed_after_cutoff == seen),
                "attempt": sum(
                    1
                    for a in s.decisions
                    if a.viewed_after_cutoff == seen and a.decision in ATTEMPT
                ),
            }
            for seen in ("no", "yes", "unsure")
        }
        for s in subs
    }
    report: dict[str, Any] = {
        "unblind_version": UNBLIND_VERSION,
        "exposure_comparison_exploratory": exposure_comparison,
        "protocol": PROTOCOL,
        "selection_sha256": manifest["selection_sha256"],
        "submissions": {s.reviewer: s.content_sha256 for s in subs},
        "items_reviewed_by_all": len(items),
        "replacements": [
            {"stratum": r.stratum, "reason": r.reason, "reserve_position": r.reserve_position}
            for r in recs
        ],
        "primary_all_reviewers_attempt": block(primary),
        "sensitivity_any_reviewer_attempt": block(lenient),
        "secondary_adjudicated": block(adjudicated) if adjudications else None,
        # Share every reviewer judged a confirmed legitimate interaction (the hard-negative
        # cohort's primary quantity; reported for every cohort).
        "all_reviewers_legitimate": block(legitimate),
        "replacement_sensitivity": block(
            {
                **primary,
                **dict.fromkeys(
                    (slot.get(r.original_event_id, r.original_event_id) for r in recs), None
                ),
            }
        )
        if recs
        else None,
        "agreement": agree,
        "exposure": exposure,
        "decision_counts": {r: dict(Counter(decisions[r].values())) for r in reviewers},
        "rpc_requests": 0,
    }
    if key is not None:
        cats = Counter(_source_category([decisions[r][e] for r in reviewers]) for e in items)
        matched: Counter[str] = Counter()
        for e in items:
            imitated = (record_of(key[e]).get("imitated") or "").lower()
            for s in subs:
                ann = next(x for x in s.decisions if x.victim_event_id == e)
                if ann.prior_counterparty_address:
                    matched[
                        "same" if ann.prior_counterparty_address.lower() == imitated else "other"
                    ] += 1
        report["source_comparison"] = {
            "categories": dict(cats),
            "reviewer_counterparty_vs_source_imitated": dict(matched),
            "note": (
                "the source labels every item a poisoning attempt"
                if manifest["sample_version"] == rs.SAMPLE_VERSION
                else "items are unlabeled candidates; no source label exists"
            )
            + "; reviewer decisions are never overwritten by source information",
        }
    return report


def _subgroups(
    stratum_of: Mapping[str, str], names: Sequence[str] | None = None
) -> dict[str, set[str]]:
    first, _, third = names if names and len(names) == 3 else ("subtype", "year", "rival")
    third = "rival" if third == "rival_lookalike" else third
    first = first.split("_")[0] if first != "frame" else "frame"
    groups: dict[str, set[str]] = {}
    for e, name in stratum_of.items():
        head, year, flag = sd.parse_stratum(name)
        head = head.split(":")[0]  # one recorded wallet per stratum: report by frame
        for g in (f"{first}={head}", f"year={year}", f"{third}={'yes' if flag else 'no'}"):
            groups.setdefault(g, set()).add(e)
    return dict(sorted(groups.items()))

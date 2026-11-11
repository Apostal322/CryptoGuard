"""Submission checks and the pre-unblinding agreement report (Phase 11.6). Neither opens
the unblinding key.

``check_submission`` lists every problem with one reviewer's file instead of stopping at
the first:
- missing or corrupt file;
- edited content (hash);
- schema or stale protocol;
- wrong cohort sheet or sample;
- mixed reviewer ids;
- unknown, missing or repeated items;
- invalid evidence references (checked by the schema).

``agreement_report`` measures consistency between two finalized submissions. Agreement is
not correctness: two reviewers can agree and both be wrong.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.agreement import BINARY, agreement, binary
from cryptoguard.ml.annotation import PROTOCOL, AnnotationError, Submission, load_submission


def _active_ids(sample_dir: Path) -> dict[int, str]:
    return {r["item"]: r["victim_event_id"] for r in rs.read_sheet(sample_dir / rs.SHEET)}


def check_submission(path: Path, sample_dir: Path, *, cohort: str) -> list[str]:
    if not path.is_file():
        return [f"{path}: missing"]
    try:
        sub = load_submission(path)
    except (AnnotationError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [str(exc)]
    problems: list[str] = []
    expected = rs.COHORTS[cohort]
    if sub.sheet_sha256 != expected[rs.SHEET]:
        problems.append(f"sheet {sub.sheet_sha256[:12]} is not the {cohort} sheet")
    if sub.selection_sha256 != expected["selection"]:
        problems.append("submission is for another sample")
    if sub.protocol != PROTOCOL:
        problems.append(f"stale protocol {sub.protocol}; current is {PROTOCOL}")
    if len({a.reviewer for a in sub.decisions} | {sub.reviewer}) != 1:
        problems.append("decisions from more than one reviewer id")
    ids = _active_ids(sample_dir)
    got = Counter((a.item, a.victim_event_id) for a in sub.decisions)
    unknown = [i for i, e in got if ids.get(i) != e]
    if unknown:
        problems.append(f"{len(unknown)} decision(s) for items not on the sheet: {unknown[:5]}")
    repeated = [k for k, n in got.items() if n > 1]
    if repeated:
        problems.append(f"repeated items: {repeated[:5]}")
    missing = sorted(set(ids) - {i for i, _ in got})
    if missing:
        problems.append(f"{len(missing)} sheet item(s) without a decision: {missing[:10]}")
    return problems


def agreement_report(paths: Sequence[Path], sample_dir: Path, *, cohort: str) -> dict[str, Any]:
    problems = {str(p): check_submission(p, sample_dir, cohort=cohort) for p in paths}
    bad = {k: v for k, v in problems.items() if v}
    if bad:
        raise AnnotationError(f"invalid submissions: {bad}")
    subs: list[Submission] = [load_submission(p) for p in paths]
    reviewers = [s.reviewer for s in subs]
    if len(set(reviewers)) != len(reviewers) or len(reviewers) < 2:
        raise AnnotationError("agreement needs finalized submissions from 2+ distinct reviewers")
    a, b = sorted(subs, key=lambda s: s.reviewer)[:2]
    la = {x.victim_event_id: x.decision for x in a.decisions}
    lb = {x.victim_event_id: x.decision for x in b.decisions}
    manifest = json.loads((sample_dir / rs.MANIFEST).read_text(encoding="utf-8"))
    stratum = {r["victim_event_id"]: r["stratum"] for r in manifest["selected"]}
    by_head: dict[str, Any] = {}
    for head in sorted({s.split("|")[0].split(":")[0] for s in stratum.values()}):
        ids = [e for e in la if stratum.get(e, "").split("|")[0].split(":")[0] == head]
        by_head[head] = (
            agreement({e: binary(la[e]) for e in ids}, {e: binary(lb[e]) for e in ids}, BINARY)
            if len(ids) >= 10
            else {"items": len(ids), "note": "fewer than 10 items: counts only"}
        )
    return {
        "cohort": cohort,
        "reviewers": [a.reviewer, b.reviewer],
        "five_category": agreement(la, lb),
        "binary": agreement(
            {k: binary(v) for k, v in la.items()}, {k: binary(v) for k, v in lb.items()}, BINARY
        ),
        "by_stratum_group": by_head,
        "per_reviewer": {
            s.reviewer: {
                "decisions": dict(Counter(x.decision for x in s.decisions)),
                "insufficient_rate": sum(x.decision == "insufficient_evidence" for x in s.decisions)
                / len(s.decisions),
                "conflicting_rate": sum(x.decision == "conflicting_evidence" for x in s.decisions)
                / len(s.decisions),
                "used_offline_evidence": sum(bool(x.used_offline_evidence) for x in s.decisions),
                "saw_later_victim_payment": dict(
                    Counter(x.saw_later_victim_payment for x in s.decisions)
                ),
            }
            for s in subs
        },
        "note": "agreement measures consistency between reviewers, not correctness",
    }

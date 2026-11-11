"""Generic frozen review cohorts (Phase 11.5). The design matches ``review_sample`` (one
representative per group, stratified sampling without replacement by keyed SHA-256 rank,
ordered reserves, a hash-committed manifest), but every cohort has its own version, seed,
frame, strata and output directory. The Phase 11.4 sample is never touched.

The manifest uses the same keys as ``review_sample``, so ``sample_design.design`` and the
review workflow read both. ``queue_sha256`` is the hash of the cohort's eligible frame.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.annotation import atomic_write

SHEET_SCHEMA_V2 = "review-sheet/2"  # adds neutral description, context and coverage notes
NEUTRAL = "Candidate for independent security review"


@dataclass(frozen=True)
class FrameItem:
    """One eligible unit. ``sheet`` is the blinded reviewer view (no label, frame, category,
    screening result or score); ``key`` is everything else, maintainer-only."""

    event_id: str
    stratum: str  # "<frame>|<year>|<flag>", parsed by sample_design.parse_stratum
    group: str
    sheet: Mapping[str, Any]
    key: Mapping[str, Any]


@dataclass(frozen=True)
class CohortDesign:
    version: str
    seed: str
    quota: Mapping[str, int]  # per stratum prefix (the frame); allocation within it
    strata_names: tuple[str, str, str]
    notes: str


def _rank(seed: str, *parts: str) -> str:
    return hashlib.sha256("|".join((seed, *parts)).encode()).hexdigest()


def frame_sha256(items: Sequence[FrameItem]) -> str:
    rows = sorted(
        json.dumps(
            {"id": i.event_id, "stratum": i.stratum, "group": i.group, "key": i.key},
            sort_keys=True,
            default=str,
        )
        for i in items
    )
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def draw(items: Sequence[FrameItem], design: CohortDesign) -> dict[str, Any]:
    ids = [i.event_id for i in items]
    if len(set(ids)) != len(ids):
        raise rs.ReviewSampleError("frame repeats an event id")
    if not items:
        raise rs.ReviewSampleError("empty frame: nothing to sample")
    by_id = {i.event_id: i for i in items}
    members: dict[str, list[str]] = defaultdict(list)
    for i in items:
        members[i.group].append(i.event_id)
    reps = [min(v, key=lambda e: _rank(design.seed, "rep", e)) for v in members.values()]
    group_size = {e: len(members[by_id[e].group]) for e in reps}
    cells: dict[str, list[str]] = defaultdict(list)
    for e in reps:
        cells[by_id[e].stratum].append(e)
    for v in cells.values():
        v.sort(key=lambda e: _rank(design.seed, "select", e))
    alloc: dict[str, int] = {}
    for frame in sorted({s.split("|")[0] for s in cells}):
        sizes = {(s,): len(v) for s, v in cells.items() if s.split("|")[0] == frame}
        quota = design.quota.get(frame, 0)
        got = rs.allocate(sizes, quota) if quota else dict.fromkeys(sizes, 0)
        alloc |= {k[0]: n for k, n in got.items()}
    packets = Counter(i.stratum for i in items)
    selected: list[dict[str, Any]] = []
    reserves: dict[str, list[str]] = {}
    table: list[dict[str, Any]] = []
    for s in sorted(cells):
        v, n = cells[s], alloc[s]
        w = round(len(v) / n, 6) if n else None
        table.append(
            {"stratum": s, "packets": packets[s], "groups": len(v), "selected": n, "weight": w}
        )
        selected += [
            {"victim_event_id": e, "stratum": s, "group_size": group_size[e], "weight": w}
            for e in v[:n]
        ]
        reserves[s] = v[n:]
    order = sorted(
        (r["victim_event_id"] for r in selected), key=lambda e: _rank(design.seed, "order", e)
    )
    sheet = [
        {
            "schema_version": SHEET_SCHEMA_V2,
            "item": n,
            "victim_event_id": e,
            "description": NEUTRAL,
            **{k: v for k, v in by_id[e].sheet.items() if k not in ("item", "victim_event_id")},
        }
        for n, e in enumerate(order, start=1)
    ]
    role = {r["victim_event_id"]: ("selected", r["stratum"]) for r in selected}
    for s, v in reserves.items():
        role |= {e: ("reserve", s) for e in v}
    key = [
        {
            "role": role[e][0],
            "stratum": role[e][1],
            "group": by_id[e].group,
            "candidate": {"event_id": e, **by_id[e].key},
            "sheet": {
                "schema_version": SHEET_SCHEMA_V2,
                "victim_event_id": e,
                "description": NEUTRAL,
                **by_id[e].sheet,
            },
        }
        for e in sorted(role)
    ]
    selection = {
        "sample_version": design.version,
        "queue_sha256": frame_sha256(items),
        "design": {
            "seed": design.seed,
            "quota": dict(design.quota),
            "strata": list(design.strata_names),
            "allocation": "quota per frame; proportional within it, at least 1 per non-empty "
            "stratum, largest remainder",
            "ranking": "sha256(seed|purpose|event id), lowest first; one representative per group",
            "notes": design.notes,
        },
        "selected": selected,
        "reserves": reserves,
    }
    sizes_hist = Counter(len(v) for v in members.values())
    manifest = {
        **selection,
        "selection_sha256": rs.selection_sha256(selection),
        "queue_packets": len(items),
        "groups": {
            "count": len(members),
            "multi_packet": sum(v for k, v in sizes_hist.items() if k > 1),
            "largest": max(sizes_hist),
        },
        "strata_table": table,
        "rpc_requests": 0,
    }
    return {"manifest": manifest, "sheet": sheet, "key": key}


def freeze(
    items: Sequence[FrameItem], design: CohortDesign, out_dir: Path
) -> tuple[dict[str, Any], bool]:
    """Write once; later calls verify the recomputed selection and refuse a different one."""
    from cryptoguard.ml.cross_dataset import git_state

    sample = draw(items, design)
    manifest = sample["manifest"]
    path = out_dir / rs.MANIFEST
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        if old.get("queue_sha256") != manifest["queue_sha256"]:
            raise rs.SampleFrozenError(f"{path}: the eligible frame changed after freezing")
        if old.get("selection_sha256") != manifest["selection_sha256"]:
            raise rs.SampleFrozenError(f"{path}: a different cohort is already frozen")
        return old, False
    out_dir.mkdir(parents=True, exist_ok=True)
    sheet, key = rs._jsonl(sample["sheet"]), rs._jsonl(sample["key"])
    manifest["files"] = {
        rs.SHEET: hashlib.sha256(sheet).hexdigest(),
        rs.KEY: hashlib.sha256(key).hexdigest(),
    }
    manifest["git"] = git_state()
    atomic_write(out_dir / rs.SHEET, sheet)
    atomic_write(out_dir / rs.KEY, key)
    atomic_write(path, json.dumps(manifest, indent=1, sort_keys=True).encode() + b"\n")
    return manifest, True

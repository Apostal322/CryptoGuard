"""Frozen, stratified review sample from the payoff-linked review queue (offline, 0 RPC).

The sample is drawn once, before any review. ``freeze`` writes a manifest whose selection
hash is committed to the repository; the manifest, reviewer sheet and unblinding key hold
addresses derived from CC BY-NC-ND data and stay in the git-ignored data directory.
Selection is a keyed SHA-256 ranking rather than a seeded RNG, so it is identical across
Python versions and can be checked by hand.

Design (``SAMPLE_VERSION``):

1. Campaign groups: packets sharing a victim, lookalike, planting transaction or imitated
   address are linked. Each group contributes one representative (its lowest rank), so no
   two sampled packets share a victim or a campaign.
2. Strata: subtype x calendar year (by block height) x whether a rival lookalike existed.
3. Allocation: a fixed quota per subtype (all representatives when there are fewer), split
   across that subtype's cells in proportion to size, at least one per non-empty cell
   (largest remainder).
4. Within a cell the lowest ranks are selected; the rest, in rank order, are reserves,
   used only to replace an item that cannot be reviewed.
5. The reviewer sheet is blinded: no source label, subtype, imitated address, payoff or
   evidence summary, and its order is a separate ranking unrelated to the strata. The
   unblinding key (full packets) is a separate file.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cryptoguard.ml.events import _UnionFind
from cryptoguard.ml.review import ReviewPacket

SAMPLE_VERSION = "review-sample/1"
SHEET_SCHEMA = "review-sheet/1"
SEED = "cryptoguard-review-sample/1"  # fixed before the only draw; never re-seeded
# Representatives per subtype (60 in all). Subtypes not listed are not sampled.
SUBTYPE_QUOTA: dict[str, int] = {
    "fake_token": 24,
    "spoofed_transfer_from": 24,
    "dust": 9,
    "zero_value": 3,
}
# First block of each calendar year (UTC), from a block explorer; a packet within a few
# blocks of a boundary could fall in the neighbouring year, which does not affect validity.
YEAR_STARTS: tuple[tuple[int, int], ...] = ((2024, 18_908_895), (2023, 16_308_190))
MANIFEST = "sample_manifest.json"
SHEET = "reviewer_sheet.jsonl"
KEY = "unblinding_key.jsonl"

Stratum = tuple[str, int, bool]


class ReviewSampleError(ValueError):
    pass


class SampleFrozenError(ReviewSampleError):
    """A different sample is already frozen in the output directory."""


def year(block: int) -> int:
    return next((y for y, start in YEAR_STARTS if block >= start), 2022)


def stratum(p: ReviewPacket) -> Stratum:
    return (p.subtype, year(p.observation_block), bool(p.competing_lookalikes))


def stratum_name(s: Stratum) -> str:
    return f"{s[0]}|{s[1]}|{'rival' if s[2] else 'no_rival'}"


def rank(*parts: str) -> str:
    return hashlib.sha256("|".join((SEED, *parts)).encode()).hexdigest()


def load_queue(path: Path) -> list[ReviewPacket]:
    """All or nothing: a malformed line or a repeated event id rejects the whole queue."""
    packets: list[ReviewPacket] = []
    seen: set[str] = set()
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            p = ReviewPacket.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ReviewSampleError(f"{path}: line {i}: {exc}") from None
        if p.victim_event_id in seen:
            raise ReviewSampleError(f"{path}: line {i}: repeated event {p.victim_event_id}")
        seen.add(p.victim_event_id)
        packets.append(p)
    if not packets:
        raise ReviewSampleError(f"{path}: empty review queue")
    return packets


def groups(packets: Sequence[ReviewPacket]) -> dict[str, str]:
    """``victim_event_id -> group root``."""
    uf = _UnionFind()
    for p in packets:
        node = "e:" + p.victim_event_id
        uf.find(node)
        for kind, value in (
            ("v", p.victim),
            ("l", p.lookalike),
            ("t", p.planting_tx),
            ("i", p.imitated),
        ):
            if value:
                uf.union(node, f"{kind}:{value.lower()}")
    return {p.victim_event_id: uf.find("e:" + p.victim_event_id) for p in packets}


def allocate[K: tuple[Any, ...]](sizes: dict[K, int], quota: int) -> dict[K, int]:
    """Proportional allocation with at least one per non-empty cell (largest remainder)."""
    total = sum(sizes.values())
    if quota >= total:
        return dict(sizes)
    cells = sorted(sizes)
    if quota < sum(1 for c in cells if sizes[c]):
        raise ReviewSampleError(f"quota {quota} is below the number of non-empty cells")
    ideal = {c: quota * sizes[c] / total for c in cells}
    n = {c: min(sizes[c], max(1, math.floor(ideal[c]))) if sizes[c] else 0 for c in cells}

    def pick(eligible: list[K], key: Callable[[K], float]) -> K:
        return max(eligible, key=lambda c: (key(c), c))

    while sum(n.values()) < quota:
        c = pick([c for c in cells if n[c] < sizes[c]], lambda c: ideal[c] - n[c])
        n[c] += 1
    while sum(n.values()) > quota:
        c = pick([c for c in cells if n[c] > 1], lambda c: n[c] - ideal[c])
        n[c] -= 1
    return n


def blind(p: ReviewPacket, item: int) -> dict[str, Any]:
    """The reviewer's view: where to look on a block explorer, nothing about the source's
    verdict or the later payment."""
    return {
        "schema_version": SHEET_SCHEMA,
        "item": item,
        "victim_event_id": p.victim_event_id,
        "chain_id": 1,
        "wallet": p.victim,
        "address_under_review": p.lookalike,
        "transaction": p.planting_tx,
        "block": p.observation_block,
    }


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _jsonl(rows: Sequence[dict[str, Any]]) -> bytes:
    return b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in rows)


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def draw(packets: Sequence[ReviewPacket], queue_sha256: str) -> dict[str, Any]:
    """The full sample (manifest, sheet and key contents); writes nothing."""
    by_id = {p.victim_event_id: p for p in packets}
    root = groups(packets)
    members: dict[str, list[str]] = defaultdict(list)
    for event_id, g in root.items():
        members[g].append(event_id)
    reps = [min(ids, key=lambda e: rank("rep", e)) for ids in members.values()]
    group_size = {e: len(members[root[e]]) for e in reps}

    cells: dict[Stratum, list[str]] = defaultdict(list)
    for e in reps:
        cells[stratum(by_id[e])].append(e)
    for ids in cells.values():
        ids.sort(key=lambda e: rank("select", e))
    packets_per_cell = Counter(stratum(p) for p in packets)

    alloc: dict[Stratum, int] = {}
    for subtype in sorted({s[0] for s in cells}):
        sizes = {s: len(ids) for s, ids in cells.items() if s[0] == subtype}
        quota = SUBTYPE_QUOTA.get(subtype, 0)
        alloc |= allocate(sizes, quota) if quota else dict.fromkeys(sizes, 0)

    selected: list[dict[str, Any]] = []
    reserves: dict[str, list[str]] = {}
    strata: list[dict[str, Any]] = []
    for s in sorted(cells):
        ids, n = cells[s], alloc[s]
        weight = round(len(ids) / n, 6) if n else None
        strata.append(
            {
                "stratum": stratum_name(s),
                "packets": packets_per_cell[s],
                "groups": len(ids),
                "selected": n,
                "weight": weight,
            }
        )
        selected += [
            {
                "victim_event_id": e,
                "stratum": stratum_name(s),
                "group_size": group_size[e],
                "weight": weight,
            }
            for e in ids[:n]
        ]
        reserves[stratum_name(s)] = ids[n:]

    order = sorted((r["victim_event_id"] for r in selected), key=lambda e: rank("order", e))
    sheet = [blind(by_id[e], i) for i, e in enumerate(order, start=1)]
    role = {r["victim_event_id"]: ("selected", r["stratum"]) for r in selected}
    for name, ids in reserves.items():
        role |= {e: ("reserve", name) for e in ids}
    key = [
        {"role": role[e][0], "stratum": role[e][1], "packet": by_id[e].model_dump(mode="json")}
        for e in sorted(role)
    ]
    design = {
        "seed": SEED,
        "subtype_quota": SUBTYPE_QUOTA,
        "year_starts": dict(YEAR_STARTS),
        "group_links": ["victim", "lookalike", "planting_tx", "imitated"],
        "strata": ["subtype", "year", "rival_lookalike"],
        "allocation": "fixed quota per subtype; proportional within subtype, at least 1 per "
        "non-empty cell, largest remainder",
        "ranking": "sha256(seed|purpose|victim_event_id), lowest first",
    }
    selection = {
        "sample_version": SAMPLE_VERSION,
        "queue_sha256": queue_sha256,
        "design": design,
        "selected": selected,
        "reserves": reserves,
    }
    group_sizes = Counter(len(ids) for ids in members.values())
    manifest = {
        **selection,
        "selection_sha256": hashlib.sha256(_canonical(selection)).hexdigest(),
        "queue_packets": len(packets),
        "groups": {
            "count": len(members),
            "multi_packet": sum(v for k, v in group_sizes.items() if k > 1),
            "largest": max(group_sizes),
        },
        "strata_table": strata,
        "rpc_requests": 0,
    }
    return {"manifest": manifest, "sheet": sheet, "key": key}


def freeze(queue: Path, out_dir: Path) -> tuple[dict[str, Any], bool]:
    """Draw and write the sample once. Returns ``(manifest, newly_written)``.

    If a manifest already exists, the draw is recomputed and compared: identical selection
    -> nothing is rewritten; anything else (changed queue, design or code) raises
    ``SampleFrozenError`` and leaves the frozen files untouched."""
    from cryptoguard.ml.cross_dataset import git_state

    queue_sha = hashlib.sha256(queue.read_bytes()).hexdigest()
    sample = draw(load_queue(queue), queue_sha)
    manifest = sample["manifest"]
    existing = out_dir / MANIFEST
    if existing.exists():
        old = json.loads(existing.read_text(encoding="utf-8"))
        if old.get("queue_sha256") != queue_sha:
            raise SampleFrozenError(
                f"{existing}: the review queue changed after the sample was frozen"
            )
        if old.get("selection_sha256") != manifest["selection_sha256"]:
            raise SampleFrozenError(f"{existing}: a different sample is already frozen")
        return old, False

    out_dir.mkdir(parents=True, exist_ok=True)
    sheet, key = _jsonl(sample["sheet"]), _jsonl(sample["key"])
    manifest["files"] = {
        SHEET: hashlib.sha256(sheet).hexdigest(),
        KEY: hashlib.sha256(key).hexdigest(),
    }
    manifest["git"] = git_state()
    _write(out_dir / SHEET, sheet)
    _write(out_dir / KEY, key)
    _write(existing, json.dumps(manifest, indent=1, sort_keys=True).encode() + b"\n")
    return manifest, True

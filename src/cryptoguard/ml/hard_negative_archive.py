"""Offline extraction of hard-negative *candidates* from the local Tsuchiya attempt archive
(Phase 11.5, 0 RPC requests). Nothing here assigns a label.

The archive's ``uncategorized`` rows are transfers between an address and a lookalike of
one of its counterparties that the source placed in none of its poisoning categories:
not zero-value, not tiny, not counterfeit. In the local subset they are genuine-token,
ordinary-value transfers to the wallet. They are the closest available frame to
"legitimate activity that looks like poisoning", and also possibly value-bearing
poisoning, so they stay ``unlabeled_candidate``.

Two streaming passes; neither decompresses to disk or executes SQL:

1. ``extract_uncategorized`` keeps every uncategorized row (bounded at ``MAX_ROWS``).
2. ``context_scan`` reruns the verified scanner with the candidates' lookalikes and
   transactions as targets. This finds every archive row in which those addresses or
   transactions also appear, including as source-labelled poisoning lookalikes, for
   the contamination screen.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from cryptoguard.ml.annotation import atomic_write
from cryptoguard.ml.fetch import TSUCHIYA_FILES, verify_local
from cryptoguard.ml.tsuchiya_archive import (
    PARSER_VERSION,
    UNCATEGORIZED,
    ArchiveReader,
    ArchiveTransfer,
    build_targets,
    load_targets,
    peak_rss_bytes,
    scan,
)

EXTRACT_VERSION = "hn-archive-extract/1"
ARCHIVE = "address_poisoning_ethereum.sql.gz"
MAX_ROWS = 50_000  # the publisher reports 8,651; anything far above means a parser fault
ROWS = "uncategorized_rows.jsonl"
SUMMARY = "extract_summary.json"
CONTEXT_DB = "context_subset.sqlite"
CONTEXT_TARGETS = "context_targets.json"
FIELDS = (
    "line",
    "block",
    "tx",
    "token",
    "sender",
    "receiver",
    "sender_is_victim",
    "value",
    "value_usd",
    "flags",
    "intended",
    "first_digits",
    "last_digits",
)


class ExtractError(RuntimeError):
    pass


def row_dict(t: ArchiveTransfer) -> dict[str, Any]:
    return {k: getattr(t, k) for k in FIELDS}


def extract_uncategorized(data_dir: Path, out_dir: Path, *, progress: Any = None) -> dict[str, Any]:
    """Pass 1: every row flagged uncategorized, written atomically with a summary."""
    archive = data_dir / "tsuchiya2025" / ARCHIVE
    if not archive.exists():
        raise FileNotFoundError(f"{archive} is missing; it is never downloaded automatically")
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    t0 = time.perf_counter()
    reader = ArchiveReader(archive)
    rows: list[dict[str, Any]] = []
    flags: Counter[int] = Counter()
    for i, t in enumerate(reader, start=1):
        if t.flags & UNCATEGORIZED:
            flags[t.flags] += 1
            rows.append(row_dict(t))
            if len(rows) > MAX_ROWS:
                raise ExtractError(f"more than {MAX_ROWS} uncategorized rows: parser fault?")
        if progress is not None and i % 1_000_000 == 0:
            progress(i, len(rows))
    out_dir.mkdir(parents=True, exist_ok=True)
    data = b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in rows)
    atomic_write(out_dir / ROWS, data)
    import hashlib

    summary = {
        "version": EXTRACT_VERSION,
        "parser_version": PARSER_VERSION,
        "source_sha256": source["sha256"],
        "rows_scanned": reader.stats.valid_rows,
        "malformed": reader.stats.data_rows - reader.stats.valid_rows,
        "uncategorized_rows": len(rows),
        "flag_combinations": {str(k): v for k, v in sorted(flags.items())},
        "rows_sha256": hashlib.sha256(data).hexdigest(),
        "runtime_seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "rpc_requests": 0,
    }
    atomic_write(out_dir / SUMMARY, json.dumps(summary, indent=1).encode() + b"\n")
    return summary


def load_rows(out_dir: Path) -> list[dict[str, Any]]:
    import hashlib

    summary = json.loads((out_dir / SUMMARY).read_text(encoding="utf-8"))
    data = (out_dir / ROWS).read_bytes()
    if hashlib.sha256(data).hexdigest() != summary["rows_sha256"]:
        raise ExtractError(f"{out_dir / ROWS}: content differs from its summary; re-extract")
    return [json.loads(line) for line in data.splitlines() if line]


def context_scan(data_dir: Path, out_dir: Path, *, progress: Any = None) -> dict[str, Any]:
    """Pass 2: every archive row touching a candidate's lookalike or transaction."""
    rows = load_rows(out_dir)
    manifest = build_targets(
        {
            "hn_lookalikes": {
                r["sender"] if not r["sender_is_victim"] else r["receiver"] for r in rows
            },
            "hn_txs": {r["tx"] for r in rows},
        }
    )
    atomic_write(out_dir / CONTEXT_TARGETS, json.dumps(manifest).encode())
    archive = data_dir / "tsuchiya2025" / ARCHIVE
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    return scan(
        archive,
        load_targets(out_dir / CONTEXT_TARGETS),
        out_dir / CONTEXT_DB,
        work_dir=out_dir / "spill",
        source_sha256=source["sha256"],
        progress=progress,
    )


REVIEW_CONTEXT_DB = "review_context.sqlite"


def review_context_scan(data_dir: Path, sheets: list[Path], out_dir: Path) -> dict[str, Any]:
    """Phase 11.7 recovery pass: every archive row touching any wallet, address under
    review or planting transaction of the frozen reviewer sheets. The rows are still only
    what the source kept (lookalike-related), never a complete wallet history."""
    from cryptoguard.ml.review_sample import read_sheet

    rows = [r for s in sheets for r in read_sheet(s)]
    manifest = build_targets(
        {
            "review_wallets": {r["wallet"] for r in rows},
            "review_addresses": {r["address_under_review"] for r in rows},
            "review_txs": {r["transaction"] for r in rows},
        }
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_path = out_dir / "review_context_targets.json"
    atomic_write(targets_path, json.dumps(manifest).encode())
    archive = data_dir / "tsuchiya2025" / ARCHIVE
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    work = out_dir / "spill"
    summary = scan(
        archive,
        load_targets(targets_path),
        out_dir / REVIEW_CONTEXT_DB,
        work_dir=work,
        source_sha256=source["sha256"],
    )
    if work.exists() and not any(work.iterdir()):
        work.rmdir()
    return summary

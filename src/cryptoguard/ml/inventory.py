"""Offline inventory of local research data (``cryptoguard ml inventory``), 0 RPC requests.

For every file under ``data/`` and the recorded replay fixtures it records:
- path, format, size and SHA-256;
- the record count, where the format makes it cheap;
- source, licence and whether it may be redistributed;
- label status.

Files are hashed in 1 MiB chunks and never loaded whole. The registry below is the single
place where provenance is declared. A file it does not know is reported as
``unregistered``, never guessed.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

INVENTORY_VERSION = "inventory/1"
CHUNK = 1 << 20

# (path prefix, source, licence, redistributable, label status)
REGISTRY: tuple[tuple[str, str, str, str, str], ...] = (
    ("data/external/tsuchiya2025/", "Tsuchiya et al., USENIX Security 2025 (KiltHub "
     "10.1184/R1/29212703.v1)", "CC BY-NC-ND 4.0", "no (non-commercial, no derivatives)",
     "source heuristics: attempt categories and confirmed payoffs"),
    ("data/external/poison-hunter/", "Poison-Hunter (published sample)", "none published",
     "no", "source pipeline detections (weak_attempt)"),
    ("data/external/ptxphish/", "PTXPhish (Chen et al., NDSS 2025)", "none published", "no",
     "expert-reviewed phishing/benign transactions (separate task)"),
    ("data/external/forta/", "Forta labelled datasets", "see data/external/forta/LICENSE",
     "per licence", "address labels (separate task)"),
    ("data/ml/poisoning/review_sample/", "derived: frozen Phase 11.4 review sample",
     "derived from CC BY-NC-ND", "no", "unlabeled until human review"),
    ("data/ml/poisoning/hard_negative/", "derived: Phase 11.5 hard-negative pool and cohort",
     "derived from CC BY-NC-ND and public chain data", "no", "unlabeled_candidate"),
    ("data/ml/poisoning/", "derived: Phase 11.2-11.4 reconciliation outputs",
     "derived from CC BY-NC-ND", "no (aggregate tables only)", "source-derived"),
    ("data/ml/pilot/", "option A pilot (eth.drpc.org, 2026-11-01)", "public chain data", "yes",
     "pilot outcomes; unknown is never benign"),
    ("data/ml/chain/", "PTXPhish chain features (collected)", "public chain data + PTXPhish",
     "no (contains PTXPhish labels)", "PTXPhish labels"),
    ("data/ml/", "derived: Phase 11 classifier runs, splits, registry", "derived", "no",
     "PTXPhish labels (separate task)"),
    ("src/cryptoguard/replay/cases/", "recorded incident fixtures (public chain data)",
     "public chain data; committed", "yes", "incident case studies (used in development)"),
    ("src/cryptoguard/replay/background_cases/", "recorded random background wallets",
     "public chain data; committed", "yes", "unlabelled_background"),
)  # fmt: skip


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(CHUNK):
            h.update(block)
    return h.hexdigest()


def _records(path: Path) -> int | None:
    suffix = path.suffix.lower()
    if suffix in (".jsonl", ".csv", ".txt"):
        with path.open("rb") as fh:
            lines = sum(1 for _ in fh)
        return lines - 1 if suffix == ".csv" else lines
    if suffix in (".sqlite", ".db"):
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            n = con.execute("select count(*) from transfers").fetchone()[0]
            con.close()
            return int(n)
        except sqlite3.Error:
            return None
    return None


def _files(root: Path, rels: tuple[str, ...]) -> Iterator[Path]:
    for rel in rels:
        base = root / rel
        if base.exists():
            yield from sorted(
                p
                for p in base.rglob("*")
                if p.is_file() and not {"spill", "__pycache__"} & set(p.parts)
            )


def inventory(root: Path) -> dict[str, Any]:
    rows = []
    for p in _files(root, ("data", "src/cryptoguard/replay/cases",
                           "src/cryptoguard/replay/background_cases")):  # fmt: skip
        rel = p.relative_to(root).as_posix()
        reg = next((r for r in REGISTRY if rel.startswith(r[0])), None)
        rows.append({
            "path": rel,
            "format": p.suffix.lstrip(".") or "none",
            "bytes": p.stat().st_size,
            "sha256": _hash(p),
            "records": _records(p),
            "source": reg[1] if reg else "unregistered",
            "licence": reg[2] if reg else "unknown",
            "redistributable": reg[3] if reg else "unknown",
            "label_status": reg[4] if reg else "unknown",
        })  # fmt: skip
    return {"version": INVENTORY_VERSION, "files": rows, "rpc_requests": 0}

"""Scaling benchmark for the archive scanner on seeded synthetic dumps (Stage Q).

Each size runs in a fresh process, so peak RSS is per size rather than cumulative.
Synthetic rows mimic the real dump's shape (subtype mix, victims receiving most plantings,
lookalikes matching their target's ends); they carry no real addresses and are never
accuracy evidence.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptoguard.ml import tsuchiya_archive as ta

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def _addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def _lookalike(rng: random.Random, target: str) -> str:
    middle = "".join(rng.choice("0123456789abcdef") for _ in range(30))
    return target[:6] + middle + target[-6:]


def synthetic_dump(path: Path, rows: int, *, seed: int = 0) -> Path:
    """A gzip PostgreSQL dump in the real archive's layout with ``rows`` data rows."""
    rng = random.Random(seed)  # noqa: S311 - seeded synthetic fixtures, not cryptography
    victims = [_addr(rng) for _ in range(max(10, rows // 20))]
    friends = [_addr(rng) for _ in range(max(10, rows // 50))]
    order = list(ta.COLUMNS)
    header = [
        "--",
        "SET statement_timeout = 0;",
        f"CREATE TABLE public.{ta.TABLE} (",
        *[f"    {n} {t}," for n, t in list(ta.COLUMNS.items())[:-1]],
        f"    {order[-1]} {ta.COLUMNS[order[-1]]}",
        ");",
        f"COPY public.{ta.TABLE} ({', '.join(order)}) FROM stdin;",
    ]
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=1, newline="\n") as fh:
        fh.write("\n".join(header) + "\n")
        for i in range(rows):
            victim, friend = rng.choice(victims), rng.choice(friends)
            lookalike = _lookalike(rng, friend)
            kind = rng.choices(("zero", "counterfeit", "tiny", "intended"), (41, 56, 2, 1))[0]
            sends = kind != "tiny" and rng.random() < 0.3
            flags = {k: "f" for k in ta.FLAG_COLUMNS}
            flags[
                {
                    "zero": "zero_value_transfer",
                    "counterfeit": "counterfeit_token_transfer",
                    "tiny": "tiny_transfer",
                    "intended": "intended_transfer",
                }[kind]
            ] = "t"
            value = {"zero": "0", "tiny": "5000", "counterfeit": "1e+06", "intended": "5e+09"}
            sender, receiver = (victim, lookalike) if sends else (lookalike, victim)
            if kind == "intended":
                sender, receiver, sends = victim, friend, True
            row = {
                "block_number": str(16_000_000 + i),
                "tx_hash": "0x" + hashlib.sha256(f"{seed}:{i}".encode()).hexdigest(),
                "addr": USDT if kind != "counterfeit" else _lookalike(rng, USDT),
                "topics_from_addr": sender,
                "topics_to_addr": receiver,
                "is_sender_victim": "t" if sends else "f",
                "value": value[kind],
                "value_usd": "NaN" if kind == "counterfeit" else "0",
                **flags,
                "intended_addr": friend,
                "num_first_matched_digits": "20" if kind == "intended" else "4",
                "num_last_matched_digits": "20" if kind == "intended" else "4",
            }
            fh.write("\t".join(row[c] for c in order) + "\n")
        fh.write("\\.\n")
    return path


def run_one(rows: int, work: Path) -> dict[str, Any]:
    """Generate, scan twice (determinism), and measure one size in this process."""
    work.mkdir(parents=True, exist_ok=True)
    dump = synthetic_dump(work / f"syn{rows}.sql.gz", rows)
    manifest = work / "targets.json"
    rng = random.Random(1)  # noqa: S311 - seeded synthetic fixtures, not cryptography
    targets = ta.build_targets({"bench_victims": [_addr(rng) for _ in range(100)]})
    manifest.write_text(json.dumps(targets), encoding="utf-8")
    t = ta.load_targets(manifest)
    t0 = time.perf_counter()
    first = ta.scan(dump, t, work / "a.sqlite", work_dir=work / "spill")
    elapsed = time.perf_counter() - t0
    second = ta.scan(dump, t, work / "b.sqlite", work_dir=work / "spill")
    volatile = ("runtime_seconds", "peak_rss_bytes", "output_bytes")
    same = {k: v for k, v in first.items() if k not in volatile} == {
        k: v for k, v in second.items() if k not in volatile
    }
    return {
        "rows": rows,
        "compressed_bytes": dump.stat().st_size,
        "decompressed_bytes": first["reader"]["decompressed_bytes"],
        "scan_seconds": round(elapsed, 2),
        "rows_per_second": round(rows / elapsed),
        "peak_rss_mib": round((ta.peak_rss_bytes() or 0) / 2**20, 1),
        "peak_spill_mib": round(first["peak_spill_bytes"] / 2**20, 2),
        "subset_bytes": first["output_bytes"],
        "distinct_lookalikes": first["distinct"]["lookalikes"],
        "deterministic": same,
    }


def bench(sizes: list[int], work: Path) -> list[dict[str, Any]]:
    """One subprocess per size, so each peak RSS is measured in isolation."""
    out = []
    for n in sizes:
        proc = subprocess.run(  # noqa: S603 - our own module, integer arguments
            [sys.executable, "-m", "cryptoguard.ml.bench_archive", str(n), str(work / str(n))],
            capture_output=True,
            text=True,
            check=True,
        )
        out.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    return out


if __name__ == "__main__":
    print(json.dumps(run_one(int(sys.argv[1]), Path(sys.argv[2]))))

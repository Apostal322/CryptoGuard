"""``cryptoguard ml ...`` commands (experimental; need the ``ml`` extra)."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from cryptoguard.ml.sources import DEFAULT_DATA_DIR

ML_DIR = Path("data") / "ml"
SAMPLE = ML_DIR / "sample.csv"
CHAIN = ML_DIR / "chain" / "ptxphish.jsonl"
TOTAL_REQUEST_CAP = 12_000  # approved budget for the whole collection, over all runs


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("ml", help="experimental ML pipeline (needs the ml extra)")
    ml = p.add_subparsers(dest="ml_command", required=True)
    f = ml.add_parser("fetch-sources", help="download pinned label sources (hash-verified)")
    f.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    s = ml.add_parser("sample", help="draw the deterministic collection sample")
    s.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    s.add_argument("--out", type=Path, default=SAMPLE)
    c = ml.add_parser("collect", help="budgeted, resumable chain data collection")
    c.add_argument("--rpc-url", required=True)
    c.add_argument("--sample", type=Path, default=SAMPLE)
    c.add_argument("--out", type=Path, default=CHAIN)
    c.add_argument("--max-requests", type=int, default=TOTAL_REQUEST_CAP)
    c.add_argument("--limit", type=int, default=None, help="collect at most this many txs")
    b = ml.add_parser("build", help="validated feature table, splits and manifest")
    b.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    t = ml.add_parser("train", help="train, select on validation, test once, record the run")
    t.add_argument("--report", type=Path, default=Path("ML_EVALUATION.md"))


def run(args: argparse.Namespace) -> int:
    from cryptoguard.ml import ml_available

    if not ml_available():
        print("error [ml_unavailable]: install the ml extra (uv sync --extra ml)")
        return 1
    if args.ml_command == "fetch-sources":
        from cryptoguard.ml.sources import SOURCES, fetch_sources

        for name, path, status in fetch_sources(args.data_dir):
            license_ = SOURCES[name].license or "no license (local use only)"
            print(f"{status:10} {name}/{path}  [{license_}]")
        return 0
    if args.ml_command == "sample":
        from cryptoguard.ml.collect import draw_sample
        from cryptoguard.ml.labels import load_ptxphish

        sample = draw_sample(load_ptxphish(args.data_dir))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        sample.to_csv(args.out, index=False, lineterminator="\n")
        print(sample.groupby(["family", "subtype"]).size().to_string())
        print(f"Wrote {len(sample)} rows to {args.out}")
        return 0
    if args.ml_command == "collect":
        import pandas as pd

        from cryptoguard.ml.collect import collect, requests_used

        sample = pd.read_csv(args.sample, dtype={"tx_hash": str})
        if args.limit is not None:
            sample = sample.head(args.limit)
        remaining = min(args.max_requests, TOTAL_REQUEST_CAP) - requests_used(args.out)
        if remaining <= 0:
            print(f"Request budget exhausted ({requests_used(args.out)} used).")
            return 1
        stats = asyncio.run(collect(sample, args.out, rpc_url=args.rpc_url, max_requests=remaining))
        # The collector records its attempts in the ledger itself, after every transaction.
        print({**stats, "requests_total": requests_used(args.out), "cap": TOTAL_REQUEST_CAP})
        return 0
    if args.ml_command == "build":
        return _build(args)
    if args.ml_command == "train":
        return _train(args)
    raise AssertionError(args.ml_command)


TABLE = ML_DIR / "dataset.csv"
SPLITS = ML_DIR / "splits.csv"
RUNS = ML_DIR / "runs"


def _build(args: argparse.Namespace) -> int:
    import json

    import pandas as pd

    from cryptoguard.ml.collect import load_collected, requests_used
    from cryptoguard.ml.dataset import build_table, write_table
    from cryptoguard.ml.labels import load_ptxphish
    from cryptoguard.ml.sources import SOURCES, local_path
    from cryptoguard.ml.splits import make_splits

    records = load_collected(CHAIN)
    table, facts = build_table(load_ptxphish(args.data_dir), records)
    split, summary = make_splits(table, records)
    facts["sample_rows"] = len(pd.read_csv(SAMPLE))
    facts["rpc_requests_used"] = requests_used(CHAIN)
    src = SOURCES["ptxphish"]
    manifest = write_table(
        table,
        {**facts, "splits": summary},
        TABLE,
        {
            "labels": local_path(args.data_dir, src, src.files[0]),
            "sample": SAMPLE,
            "chain": CHAIN,
        },
    )
    table.assign(split=split)[["tx_hash", "split"]].to_csv(SPLITS, index=False, lineterminator="\n")
    print(
        json.dumps({k: manifest[k] for k in ("rows", "block_range", "groups", "splits")}, indent=1)
    )
    return 0


def _train(args: argparse.Namespace) -> int:
    import hashlib
    import json
    from datetime import UTC, datetime

    import pandas as pd

    from cryptoguard.ml.report import render_report
    from cryptoguard.ml.train import ledger_entry, promotion_gate, run_training, save_run

    table = pd.read_csv(TABLE, dtype={"tx_hash": str, "group": str})
    split = pd.read_csv(SPLITS, dtype=str).set_index("tx_hash").loc[table["tx_hash"], "split"]
    split.index = table.index
    manifest_path = TABLE.with_suffix(".manifest.json")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    out = run_training(table, split)
    gate = promotion_gate(out["results"], out["selected"])
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + manifest_sha[:8]
    config = {
        "table_sha256": json.loads(manifest_path.read_text())["table"]["sha256"],
        "splits": json.loads(manifest_path.read_text())["splits"],
    }
    entry = ledger_entry(run_id, config, out, gate, manifest_sha)
    run_dir = save_run(RUNS / run_id, entry, out)
    with (RUNS / "ledger.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({k: entry[k] for k in entry if k != "results"}, default=str) + "\n")
    report = render_report(entry, out, json.loads(manifest_path.read_text()))
    args.report.write_text(report, encoding="utf-8")
    sel = entry["selected"]
    print(
        f"run {run_id}: selected {sel['name']} ({sel['feature_set']}), "
        f"test AP {entry['test']['average_precision']:.3f}, gate {gate['validated_for_shadow']}, "
        f"{out['seconds']} s -> {run_dir}; wrote {args.report}"
    )
    return 0

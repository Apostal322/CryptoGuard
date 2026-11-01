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
    pr = ml.add_parser("promote", help="register a run at an approval level it has evidence for")
    pr.add_argument("run_dir", type=Path)
    pr.add_argument(
        "--approval",
        choices=("research_only", "shadow_approved"),
        default="research_only",
        help="shadow_approved needs a pass on an untouched holdout recorded in the model card",
    )
    au = ml.add_parser("audit", help="offline generalization audit of a run (no RPC)")
    au.add_argument("run_dir", type=Path)
    au.add_argument("--out", type=Path, default=ML_DIR / "audit")
    au.add_argument("--tables", type=Path, default=Path("ML_AUDIT_TABLES.md"))
    sc = ml.add_parser("score", help="shadow-mode score for one transaction (not a finding)")
    sc.add_argument("tx_hash")
    sc.add_argument("--rpc-url", required=True)
    ml.add_parser("monitor", help="feature drift of shadow-scored transactions")


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

        from cryptoguard.ml.collect import RequestLedger, budget_path, collect

        sample = pd.read_csv(args.sample, dtype={"tx_hash": str})
        if args.limit is not None:
            sample = sample.head(args.limit)
        # The cap is a total over all runs: this run may use what is left, or less.
        probe = RequestLedger(budget_path(args.out), cap=TOTAL_REQUEST_CAP)
        cap = min(TOTAL_REQUEST_CAP, probe.used() + args.max_requests)
        ledger = RequestLedger(budget_path(args.out), cap=cap)
        if ledger.used() >= cap:
            print(f"Request budget exhausted ({ledger.used()} of {cap} used).")
            return 1
        stats = asyncio.run(collect(sample, args.out, ledger=ledger, rpc_url=args.rpc_url))
        print({**stats, "requests_total": ledger.used(), "cap": cap})
        return 0
    if args.ml_command == "audit":
        return _audit(args)
    if args.ml_command == "build":
        return _build(args)
    if args.ml_command == "train":
        return _train(args)
    if args.ml_command == "promote":
        from cryptoguard.ml.registry import ModelRegistryError, promote

        try:
            print(promote(args.run_dir, approval=args.approval))
        except ModelRegistryError as exc:
            print(f"error [not_promoted]: {exc}")
            return 1
        return 0
    if args.ml_command in ("score", "monitor"):
        return _shadow(args)
    raise AssertionError(args.ml_command)


def _shadow(args: argparse.Namespace) -> int:
    import json

    from cryptoguard.blockchain.rpc import JsonRpcClient
    from cryptoguard.core.config import Settings
    from cryptoguard.ml.inference import loaded_model, score_transaction
    from cryptoguard.ml.monitoring import drift_report

    settings = Settings(ml_shadow="shadow")  # the command itself is the opt-in
    if args.ml_command == "monitor":
        model = loaded_model(settings, require_shadow_approval=False)
        print(json.dumps(drift_report(model.card, Path(settings.ml_score_log_path)), indent=1))
        return 0

    async def run() -> str:
        from cryptoguard.core.hexutil import parse_quantity

        client = JsonRpcClient(args.rpc_url, timeout=20)
        try:
            chain_id = parse_quantity(await client.call("eth_chainId", []))
            # Explicit CLI use may score with a research-only model; the output says so.
            result = await score_transaction(
                client, args.tx_hash, settings, chain_id=chain_id, require_shadow_approval=False
            )
            return result.model_dump_json(indent=1)
        finally:
            await client.aclose()

    print(asyncio.run(run()))
    return 0


TABLE = ML_DIR / "dataset.csv"
SPLITS = ML_DIR / "splits.csv"
RUNS = ML_DIR / "runs"


def _load_table_and_splits() -> tuple[object, object]:
    import pandas as pd

    table = pd.read_csv(TABLE, dtype={"tx_hash": str, "group": str})
    split = pd.read_csv(SPLITS, dtype=str).set_index("tx_hash").loc[table["tx_hash"], "split"]
    split.index = table.index
    return table, split


def _audit(args: argparse.Namespace) -> int:
    import hashlib
    import json
    import time

    from cryptoguard.ml.audit import audit_id, render_tables, run_audit
    from cryptoguard.ml.collect import load_collected

    started = time.perf_counter()
    table, split = _load_table_and_splits()
    result = run_audit(table, split, load_collected(CHAIN), args.run_dir)  # type: ignore[arg-type]
    result["inputs"] = {
        "table_sha256": hashlib.sha256(TABLE.read_bytes()).hexdigest(),
        "splits_sha256": hashlib.sha256(SPLITS.read_bytes()).hexdigest(),
        "chain_sha256": hashlib.sha256(CHAIN.read_bytes()).hexdigest(),
        "run": args.run_dir.name,
    }
    result["seconds"] = round(time.perf_counter() - started, 1)
    ident = audit_id({k: v for k, v in result.items() if k != "seconds"})
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"audit-{ident}.json"
    path.write_text(json.dumps(result, indent=1, default=str), encoding="utf-8", newline="\n")
    args.tables.write_text(render_tables(result, ident), encoding="utf-8", newline="\n")
    print(f"audit {ident} in {result['seconds']} s -> {path}; wrote {args.tables}")
    return 0


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
    # Dataset identity = the table and split bytes (the manifest also holds bookkeeping such
    # as the cumulative RPC count, which changes without the data changing).
    table_sha = hashlib.sha256(TABLE.read_bytes()).hexdigest()
    splits_sha = hashlib.sha256(SPLITS.read_bytes()).hexdigest()
    data_id = hashlib.sha256(f"{table_sha}:{splits_sha}".encode()).hexdigest()
    out = run_training(table, split)
    gate = promotion_gate(out["results"], out["selected"])
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + data_id[:8]
    config = {
        "table_sha256": table_sha,
        "splits_sha256": splits_sha,
        "splits": json.loads(manifest_path.read_text())["splits"],
    }
    entry = ledger_entry(run_id, config, out, gate, manifest_sha)
    run_dir = save_run(RUNS / run_id, entry, out)
    with (RUNS / "ledger.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({k: entry[k] for k in entry if k != "results"}, default=str) + "\n")
    report = render_report(entry, out, json.loads(manifest_path.read_text()))
    args.report.write_text(report, encoding="utf-8", newline="\n")  # same bytes on every OS
    sel = entry["selected"]
    print(
        f"run {run_id}: selected {sel['name']} ({sel['feature_set']}), "
        f"test AP {entry['test']['average_precision']:.3f}, gate {gate['validated_for_shadow']}, "
        f"{out['seconds']} s -> {run_dir}; wrote {args.report}"
    )
    return 0

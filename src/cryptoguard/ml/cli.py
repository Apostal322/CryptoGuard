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
    pz = ml.add_parser(
        "poisoning-report",
        help="offline Phase 11.2 report: Poison-Hunter validation, pilot, candidates (no RPC)",
    )
    pz.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    pz.add_argument("--pilot-dir", type=Path, default=ML_DIR / "pilot")
    pz.add_argument("--out", type=Path, default=ML_DIR / "poisoning")
    pz.add_argument("--tables", type=Path, default=Path("ML_POISONING_TABLES.md"))
    pc = ml.add_parser(
        "plan-collection", help="estimate a wallet-history collection job (never collects)"
    )
    pc.add_argument("--wallets", type=int, required=True)
    pc.add_argument("--window-blocks", type=int, required=True)
    pc.add_argument("--request-cap", type=int, required=True)
    pc.add_argument("--log-range-blocks", type=int, default=100)
    ff = ml.add_parser(
        "fetch-file",
        help="download ONE named, pinned research file after explicit approval (verified)",
    )
    ff.add_argument("name", help="pinned file name, e.g. address_poisoning_ethereum.sql.gz")
    ff.add_argument("--dest", type=Path, default=DEFAULT_DATA_DIR / "tsuchiya2025")
    ff.add_argument("--reserve-gib", type=float, default=10.0)
    sa = ml.add_parser(
        "scan-archive",
        help="one offline pass over the local Tsuchiya archive (verified; never downloads)",
    )
    sa.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    sa.add_argument("--out", type=Path, default=ML_DIR / "poisoning")
    sa.add_argument("--force", action="store_true", help="rescan even if a cached scan matches")
    cr = ml.add_parser(
        "cross-dataset-report",
        help="reconcile the scanned archive with Poison-Hunter, payoffs and incidents (no RPC)",
    )
    cr.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    cr.add_argument("--out", type=Path, default=ML_DIR / "poisoning")
    cr.add_argument("--tables", type=Path, default=Path("ML_CROSS_DATASET_TABLES.md"))
    fr = ml.add_parser(
        "freeze-review-sample",
        help="draw the stratified review sample once, before any review (offline, no RPC)",
    )
    fr.add_argument(
        "--queue", type=Path, default=ML_DIR / "poisoning" / "review_packets_payoff_linked.jsonl"
    )
    fr.add_argument("--out", type=Path, default=ML_DIR / "poisoning" / "review_sample")
    bz = ml.add_parser("bench-archive", help="archive-scanner scaling on synthetic dumps")
    bz.add_argument("sizes", type=int, nargs="+")
    bz.add_argument("--work", type=Path, default=ML_DIR / "bench")


def run(args: argparse.Namespace) -> int:
    from cryptoguard.ml import ml_available

    # Pure-Python commands: no ml extra needed.
    if args.ml_command == "poisoning-report":
        from cryptoguard.ml.poisoning_report import build, write

        written = write(build(args.data_dir, args.pilot_dir), args.out, args.tables)
        print(f"Wrote {written} and {args.tables} (0 RPC requests).")
        return 0
    if args.ml_command == "plan-collection":
        import json

        from cryptoguard.ml.planner import (
            CollectionAssumptions,
            CollectionJob,
            PlanRejected,
            plan,
        )

        job = CollectionJob(
            wallets=args.wallets, window_blocks=args.window_blocks, request_cap=args.request_cap
        )
        try:
            body = plan(job, CollectionAssumptions(log_range_blocks=args.log_range_blocks))
        except PlanRejected as exc:
            print(f"rejected: {exc}")
            return 2
        print(json.dumps(body, indent=1))
        return 0
    if args.ml_command == "fetch-file":
        return _fetch_file(args)
    if args.ml_command == "scan-archive":
        return _scan_archive(args)
    if args.ml_command == "cross-dataset-report":
        return _cross_dataset_report(args)
    if args.ml_command == "freeze-review-sample":
        return _freeze_review_sample(args)
    if args.ml_command == "bench-archive":
        import json

        from cryptoguard.ml.bench_archive import bench

        print(json.dumps(bench(args.sizes, args.work), indent=1))
        return 0
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


def _fetch_file(args: argparse.Namespace) -> int:
    import json

    from cryptoguard.ml.fetch import TSUCHIYA_FILES, DownloadError, download

    pinned = TSUCHIYA_FILES.get(args.name)
    if pinned is None:
        print(f"error: {args.name!r} is not pinned; known: {', '.join(TSUCHIYA_FILES)}")
        return 2
    last = [-1]

    def progress(done: int, total: int) -> None:
        pct = done * 100 // total
        if pct >= last[0] + 5:
            last[0] = pct
            print(f"{pct:3d}% {done:,}/{total:,} bytes", flush=True)

    try:
        record = download(
            pinned, args.dest, reserve_bytes=int(args.reserve_gib * (1 << 30)), progress=progress
        )
    except DownloadError as exc:
        print(f"error [{type(exc).__name__}]: {exc}")
        return 1
    print(json.dumps(record, indent=1))
    return 0


def _scan_archive(args: argparse.Namespace) -> int:
    import time

    from cryptoguard.ml.cross_dataset import run_scan
    from cryptoguard.ml.fetch import IntegrityError
    from cryptoguard.ml.tsuchiya_archive import ArchiveError, ReaderStats

    t0 = time.perf_counter()

    def progress(stats: ReaderStats) -> None:
        print(
            f"{stats.data_rows:>12,} rows  {stats.decompressed_bytes / 1e9:6.2f} GB  "
            f"{time.perf_counter() - t0:7.0f} s",
            flush=True,
        )

    try:
        s = run_scan(args.data_dir, args.out, force=args.force, progress=progress)
    except (FileNotFoundError, IntegrityError, ArchiveError) as exc:
        print(f"error [{type(exc).__name__}]: {exc}")
        return 1
    print(
        f"{'cached' if s['cached'] else 'scanned'}: {s['reader']['valid_rows']:,} valid rows, "
        f"{s['reader']['malformed_rows']:,} malformed, {s['stored_target_rows']:,} stored; "
        f"{s['runtime_seconds']} s, peak RSS {s['peak_rss_bytes']} bytes (0 RPC requests)."
    )
    return 0


def _cross_dataset_report(args: argparse.Namespace) -> int:
    from cryptoguard.ml.cross_dataset import build_report, write_report
    from cryptoguard.ml.tsuchiya_archive import ArchiveError

    try:
        report = build_report(args.data_dir, args.out)
    except (FileNotFoundError, ArchiveError) as exc:
        print(f"error [{type(exc).__name__}]: {exc} (run `cryptoguard ml scan-archive` first)")
        return 1
    written = write_report(report, args.out, args.tables)
    print(f"Wrote {written} and {args.tables} (0 RPC requests).")
    return 0


def _freeze_review_sample(args: argparse.Namespace) -> int:
    from cryptoguard.ml.review_sample import ReviewSampleError, freeze

    try:
        manifest, written = freeze(args.queue, args.out)
    except FileNotFoundError as exc:
        print(f"error [FileNotFoundError]: {exc} (run `cryptoguard ml cross-dataset-report`)")
        return 1
    except ReviewSampleError as exc:
        print(f"error [{type(exc).__name__}]: {exc}")
        return 1
    for row in manifest["strata_table"]:
        print(f"{row['stratum']:36} {row['groups']:5} groups  {row['selected']:3} selected")
    state = "Froze" if written else "Already frozen (unchanged):"
    print(
        f"{state} {len(manifest['selected'])} of {manifest['queue_packets']} packets in "
        f"{args.out}; selection sha256 {manifest['selection_sha256']} (0 RPC requests)."
    )
    return 0


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

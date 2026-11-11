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
    _add_review_parser(ml)
    es = ml.add_parser("experiment-spec", help="write the pre-registered experiment spec (JSON)")
    es.add_argument("--out", type=Path, default=Path("docs/ml/experiment-spec.json"))
    vr = ml.add_parser("verify-research", help="offline reproducibility check of research inputs")
    vr.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    vr.add_argument("--out", type=Path, default=ML_DIR / "verify-research.json")
    vr.add_argument("--skip-archive-hash", action="store_true", help="size check only (fast)")
    dg = ml.add_parser("diagnostics", help="label-free offline diagnostics (aggregate output)")
    dg.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    dg.add_argument("--out", type=Path, default=ML_DIR / "diagnostics.json")
    ls = ml.add_parser(
        "lookalike-study", help="Phase 12.1 lookalike prioritization study (aggregate output)"
    )
    ls.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ls.add_argument("--out", type=Path, default=ML_DIR / "research" / "lookalike-study.json")
    ls.add_argument(
        "--graph-scan", action="store_true", help="first run the graph-context archive pass"
    )
    ls.add_argument(
        "--lazy-graph", action="store_true", help="Phase 12.1 per-address lookups (reference)"
    )
    rv = ml.add_parser(
        "recency-validation", help="Phase 12.2 recency validation (aggregate output)"
    )
    rv.add_argument(
        "--out", type=Path, default=ML_DIR / "research" / "phase12.2" / "recency-validation.json"
    )
    ur = ml.add_parser(
        "unconfirmed-recency",
        help="recency on the source's unconfirmed payoffs (two offline archive passes)",
    )
    ur.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ur.add_argument("--extract", action="store_true", help="run pass 1 (unconfirmed rows)")
    ur.add_argument("--scan", action="store_true", help="run pass 2 (victim-side rows)")
    ur.add_argument(
        "--out", type=Path, default=ML_DIR / "research" / "phase12.2" / "unconfirmed-recency.json"
    )
    brd = ml.add_parser(
        "benchmark-readiness",
        help="Phase 12.8 data inventory, eligibility and blind development regression (offline)",
    )
    brd.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.8")
    brd.add_argument("--no-archive", action="store_true", help="skip the archive tie analysis")
    brd.add_argument("--no-history", action="store_true", help="skip the git-history scan")
    rbl = ml.add_parser(
        "review-blinding",
        help="Phase 12.9 exposure audit of the frozen review cohorts (offline; aggregates)",
    )
    rbl.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.9" / "blinding")
    rbl.add_argument("--no-history", action="store_true", help="skip the git-history channel")
    iac = ml.add_parser(
        "incident-acquisition",
        help="Phase 12.9 lead eligibility, pilot selection and collection manifest (no RPC)",
    )
    iac.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.9" / "acquisition")
    iac.add_argument(
        "--write-public",
        action="store_true",
        help="write the public registry (citations, statuses, salted commitments only)",
    )
    bpw = ml.add_parser(
        "benchmark-power",
        help="sample-size planning for a paired exposure comparison (assumptions are inputs)",
    )
    bpw.add_argument(
        "--p-better",
        type=float,
        required=True,
        help="P(a discordant incident favours the better method)",
    )
    bpw.add_argument(
        "--discordance",
        type=float,
        required=True,
        help="share of eligible incidents on which the two methods disagree",
    )
    bpw.add_argument("--eligible-rate", type=float, default=1.0)
    bpw.add_argument("--deff", type=float, default=1.0, help="cluster design effect")
    bpw.add_argument("--power", type=float, default=0.8)
    bpw.add_argument("--alpha", type=float, default=0.05)
    ava = ml.add_parser(
        "adaptive-validation",
        help="Phase 12.7.1 debiased synthetic validation and adaptive attacker (offline)",
    )
    ava.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.7.1")
    ava.add_argument(
        "--manifest-only",
        action="store_true",
        help="generate the sealed scenario manifest without running any selector",
    )
    adv = ml.add_parser(
        "adversarial-ranking",
        help="Phase 12.7 adversarial candidate exposure and learning-to-rank study (offline)",
    )
    adv.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.7")
    adv.add_argument(
        "--no-ltr", action="store_true", help="skip the archive learning-to-rank study"
    )
    adv.add_argument("--perf-max", type=int, default=100_000, help="largest performance population")
    adv.add_argument(
        "--posthoc",
        action="store_true",
        help="only the post-hoc design-bias checks (writes posthoc-checks.json)",
    )
    rs = ml.add_parser(
        "reliability-study",
        help="Phase 12.6 signer provenance, evidence groups and spam resilience (offline)",
    )
    rs.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.6.1")
    rs.add_argument(
        "--episode-cache",
        type=Path,
        default=ML_DIR / "research" / "phase12.5" / "episodes.jsonl",
        help="the Phase 12.5 archive episode cache (development split used only)",
    )
    cr = ml.add_parser(
        "candidate-research",
        help="Phase 12.5 candidate discovery and ranking research (offline, no RPC)",
    )
    cr.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.5")
    cr.add_argument("--rebuild-cache", action="store_true", help="re-read the archive subset")
    rk = ml.add_parser(
        "candidate-ranking",
        help="offline shadow ranking of one recorded window (research only, no RPC)",
    )
    rk.add_argument("--fixture", type=Path, required=True)
    rk.add_argument("--cutoff-block", type=int, required=True)
    rk.add_argument("--cutoff-index", type=int, default=0)
    ob = ml.add_parser(
        "observation-study",
        help="Phase 12.4 observation coverage and candidate discovery (offline, no RPC)",
    )
    ob.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.4")
    ib = ml.add_parser(
        "incident-benchmark", help="Phase 12.3 independent incident benchmark (offline)"
    )
    ib.add_argument("step", choices=("verify", "resolve", "prepare", "run", "report"))
    ib.add_argument("--case", help="prepare: the pre-registered case id")
    ib.add_argument(
        "--located", type=Path, help="prepare: `replay locate` or `find-transfers` JSON"
    )
    ib.add_argument("--found", type=Path, help="resolve: `replay find-transfers` JSON")
    ib.add_argument("--title", help="prepare: the case title")
    ib.add_argument("--first-report", help="prepare: ISO date of the first public report")
    ib.add_argument(
        "--manifest",
        type=Path,
        nargs="+",
        default=[
            Path("docs/ml/incident-benchmark/candidates.json"),
            Path("docs/ml/incident-benchmark/stage2-resolved.json"),
        ],
        help="candidate manifests, merged (missing files are skipped)",
    )
    ib.add_argument("--out", type=Path, default=ML_DIR / "research" / "phase12.3")
    iv = ml.add_parser("inventory", help="hash and describe every local research data file")
    iv.add_argument("--root", type=Path, default=Path("."))
    iv.add_argument("--out", type=Path, default=ML_DIR / "inventory.json")
    hx = ml.add_parser(
        "hard-negative-extract",
        help="two offline passes over the local archive for uncategorized lookalike transfers",
    )
    hx.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    hx.add_argument("--out", type=Path, default=ML_DIR / "poisoning" / "hard_negative")
    hs = ml.add_parser(
        "hard-negative-study",
        help="candidate pool, contamination screen, matching, separability, cohort (offline)",
    )
    hs.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    hs.add_argument("--poisoning-dir", type=Path, default=ML_DIR / "poisoning")
    hs.add_argument("--tables", type=Path, default=Path("ML_HARD_NEGATIVE_TABLES.md"))
    hs.add_argument("--no-freeze", action="store_true", help="draw without freezing")
    bz = ml.add_parser("bench-archive", help="archive-scanner scaling on synthetic dumps")
    bz.add_argument("sizes", type=int, nargs="+")
    bz.add_argument("--work", type=Path, default=ML_DIR / "bench")


def run(args: argparse.Namespace) -> int:
    from cryptoguard.ml import ml_available

    # Pure-Python commands: no ml extra needed.
    if args.ml_command == "benchmark-readiness":
        import json

        from cryptoguard.ml import benchmark_readiness

        result = benchmark_readiness.main(
            ML_DIR / "poisoning",
            args.out,
            archive=not args.no_archive,
            history=not args.no_history,
        )
        brief = {k: result[k] for k in ("eligibility_summary", "resources")}
        print(json.dumps(brief, indent=1, default=str))
        return 0
    if args.ml_command in ("review-blinding", "incident-acquisition"):
        import json
        import subprocess

        try:
            git = subprocess.run(
                ["git", "rev-parse", "HEAD"],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            git = None
        if args.ml_command == "review-blinding":
            from cryptoguard.ml import review_blinding

            summary = review_blinding.main(
                Path(), ML_DIR / "poisoning", args.out, history=not args.no_history
            )
        else:
            from cryptoguard.ml import incident_acquisition

            summary = incident_acquisition.main(
                Path(), ML_DIR / "poisoning", args.out, write_public=args.write_public, git=git
            )
        summary["git"] = git
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.json").write_text(
            json.dumps(summary, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        print(json.dumps(summary, indent=1, sort_keys=True, default=str))
        return 0
    if args.ml_command == "benchmark-power":
        import json

        from cryptoguard.ml import power

        needed = power.incidents_needed(
            args.p_better,
            args.discordance,
            power=args.power,
            alpha=args.alpha,
            eligible_rate=args.eligible_rate,
            deff=args.deff,
        )
        print(json.dumps(needed, indent=1))
        return 0
    if args.ml_command == "adaptive-validation":
        import json

        from cryptoguard.ml import adaptive_validation

        result = adaptive_validation.main(
            ML_DIR / "poisoning", args.out, manifest_only=args.manifest_only
        )
        brief = result.get("manifest") or {
            "H1": result["E2"]["H1"]["verdict"],
            "resources": result["resources"],
        }
        print(json.dumps(brief, indent=1, default=str))
        return 0
    if args.ml_command == "adversarial-ranking":
        import json

        from cryptoguard.ml import adversarial_benchmark

        if args.posthoc:
            checks = adversarial_benchmark.posthoc_checks()
            args.out.mkdir(parents=True, exist_ok=True)
            (args.out / "posthoc-checks.json").write_text(
                json.dumps(checks, indent=1, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"Wrote {args.out / 'posthoc-checks.json'}")
            return 0
        result = adversarial_benchmark.main(
            ML_DIR / "poisoning", args.out, ltr=not args.no_ltr, perf_max=args.perf_max
        )
        brief = {k: result[k] for k in ("resources",)} | {"H1": result["summary"].get("H1")}
        print(json.dumps(brief, indent=1, default=str))
        print(f"Wrote {args.out / 'adversarial-ranking.json'}")
        return 0
    if args.ml_command == "reliability-study":
        import json

        from cryptoguard.ml import reliability_study

        result = reliability_study.main(ML_DIR / "poisoning", args.out, args.episode_cache)
        brief = {k: result[k] for k in ("rsig_consistency", "resources")}
        print(json.dumps(brief, indent=1, default=str))
        print(f"Wrote {args.out / 'reliability-study.json'}")
        return 0
    if args.ml_command == "candidate-research":
        import json

        from cryptoguard.ml import candidate_research

        result = candidate_research.main(ML_DIR / "poisoning", args.out, args.rebuild_cache)
        print(json.dumps(result["summary"], indent=1, default=str))
        print(f"Wrote {args.out / 'candidate-research.json'}")
        return 0
    if args.ml_command == "candidate-ranking":
        import json

        from cryptoguard.ml import candidate_features
        from cryptoguard.replay.models import ReplayFixture

        fixture = ReplayFixture.model_validate_json(args.fixture.read_text(encoding="utf-8"))
        ranked = candidate_features.rank(fixture, (args.cutoff_block, args.cutoff_index))
        print(json.dumps(candidate_features.serialize(ranked), indent=1, default=str))
        return 0
    if args.ml_command == "observation-study":
        import json

        from cryptoguard.ml import observation_study

        result = observation_study.main(ML_DIR / "poisoning", args.out)
        summary = {
            r["case_id"]: {v: r["variants"][v]["distinct_lookalikes"] for v in ("C0", "C1", "C2")}
            | {"screen_flagged": r["payment_screen_unlabelled"]["flagged"]}
            for r in result["windows"]
        }
        print(json.dumps({"windows": summary, "resources": result["resources"]}, indent=1))
        print(f"Wrote {args.out / 'observation-study.json'}")
        return 0
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
    if args.ml_command == "review":
        return _review(args)
    if args.ml_command == "experiment-spec":
        from cryptoguard.ml.experiment_spec import spec_json

        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(spec_json(), encoding="utf-8", newline="\n")
        print(f"Wrote {args.out} (inactive until reviewed labels exist).")
        return 0
    if args.ml_command == "verify-research":
        import json

        from cryptoguard.ml.verify_research import verify

        report = verify(args.data_dir, ML_DIR, hash_archive=not args.skip_archive_hash)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        for c in report["checks"]:
            print(f"{c['status']:8} {c['check']}: {c['detail']}")
        print(f"Wrote {args.out}.")
        return 0 if not any(c["status"] == "FAIL" for c in report["checks"]) else 1
    if args.ml_command == "diagnostics":
        import json

        from cryptoguard.ml.diagnostics import run_diagnostics

        report = run_diagnostics(args.data_dir, ML_DIR / "poisoning")
        args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        print(json.dumps({k: v for k, v in report.items() if k != "notes"}, indent=1)[:4000])
        return 0
    if args.ml_command == "lookalike-study":
        import json

        from cryptoguard.ml import lookalike_ranking, lookalike_study

        poisoning = ML_DIR / "poisoning"
        if args.graph_scan:
            lookalike_ranking.graph_context_scan(args.data_dir, poisoning)
        report = lookalike_study.run(poisoning, lazy_graph=args.lazy_graph)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1, default=str) + "\n", encoding="utf-8")
        print(json.dumps(report["primary"], indent=1))
        print(f"Wrote {args.out} (aggregate only; 0 RPC requests).")
        return 0
    if args.ml_command == "recency-validation":
        import json

        from cryptoguard.ml import recency_validation

        report = recency_validation.run(ML_DIR / "poisoning")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1, default=str) + "\n", encoding="utf-8")
        for key in ("manipulation_check", "H1_symmetric_confirmation", "H2_production_warnings"):
            print(key, json.dumps(report[key], indent=1))
        print(f"Wrote {args.out} (aggregate only; 0 RPC requests).")
        return 0
    if args.ml_command == "unconfirmed-recency":
        import json

        from cryptoguard.ml import unconfirmed_recency as ur_

        poisoning = ML_DIR / "poisoning"
        if args.extract:
            print(json.dumps(ur_.extract(args.data_dir, poisoning), indent=1))
        if args.scan:
            summary = ur_.context_scan(args.data_dir, poisoning)
            print(json.dumps({k: summary[k] for k in ("stored_target_rows", "runtime_seconds")}))
        if not (args.extract or args.scan):
            report = ur_.run(poisoning)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=1, default=str) + "\n", encoding="utf-8")
            for key in ("episodes", "U_H1", "U_H2", "conclusion"):
                print(key, json.dumps(report[key], indent=1))
            print(f"Wrote {args.out} (aggregate only; 0 RPC requests).")
        return 0
    if args.ml_command == "incident-benchmark":
        import json

        from cryptoguard.ml import incident_benchmark as ib_

        args.out.mkdir(parents=True, exist_ok=True)
        verified_path = args.out / "incident-verify.json"
        run_path = args.out / "incident-benchmark.json"
        if args.step == "verify":
            rows = ib_.verify(ib_.load_manifests(args.manifest), ML_DIR / "poisoning")
            verified_path.write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
            for r in rows:
                print(f"{r['case_id']:40} {r['tier']:18} {r['status']}")
        elif args.step == "resolve":
            if not (args.case and args.found):
                print("resolve needs --case and --found.")
                return 1
            stage2 = ib_.load_manifest(ib_.STAGE2)
            cand = next((c for c in stage2.candidates if c.case_id == args.case), None)
            if cand is None:
                print(f"{args.case} is not in {ib_.STAGE2}.")
                return 1
            out = (
                ib_.load_manifest(ib_.RESOLVED)
                if ib_.RESOLVED.exists()
                else stage2.model_copy(
                    update={
                        "protocol": f"{ib_.PROTOCOL} with {ib_.AMENDMENT}",
                        "discovery": {"resolved_from": ib_.STAGE2.as_posix()},
                        "candidates": [],
                        "not_usable_sources": [],
                    }
                )
            )
            if any(c.case_id == args.case for c in out.candidates):
                print(f"{args.case} is already resolved in {ib_.RESOLVED}; never overwritten.")
                return 1
            try:
                done = ib_.resolve(cand, json.loads(args.found.read_text(encoding="utf-8")))
            except ValueError as exc:
                print(f"not resolved: {exc}")
                return 1
            out = out.model_copy(update={"candidates": [*out.candidates, done]})
            ib_.RESOLVED.write_text(out.model_dump_json(indent=2) + "\n", encoding="utf-8")
            print(f"Resolved {args.case}: harm {done.identifiers['harm_tx']} -> {ib_.RESOLVED}")
        elif args.step == "prepare":
            if not (args.case and args.located and args.title and args.first_report):
                print("prepare needs --case, --located, --title and --first-report.")
                return 1
            cand = next(
                (c for c in ib_.load_manifests(args.manifest).candidates if c.case_id == args.case),
                None,
            )
            if cand is None:
                print(f"{args.case} is not in {args.manifest}.")
                return 1
            case_dir = ib_.NEW_CASES / cand.case_id
            if (case_dir / "manifest.json").exists():
                print(f"{case_dir / 'manifest.json'} exists; it is never overwritten.")
                return 1
            try:
                m = ib_.prepare(
                    cand,
                    json.loads(args.located.read_text(encoding="utf-8")),
                    title=args.title,
                    first_report=args.first_report,
                )
            except ValueError as exc:
                print(f"not prepared: {exc}")
                return 1
            case_dir.mkdir(parents=True)
            (case_dir / "manifest.json").write_text(m.model_dump_json(indent=2) + "\n")
            print(
                f"Wrote {case_dir / 'manifest.json'}: window {m.evaluation.from_block}.."
                f"{m.evaluation.to_block}"
            )
        elif args.step == "run":
            from cryptoguard.ml import lookalike_ranking

            if not verified_path.exists():
                print(f"{verified_path} is missing: run the verify step first.")
                return 1
            result = ib_.run(
                json.loads(verified_path.read_text(encoding="utf-8")),
                lookalike_ranking.protected_entities(ML_DIR / "poisoning"),
            )
            run_path.write_text(json.dumps(result, indent=1, default=str) + "\n", encoding="utf-8")
            print(
                json.dumps(
                    {k: result[k] for k in ("summary_level_I", "summary_level_III")}, indent=1
                )
            )
        else:
            for p in (verified_path, run_path):
                if not p.exists():
                    print(f"{p} is missing: run the verify and run steps first.")
                    return 1
            md = ib_.report(
                json.loads(verified_path.read_text(encoding="utf-8")),
                json.loads(run_path.read_text(encoding="utf-8")),
            )
            (args.out / "incident-benchmark.md").write_text(md, encoding="utf-8")
            print(md)
        return 0
    if args.ml_command == "inventory":
        import json

        from cryptoguard.ml.inventory import inventory

        inv = inventory(args.root)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(inv, indent=1) + "\n", encoding="utf-8")
        unregistered = [f["path"] for f in inv["files"] if f["source"] == "unregistered"]
        print(f"{len(inv['files'])} files described in {args.out}; unregistered: {unregistered}")
        return 0
    if args.ml_command == "hard-negative-extract":
        import json

        from cryptoguard.ml.hard_negative_archive import context_scan, extract_uncategorized

        try:
            first = extract_uncategorized(args.data_dir, args.out)
            second = context_scan(args.data_dir, args.out)
        except FileNotFoundError as exc:
            print(f"error [FileNotFoundError]: {exc}")
            return 1
        print(json.dumps({"extract": first, "context_rows": second.get("stored_rows")}, indent=1))
        return 0
    if args.ml_command == "hard-negative-study":
        from cryptoguard.ml.hn_study import run

        try:
            report = run(
                args.data_dir,
                args.poisoning_dir,
                args.poisoning_dir / "hard_negative",
                args.tables,
                freeze_cohort=not args.no_freeze,
            )
        except FileNotFoundError as exc:
            print(f"error [FileNotFoundError]: {exc} (run `cryptoguard ml hard-negative-extract`)")
            return 1
        c = report["cohort"]
        print(
            f"Pool: {sum(f['candidates'] for f in report['pool']['frames'].values()):,} "
            f"unlabeled candidates; cohort {c['version']}: {c['selected']} items "
            f"(selection {c['selection_sha256'][:12]}); wrote {args.tables} (0 RPC requests)."
        )
        return 0
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

        from cryptoguard.blockchain.budget import RequestLedger
        from cryptoguard.ml.collect import budget_path, collect

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


SAMPLE_DIR = ML_DIR / "poisoning" / "review_sample"
REVIEW_WORK = ML_DIR / "poisoning" / "review"
HN_DIR = ML_DIR / "poisoning" / "hard_negative"
COHORT_DIRS = {"review-sample/1": SAMPLE_DIR, "hard-negative-candidates/1": HN_DIR / "cohort_v1"}
COHORT_WORK = {"review-sample/1": REVIEW_WORK, "hard-negative-candidates/1": HN_DIR / "review"}
QUEUE = ML_DIR / "poisoning" / "review_packets_payoff_linked.jsonl"


def _add_review_parser(ml: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    rv = ml.add_parser("review", help="independent human review of the frozen sample (offline)")
    sub = rv.add_subparsers(dest="review_command", required=True)
    for name, text in (
        ("verify", "check the frozen sample against its committed hashes (reads only)"),
        ("audit", "recompute and check the sampling design; aggregate JSON"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("--sample", type=Path, default=None)
        p.add_argument("--queue", type=Path, default=QUEUE)
    sub.choices["audit"].add_argument("--out", type=Path, default=REVIEW_WORK / "design_audit.json")
    pk = sub.add_parser("package", help="make one reviewer's package (blinded sheet only)")
    pk.add_argument("--reviewer", required=True, help="pseudonym, e.g. A")
    pk.add_argument("--out", type=Path, required=True)
    pk.add_argument("--sample", type=Path, default=None)
    pk.add_argument("--work", type=Path, default=None)
    sv = sub.add_parser("serve", help="run the local review app for one reviewer package")
    sv.add_argument("--package", type=Path, required=True)
    sv.add_argument("--port", type=int, default=0)
    sv.add_argument("--no-browser", action="store_true")
    st = sub.add_parser("status", help="progress of one reviewer package (no decisions shown)")
    st.add_argument("--package", type=Path, required=True)
    rp = sub.add_parser("replace", help="replace a technically inaccessible item (maintainer)")
    rp.add_argument("--event", required=True)
    rp.add_argument(
        "--reason",
        required=True,
        choices=["transaction_not_found", "chain_data_unavailable", "sheet_record_malformed"],
    )
    rp.add_argument("--evidence", required=True)
    rp.add_argument("--exposed", default="", help="reviewers who already saw the original")
    rp.add_argument("--by", required=True)
    rp.add_argument("--sample", type=Path, default=None)
    rp.add_argument("--work", type=Path, default=None)
    ub = sub.add_parser("unblind", help="gate, then compare reviews with the source (maintainer)")
    ub.add_argument("--submission", type=Path, action="append", required=True)
    ub.add_argument("--adjudication", type=Path)
    ub.add_argument("--sample", type=Path, default=None)
    ub.add_argument("--work", type=Path, default=None)
    be = sub.add_parser("build-evidence", help="offline pre-cutoff evidence packets (maintainer)")
    be.add_argument("--sample", type=Path, default=None)
    be.add_argument("--work", type=Path, default=None)
    tp = sub.add_parser("training-package", help="synthetic training items for a reviewer")
    tp.add_argument("--reviewer", required=True)
    tp.add_argument("--out", type=Path, required=True)
    ag = sub.add_parser("agreement", help="agreement between finalized submissions (no key)")
    ag.add_argument("--submission", type=Path, action="append", required=True)
    ag.add_argument("--sample", type=Path, default=None)
    ck = sub.add_parser("check-submission", help="validate one submission file (no key)")
    ck.add_argument("submission", type=Path)
    ck.add_argument("--sample", type=Path, default=None)
    for p in (sub.choices["verify"], pk, rp, ub, be, ag, ck):
        p.add_argument(
            "--cohort",
            default="review-sample/1",
            choices=["review-sample/1", "hard-negative-candidates/1"],
        )


def _review(args: argparse.Namespace) -> int:
    import json

    from cryptoguard.ml import review_sample as rs
    from cryptoguard.ml.annotation import AnnotationError

    cmd = args.review_command
    cohort = getattr(args, "cohort", rs.SAMPLE_VERSION)
    if getattr(args, "sample", "unset") is None:
        args.sample = COHORT_DIRS[cohort]
    if getattr(args, "work", "unset") is None:
        args.work = COHORT_WORK[cohort]
    try:
        if cmd == "verify":
            queue = args.queue if cohort == rs.SAMPLE_VERSION else None
            manifest = rs.verify_frozen(args.sample, queue=queue, cohort=cohort)
            print(
                f"Frozen sample verified: {len(manifest['selected'])} items, selection "
                f"{manifest['selection_sha256']}; all five committed hashes match."
            )
            return 0
        if cmd == "audit":
            from cryptoguard.ml.sample_design import audit

            manifest = rs.verify_frozen(args.sample, queue=args.queue)
            report = audit(rs.load_queue(args.queue), manifest)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
            print(json.dumps(report["checks"], indent=1))
            print(f"Wrote {args.out} (aggregate only; 0 RPC requests).")
            return 0 if report["all_checks_pass"] else 2
        if cmd == "package":
            from cryptoguard.ml.unblind import make_package

            out = make_package(args.sample, args.work, args.reviewer, args.out, cohort=cohort)
            print(f"Reviewer package for {args.reviewer} in {out} (blinded sheet only).")
            return 0
        if cmd == "serve":
            return _review_serve(args)
        if cmd == "build-evidence":
            from cryptoguard.ml.evidence import build_cohort

            dbs = [ML_DIR / "poisoning" / "archive_subset.sqlite",
                   HN_DIR / "context_subset.sqlite",
                   REVIEW_WORK / "review_context.sqlite"]  # fmt: skip
            m = build_cohort(args.sample, args.work / "evidence", archive_dbs=dbs, cohort=cohort)
            print(f"{m['items']} packets for {cohort}; sha256 {m['packets_sha256']} "
                  f"(0 RPC requests).")  # fmt: skip
            return 0
        if cmd == "training-package":
            from cryptoguard.ml.training import make_package as training_package

            out = training_package(args.reviewer, args.out)
            print(f"Training package for {args.reviewer} in {out} (synthetic items only).")
            return 0
        if cmd == "agreement":
            from cryptoguard.ml.submissions import agreement_report

            report = agreement_report(args.submission, args.sample, cohort=cohort)
            print(json.dumps(report, indent=1))
            return 0
        if cmd == "check-submission":
            from cryptoguard.ml.submissions import check_submission

            problems = check_submission(args.submission, args.sample, cohort=cohort)
            print("valid" if not problems else "\n".join(problems))
            return 0 if not problems else 1
        if cmd == "status":
            from cryptoguard.ml.review_server import ReviewApp

            state = ReviewApp(args.package).state()
            print(
                f"Reviewer {state['reviewer']}: {len(state['decisions'])} of "
                f"{len(state['items'])} items saved; finalized: {state['finalized']}."
            )
            return 0
        if cmd == "replace":
            from cryptoguard.ml.unblind import record_replacement

            rec = record_replacement(
                args.sample,
                args.work,
                original_event_id=args.event,
                reason=args.reason,
                evidence=args.evidence,
                exposed=[x for x in args.exposed.split(",") if x],
                recorded_by=args.by,
                cohort=cohort,
            )
            print(
                f"Item {rec.original_item} replaced by item {rec.replacement_item} (reserve "
                f"{rec.reserve_position}); remake reviewer packages to include it."
            )
            return 0
        if cmd == "unblind":
            from cryptoguard.ml.unblind import unblind

            report = unblind(
                args.sample, args.work, args.submission, args.adjudication, cohort=cohort
            )
            primary = report["primary_all_reviewers_attempt"]["overall"]
            keys = ("items", "positives", "estimate", "wilson95_design")
            print(json.dumps({k: primary.get(k) for k in keys}, indent=1))
            print(f"Wrote {args.work / 'unblinded_report.json'} (0 RPC requests).")
            return 0
    except (rs.ReviewSampleError, AnnotationError, FileNotFoundError) as exc:
        print(f"error [{type(exc).__name__}]: {exc}")
        return 1
    raise AssertionError(cmd)


def _review_serve(args: argparse.Namespace) -> int:
    import webbrowser

    from cryptoguard.ml.review_server import ReviewApp, serve

    app = ReviewApp(args.package)
    with app.store:
        httpd, url = serve(app, args.port)
        print(f"Reviewer {app.pkg['reviewer']}: open {url}")
        print("Keep this window open while reviewing; press Ctrl+C to stop (saves are on disk).")
        if not args.no_browser:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
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

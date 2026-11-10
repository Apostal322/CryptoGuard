"""Phase 12.8 offline readiness study (protocol 12.8, section 13): what local data exist,
which of it is eligible for which benchmark task, and what the blind harness reports on the
known development windows. No RPC; nothing here is independent validation.

Outputs are aggregates. Record-level content of restricted sources (the CC BY-NC-ND archive,
the frozen review sheets) is never written to a tracked location, and the frozen cohort
files are only read through the existing blinded-sheet helpers.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

from cryptoguard.ml import benchmark_contract as bc
from cryptoguard.ml import benchmark_eval as be

STUDY_VERSION = "benchmark-readiness/1"
MECHANISM_MAP = {
    "zero_value_transfer": "zero_value_token",
    "spoofed_transfer_from": "spoofed_transfer",
    "counterfeit_token": "fake_token",
    "token_airdrop": "other",
    "unknown": "unknown",
}
ARCHIVE_LAST_DATE = "2024-06-30"
REGISTRIES = (
    Path("docs/ml/incident-benchmark/candidates.json"),
    Path("docs/ml/incident-benchmark/stage2-candidates.json"),
)
BLIND_V2 = Path("data/ml/research/phase12.4/blind-v2/fixture.json")
DEGRADATIONS = ("signer_lookups", "receipts", "native", "first_half", "recipient_history")


# --- D1: inventory ----------------------------------------------------------------------------


def _tree(path: Path) -> tuple[int, int]:
    files = size = 0
    if path.is_file():
        return 1, path.stat().st_size
    for root, _dirs, names in os.walk(path):
        for n in names:
            files += 1
            with contextlib.suppress(OSError):
                size += (Path(root) / n).stat().st_size
    return files, size


def _lines(path: Path) -> int | None:
    if not path.is_file():
        return None
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def _licence(rel: str) -> tuple[str, str, str]:
    from cryptoguard.ml.inventory import REGISTRY

    reg = next((r for r in REGISTRY if rel.startswith(r[0])), None)
    return (reg[2], reg[3], reg[4]) if reg else ("unknown", "unknown", "unknown")


def inventory(root: Path) -> list[dict[str, Any]]:
    """One row per local source (sizes by ``stat`` only; nothing large is read)."""
    rows: list[dict[str, Any]] = []

    def add(source_id: str, klass: str, rel: str, **extra: Any) -> None:
        path = root / rel
        files, size = _tree(path) if path.exists() else (0, 0)
        lic, redist, label = _licence(rel if rel.endswith("/") or path.is_file() else rel + "/")
        rows.append(
            {
                "source_id": source_id,
                "class": klass,
                "path": rel,
                "exists": path.exists(),
                "files": files,
                "bytes": size,
                "licence": lic,
                "redistributable": redist,
                "label_status": label,
                **extra,
            }
        )

    p = "data/ml/poisoning"
    add(
        "tsuchiya-archive",
        "source_derived_events",
        "data/external/tsuchiya2025",
        chain="ethereum",
        period="2022-07..2024-06",
        label_source="source heuristics",
        label_confidence="weak (source-defined; every poisoning row meets the source's own rule)",
        outcome="source-confirmed payoffs",
        eligibility="development only; test split spent",
    )
    cache = root / "data/ml/research/phase12.5/episodes.jsonl"
    splits: dict[str, int] = {}
    if cache.is_file():
        with cache.open(encoding="utf-8") as fh:
            for line in fh:
                s = json.loads(line)["split"]
                splits[s] = splits.get(s, 0) + 1
    add(
        "archive-episodes",
        "source_derived_events",
        "data/ml/research/phase12.5/episodes.jsonl",
        records=sum(splits.values()) or None,
        splits=splits,
        label_source="source payoff confirmation",
        label_confidence="supported (paid lookalike; payoff-conditioned)",
        outcome="paid lookalike",
        eligibility="development split: exploratory; test split: spent (12.1)",
    )
    add(
        "archive-subset",
        "source_derived_events",
        f"{p}/archive_subset.sqlite",
        eligibility="development only",
    )
    add(
        "review-packets",
        "candidate_events_without_outcome",
        f"{p}/review_packets_payoff_linked.jsonl",
        records=_lines(root / p / "review_packets_payoff_linked.jsonl"),
        eligibility="reviewer evidence; unlabeled until review",
    )
    submissions = sum(1 for _ in (root / p).rglob("submission.json")) if (root / p).exists() else 0
    add(
        "cohort-A",
        "human_review_frozen",
        f"{p}/review_sample",
        records=_lines(root / p / "review_sample/reviewer_sheet.jsonl"),
        reviewer_submissions=submissions,
        eligibility="protected: frozen, unreviewed; never used for development",
    )
    add(
        "cohort-B",
        "human_review_frozen",
        f"{p}/hard_negative/cohort_v1",
        records=_lines(root / p / "hard_negative/cohort_v1/reviewer_sheet.jsonl"),
        reviewer_submissions=submissions,
        eligibility="protected: frozen, unreviewed; never used for development",
    )
    add(
        "hard-negative-pool",
        "candidate_events_without_outcome",
        f"{p}/hard_negative",
        eligibility="unlabeled candidates; not negatives",
    )
    add(
        "unconfirmed-payoffs",
        "source_derived_events",
        f"{p}/unconfirmed",
        eligibility="exhausted for recency testing (12.2 follow-up)",
    )
    add(
        "poison-hunter",
        "source_derived_events",
        "data/external/poison-hunter",
        label_confidence="weak (pipeline detections)",
        eligibility="data card only",
    )
    add(
        "ptxphish",
        "separate_task",
        "data/external/ptxphish",
        eligibility="phishing-transaction task; no overlap with poisoning windows",
    )
    add(
        "forta", "separate_task", "data/external/forta", eligibility="address labels; separate task"
    )
    add(
        "replay-incident-windows",
        "wallet_windows_verified_incident",
        "src/cryptoguard/replay/cases",
        eligibility="development; all touch frozen Cohort B (protected)",
    )
    add(
        "background-windows",
        "wallet_windows_unlabelled",
        "src/cryptoguard/replay/background_cases",
        eligibility="unlabelled background: not negatives; some protected",
    )
    add(
        "level-I-incident-windows",
        "wallet_windows_verified_incident",
        "docs/ml/incident-benchmark/cases",
        eligibility="development cases (12.3-12.7.1)",
    )
    add(
        "blind-v2-window",
        "wallet_windows_verified_incident",
        BLIND_V2.as_posix(),
        eligibility="development (re-recording of a known incident)",
    )
    add(
        "campaign-expansion",
        "wallet_windows_unlabelled",
        "src/cryptoguard/replay/campaign_cases",
        eligibility="campaign analysis; unlabelled",
    )
    rows.append(
        {
            "source_id": "synthetic-generators",
            "class": "controlled_synthetic",
            "path": "src/cryptoguard/ml (reliability, adversarial and adaptive generators)",
            "exists": True,
            "licence": "project code",
            "redistributable": "yes",
            "label_status": "synthetic oracle",
            "eligibility": "controlled robustness only; never real-world performance",
        }
    )
    return rows


# --- D2: local windows and leads ------------------------------------------------------------


def _protected(poisoning_dir: Path) -> tuple[frozenset[str], frozenset[str]] | None:
    from cryptoguard.ml.lookalike_ranking import protected_entities

    try:
        return protected_entities(poisoning_dir)
    except (OSError, ValueError):
        return None


def local_windows(poisoning_dir: Path) -> list[dict[str, Any]]:
    """Every recorded window with its manifest (if any) and whether it touches a frozen
    cohort. A window whose protection cannot be checked is treated as protected."""
    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.ml.observation_study import touches_frozen_any
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import ReplayFixture, load_cases

    blind = _protected(poisoning_dir)
    out: list[dict[str, Any]] = []

    def add(name: str, kind: str, fixture: Any, manifest: Any, cluster: str) -> None:
        protected = True if blind is None else bool(touches_frozen_any(fixture, blind))
        out.append(
            {
                "name": name,
                "kind": kind,
                "fixture": fixture,
                "manifest": manifest,
                "cluster": cluster,
                "protected": protected,
            }
        )

    for c in load_cases():
        if c.fixture is not None:
            add(c.manifest.case_id, "replay_incident", c.fixture, c.manifest, c.manifest.case_id)
    level1 = [c for c in ib.load_new_cases() if c.fixture is not None]
    for c in level1:
        add(c.manifest.case_id, "level_I_incident", c.fixture, c.manifest, c.manifest.case_id)
    if BLIND_V2.exists():
        base = next((c for c in level1 if c.manifest.case_id.startswith("scamsniffer")), None)
        if base is not None:
            fx = ReplayFixture.model_validate_json(BLIND_V2.read_text(encoding="utf-8"))
            add(
                "scamsniffer-blind-v2",
                "level_I_rerecording",
                fx,
                base.manifest,
                base.manifest.case_id,
            )
    for b in load_background():
        if b.fixture is not None:
            add(b.manifest.case_id, "background", b.fixture, None, b.manifest.case_id)
    return out


def case_of(w: dict[str, Any]) -> tuple[bc.BenchmarkCase, bc.Outcome | None]:
    """The benchmark case and sealed outcome of one local window. Every local incident is a
    development case; a background window has no outcome."""
    from cryptoguard.replay.observation import coverage_of

    fx, man = w["fixture"], w["manifest"]
    schema = coverage_of(fx).schema_version
    if man is None:
        case = bc.BenchmarkCase(
            case_id=w["name"],
            chain_id=fx.chain_id,
            victim=fx.wallet,
            from_block=fx.from_block,
            to_block=fx.to_block,
            cutoff=(fx.to_block + 1, 0),
            cutoff_rule="end of window (no outcome)",
            observation_schema=schema,
            source=bc.CaseSource(publisher="random background wallet", url=""),
            cluster_id=w["cluster"],
            population="development",
            development_reasons=("background window used in development",),
        )
        return case, None
    src = man.public_sources[0]
    case = bc.BenchmarkCase(
        case_id=w["name"],
        chain_id=man.chain_id,
        victim=man.victim,
        from_block=fx.from_block,
        to_block=fx.to_block,
        cutoff=(man.harm.block_number, 0),
        cutoff_rule="strictly before the harmful block",
        observation_schema=schema,
        source=bc.CaseSource(
            publisher=src.title, url=src.url, published=str(man.first_public_report)
        ),
        cluster_id=w["cluster"],
        population="development",
        development_reasons=("known incident used in Phases 12.3-12.7.1",),
    )
    today = date(2026, 11, 10)
    labels = [
        bc.Label(
            label_id=f"{w['name']}:outcome",
            subject=man.harm.recipient,
            dimension="outcome",
            value="paid_to_candidate",
            evidence=(
                bc.EvidenceRef(kind="chain_transaction", ref=man.harm.transaction_hash),
                bc.EvidenceRef(kind="incident_report", ref=src.url),
            ),
            source=src.title,
            determined_at=today,
            method="incident manifest (public report, on-chain check)",
            confidence="verified",
            cutoff_relation="post_cutoff_outcome",
        )
    ]
    planting = _planting(w, man.harm.recipient)
    if planting is not None:
        mech, tx = planting
        labels.append(
            bc.Label(
                label_id=f"{w['name']}:mechanism",
                subject=man.harm.recipient,
                dimension="mechanism",
                value=mech,
                evidence=(bc.EvidenceRef(kind="chain_transaction", ref=tx),),
                source="recorded window (forensic reading after the outcome)",
                determined_at=today,
                method="first pre-harm record between the victim and the paid address",
                confidence="supported",
                cutoff_relation="forensic",
                limitations=("derived with outcome knowledge; never a model input",),
            )
        )
    outcome = bc.Outcome(
        case_id=w["name"],
        verified=bool(man.onchain_verification),
        paid_address=man.harm.recipient,
        intended_recipient=man.intended_recipient,
        harm_tx=man.harm.transaction_hash,
        harm_block=man.harm.block_number,
        labels=tuple(labels),
    )
    return case, outcome


def _planting(w: dict[str, Any], paid: str) -> tuple[str, str] | None:
    """Forensic mechanism label: read from the best recording of the same incident (a /2
    re-recording if one exists), using the first pre-harm record involving the paid address."""
    from cryptoguard.ml import candidate_discovery as cd
    from cryptoguard.ml.payments import TRUSTED_TOKENS
    from cryptoguard.replay.models import ReplayFixture

    fixtures = [w["fixture"]]
    if w["name"].startswith("scamsniffer") and BLIND_V2.exists():
        fixtures.insert(0, ReplayFixture.model_validate_json(BLIND_V2.read_text(encoding="utf-8")))
    cutoff = (w["manifest"].harm.block_number, 0)
    for fx in fixtures:
        for o in cd.observations(fx):
            if o.counterparty != paid.lower() or (o.block, o.tx_index) >= cutoff:
                continue
            if o.kind == "native":
                return "native_dust", o.tx_hash
            if o.kind == "erc20" and o.emitter not in TRUSTED_TOKENS:
                return "fake_token", o.tx_hash
            if o.kind == "erc20" and o.direction == "out":
                return "spoofed_transfer", o.tx_hash
            if o.kind == "erc20" and o.value == 0:
                return "zero_value_token", o.tx_hash
    return None


def window_rows(windows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Coverage matrix, quality status and eligibility of each local window. Protected
    windows are classified but never computed on."""
    rows = []
    for w in windows:
        fx = w["fixture"]
        case, outcome = case_of(w)
        cov = bc.coverage_matrix(fx)
        issues = bc.case_quality(case, fx, outcome, protected=w["protected"])
        row: dict[str, Any] = {
            "window": w["name"],
            "kind": w["kind"],
            "observation_schema": case.observation_schema,
            "blocks": fx.to_block - fx.from_block + 1,
            "protected": w["protected"],
            "population": "protected" if w["protected"] else case.population,
            "has_outcome": outcome is not None,
            "coverage": cov,
            "incomplete_categories": sorted(k for k, v in cov.items() if v != "complete"),
            "mechanism_eligibility": {
                k: v["state"] for k, v in bc.mechanism_eligibility(cov).items()
            },
            "quality_status": bc.status(issues),
            "issues": sorted({i.code for i in issues}),
            "independent": False,
        }
        if not w["protected"]:
            row["transfers"] = len(fx.transfers)
            row["wallet_transactions"] = len(fx.wallet_transactions)
            row["native_inbound"] = len(fx.native_inbound or [])
            row["candidates"] = be.predict(case, fx).burden["candidates"]
        rows.append(row)
    return rows


def leads(root: Path) -> list[dict[str, Any]]:
    """Incident leads already in the committed registries. A lead is not a validated
    incident; identifiers are reported as present/absent only."""
    cache = root / "data/ml/research/phase12.5/episodes.jsonl"
    archive_victims: set[str] = set()
    if cache.is_file():
        with cache.open(encoding="utf-8") as fh:
            archive_victims = {json.loads(line)["victim"].lower() for line in fh}
    out = []
    for reg in REGISTRIES:
        path = root / reg
        if not path.is_file():
            continue
        for c in json.loads(path.read_text(encoding="utf-8"))["candidates"]:
            ids = c.get("identifiers", {})
            recorded = (
                bool(c.get("fixture_case_id"))
                or (root / "docs/ml/incident-benchmark/cases" / c["case_id"]).exists()
            )
            have = sorted(k for k, v in ids.items() if v)
            needs = [k for k in ("victim", "harm_tx") if k not in have]
            victim = (ids.get("victim") or "").lower()
            # the event date is the case id's suffix when it has one, else the source date
            tail = c["case_id"][-10:]
            day = tail if tail[4:5] == "-" and tail[7:8] == "-" else str(c["source"]["date"])[:10]
            out.append(
                {
                    "lead": c["case_id"],
                    "publisher": c["source"]["publisher"][:60],
                    "source_date": c["source"]["date"],
                    "mechanism_claimed": MECHANISM_MAP.get(c["mechanism"], "unknown"),
                    "identifier_status": c["identifier_status"].split(":")[0],
                    "identifiers_present": have,
                    "recorded": recorded,
                    "status": "development (recorded and analysed)"
                    if recorded
                    else "lead: identifiers incomplete"
                    if needs
                    else "lead: identifiers complete, not recorded",
                    "missing_for_collection": needs,
                    "within_archive_period": len(day) == 10 and day <= ARCHIVE_LAST_DATE,
                    "victim_in_archive_episodes": (victim in archive_victims) if victim else None,
                }
            )
    return out


# --- D3: development regression through the blind harness -----------------------------------


def development_regression(
    windows: Sequence[dict[str, Any]], ledger_path: Path | None
) -> dict[str, Any]:
    usable = [w for w in windows if not w["protected"] and w["manifest"] is not None]
    pairs = [(w, *case_of(w)) for w in usable]
    vault = be.OutcomeVault({c.case_id: o for _, c, o in pairs if o is not None})
    ledger = be.Ledger(ledger_path)
    results, audits = [], {}
    for w, case, _ in pairs:
        fx = w["fixture"]
        results.append(be.run_case(case, fx, vault, ledger))
        request = bc.collector_request(case, max_requests=2_500)
        audits[case.case_id] = be.leakage_audit(
            case,
            fx,
            be.predict(case, fx),
            request,
            protected=w["protected"],
            dev_reasons=case.development_reasons,
        )
    cases = [c for _, c, _ in pairs]
    grp = be.groups(cases, {c.case_id: o for _, c, o in pairs if o is not None})
    return {
        "label": "known development cases - not independent validation",
        "cases": {r["case_id"]: r for r in results},
        "metrics": be.aggregate(results),
        "leakage_audit": audits,
        "groups": grp,
        "split_feasibility": be.split_feasibility(len(set(grp.values()))),
        "ledger_refused_reruns": len(ledger.refused),
    }


# --- D4: missingness sensitivity (in memory; never written) ---------------------------------


def degrade(fixture: Any, what: str) -> Any:
    """A copy of a recording with one kind of information removed and its coverage marked
    accordingly. Artificial: it says nothing about real recorder failures."""
    from cryptoguard.replay.observation import (
        OBSERVATION_V2,
        CategoryCoverage,
        ObservationCoverage,
        coverage_of,
    )

    cats = dict(coverage_of(fixture).categories)

    def mark(category: str, state: str) -> None:
        cats[category] = CategoryCoverage(status=state)

    update: dict[str, Any] = {}
    if what == "signer_lookups":
        update["transfers"] = [t.model_copy(update={"tx_sender": None}) for t in fixture.transfers]
        mark("erc20_outgoing_signers", "partial")
    elif what == "receipts":
        update["native_inbound"] = [
            n.model_copy(update={"succeeded": None}) for n in fixture.native_inbound or []
        ]
    elif what == "native":
        update["native_inbound"] = []
        update["unattributed_inbound"] = []
        mark("native_inbound_external", "not_collected")
        mark("native_inbound_zero_value", "not_collected")
        mark("native_inbound_unattributed", "not_collected")
    elif what == "first_half":
        mid = (fixture.from_block + fixture.to_block) // 2
        update["transfers"] = [t for t in fixture.transfers if t.block_number >= mid]
        update["native_inbound"] = [
            n for n in fixture.native_inbound or [] if n.block_number >= mid
        ]
        for c in ("erc20_transfer_logs", "wallet_signed_transactions", "native_inbound_external"):
            if cats[c].status == "complete":
                mark(c, "truncated")
    elif what == "recipient_history":
        mark("wallet_signed_transactions", "partial")
    else:
        raise ValueError(what)
    update["observation"] = ObservationCoverage(schema_version=OBSERVATION_V2, categories=cats)
    return fixture.model_copy(update=update)


def missingness(windows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for w in windows:
        if w["protected"] or w["manifest"] is None:
            continue
        case, outcome = case_of(w)
        if outcome is None:
            continue
        rows = {}
        for what in ("none", *DEGRADATIONS):
            fx = w["fixture"] if what == "none" else degrade(w["fixture"], what)
            vault = be.OutcomeVault({case.case_id: outcome})
            r = be.run_case(case, fx, vault, be.Ledger(None))
            mech = r.get("mechanism_label")
            rows[what] = {
                "quality_status": bc.status(bc.case_quality(case, fx, outcome)),
                "mechanism_eligible": r.get("mechanism_eligible"),
                "labelled_mechanism": mech,
                "candidates": r["candidates"],
                "generated": r.get("T2_generated"),
                "rank_B0": (r.get("T3_rank") or {}).get("B0"),
                "failure": r["failure"],
            }
        out[w["name"]] = rows
    return out


# --- D5: are recency ties right on the archive development split? ---------------------------


def tie_analysis(poisoning_dir: Path) -> dict[str, Any]:
    """Among development-split episodes where the paid lookalike ties at least one rival on
    similarity, how often is it the most recently planted of the tied ones, against the
    chance rate 1/t? Source-conditional development evaluation; the test split is dropped
    before any feature is computed."""
    from cryptoguard.ml import lookalike_ranking as lr

    t0 = time.perf_counter()
    episodes, _ = lr.load_episodes(poisoning_dir)
    addrs, txs = lr.protected_entities(poisoning_dir)
    overlap = lr.protected_overlap(episodes, addrs, txs)
    kept = [e for e, o in zip(episodes, overlap, strict=True) if not o]
    grp, _mode = lr.protocol_groups(kept)
    split = lr.temporal_split(kept, grp)
    dev = [(e, g) for e, g, s in zip(kept, grp, split, strict=True) if s == "dev"]
    d_tied: list[float] = []
    g_tied: list[int] = []
    d_all: list[float] = []
    g_all: list[int] = []
    sizes: list[int] = []
    evaluable = 0
    for e, g in dev:
        f = lr.candidate_features(e, lr.View(), None, None)
        if not f or f[e.paid]["B0"] is None:
            continue
        evaluable += 1

        def newest_share(cands: list[str], f: dict[str, Any] = f, paid: str = e.paid) -> float:
            top = max(float(f[c]["T0"] or 0.0) for c in cands)
            best = [c for c in cands if float(f[c]["T0"] or 0.0) == top]
            return (1.0 / len(best)) if paid in best else 0.0

        everyone = list(f)
        d_all.append(newest_share(everyone) - 1.0 / len(everyone))
        g_all.append(g)
        tied = [c for c in f if f[c]["B0"] == f[e.paid]["B0"]]
        if len(tied) >= 2:
            d_tied.append(newest_share(tied) - 1.0 / len(tied))
            g_tied.append(g)
            sizes.append(len(tied))
    out: dict[str, Any] = {
        "population": "12.1 archive development split (source-conditional; test split not used)",
        "dev_episodes": len(dev),
        "evaluable": evaluable,
        "tied_episodes": len(d_tied),
        "tied_size_mean": round(sum(sizes) / len(sizes), 2) if sizes else None,
        "seconds": round(time.perf_counter() - t0, 1),
    }
    if d_tied:
        chance = sum(1.0 / s for s in sizes) / len(sizes)
        excess = lr.paired(d_tied, g_tied)
        out["tied"] = {
            "paid_is_newest_share": round(chance + excess["mean"], 4),
            "chance": round(chance, 4),
            "excess_over_chance": excess,
        }
    if d_all:
        out["all_candidates_excess_over_chance"] = lr.paired(d_all, g_all)
    return out


# --- entry point ----------------------------------------------------------------------------


def main(
    poisoning_dir: Path, out: Path, *, archive: bool = True, history: bool = True
) -> dict[str, Any]:
    import subprocess

    from cryptoguard.ml import power, repo_safety
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    t0 = time.perf_counter()
    root = Path()
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
    windows = local_windows(poisoning_dir)
    rows = window_rows(windows)
    out.mkdir(parents=True, exist_ok=True)
    regression = development_regression(windows, out / "ledger-development.jsonl")
    incidents = [r for r in rows if r["has_outcome"]]
    result: dict[str, Any] = {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.8",
        "git": git,
        "rpc_requests": 0,
        "inventory": inventory(root),
        "windows": rows,
        "eligibility_summary": {
            "windows": len(rows),
            "incident_windows": len(incidents),
            "protected_windows": sum(r["protected"] for r in rows),
            "development_incident_windows": sum(1 for r in incidents if not r["protected"]),
            "independent_incidents": sum(r["independent"] for r in rows),
            "independent_victims": 0,
            "all_mechanisms_eligible_windows": sum(
                r["mechanism_eligibility"]["all_mechanisms"] == "complete" for r in rows
            ),
            "observation_schemas": be._count(r["observation_schema"] for r in rows),
        },
        "leads": leads(root),
        "development_regression": regression,
        "missingness": missingness(windows),
        "baseline_registry": list(be.REGISTRY),
        "spent_populations": list(be.SPENT_POPULATIONS),
        "power": {
            "sign_test": [power.sign_test_power(n, 0.8) for n in (5, 10, 20, 30, 50)],
            "plan_grid_eligible_rate_0.5": power.paired_plan_grid(),
            "plan_grid_clustered_deff_1.5": power.paired_plan_grid(deff=1.5),
        },
        "public_safety": repo_safety.scan(root, history=history),
    }
    protected = _protected(poisoning_dir)
    if protected is not None:
        overlap = repo_safety.restricted_identifier_overlap(root, protected[0] | protected[1])
        result["public_safety"]["frozen_cohort_identifiers_in_tracked_files"] = {
            "files": len(overlap),
            "identifiers": sum(overlap.values()),
            "note": "Cohort B was drawn from already-public recorded windows; no key is tracked",
        }
    if archive and (poisoning_dir / "archive_subset.sqlite").exists():
        result["tie_analysis"] = tie_analysis(poisoning_dir)
    else:
        result["tie_analysis"] = "not run"
    peak = peak_rss_bytes()
    result["resources"] = {
        "seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
    }
    (out / "readiness.json").write_text(
        json.dumps(result, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result

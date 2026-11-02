"""Offline Phase 11.2 report: Poison-Hunter validation, pilot reconstruction, candidate
generation on the recorded replay fixtures, and the dataset decision gates (0 RPC requests).

Every number in ML_PILOT_AUDIT.md and ML_POISONING_DATASET.md is produced here from local
artifacts, and the JSON written next to the tables records their hashes.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

from cryptoguard.ml.candidates import (
    CANDIDATE_VERSION,
    EVENT_FEATURE_VERSION,
    PriorIndex,
    event_features,
    generate_with_stats,
)
from cryptoguard.ml.events import (
    TASK_ID,
    LabelRecord,
    PoisoningEvent,
    campaign_groups,
    deduplicate,
    manifest,
    quality_gates,
    resolve_labels,
)
from cryptoguard.ml.history import events_from_fixture
from cryptoguard.ml.pilot import load_yield, reconstruct, render_markdown
from cryptoguard.ml.poison_hunter import PoisonHunterRecord, parse_sample, profile
from cryptoguard.ml.tsuchiya import SOURCE_FILE as PAYOFF_FILE
from cryptoguard.ml.tsuchiya import cross_check, parse_payoffs
from cryptoguard.ml.tsuchiya import profile as payoff_profile

_SUBTYPE = {"dust": "dust", "zero": "zero_value", "fake": "fake_token"}


def poison_hunter_events(records: list[PoisonHunterRecord]) -> list[PoisoningEvent]:
    """Valid Poison-Hunter rows as events (weak labels; no wallet history recorded)."""
    return [
        PoisoningEvent(
            chain_id=1,
            victim=r.victim,
            lookalike=r.lookalike,
            imitated=r.imitated,
            planting_tx=r.planting_tx,
            planting_block=r.block_number or 0,
            planting_tx_index=None,
            planting_log_index=None,  # not in the source: batch rows differ by victim only
            observation_timestamp=None,
            subtype=_SUBTYPE.get(r.subtype, "unknown"),
            tx_signer=r.tx_signer,
            log_contract=r.log_contract,
            token_contract=r.log_contract if r.subtype != "fake" else None,
            candidate_method=f"poison-hunter-sample:line{r.source_line}",
            coverage="unavailable",
        )
        for r in records
        if r.status == "valid"
    ]


def _git_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError:
        return None
    return out.stdout.strip() or None


def candidate_evaluation() -> dict[str, Any]:
    """Candidate recall on the 4 recorded incidents and candidate volume on background
    wallets. The incidents were used while developing the detector: not untouched data."""
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.engine import replay
    from cryptoguard.replay.models import load_cases

    index = PriorIndex()
    incidents: list[dict[str, Any]] = []
    for case in load_cases():
        m, fx = case.manifest, case.fixture
        if fx is None:
            continue
        cands, stats = generate_with_stats(fx)
        harm = m.harm.recipient.lower()
        hits = [
            c
            for c in cands
            if c.event.lookalike == harm and c.event.planting_block <= m.harm.block_number
        ]
        events, coverage = events_from_fixture(fx)
        feats = [event_features(c, events, coverage, index) for c in hits[:1]]
        for c in cands:
            index.add(c.event)
        detector = replay(m, fx)
        lead = [r.lead_time_blocks for r in detector.results if r.lead_time_blocks is not None]
        incidents.append(
            {
                "case": m.case_id,
                "candidates": stats.candidates,
                "by_method": stats.by_method,
                "harmful_lookalike_found": bool(hits),
                "candidate_lead_blocks": (
                    m.harm.block_number - min(c.event.planting_block for c in hits)
                    if hits
                    else None
                ),
                "detector_best_lead_blocks": max(lead) if lead else None,
                "first_hit_methods": list(hits[0].methods) if hits else [],
                "first_hit_history_status": feats[0].history.history_status if feats else None,
                "runtime_ms": stats.runtime_ms,
                "peak_kib": stats.peak_kib,
            }
        )
    background: list[dict[str, Any]] = []
    for bg in load_background():
        fx = bg.fixture
        if fx is None:
            continue
        cands, stats = generate_with_stats(fx)
        background.append(
            {
                "case": fx.case_id,
                "blocks": fx.to_block - fx.from_block + 1,
                "candidates": stats.candidates,
                "by_method": stats.by_method,
            }
        )
    blocks = sum(b["blocks"] for b in background)
    return {
        "version": CANDIDATE_VERSION,
        "incidents": incidents,
        "incident_recall": f"{sum(i['harmful_lookalike_found'] for i in incidents)}/"
        f"{len(incidents)}",
        "background": background,
        "background_candidates_per_wallet_day": round(
            sum(b["candidates"] for b in background) / (blocks / 7_200), 3
        )
        if blocks
        else None,
        "caveat": "Incidents were used during detector development; background candidates "
        "are unlabelled (not false positives).",
    }


def payoff_cross_check(
    path: Path,
    rows: list[PoisonHunterRecord],
    pilot_dir: Path,
    candidates: list[tuple[int, str, str]],
) -> dict[str, Any]:
    """Tsuchiya et al.'s payoff transfers against Poison-Hunter rows, pilot outcomes and
    the recorded incidents. Aggregates and Poison-Hunter line numbers only (CC BY-NC-ND)."""
    from cryptoguard.replay.models import load_cases

    parsed = parse_payoffs(path)
    outcomes = None
    if (pilot_dir / "yield.jsonl").exists():
        outcomes = [y.outcome for y in load_yield(pilot_dir, candidates)[0]]
    incidents = [
        {
            "case": m.case_id,
            "victim": m.victim,
            "block": m.harm.block_number,
            "tx": m.harm.transaction_hash,
            "token": m.harm.token,
        }
        for m in (case.manifest for case in load_cases())
    ]
    return {
        "source": payoff_profile(parsed),
        **cross_check(parsed.valid, rows, outcomes, incidents),
    }


def build(data_dir: Path, pilot_dir: Path) -> dict[str, Any]:
    t0 = time.perf_counter()
    sample = data_dir / "poison-hunter" / "phishing_transfers_sample.csv"
    parsed = parse_sample(sample)
    ph = profile(parsed)
    events, dropped = deduplicate(poison_hunter_events(parsed.records))
    labels = [
        LabelRecord(
            victim_event_id=e.victim_event_id,
            tier="weak_attempt",
            source="poison-hunter-sample",
            available_at="2024 (publication)",
        )
        for e in events
    ]
    resolved = resolve_labels(labels)
    groups = campaign_groups(events)
    gates = quality_gates(events, resolved, license_ok=False)
    candidates = [(r.source_line, r.victim, r.lookalike) for r in parsed.valid]
    pilot = reconstruct(pilot_dir, candidates) if (pilot_dir / "yield.jsonl").exists() else None
    payoff_path = data_dir / "tsuchiya2025" / PAYOFF_FILE
    payoffs = (
        payoff_cross_check(payoff_path, parsed.valid, pilot_dir, candidates)
        if payoff_path.exists()
        else None
    )
    cand_eval = candidate_evaluation()
    runtime = time.perf_counter() - t0
    return {
        "task": TASK_ID,
        "git": _git_sha(),
        "python": platform.python_version(),
        "versions": {"candidates": CANDIDATE_VERSION, "event_features": EVENT_FEATURE_VERSION},
        "poison_hunter": ph,
        "events": {
            "victim_events": len(events),
            "duplicates_dropped": dropped,
            "campaign_groups": len(set(groups.values())),
            "largest_group": max(
                (list(groups.values()).count(g) for g in set(groups.values())), default=0
            ),
            "manifest": manifest(events, labels),
            "label_tiers": {
                t: list(resolved.values()).count(t) for t in sorted(set(resolved.values()))
            },
        },
        "gates": [g.model_dump() for g in gates],
        "pilot": pilot,
        "payoff_cross_check": payoffs,
        "candidates": cand_eval,
        "runtime_seconds": round(runtime, 2),
        "rpc_requests": 0,
    }


_OUTCOME_SHORT = {
    "confirmed_direct_payment": "confirmed",
    "no_direct_payment_observed_with_complete_declared_coverage": "complete, none seen",
    "partial_coverage": "partial",
    "unresolved": "unresolved",
    "not_evaluated": "not evaluated",
    "no_pilot_record": "no pilot record",
}


def render_payoffs(x: dict[str, Any]) -> list[str]:
    src = x["source"]
    lo, hi = x["payoff_block_range"]
    sha = "matches" if src["source_sha256_matches_pinned"] else "**differs from**"
    md5 = "matches" if src["source_md5_matches_published"] else "**differs from**"
    lines = [
        "## Cross-check with Tsuchiya et al. payoff transfers",
        "",
        "Source: KiltHub DOI 10.1184/R1/29212703.v1 (CC BY-NC-ND 4.0), kept local. "
        f"SHA-256 `{src['source_sha256'][:16]}…` ({sha} the pinned hash); MD5 {md5} the "
        "value KiltHub publishes.",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Rows / valid / quarantined | {src['rows']} / {src['valid']} / "
        f"{len(src['quarantined'])} |",
        f"| Payoff block range | {lo:,}-{hi:,} |",
        f"| Tokens | {', '.join(f'{k} {v}' for k, v in src['tokens'].items())} |",
        f"| Distinct payers / lookalikes | {src['distinct_payers']} / "
        f"{src['distinct_lookalikes']} |",
        f"| Amounts not exactly representable (float-encoded) | {src['inexact_values']} |",
        f"| Accepted by the detector predicate / candidate rule | "
        f"{src['detector_predicate_accepts']} / {src['candidate_rule_accepts']} (implied by "
        "the study's 3+4 selection: a consistency check, not recall) |",
        "",
        f"Poison-Hunter rows by pilot outcome (window: {x['window_blocks']:,} blocks after "
        "the planting):",
        "",
        "| Pilot outcome | Rows | In payoff period | In 3+4 definition | Paid this lookalike "
        "(in window) | Paid another lookalike of the same address | Lookalike paid by "
        "another victim |",
        "|---|---|---|---|---|---|---|",
    ]
    for outcome, b in x["by_outcome"].items():
        lines.append(
            f"| {_OUTCOME_SHORT.get(outcome, outcome)} | {b['rows']} | {b['in_period']} | "
            f"{b['in_definition']} | {b['victim_paid_this_lookalike']} "
            f"({b['victim_paid_this_lookalike_in_window']}) | "
            f"{b['victim_paid_other_lookalike_of_same_address']} | "
            f"{b['lookalike_paid_by_another_victim']} |"
        )
    lines += [
        "",
        "Complete-coverage rows contradicted by a payoff to the same lookalike in the window: "
        f"{len(x['contradicted_complete_rows'])}.",
        "",
    ]
    for f in x["findings"]:
        d = f["blocks_after_planting"]
        when = (
            "at an unknown block"
            if d is None
            else f"{abs(d):,} blocks {'after' if d > 0 else 'before'} the planting"
        )
        intended = "the same" if f["same_intended_address"] else "a different"
        lines.append(
            f"- Line {f['line']} ({_OUTCOME_SHORT.get(f['outcome'], f['outcome'])}): paid "
            f"{f['paid']}, {when}, about ${f['value_usd']:,}, meaning to pay {intended} "
            f"address; affix {f['paid_affix'][0]}+{f['paid_affix'][1]} (row lookalike "
            f"{f['row_affix'][0]}+{f['row_affix'][1]})."
        )
    lines += [
        "",
        "| Incident | In payoff period | Token in file | Harmful tx listed | Victim listed |",
        "|---|---|---|---|---|",
        *(
            f"| {i['case']} | {'yes' if i['in_period'] else 'no'} | "
            f"{'yes' if i['token_in_file'] else 'no'} | {'yes' if i['harm_tx_listed'] else 'no'}"
            f" | {'yes' if i['victim_listed'] else 'no'} |"
            for i in x["incidents"]
        ),
        "",
        "Absence from the payoff file is not evidence of no payment: it has no native-ETH "
        "payoffs, covers only lookalikes the study itself detected (at least 3 leading and "
        "4 trailing matching characters), and ends at the block above.",
        "",
    ]
    return lines


def render(report: dict[str, Any]) -> str:
    ph, ev, cand = report["poison_hunter"], report["events"], report["candidates"]
    lines = [
        "# ML Phase 11.2 tables",
        "",
        "Generated by `cryptoguard ml poisoning-report` from local artifacts (0 RPC requests).",
        f"Git `{report['git']}`; runtime {report['runtime_seconds']} s (per-window generation "
        "memory is in the JSON report).",
        "",
        "## Poison-Hunter sample",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Source SHA-256 | `{ph['source_sha256'][:16]}…` (matches the pinned hash) |",
        f"| Rows / valid / quarantined | {ph['rows']} / {ph['valid']} / {len(ph['quarantined'])} |",
        f"| Subtypes | {', '.join(f'{k} {v}' for k, v in ph['subtypes'].items())} |",
        f"| Distinct victims / lookalikes / planting txs | {ph['distinct_victims']} / "
        f"{ph['distinct_lookalikes']} / {ph['distinct_planting_txs']} |",
        f"| Planting txs with several rows (batches) | {ph['planting_txs_with_several_rows']} |",
        f"| Duplicate victim-events | {ph['duplicate_victim_events']} |",
        f"| Victims / lookalikes in several rows | {ph['victims_in_several_rows']} / "
        f"{ph['lookalikes_in_several_rows']} |",
        f"| Block range | {ph['block_range'][0]:,}-{ph['block_range'][1]:,} |",
        f"| Lookalike by CryptoGuard's detector predicate | {ph['cryptoguard_lookalike']} of "
        f"{ph['valid']} |",
        f"| Lookalike by Tsuchiya et al. (≥3 leading, ≥4 trailing) | {ph['tsuchiya_lookalike']} "
        f"of {ph['valid']} |",
        f"| Source field 16 equals prefix+suffix match | "
        f"{ph['source_similarity_equals_prefix_plus_suffix']} of {ph['valid']} |",
        "",
    ]
    for q in ph["quarantined"]:
        lines.append(f"Quarantined line {q['line']}: " + "; ".join(q["issues"]) + ".")
    lines += [
        "",
        "## Event dataset and gates",
        "",
        f"{ev['victim_events']} victim-events after dropping {ev['duplicates_dropped']} "
        f"duplicates; {ev['campaign_groups']} campaign groups (largest {ev['largest_group']} "
        f"events); labels: {ev['label_tiers']}; manifest `{ev['manifest']['sha256'][:16]}…`.",
        "",
        "| Gate | Passed | Detail |",
        "|---|---|---|",
        *(
            f"| {g['gate']} | {'yes' if g['passed'] else '**no**'} | {g['detail']} |"
            for g in report["gates"]
        ),
        "",
    ]
    if report["pilot"] is not None:
        lines += ["## Pilot reconstruction", "", render_markdown(report["pilot"])]
    if report.get("payoff_cross_check") is not None:
        lines += render_payoffs(report["payoff_cross_check"])
    lines += [
        "## Candidate generation (recorded replay fixtures)",
        "",
        "| Incident | Candidates | Harmful lookalike found | Candidate lead (blocks) | "
        "Detector lead (blocks) | First-hit rules |",
        "|---|---|---|---|---|---|",
    ]
    for i in cand["incidents"]:
        lines.append(
            f"| {i['case']} | {i['candidates']} | {'yes' if i['harmful_lookalike_found'] else 'no'}"
            f" | {i['candidate_lead_blocks']} | {i['detector_best_lead_blocks']} | "
            f"{', '.join(i['first_hit_methods'])} |"
        )
    lines += [
        "",
        f"Background wallets: {len(cand['background'])} recorded windows, "
        f"{sum(b['candidates'] for b in cand['background'])} candidates, "
        f"{cand['background_candidates_per_wallet_day']} per wallet-day (unlabelled). "
        + cand["caveat"],
        "",
    ]
    return "\n".join(lines)


def write(report: dict[str, Any], out_dir: Path, tables: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    text = render(report)
    tables.write_text(text, encoding="utf-8", newline="\n")
    report = {**report, "tables_sha256": hashlib.sha256(text.encode()).hexdigest()}
    path = out_dir / "poisoning-report.json"
    path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path

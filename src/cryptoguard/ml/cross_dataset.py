"""Cross-dataset validation: Poison-Hunter sample, Tsuchiya et al. attempt archive and
payoff list, with the recorded incidents kept as a separate case-study source.

Stages (all offline, 0 RPC requests):

1. ``build_target_manifest`` - deterministic list of addresses and transactions to keep.
2. ``run_scan`` - one verified pass over the archive (``tsuchiya_archive.scan``).
3. ``reconcile`` - match levels, attempt/victim/address outcomes, temporal categories,
   competing lookalikes and source overlap, from the stored subset.

Everything that leaves this module is aggregate or keyed by Poison-Hunter line number;
address-level tables stay in the git-ignored data directory (CC BY-NC-ND 4.0).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptoguard.ml.fetch import TSUCHIYA_FILES, verify_local
from cryptoguard.ml.poison_hunter import PoisonHunterRecord, parse_sample
from cryptoguard.ml.tsuchiya import PayoffTransfer, parse_payoffs
from cryptoguard.ml.tsuchiya_archive import (
    PARSER_VERSION,
    ArchiveError,
    build_targets,
    load_subset,
    load_targets,
    scan,
)

ARCHIVE = "address_poisoning_ethereum.sql.gz"
PAYOFFS = "payoff_transfers_ethereum.csv"


def git_state() -> dict[str, Any]:
    """HEAD commit and whether tracked files differ from it (a run on a dirty tree is
    reproducible only with that diff)."""
    import subprocess

    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(  # noqa: S603 - fixed git arguments
                ["git", *args],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError:
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    status = git("status", "--porcelain", "--untracked-files=no")
    return {"commit": git("rev-parse", "HEAD"), "dirty": None if status is None else bool(status)}


def incident_refs() -> list[dict[str, Any]]:
    from cryptoguard.replay.models import load_cases

    return [
        {
            "case": m.case_id,
            "victim": m.victim.lower(),
            "recipient": m.harm.recipient.lower(),
            "block": m.harm.block_number,
            "tx": m.harm.transaction_hash.lower(),
            "token": m.harm.token.lower(),
        }
        for m in (case.manifest for case in load_cases())
    ]


def build_target_manifest(
    ph: list[PoisonHunterRecord], payoffs: list[PayoffTransfer], incidents: list[dict[str, Any]]
) -> dict[str, Any]:
    """Addresses whose archive rows (as sender or receiver) and transactions to keep.

    Imitated/intended addresses are deliberately not targets: they can be exchange wallets
    with millions of rows, and every row a victim takes part in already carries them."""
    return build_targets(
        {
            "ph_victims": [r.victim for r in ph],
            "ph_lookalikes": [r.lookalike for r in ph],
            "ph_txs": [r.planting_tx for r in ph],
            "payoff_victims": [p.payer for p in payoffs],
            "payoff_lookalikes": [p.lookalike for p in payoffs],
            "payoff_txs": [p.tx_hash for p in payoffs],
            "incident_victims": [i["victim"] for i in incidents],
            "incident_recipients": [i["recipient"] for i in incidents],
            "incident_txs": [i["tx"] for i in incidents],
        }
    )


def run_scan(
    data_dir: Path, out_dir: Path, *, force: bool = False, progress: Any = None
) -> dict[str, Any]:
    """Verify the local archive, build the target manifest and scan once (cached when the
    archive, manifest and parser are unchanged). Raises if a source file is missing:
    nothing is downloaded here."""
    src = data_dir / "tsuchiya2025"
    archive = src / ARCHIVE
    if not archive.exists():
        raise FileNotFoundError(
            f"{archive} is missing. It is never fetched automatically; after approval run "
            f"`cryptoguard ml fetch-file {ARCHIVE}`."
        )
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    ph = parse_sample(data_dir / "poison-hunter" / "phishing_transfers_sample.csv").valid
    payoffs = parse_payoffs(src / PAYOFFS).valid
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "archive_targets.json"
    manifest = build_target_manifest(ph, payoffs, incident_refs())
    manifest_path.write_text(json.dumps(manifest, indent=0), encoding="utf-8")
    targets = load_targets(manifest_path)
    db = out_dir / "archive_subset.sqlite"
    if db.exists() and not force:
        try:
            _, summary = load_subset(db)
        except ArchiveError:
            summary = None
        if (
            summary is not None
            and summary.get("source_sha256") == source["sha256"]
            and summary.get("target_manifest_sha256") == targets.sha256
            and summary.get("parser_version") == PARSER_VERSION
        ):
            return {**summary, "cached": True}
    summary = scan(
        archive,
        targets,
        db,
        work_dir=out_dir / "spill",
        source_sha256=source["sha256"],
        progress=progress,
    )
    summary["source"] = {
        **source,
        "url": TSUCHIYA_FILES[ARCHIVE].url,
        "record": TSUCHIYA_FILES[ARCHIVE].source,
        "license": TSUCHIYA_FILES[ARCHIVE].license,
    }
    summary["target_groups"] = {k: len(v) for k, v in manifest["groups"].items()}
    summary["git"] = git_state()
    (out_dir / "archive-scan.json").write_text(
        json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8"
    )
    return {**summary, "cached": False}


# Reference counts printed by the publisher's guidance.ipynb (KiltHub v1).
PUBLISHED = {
    "rows": 34_905_969,
    "poisoning_transfers": 17_365_954,
    "poisoning_txs": 1_691_529,
    "tiny_transfer": 308_881,
    "zero_value_transfer": 7_185_298,
    "counterfeit_token_transfer": 9_871_775,
    "counterfeit_token_contracts": 6_280,
    "victims": 1_330_948,
    "lookalikes": 6_492_215,
    "is_not_categorized": 8_651,
}


def reproduced_counts(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Our scan's counts next to the publisher's, row by row."""
    d, c = summary["distinct"], summary["categories"]
    ours = {
        "rows": summary["reader"]["valid_rows"],
        "poisoning_transfers": summary["poisoning_transfers"],
        "poisoning_txs": d["poisoning_txs"],
        "tiny_transfer": c["tiny_transfer"],
        "zero_value_transfer": c["zero_value_transfer"],
        "counterfeit_token_transfer": c["counterfeit_token_transfer"],
        "counterfeit_token_contracts": d["counterfeit_token_contracts"],
        "victims": d["victims"],
        "lookalikes": d["lookalikes"],
        "is_not_categorized": c["is_not_categorized"],
    }
    return [
        {"quantity": k, "published": v, "reproduced": ours[k], "match": ours[k] == v}
        for k, v in PUBLISHED.items()
    ]


def decision_gates(summary: dict[str, Any], rec: dict[str, Any]) -> list[dict[str, str]]:
    """Stage Z gates, evaluated from the evidence actually available."""
    repro = reproduced_counts(summary)
    integrity = summary["reader"]["malformed_rows"] == 0 and all(r["match"] for r in repro)
    linked = rec["payoffs"]["linkage"].get("attempt_before_payoff", 0)

    def gate(name: str, status: str, detail: str) -> dict[str, str]:
        return {"gate": name, "status": status, "detail": detail}

    return [
        gate(
            "1 Data integrity",
            "pass" if integrity else "fail",
            "pinned size/MD5/SHA-256; 0 malformed rows; publisher counts reproduced"
            if integrity
            else "see the reproduced-count table and malformed-row reasons",
        ),
        gate(
            "2 Event identity",
            "partial",
            "transactions, attempts (victim, lookalike, tx) and Poison-Hunter victim-events are "
            f"distinct; the archive has no log index ({summary['repeated_transfer_keys']:,} "
            "repeated transfer keys) and no campaign identifier",
        ),
        gate(
            "3 Label validity",
            "fail",
            "archive categories are the source's heuristic labels (lookalike rule, "
            "thresholds), not independent review of attempts; payoffs are confirmed "
            "outcomes, not attempt labels",
        ),
        gate(
            "4 Temporal integrity",
            "partial",
            "block-level ordering only (no transaction index or timestamps in the archive): "
            "same-block pairs are 'order unknown'; fixture-based features keep exact cutoffs",
        ),
        gate(
            "5 Independent evaluation",
            "fail",
            "no verified negatives in any source; not listed or not paid does not mean benign",
        ),
        gate(
            "6 Leakage control",
            "partial",
            "campaign grouping and grouped temporal splits exist, but there are no trainable "
            "labels to split",
        ),
        gate(
            "7 Baseline comparability",
            "fail",
            "the archive holds only poisoning-related transfers, not the wallet histories the "
            "deterministic detector needs, so both cannot run on the same observations",
        ),
        gate(
            "8 Operational usefulness",
            "fail",
            "alert volume on ordinary wallets is known only from 27 recorded wallet-days; "
            f"{linked:,} payoff-linked attempts are retrospective, not prospective",
        ),
    ]


def build_report(data_dir: Path, out_dir: Path) -> dict[str, Any]:
    """Reconcile the stored subset with Poison-Hunter, payoffs and incidents (offline)."""
    import time

    from cryptoguard.ml.events import campaign_groups, deduplicate
    from cryptoguard.ml.poisoning_report import poison_hunter_events
    from cryptoguard.ml.reconcile import reconcile
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    t0 = time.perf_counter()
    rows, summary = load_subset(out_dir / "archive_subset.sqlite")
    ph = parse_sample(data_dir / "poison-hunter" / "phishing_transfers_sample.csv").valid
    payoffs = parse_payoffs(data_dir / "tsuchiya2025" / PAYOFFS).valid
    events, _ = deduplicate(poison_hunter_events(ph))
    groups_by_event = campaign_groups(events)
    groups = {e.lookalike: groups_by_event[e.victim_event_id] for e in events}
    rec = reconcile(rows, summary, ph, payoffs, incident_refs(), groups)
    from cryptoguard.ml.reconcile import ArchiveIndex, payoff_review_packets
    from cryptoguard.ml.review import export_packets

    packets = payoff_review_packets(payoffs, ArchiveIndex(rows))
    rec["review_packets"] = {
        "payoff_linked_attempts": export_packets(
            packets, out_dir / "review_packets_payoff_linked.jsonl"
        ),
        "with_competing_lookalikes": sum(1 for p in packets if p.competing_lookalikes),
        "note": "local review queue (addresses; git-ignored); no label is assigned",
    }
    scan_meta = json.loads((out_dir / "archive-scan.json").read_text(encoding="utf-8"))
    if scan_meta.get("target_manifest_sha256") != summary["target_manifest_sha256"]:
        raise ArchiveError("archive-scan.json does not describe the stored subset; rescan")
    extra = ("source", "target_groups", "output_bytes", "git")
    return {
        "scan": {**summary, **{k: scan_meta[k] for k in extra if k in scan_meta}},
        "reproduced": reproduced_counts(summary),
        "reconcile": rec,
        "gates": decision_gates(summary, rec),
        "git": git_state(),
        "reconcile_runtime_seconds": round(time.perf_counter() - t0, 1),
        "reconcile_peak_rss_bytes": peak_rss_bytes(),
        "rpc_requests": 0,
    }


def _pct(n: int, d: int) -> str:
    return f"{n:,} / {d:,} ({n / d:.1%})" if d else f"{n:,} / 0"


def _kv(d: dict[str, Any]) -> str:
    return ", ".join(f"{k} {v:,}" for k, v in d.items()) or "none"


def _q(q: dict[str, Any] | None) -> str:
    if not q:
        return "n/a"
    return (
        f"n {q['n']:,}; min {q['min']:,}, p25 {q['p25']:,.0f}, median {q['median']:,.0f}, "
        f"p75 {q['p75']:,.0f}, max {q['max']:,}"
    )


def _below_3_4(key: str) -> bool:
    try:
        a, b = (int(x) for x in key.split("+"))
    except ValueError:
        return True  # missing digit counts
    return a < 3 or b < 4


def _yes(flag: bool) -> str:
    return "yes" if flag else "no"


def render(report: dict[str, Any]) -> str:
    """Aggregate-only Markdown tables (no addresses or hashes from the sources)."""
    s, rec = report["scan"], report["reconcile"]
    src = s.get("source") or {}
    rd = s["reader"]
    blocks, pblocks = s["block_range"], s["poisoning_block_range"]
    preamble = ", ".join(f"{k} {v}" for k, v in rd["preamble_statements"].items())
    lines = [
        "# Cross-dataset validation tables (Phase 11.3)",
        "",
        "Generated by `cryptoguard ml cross-dataset-report` from local, git-ignored files "
        f"(0 RPC requests) at git `{(report.get('git') or {}).get('commit') or '?'}`"
        f"{' with uncommitted changes' if (report.get('git') or {}).get('dirty') else ''}. "
        "Narrative and limitations: "
        "[ML_CROSS_DATASET_VALIDATION.md](ML_CROSS_DATASET_VALIDATION.md).",
        "",
        "## Source and scan",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Archive | `address_poisoning_ethereum.sql.gz`, {src.get('size', 0):,} bytes, "
        f"KiltHub {src.get('record', '?')} ({src.get('license', '?')}) |",
        f"| Integrity | size and MD5 match the published values; SHA-256 "
        f"`{str(src.get('sha256', '?'))[:16]}…` pinned |",
        f"| Format | PostgreSQL plain dump, one table, one COPY block; parser "
        f"`{s['parser_version']}` |",
        f"| Decompressed bytes read | {rd['decompressed_bytes']:,} |",
        f"| Data rows / valid / malformed | {rd['data_rows']:,} / {rd['valid_rows']:,} / "
        f"{rd['malformed_rows']:,} |",
        f"| Preamble statements (recognised and skipped, never executed) | {preamble} |",
        f"| Block range: all rows / poisoning rows | {blocks[0]:,}-{blocks[1]:,} / "
        f"{pblocks[0]:,}-{pblocks[1]:,} |",
        f"| Missing amount / USD value (NaN) | {s['nan_value']:,} / {s['nan_value_usd']:,} |",
        f"| Repeated (tx, token, from, to, value) keys | {s['repeated_transfer_keys']:,} "
        "(no log index, so repeats cannot be told from duplicates) |",
        f"| Poisoning rows whose declared digit counts differ from the addresses | "
        f"{s['declared_digits_disagree']:,} |",
        f"| Rows stored for the target manifest | {s['stored_target_rows']:,} "
        f"({s.get('output_bytes', 0):,} bytes) |",
        f"| Scan runtime / peak RSS / peak spill | {s['runtime_seconds']:,} s / "
        f"{(s['peak_rss_bytes'] or 0) / 2**20:,.0f} MiB / "
        f"{s['peak_spill_bytes'] / 2**20:,.0f} MiB |",
        "",
        "## Publisher counts reproduced",
        "",
        "| Quantity | Published (guidance.ipynb) | Reproduced | Match |",
        "|---|---|---|---|",
        *(
            f"| {r['quantity']} | {r['published']:,} | {r['reproduced']:,} | "
            f"{'yes' if r['match'] else '**no**'} |"
            for r in report["reproduced"]
        ),
        "",
        "## Poisoning rows by subtype and direction",
        "",
        "| Subtype | Rows | Victim receives | Victim sends (spoofed sender) |",
        "|---|---|---|---|",
    ]
    for name, n in sorted(s["poisoning_by_subtype"].items()):
        recv = s["poisoning_direction"].get(f"{name}/victim_receives", 0)
        send = s["poisoning_direction"].get(f"{name}/victim_sends", 0)
        lines.append(f"| {name} | {n:,} | {recv:,} | {send:,} |")
    lows = {k: v for k, v in s["poisoning_digit_pairs"].items() if _below_3_4(k)}
    low_detail = f" ({_kv(dict(sorted(lows.items())))})" if lows else ""
    lines += [
        "",
        f"Poisoning rows whose declared digits are below 3 leading + 4 trailing: "
        f"{sum(lows.values()):,} of {s['poisoning_transfers']:,}{low_detail}.",
        "",
        "## CryptoGuard candidate rules on source-labelled poisoning rows",
        "",
        "Denominator: the source's poisoning rows of each subtype (rows can carry several "
        "subtypes). Single-transfer rules only. `lookalike_in` assumes the intended address "
        "was an earlier counterparty, which the source's own selection presumes, so it "
        "measures agreement with the source's rule, not detection. `spoofed_out` needs the "
        "transaction signer, which the archive lacks.",
        "",
        "| Subtype | Rows | zero_value_in | dust_in | lookalike_in | untrusted_token_in | "
        "Any rule | Detector predicate |",
        "|---|---|---|---|---|---|---|---|",
    ]
    cov = s["rule_coverage"]
    for name, n in sorted(s["poisoning_by_subtype"].items()):
        cells = " | ".join(
            _pct(cov.get(f"{name}/{m}", 0), n)
            for m in ("zero_value_in", "dust_in", "lookalike_in", "untrusted_token_in")
        )
        lines.append(
            f"| {name} | {n:,} | {cells} | {_pct(s['any_candidate_rule'].get(name, 0), n)} | "
            f"{_pct(cov.get(f'{name}/detector_predicate', 0), n)} |"
        )
    ph = rec["poison_hunter"]
    lines += [
        "",
        "## Poison-Hunter rows against the archive",
        "",
        f"Unit: {ph['unit']}. Each row gets its strongest level.",
        "",
        "| Match level | Rows | Distinct victims | Distinct lookalikes | Distinct planting txs |",
        "|---|---|---|---|---|",
        *(
            f"| {lv} | {n} | {ph['distinct_victims'][lv]} | {ph['distinct_lookalikes'][lv]} | "
            f"{ph['distinct_planting_txs'][lv]} |"
            for lv, n in ph["levels"].items()
        ),
        "",
        f"Subtype agreement on exact matches: {_kv(ph['subtype_agreement_on_exact'])}. "
        f"Rows without an exact match: {_kv(ph['not_exact_reasons'])}. Transaction-only "
        f"matches (batched plantings): {_kv(ph['tx_only_detail'])}.",
        "",
    ]
    po = rec["payoffs"]
    cmp = po["similarity_recency_comparison"]
    linked = po["linked_distinct"]
    lines += [
        "## Payoffs linked to earlier attempts",
        "",
        f"Unit: {po['unit']}; {po['payoffs']:,} payoffs.",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Archive status of the payoff row | {_kv(po['archive_status'])} |",
        f"| Linkage | {_kv(po['linkage'])} |",
        f"| Linked: distinct victims / lookalikes / payoff txs | {linked['victims']:,} / "
        f"{linked['lookalikes']:,} / {linked['payoff_txs']:,} |",
        f"| Blocks from the last pair attempt to the payoff | "
        f"{_q(po['blocks_from_last_attempt_to_payoff'])} |",
        f"| Pair attempts before the payoff | {_q(po['attempts_by_pair_before_payoff'])} |",
        f"| Rival lookalikes that reached the victim before the payoff | "
        f"{_q(po['rival_lookalikes_before_payoff'])} |",
        f"| Payoffs with a rival imitating the same intended address | "
        f"{_pct(po['payoffs_with_rival_of_same_intended'], po['payoffs'])} |",
        f"| Of those (linked): paid lookalike was the most similar | "
        f"{cmp['paid_lookalike_most_similar']:,} of {cmp['payoffs_compared']:,} "
        f"(uniform expectation {cmp['expected_if_uniform']:,}) |",
        f"| Of those (linked): paid lookalike was the most recent | "
        f"{cmp['paid_lookalike_most_recent']:,} of {cmp['payoffs_compared']:,} "
        f"(uniform expectation {cmp['expected_if_uniform_recent']:,}) |",
        "",
        f"Both comparisons cover {cmp['payoffs_compared']:,} payoffs from "
        f"{cmp['distinct_victims_compared']:,} victims. They are observational: payoffs of one "
        "victim are not independent, the uniform expectation counts ties, and neither "
        "similarity nor recency is shown to cause a payment.",
        "",
    ]
    rq = rec.get("review_packets")
    if rq:
        lines += [
            f"Review queue: {rq['payoff_linked_attempts']:,} payoff-linked attempt events "
            f"({rq['with_competing_lookalikes']:,} with competing lookalikes) exported for "
            "independent review; no label is assigned and the packets stay local.",
            "",
        ]
    oc = rec["outcomes"]
    lines += [
        "## Outcome levels for the Poison-Hunter rows",
        "",
        f"Unit: {oc['unit']} ({oc['rows']} rows). Note: {oc['note']}.",
        "",
        "| Outcome | Rows |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in oc["outcomes"].items()),
        "",
        f"Payment pairs by temporal category: {_kv(oc['payment_pairs_by_temporal_category'])}.",
        "",
        "## Recorded incidents (case studies, not evaluation data)",
        "",
        "| Incident | Harm in archive period | Victim attempts | Harm-recipient attempts | "
        "Pair attempts before harm | Harm tx in archive |",
        "|---|---|---|---|---|---|",
        *(
            f"| {i['case']} | {_yes(i['harm_in_archive_period'])} | "
            f"{i['victim_attempts_in_archive']} | {i['harm_recipient_attempts_in_archive']} | "
            f"{i['pair_attempts_before_harm']} | {_yes(i['harm_tx_in_archive'])} |"
            for i in rec["incidents"]
        ),
        "",
        "## Decision gates",
        "",
        "| Gate | Status | Evidence |",
        "|---|---|---|",
        *(f"| {g['gate']} | {g['status']} | {g['detail']} |" for g in report["gates"]),
        "",
        f"Reconciliation runtime {report['reconcile_runtime_seconds']} s, peak RSS "
        f"{(report['reconcile_peak_rss_bytes'] or 0) / 2**20:,.0f} MiB.",
        "",
    ]
    return "\n".join(lines)


def write_report(report: dict[str, Any], out_dir: Path, tables: Path) -> Path:
    import hashlib

    text = render(report)
    tables.write_text(text, encoding="utf-8", newline="\n")
    body = {**report, "tables_sha256": hashlib.sha256(text.encode()).hexdigest()}
    path = out_dir / "cross-dataset.json"
    path.write_text(json.dumps(body, indent=1, sort_keys=True, default=str), encoding="utf-8")
    return path

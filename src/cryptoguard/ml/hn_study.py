"""Phase 11.5 hard-negative study: one reproducible offline run (``cryptoguard ml
hard-negative-study``), 0 RPC requests.

The run:
1. builds the candidate pool from the recorded wallet windows and the archive's
   uncategorized rows;
2. screens every candidate against all local known-positive records;
3. matches the archive candidates to the payoff-linked source positives (excluding the
   60 reserved review items) and reports balance;
4. measures how easily the two frames are told apart (source separability, not fraud
   detection);
5. freezes the review cohort, once;
6. writes aggregate JSON and a Markdown table file.

Nothing it writes assigns a label.
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptoguard.ml import hard_negatives as hn
from cryptoguard.ml.annotation import atomic_write
from cryptoguard.ml.matching import Unit, cem
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.ml.tsuchiya_archive import POISONING, peak_rss_bytes

STUDY_VERSION = "hn-study/1"


def positive_units(poisoning_dir: Path) -> list[dict[str, Any]]:
    """Covariates of the payoff-linked source positives, from the archive row of each
    packet's planting. The 60 items reserved for the human-review study are excluded."""
    import hashlib

    from cryptoguard.ml.review_sample import read_sheet

    packets = [
        json.loads(line)
        for line in (poisoning_dir / "review_packets_payoff_linked.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    reserved = {
        r["victim_event_id"]
        for r in read_sheet(poisoning_dir / "review_sample" / "reviewer_sheet.jsonl")
    }
    con = sqlite3.connect(f"file:{poisoning_dir / 'archive_subset.sqlite'}?mode=ro", uri=True)
    out = []
    for p in packets:
        if p["victim_event_id"] in reserved:
            continue
        row = con.execute(
            "select block, token, sender_is_victim, value_usd, first_digits, last_digits "
            "from transfers where tx = ? and (sender = ? or receiver = ?) and flags & ? limit 1",
            (p["planting_tx"], p["lookalike"], p["lookalike"], POISONING),
        ).fetchone()
        if row is None:
            continue
        block, token, sv, usd, fd, ld = row
        out.append(
            {
                "id": "p:" + hashlib.sha256(p["victim_event_id"].encode()).hexdigest()[:16],
                "block": block,
                "token": token,
                "victim_sends": bool(sv),
                "value_usd": usd,
                "similarity": (fd, ld) if fd is not None and ld is not None else None,
                "subtype": p["subtype"],
            }
        )
    con.close()
    return out


def _unit(
    uid: str,
    *,
    block: int,
    trusted: bool,
    victim_sends: bool,
    usd: float | None,
    sim: tuple[int, int] | None,
) -> Unit:
    from cryptoguard.ml.review_sample import year

    nan = usd is not None and math.isnan(usd)
    usd = None if nan else usd
    return Unit(
        uid,
        {
            "year": year(block),
            "victim_sends": victim_sends,
            "token_trusted": trusted,
            "value_bin": hn.value_bin(usd),
            "similarity_bin": hn.similarity_bin(sim),
        },
        {
            "log10_value_usd": None if usd is None else math.log10(usd + 1e-6),
            "similarity_total": None if sim is None else float(sum(sim)),
            "token_trusted": float(trusted),
            "victim_sends": float(victim_sends),
            "block_millions": block / 1e6,
        },
    )


def univariate_auc(pos: Sequence[float], neg: Sequence[float]) -> float | None:
    """How well one covariate alone separates the frames (0.5 = not at all)."""
    if not pos or not neg:
        return None
    ranked = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(1 for k in range(i, j) if ranked[k][1] == 1)
        i = j
    auc = (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))
    return max(auc, 1 - auc)  # separability, direction-free


def separability(pos: Sequence[Unit], neg: Sequence[Unit]) -> dict[str, Any]:
    names = sorted({k for u in (*pos, *neg) for k in u.numeric})
    uni = {}
    for k in names:
        a = [v for u in pos if (v := u.numeric.get(k)) is not None]
        b = [v for u in neg if (v := u.numeric.get(k)) is not None]
        miss_a, miss_b = len(pos) - len(a), len(neg) - len(b)
        uni[k] = {
            "auc_separability": univariate_auc(a, b),
            "missing_share_source_positive": round(miss_a / len(pos), 3) if pos else None,
            "missing_share_candidate": round(miss_b / len(neg), 3) if neg else None,
        }
    out: dict[str, Any] = {
        "task": "predict which frame a row came from (NOT fraud detection)",
        "univariate": uni,
    }
    try:  # optional: the ml extra
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedKFold, cross_val_score
    except ImportError:
        out["multivariate"] = "scikit-learn not installed (ml extra): skipped"
        return out
    families = {
        "value_only": ["log10_value_usd"],
        "similarity_only": ["similarity_total"],
        "token_only": ["token_trusted"],
        "direction_only": ["victim_sends"],
        "time_only": ["block_millions"],
        "all_without_value": [
            "similarity_total",
            "token_trusted",
            "victim_sends",
            "block_millions",
        ],
    }
    multi = {}
    rows = [*pos, *neg]
    y = np.array([1] * len(pos) + [0] * len(neg))
    for fam, cols in families.items():
        x = np.array(
            [
                [u.numeric.get(c) if u.numeric.get(c) is not None else -99.0 for c in cols]
                for u in rows
            ],
            dtype=float,
        )
        miss = np.array([[float(u.numeric.get(c) is None) for c in cols] for u in rows])
        x = np.hstack([x, miss])
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
        scores = cross_val_score(LogisticRegression(max_iter=1000), x, y, cv=cv, scoring="roc_auc")
        multi[fam] = {
            "cv_roc_auc_mean": round(float(scores.mean()), 4),
            "cv_roc_auc_sd": round(float(scores.std()), 4),
        }
    out["multivariate"] = multi
    out["multivariate_note"] = (
        "5-fold stratified CV, logistic regression with missingness indicators; rows are not "
        "grouped by campaign, so these AUCs are optimistic; diagnostic only"
    )
    return out


def run(
    data_dir: Path,
    poisoning_dir: Path,
    out_dir: Path,
    tables: Path | None,
    *,
    freeze_cohort: bool = True,
) -> dict[str, Any]:
    from cryptoguard.ml import cohort as ch
    from cryptoguard.ml.contamination import summary
    from cryptoguard.ml.cross_dataset import git_state
    from cryptoguard.ml.hard_negative_archive import load_rows

    t0 = time.perf_counter()
    timings: dict[str, float] = {}
    hn_dir = poisoning_dir / "hard_negative"
    rows = load_rows(hn_dir)
    extract = json.loads((hn_dir / "extract_summary.json").read_text(encoding="utf-8"))
    t = time.perf_counter()
    fixture = hn.fixture_candidates()
    timings["fixture_candidates_s"] = round(time.perf_counter() - t, 2)
    t = time.perf_counter()
    archive = hn.archive_candidates(rows)
    timings["archive_candidates_s"] = round(time.perf_counter() - t, 2)
    t = time.perf_counter()
    index, known_counts = hn.known_index(data_dir, poisoning_dir)
    timings["known_index_s"] = round(time.perf_counter() - t, 2)
    t = time.perf_counter()
    pool = hn.screen_all([*fixture, *archive], index)
    timings["screen_s"] = round(time.perf_counter() - t, 2)
    screened = [c.screened for c in pool if c.screened]

    # Matching: archive candidates (screened, not known positive) vs source positives.
    t = time.perf_counter()
    positives = positive_units(poisoning_dir)
    pos_units = [
        _unit(
            p["id"],
            block=p["block"],
            trusted=p["token"] in TRUSTED_TOKENS,
            victim_sends=p["victim_sends"],
            usd=p["value_usd"],
            sim=p["similarity"],
        )
        for p in positives
    ]
    eligible_arc = [
        c
        for c in pool
        if c.frame == "archive_uncategorized"
        and c.screened
        and c.screened.status != "known_positive_overlap"
    ]
    cand_units = [
        _unit(
            "c:" + c.event.victim_event_id,
            block=c.event.planting_block,
            trusted=c.token_trusted,
            victim_sends=False,
            usd=c.value_usd,
            sim=c.similarity,
        )
        for c in eligible_arc
    ]
    strict_keys = ["year", "victim_sends", "token_trusted", "value_bin", "similarity_bin"]
    strict = cem(pos_units, cand_units, keys=strict_keys)
    relaxed = cem(pos_units, cand_units, keys=["year", "similarity_bin"])
    timings["matching_s"] = round(time.perf_counter() - t, 2)
    sep = separability(pos_units, cand_units)

    items, excluded = hn.cohort_items(pool)
    design = hn.cohort_design(items)
    cohort_dir = poisoning_dir / "hard_negative" / "cohort_v1"
    if freeze_cohort:
        manifest, written = ch.freeze(items, design, cohort_dir)
    else:
        manifest, written = ch.draw(items, design)["manifest"], False

    def drop_pairs(m: dict[str, Any]) -> dict[str, Any]:
        return {
            k: v
            for k, v in m.items()
            if k not in ("pairs", "unmatched_positives", "unmatched_candidates")
        } | {
            "unmatched_positive_count": len(m["unmatched_positives"]),
            "unmatched_candidate_count": len(m["unmatched_candidates"]),
        }

    bg = [c for c in pool if c.frame.startswith("fixture_background")]
    from cryptoguard.replay.background import load_background

    windows = [b.fixture for b in load_background() if b.fixture]
    wallet_days = sum(f.to_block - f.from_block for f in windows) / 7_200
    report = {
        "study_version": STUDY_VERSION,
        "git": git_state(),
        "inputs": {
            "archive_extract": {
                k: extract[k]
                for k in (
                    "version",
                    "source_sha256",
                    "rows_scanned",
                    "uncategorized_rows",
                    "rows_sha256",
                )
            },
            "known_positive_records": known_counts,
            "screen_coverage": [c.__dict__ for c in index.coverage],
        },
        "pool": hn.pool_summary(pool),
        "contamination": summary(screened),
        "contamination_by_frame": {
            f: summary([c.screened for c in pool if c.frame.split(":")[0] == f and c.screened])
            for f in sorted({c.frame.split(":")[0] for c in pool})
        },
        "operational_background": {
            "recorded_windows": len(windows),
            "windows_with_candidates": len({c.frame for c in bg}),
            "wallet_days": round(wallet_days, 1),
            "candidates": len(bg),
            "per_1000_wallet_days": round(1000 * len(bg) / wallet_days, 1) if wallet_days else None,
            "note": "unlabeled candidate volume on randomly drawn recorded wallets; not false "
            "alerts and not an Ethereum-wide rate",
        },
        "matching": {
            "positives_frame": "payoff-linked source positives minus the 60 reserved review items",
            "positives": len(pos_units),
            "candidates": len(cand_units),
            "strict": drop_pairs(strict),
            "relaxed_year_similarity": drop_pairs(relaxed),
        },
        "separability": sep,
        "cohort": {
            "version": manifest["sample_version"],
            "frame_sha256": manifest["queue_sha256"],
            "selection_sha256": manifest["selection_sha256"],
            "frame_items": manifest["queue_packets"],
            "excluded_known_positive": excluded,
            "groups": manifest["groups"],
            "strata_table": manifest["strata_table"],
            "selected": len(manifest["selected"]),
            "files": manifest.get("files"),
            "newly_frozen": written,
        },
        "timings": timings | {"total_s": round(time.perf_counter() - t0, 1)},
        "peak_rss_bytes": peak_rss_bytes(),
        "rpc_requests": 0,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(out_dir / "hn-study.json", hn.dump(report).encode() + b"\n")
    if tables is not None:
        tables.write_text(render(report), encoding="utf-8", newline="\n")
    return report


def _fmt(v: Any) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def render(r: dict[str, Any]) -> str:
    """Aggregate-only tables (no address, transaction or event id)."""
    lines = [
        "# Hard-negative study tables (generated)",
        "",
        f"Generated by `cryptoguard ml hard-negative-study` ({r['study_version']}) at commit "
        f"`{(r['git'].get('commit') or '')[:7]}`"
        f"{' (dirty tree)' if r['git'].get('dirty') else ''}. "
        "0 RPC requests. Every candidate is `unlabeled_candidate`.",
        "",
        "## Candidate pool",
        "",
        "| Frame | Candidates | Wallets | Block range | Trusted token |",
        "|---|---|---|---|---|",
    ]
    for f, v in r["pool"]["frames"].items():
        lines.append(
            f"| {f} | {v['candidates']:,} | {v['wallets']:,} | {v['blocks'][0]:,}-"
            f"{v['blocks'][1]:,} | {v['token_trusted']:,} |"
        )
    lines += [
        "",
        "### Structural categories (multi-label; not intent)",
        "",
        "| Frame | " + " | ".join("ABCDEFGH") + " |",
        "|---|" + "---|" * 8,
    ]
    for f, v in r["pool"]["frames"].items():
        cats = v["categories"]
        row = [str(sum(n for k, n in cats.items() if k.startswith(x + "_"))) for x in "ABCDEFGH"]
        lines.append(f"| {f} | " + " | ".join(row) + " |")
    lines += [
        "",
        "## Contamination screen",
        "",
        "| Frame | "
        + " | ".join(
            (
                "exact_event",
                "exact_tx",
                "victim_lookalike",
                "shared_infrastructure",
                "related_campaign",
                "weak_similarity",
                "none",
            )
        )
        + " |",
        "|---|" + "---|" * 7,
    ]
    for f, s in r["contamination_by_frame"].items():
        lv = s["by_level"]
        lines.append(
            f"| {f} | "
            + " | ".join(
                str(lv.get(k, 0))
                for k in (
                    "exact_event",
                    "exact_tx",
                    "victim_lookalike",
                    "shared_infrastructure",
                    "related_campaign",
                    "weak_similarity",
                    "none",
                )
            )
            + " |"
        )
    lines += [
        "",
        "| Frame | known_positive_overlap | potential_positive_overlap | "
        "no_known_overlap | insufficient_information |",
        "|---|---|---|---|---|",
    ]
    for f, s in r["contamination_by_frame"].items():
        st = s["by_status"]
        lines.append(
            f"| {f} | "
            + " | ".join(
                str(st.get(k, 0))
                for k in (
                    "known_positive_overlap",
                    "potential_positive_overlap",
                    "no_known_overlap",
                    "insufficient_information",
                )
            )
            + " |"
        )
    m = r["matching"]
    lines += [
        "",
        "## Matching (archive candidates vs source positives)",
        "",
        f"Positives: {m['positives']:,} ({m['positives_frame']}); candidates: {m['candidates']:,}.",
        "",
        "| Design | Keys | Matched positives | Matched candidates | Candidates without support |",
        "|---|---|---|---|---|",
    ]
    for name in ("strict", "relaxed_year_similarity"):
        d = m[name]
        lines.append(
            f"| {name} | {', '.join(d['keys'])} | {d['matched_positives']:,} | "
            f"{d['matched_candidates']:,} | {d['candidates_without_support']:,} |"
        )
    lines += [
        "",
        "Standardized mean differences (before matching):",
        "",
        "| Covariate | SMD | Missing (positives) | Missing (candidates) |",
        "|---|---|---|---|",
    ]
    for k, v in m["strict"]["balance_before"].items():
        if isinstance(v, dict):
            lines.append(
                f"| {k} | {_fmt(v['smd'])} | {v['missing_positive']} | {v['missing_candidate']} |"
            )
    s = r["separability"]
    lines += [
        "",
        "## Source separability (which frame a row came from; NOT fraud detection)",
        "",
        "| Covariate | Univariate separability AUC |",
        "|---|---|",
    ]
    for k, v in s["univariate"].items():
        lines.append(f"| {k} | {_fmt(v['auc_separability'])} |")
    if isinstance(s.get("multivariate"), dict):
        lines += ["", "| Feature family | CV ROC-AUC (mean ± sd) |", "|---|---|"]
        for k, v in s["multivariate"].items():
            lines.append(f"| {k} | {v['cv_roc_auc_mean']:.3f} ± {v['cv_roc_auc_sd']:.3f} |")
        lines += ["", s["multivariate_note"] + "."]
    c = r["cohort"]
    lines += [
        "",
        "## Review cohort",
        "",
        f"`{c['version']}`: {c['selected']} of {c['frame_items']:,} eligible items "
        f"({c['groups']['count']:,} groups). Frame SHA-256 `{c['frame_sha256']}`, "
        f"selection SHA-256 `{c['selection_sha256']}`.",
        "",
        "| Stratum | Items | Groups | Selected | Weight |",
        "|---|---|---|---|---|",
    ]
    for row in c["strata_table"]:
        frame, period, flag = row["stratum"].split("|")
        name, wallet = (
            (frame.split(":")[0], " (one recorded wallet)") if ":" in frame else (frame, "")
        )
        lines.append(
            f"| {name}{wallet}, {period}, potential overlap {flag} | {row['packets']:,} | "
            f"{row['groups']:,} | {row['selected']} | {_fmt(row['weight'])} |"
        )
    o = r["operational_background"]
    lines += [
        "",
        "## Background candidate volume (unlabeled)",
        "",
        f"{o['candidates']} candidates on {o['recorded_windows']} recorded random wallets "
        f"({o['wallet_days']} wallet-days; {o['windows_with_candidates']} wallets with any): "
        f"{o['per_1000_wallet_days']} per 1,000 wallet-days. {o['note']}.",
    ]
    t = r["timings"]
    lines += [
        "",
        f"Runtime {t['total_s']} s; peak RSS {(r['peak_rss_bytes'] or 0) / 2**20:.0f} MiB.",
        "",
    ]
    return "\n".join(lines)


def counts(items: Sequence[Any]) -> dict[str, int]:
    return dict(Counter(items))

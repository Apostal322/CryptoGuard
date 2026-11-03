"""Recency on the source's *unconfirmed* payoffs (``recency-unconfirmed/1``), as
pre-registered in docs/ml/protocol-12.2-unconfirmed.md. Two offline archive passes, then an
aggregate-only analysis; 0 RPC requests.

The source confirmed a payoff only after checking that a poisoning transfer lies between the
intended transfer and the payoff. Its unconfirmed payoffs never went through that check, so
the population tests whether the confirmation step produced the Phase 12.1 recency effect.
Its labels are uncertain by the source's own account, and it shares the source's collection:
this is not independent validation.
"""

from __future__ import annotations

import hashlib
import json
import random
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any

from cryptoguard.ml import lookalike_ranking as lr

STUDY_VERSION = "recency-unconfirmed/1"
PROTOCOL = "protocol-12.2-unconfirmed/1"
SEED = 20261104
DELTA_R = 0.3817  # Phase 12.2 T0 - B0 on all R episodes (protocol section 5)
HALF = 0.19
OUT_DIR = "unconfirmed"
ROWS = "rows.jsonl"
SUMMARY = "extract_summary.json"
TARGETS = "victim_targets.json"
SUBSET = "victim_subset.sqlite"
MAX_ROWS = 100_000  # the publisher's notebook implies 13,683


# --- the two archive passes --------------------------------------------------------------


def extract(data_dir: Path, poisoning_dir: Path) -> dict[str, Any]:
    """Pass 1: every archive row flagged ``payoff_transfer_unconfirmed``."""
    from cryptoguard.ml.annotation import atomic_write
    from cryptoguard.ml.fetch import TSUCHIYA_FILES, verify_local
    from cryptoguard.ml.hard_negative_archive import ARCHIVE, row_dict
    from cryptoguard.ml.tsuchiya_archive import (
        PARSER_VERSION,
        PAYOFF_UNCONFIRMED,
        ArchiveReader,
        peak_rss_bytes,
    )

    archive = data_dir / "tsuchiya2025" / ARCHIVE
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    t0 = time.perf_counter()
    reader = ArchiveReader(archive)
    rows: list[dict[str, Any]] = []
    flags: Counter[int] = Counter()
    for t in reader:
        if t.flags & PAYOFF_UNCONFIRMED:
            flags[t.flags] += 1
            rows.append(row_dict(t))
            if len(rows) > MAX_ROWS:
                raise RuntimeError(f"more than {MAX_ROWS} unconfirmed rows: parser fault?")
    out = poisoning_dir / OUT_DIR
    out.mkdir(parents=True, exist_ok=True)
    data = b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in rows)
    atomic_write(out / ROWS, data)
    summary = {
        "parser_version": PARSER_VERSION,
        "source_sha256": source["sha256"],
        "rows_scanned": reader.stats.valid_rows,
        "unconfirmed_rows": len(rows),
        "flag_combinations": {str(k): v for k, v in sorted(flags.items())},
        "rows_sha256": hashlib.sha256(data).hexdigest(),
        "runtime_seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "rpc_requests": 0,
    }
    atomic_write(out / SUMMARY, json.dumps(summary, indent=1).encode() + b"\n")
    return summary


def load_rows(poisoning_dir: Path) -> list[dict[str, Any]]:
    out = poisoning_dir / OUT_DIR
    summary = json.loads((out / SUMMARY).read_text(encoding="utf-8"))
    data = (out / ROWS).read_bytes()
    if hashlib.sha256(data).hexdigest() != summary["rows_sha256"]:
        raise RuntimeError(f"{out / ROWS}: content differs from its summary; re-extract")
    return [json.loads(line) for line in data.splitlines() if line]


def u_victims(poisoning_dir: Path) -> tuple[list[str], dict[str, int]]:
    """Senders of unconfirmed rows, minus Phase 12.1 payoff victims, protected wallets and
    incident victims (protocol section 2)."""
    groups = json.loads((poisoning_dir / "archive_targets.json").read_text(encoding="utf-8"))
    groups = groups["groups"]
    studied = set(groups["payoff_victims"])
    incident = set(groups["incident_victims"])
    protected = lr.protected_wallets(poisoning_dir)
    excluded: Counter[str] = Counter()
    keep: set[str] = set()
    for v in {r["sender"] for r in load_rows(poisoning_dir)}:
        if v in studied:
            excluded["phase12_1_payoff_victim"] += 1
        elif v in protected:
            excluded["protected_review_wallet"] += 1
        elif v in incident:
            excluded["incident_victim"] += 1
        else:
            keep.add(v)
    return sorted(keep), dict(sorted(excluded.items()))


def context_scan(data_dir: Path, poisoning_dir: Path) -> dict[str, Any]:
    """Pass 2: every archive row touching a U victim."""
    from cryptoguard.ml.annotation import atomic_write
    from cryptoguard.ml.fetch import TSUCHIYA_FILES, verify_local
    from cryptoguard.ml.hard_negative_archive import ARCHIVE
    from cryptoguard.ml.tsuchiya_archive import build_targets, load_targets, scan

    victims, _ = u_victims(poisoning_dir)
    out = poisoning_dir / OUT_DIR
    atomic_write(out / TARGETS, json.dumps(build_targets({"u_victims": victims})).encode())
    archive = data_dir / "tsuchiya2025" / ARCHIVE
    source = verify_local(TSUCHIYA_FILES[ARCHIVE], archive, gzip_crc=False)
    work = out / "spill"
    summary = scan(
        archive,
        load_targets(out / TARGETS),
        out / SUBSET,
        work_dir=work,
        source_sha256=source["sha256"],
    )
    if work.exists() and not any(work.iterdir()):
        work.rmdir()
    return summary


# --- episodes -------------------------------------------------------------------------------


def load_u_episodes(poisoning_dir: Path) -> tuple[list[lr.Episode], dict[str, int]]:
    from cryptoguard.ml.tsuchiya_archive import PAYOFF, PAYOFF_UNCONFIRMED

    victims, excluded_c = u_victims(poisoning_dir)
    excluded: Counter[str] = Counter(excluded_c)
    addresses, txs = lr.protected_entities(poisoning_dir)
    con = lr._connect(poisoning_dir / OUT_DIR / SUBSET)
    episodes: list[lr.Episode] = []
    try:
        for v in victims:
            rows = [
                lr._row(t)
                for t in con.execute(lr._ROWS + " where sender = ? or receiver = ?", (v, v))
            ]
            if any(r.flags & PAYOFF for r in rows):
                excluded["has_confirmed_payoff_row"] += 1
                continue
            ep = lr.episode_from_rows(v, rows, payoff_flag=PAYOFF_UNCONFIRMED)
            if isinstance(ep, str):
                excluded[ep] += 1
                continue
            if set(ep.candidates) & addresses or any(
                r.tx in txs or {r.sender, r.receiver} & addresses for r in ep.plantings
            ):
                excluded["protected_entity_overlap"] += 1
                continue
            episodes.append(ep)
    finally:
        con.close()
    return episodes, dict(sorted(excluded.items()))


# --- analysis -------------------------------------------------------------------------------


def _group_bootstrap_diff(
    d_r: list[float], g_r: list[int], d_u: list[float], g_u: list[int], n: int = 2_000
) -> list[float]:
    """95% interval of mean(d_r) - mean(d_u), resampling groups of each population
    independently."""
    import numpy as np

    rng = np.random.default_rng(SEED)

    def sums(d: list[float], g: list[int]) -> tuple[Any, Any]:
        _ids, inv = np.unique(np.asarray(g), return_inverse=True)
        return np.bincount(inv, weights=np.asarray(d, float)), np.bincount(inv)

    sr, cr = sums(d_r, g_r)
    su, cu = sums(d_u, g_u)
    pr = rng.integers(0, len(sr), size=(n, len(sr)))
    pu = rng.integers(0, len(su), size=(n, len(su)))
    boot = sr[pr].sum(1) / cr[pr].sum(1) - su[pu].sum(1) / cu[pu].sum(1)
    lo, hi = np.percentile(boot, [2.5, 97.5])
    return [float(lo), float(hi)]


def _contrast(diff: float, ci: list[float]) -> str:
    """Protocol section 5, U-H2."""
    lo, hi = ci
    if lo > 0 and diff >= HALF:
        return "confirmation_implicated"
    if hi < HALF:
        return "not_implicated"
    return "inconclusive"


def _conclusion(h1: str, h2: str) -> str:
    if h1 == "survives" and h2 == "not_implicated":
        return "the confirmation step does not explain recency"
    if h1 == "explained_or_null" and h2 == "confirmation_implicated":
        return "recency is plausibly a confirmation artifact"
    return "inconclusive"


def run(poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml import recency_validation as rv
    from cryptoguard.ml.lookalike_study import _year, subtype

    t_start = time.perf_counter()
    eps, excluded = load_u_episodes(poisoning_dir)
    if len(eps) < 2:
        raise RuntimeError(f"only {len(eps)} eligible U episodes")
    tokens = lr.TokenIndex.build(eps)
    feats: list[rv.Feats] = []
    for e in eps:
        fe = lr.candidate_features(e, lr.View(), None, tokens)
        if fe is None:
            raise RuntimeError("an eligible U episode is not evaluable at its cutoff")
        feats.append(fe)
    grp, linkage = lr.protocol_groups(eps)
    t0 = [rv._top1(rv._single(f, "T0"), e.paid, f) for f, e in zip(feats, eps, strict=True)]
    b0 = [rv._top1(rv._single(f, "B0"), e.paid, f) for f, e in zip(feats, eps, strict=True)]
    rnd = [1 / len(f) for f in feats]
    h1 = lr.paired([a - b for a, b in zip(t0, b0, strict=True)], grp, seed=SEED)
    h1 |= {"T0_top1": rv._mean(t0), "B0_top1": rv._mean(b0), "random_top1": rv._mean(rnd)}
    h1["decision"] = rv._decision(h1, h1["p"])

    # U-H2: contrast with Phase 12.2's R effect, recomputed per episode from the same code.
    r_eps, _ = lr.load_episodes(poisoning_dir)
    r_tokens = lr.TokenIndex.build(r_eps)
    r_feats = [lr.candidate_features(e, lr.View(), None, r_tokens) for e in r_eps]
    r_grp, _ = lr.protocol_groups(r_eps)
    d_r = [
        rv._top1(rv._single(f, "T0"), e.paid, f) - rv._top1(rv._single(f, "B0"), e.paid, f)
        for f, e in zip(r_feats, r_eps, strict=True)
        if f is not None
    ]
    delta_r = statistics.fmean(d_r)
    d_u = [a - b for a, b in zip(t0, b0, strict=True)]
    diff = delta_r - h1["mean"]
    ci = _group_bootstrap_diff(d_r, r_grp, d_u, grp)
    h2 = {
        "delta_R": round(delta_r, 4),
        "delta_R_registered": DELTA_R,
        "delta_U": round(h1["mean"], 4),
        "D": round(diff, 4),
        "ci95": ci,
        "decision": _contrast(diff, ci),
    }
    report: dict[str, Any] = {
        "task": STUDY_VERSION,
        "protocol": PROTOCOL,
        "classification": "same-source, never-examined, label-uncertain; not independent",
        "episodes": len(eps),
        "exclusions": excluded,
        "groups": {
            "linkage": linkage,
            "count": len(set(grp)),
            "largest": max(Counter(grp).values()),
        },
        "k": {
            "mean": round(statistics.fmean(len(f) for f in feats), 2),
            "median": statistics.median(len(f) for f in feats),
            "bins": dict(Counter(rv._kbin(len(f)) for f in feats)),
        },
        "U_H1": h1,
        "U_H2": h2,
        "conclusion": _conclusion(h1["decision"], h2["decision"]),
    }

    # UE1: the source's rule on U (stratified on an outcome attribute).
    sr = [rv.confirmation_rule(e, e.payoff_block - 1) for e in eps]
    ue1: dict[str, Any] = {"label": "stratified on an outcome attribute"}
    for name, pos in (("SR_any", 0), ("SR_latest", 1)):
        for value in (True, False):
            ix = [
                i for i, (e, s) in enumerate(zip(eps, sr, strict=True)) if s[e.paid][pos] is value
            ]
            key = f"paid_{name}_{'passes' if value else 'fails'}"
            ue1[key] = rv._cmp(
                [t0[i] for i in ix], [b0[i] for i in ix], [grp[i] for i in ix], n_perm=2_000
            ) | {"random_top1": rv._mean([rnd[i] for i in ix])}
        none = sum(1 for e, s in zip(eps, sr, strict=True) if s[e.paid][pos] is None)
        ue1[f"paid_{name}_not_evaluable"] = none
    report["UE1_rule_on_U"] = ue1

    # UE2: controls.
    rng = random.Random(SEED)  # noqa: S311 - seeded research sampling, not security
    perm: list[float] = []
    for f, e in zip(feats, eps, strict=True):
        vals = [f[c]["T0"] for c in f]
        acc = 0.0
        for _ in range(200):
            rng.shuffle(vals)
            acc += lr.top1(
                {c: float(v or 0.0) for c, v in zip(f, vals, strict=True)}, e.paid, len(f)
            )
        perm.append(acc / 200)
    old = [
        rv._top1({c: -float(f[c]["T0"] or 0.0) for c in f}, e.paid, f)
        for f, e in zip(feats, eps, strict=True)
    ]
    report["UE2_controls"] = {
        "random_top1": rv._mean(rnd),
        "within_episode_permutation_top1": rv._mean(perm),
        "oldest_first_top1": rv._mean(old),
    }

    # UE3: strata.
    report["UE3_strata"] = {
        "year": rv._strata([_year(e.payoff_block) for e in eps], grp, t0, b0, rnd),
        "paid_subtype": rv._strata([subtype(e) for e in eps], grp, t0, b0, rnd),
        "k": rv._strata([rv._kbin(len(f)) for f in feats], grp, t0, b0, rnd),
    }

    # UE4 and UE6: production replay.
    op0: list[float] = []
    op1: list[float] = []
    og: list[int] = []
    warned = Counter[str]()
    for i, e in enumerate(eps):
        cases = rv.production_cases(e, e.payoff_block - 1)
        sus = {x.suspect.lower() for x in cases}
        warned["paid"] += e.paid in sus
        warned["rival"] += sum(1 for c in feats[i] if c != e.paid and c in sus)
        warned["rival_candidates"] += len(feats[i]) - 1
        if e.paid in sus and len(cases) >= 2:
            a, b = rv._op_top1(cases, e.paid, e.payoff_block - 1)
            op0.append(a)
            op1.append(b)
            og.append(grp[i])
    ue4 = rv._cmp(op1, op0, og, n_perm=2_000)
    report["UE4_production_warnings"] = {
        **{k: v for k, v in ue4.items() if k not in ("T0_top1", "B0_top1")},
        "OP1_top1": ue4.get("T0_top1"),
        "OP0_top1": ue4.get("B0_top1"),
    }
    report["UE6_warned_share"] = {
        "paid": round(warned["paid"] / len(eps), 4),
        "rival": round(warned["rival"] / warned["rival_candidates"], 4)
        if warned["rival_candidates"]
        else None,
    }

    # UE5: without infrastructure shared with Phase 12.1.
    r_keys = {c for e in r_eps for c in e.candidates} | {r.tx for e in r_eps for r in e.plantings}
    shared = [bool(set(e.candidates) & r_keys or {r.tx for r in e.plantings} & r_keys) for e in eps]
    ix = [i for i in range(len(eps)) if not shared[i]]
    report["UE5_without_shared_infrastructure"] = rv._cmp(
        [t0[i] for i in ix], [b0[i] for i in ix], [grp[i] for i in ix], n_perm=2_000
    ) | {"episodes_sharing": sum(shared), "random_top1": rv._mean([rnd[i] for i in ix])}

    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    peak = peak_rss_bytes()
    report["resources"] = {
        "total_seconds": round(time.perf_counter() - t_start, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
        "rpc_requests": 0,
    }
    return report

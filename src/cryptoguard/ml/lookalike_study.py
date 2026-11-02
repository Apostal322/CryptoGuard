"""Phase 12.1 experiments (``cryptoguard ml lookalike-study``), as pre-registered in
docs/ml/protocol-12.1.md. Aggregate output only; 0 RPC requests.

Only the four primary comparisons are confirmatory. Everything else in the output is
exploratory and labelled so.
"""

from __future__ import annotations

import json
import random
import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptoguard.ml import lookalike_ranking as lr

STUDY_VERSION = "lookalike-study/1"
SEED = 20261102
PUBLIC_TOKENS = frozenset(
    {
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    }
)
PRIMARY = {"P-H1": "B3", "P-H2": "T0", "P-H3": "G1", "P-H5": "H"}
KEY_METHODS = ("random", "B0", "B1", "B3", "T0", "T2", "G1", "H")
Feats = dict[str, dict[str, lr.Value]]
Method = Callable[[Mapping[str, Mapping[str, lr.Value]]], "lr.Scores | None"]


def methods() -> dict[str, Method]:
    out: dict[str, Method] = {"random": lambda f: None}
    for name in lr.FEATURES:
        out[name] = lr.single(name)
    out["H"] = lr.hybrid(lr.HYBRID)
    return out


def _score(
    feats: Sequence[Feats | None], eps: Sequence[lr.Episode], ms: Mapping[str, Method]
) -> dict[str, dict[str, list[Any]]]:
    """Per method: top-1, MRR, abstention and the top set for every evaluable episode."""
    res: dict[str, dict[str, list[Any]]] = {m: defaultdict(list) for m in ms}
    for f, e in zip(feats, eps, strict=True):
        if f is None:
            continue
        k = len(f)
        for name, m in ms.items():
            s = m(f)
            r = res[name]
            r["top1"].append(lr.top1(s, e.paid, k))
            r["mrr"].append(lr.mrr(s, e.paid, k))
            r["abstain"].append(s is None)
            r["top"].append(
                frozenset(f)
                if s is None
                else frozenset(c for c, v in s.items() if v == max(s.values()))
            )
    return res


def _summary(r: Mapping[str, list[Any]]) -> dict[str, Any]:
    n = len(r["top1"])
    return {
        "episodes": n,
        "top1": round(statistics.fmean(r["top1"]), 4) if n else None,
        "mrr": round(statistics.fmean(r["mrr"]), 4) if n else None,
        "abstain_share": round(sum(r["abstain"]) / n, 4) if n else None,
    }


def _subset(r: Mapping[str, list[Any]], idx: Sequence[int]) -> dict[str, list[Any]]:
    return {k: [v[i] for i in idx] for k, v in r.items()}


def subtype(ep: lr.Episode) -> str:
    from cryptoguard.ml.tsuchiya_archive import COUNTERFEIT, TINY, ZERO

    rows = [r for r in ep.plantings if lr.lookalike_of(r, ep.victim) == ep.paid]
    last = max(rows, key=lambda r: (r.block, r.line))
    if last.sender == ep.victim:
        return "spoofed_transfer_from"
    if last.flags & COUNTERFEIT:
        return "fake_token"
    if last.flags & TINY:
        return "tiny"
    return "zero_value" if last.flags & ZERO else "other"


def _year(block: int) -> str:
    from cryptoguard.ml.review_sample import YEAR_STARTS

    y = next((y for y, start in YEAR_STARTS if block >= start), 2022)
    return "2024+" if y >= 2024 else str(y)


def _kbin(k: int) -> str:
    return "2" if k == 2 else "3-5" if k <= 5 else "6+"


# --- the exploratory learned model --------------------------------------------------------

_LOG = ("B3", "T1", "T4", "G1", "G2", "G3")
_LEARNED = ("B0", "B1", "B2", "B3", "T0", "T1", "T2", "T3", "T4", "G1", "G2", "G3")


def _vec(f: Mapping[str, lr.Value], indicators: bool) -> list[float]:
    import math

    out: list[float] = []
    for name in _LEARNED:
        v = f[name]
        x = 0.0 if v is None else float(v)
        if v is not None and name in _LOG:
            x = math.log1p(x)
        if v is not None and name == "T0":
            x = -math.log1p(-x)
        out.append(x)
        if indicators:
            out.append(1.0 if v is None else 0.0)
    return out


def learned(
    feats: Sequence[Feats | None],
    eps: Sequence[lr.Episode],
    split: Sequence[str],
    *,
    indicators: bool = True,
) -> tuple[Method, dict[str, Any]]:
    """Conditional logit as L2 logistic regression on paid-minus-rival differences, fitted
    on development episodes only (exploratory)."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    dev = [(f, e) for f, e, s in zip(feats, eps, split, strict=True) if s == "dev" and f]
    raw = np.array([_vec(v, indicators) for f, _ in dev for v in f.values()])
    mu, sd = raw.mean(axis=0), raw.std(axis=0)
    sd[sd == 0] = 1.0
    xs, ys = [], []
    for f, e in dev:
        z = {c: (np.array(_vec(v, indicators)) - mu) / sd for c, v in f.items()}
        for c in f:
            if c != e.paid:
                xs += [z[e.paid] - z[c], z[c] - z[e.paid]]
                ys += [1, 0]
    model = LogisticRegression(C=1.0, fit_intercept=False, max_iter=2_000, random_state=0)
    model.fit(np.array(xs), np.array(ys))
    w = model.coef_[0]

    def score(f: Mapping[str, Mapping[str, lr.Value]]) -> lr.Scores:
        return {c: float(((np.array(_vec(v, indicators)) - mu) / sd) @ w) for c, v in f.items()}

    names = [n for name in _LEARNED for n in ((name, name + "_missing") if indicators else (name,))]
    info = {
        "dev_episodes": len(dev),
        "pairs": len(ys),
        "weights": {n: round(float(x), 4) for n, x in zip(names, w, strict=True)},
    }
    return score, info


# --- Task 1: candidate coverage -------------------------------------------------------------


def coverage(poisoning_dir: Path, protected: frozenset[str]) -> dict[str, Any]:
    """``candidates/2`` on archive history before each payoff-linked planting (exploratory)."""
    import sqlite3

    from cryptoguard.ml import candidates as cand
    from cryptoguard.ml.diagnostics import _fixture

    packets = [
        p
        for p in map(
            json.loads,
            (poisoning_dir / "review_packets_payoff_linked.jsonl")
            .read_text(encoding="utf-8")
            .splitlines(),
        )
        if p["victim"] not in protected
    ]
    con = sqlite3.connect(
        f"file:{(poisoning_dir / 'archive_subset.sqlite').as_posix()}?mode=ro", uri=True
    )
    q = (
        "select line, block, tx, token, sender, receiver, value, flags from transfers "
        "where (sender = ? or receiver = ?) and block between ? and ? order by block, line"
    )
    out: dict[str, Any] = {
        "population": "payoff-linked source positives minus protected wallets",
        "attempts": len(packets),
    }
    for label, window in (("7d", 50_400), ("30d", 216_000), ("all", 10**9)):
        for mode in ("strict", "optimistic"):
            hit: Counter[str] = Counter()
            total: Counter[str] = Counter()
            reasons: Counter[str] = Counter()
            for p in packets:
                v, b = p["victim"], p["observation_block"]
                rows = con.execute(q, (v, v, max(0, b - window), b)).fetchall()
                total[p["subtype"]] += 1
                fx = _fixture(v, rows, b, mode == "optimistic", window=min(window, b))
                emitted = any(
                    c.event.planting_tx == p["planting_tx"] and c.event.lookalike == p["lookalike"]
                    for c in cand.generate(fx)
                )
                if emitted:
                    hit[p["subtype"]] += 1
                    continue
                planting = [
                    r for r in rows if r[2] == p["planting_tx"] and p["lookalike"] in (r[4], r[5])
                ]
                if not planting:
                    reasons["planting_row_absent"] += 1
                elif planting[0][4] == v:
                    reasons["outgoing_needs_signer"] += 1
                else:
                    chosen = (
                        {r[5] for r in rows if r[4] == v and r[1] < b}
                        if mode == "optimistic"
                        else set()
                    )
                    if not chosen:
                        reasons["incoming_no_signed_payment_in_window"] += 1
                    elif not any(cand.similar(p["lookalike"], c) for c in chosen):
                        reasons["incoming_below_generator_similarity"] += 1
                    else:
                        reasons["other"] += 1
            n = sum(total.values())
            out[f"{label}_{mode}"] = {
                "emitted": sum(hit.values()),
                "share": round(sum(hit.values()) / n, 4) if n else None,
                "by_subtype": {s: f"{hit[s]}/{total[s]}" for s in sorted(total)},
                "miss_reasons": dict(reasons),
            }
    con.close()
    return out


# --- P2 and P3 ------------------------------------------------------------------------------


def availability() -> dict[str, Any]:
    """Which ranking features a production-like recording can compute (P2, P3)."""
    from cryptoguard.ml import candidates as cand
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases

    out: dict[str, Any] = {}
    for label, fixtures in (
        ("P2_background", [b.fixture for b in load_background() if b.fixture]),
        ("P3_incidents", [c.fixture for c in load_cases() if c.fixture]),
    ):
        n = with_ref = multi = 0
        per_wallet: list[int] = []
        t0 = time.perf_counter()
        for fx in fixtures:
            cs = cand.generate(fx)
            n += len(cs)
            with_ref += sum(1 for c in cs if c.best_match is not None)
            looks = {c.event.lookalike for c in cs}
            per_wallet.append(len(looks))
            multi += len(looks) >= 2
        out[label] = {
            "windows": len(fixtures),
            "candidates": n,
            "candidates_with_reference": with_ref,
            "windows_with_2plus_lookalikes": multi,
            "distinct_lookalikes_per_window": per_wallet,
            "seconds": round(time.perf_counter() - t0, 3),
            "features_computable": {
                "B0_B3_T3": "yes, from the wallet's own signed history",
                "B1": "no: needs the source's intended address",
                "B2": "partly: counterfeit needs token reputation",
                "T0_T1_T2_T4": "yes",
                "G1_G2_G3": "no: needs a cross-wallet index at the cutoff",
            },
        }
    return out


def _before(c: int) -> Callable[[lr.Row], bool]:
    return lambda r: r.block <= c


def coverage_symmetry(
    episodes: Sequence[lr.Episode], poisoning_dir: Path, gpath: Path
) -> dict[str, Any]:
    """Do paid and rival lookalikes get the same historical observation? The graph pass
    must have targeted every candidate and planting tx, and must hold every planting row
    the victim-side subset holds, for paid and rivals alike. The older subset's targeting
    is reported to show the asymmetry this pass removes."""
    import sqlite3

    from cryptoguard.ml.tsuchiya_archive import load_targets

    manifest = load_targets(poisoning_dir / lr.RESEARCH_DIR / "graph_context_targets.json")
    old = json.loads((poisoning_dir / "archive_targets.json").read_text(encoding="utf-8"))
    old_lookalikes = set(old["groups"].get("payoff_lookalikes", ()))
    con = sqlite3.connect(f"file:{gpath.as_posix()}?mode=ro", uri=True)
    try:
        meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
        scanned = json.loads(meta["summary"])["target_manifest_sha256"]
        acc: dict[str, Counter[str]] = {"paid": Counter(), "rival": Counter()}
        rows_seen: dict[str, list[int]] = {"paid": [], "rival": []}
        for e in episodes:
            c = e.payoff_block - 1
            by_l: defaultdict[str, list[lr.Row]] = defaultdict(list)
            for r in e.plantings:
                by_l[lr.lookalike_of(r, e.victim)].append(r)
            for lk, rows in by_l.items():
                side = "paid" if lk == e.paid else "rival"
                a = acc[side]
                a["candidates"] += 1
                a["targeted_address"] += lk in manifest.addresses
                a["targeted_in_old_subset"] += lk in old_lookalikes
                a["planting_rows"] += len(rows)
                a["planting_txs_targeted"] += sum(r.tx in manifest.txs for r in rows)
                a["planting_rows_in_graph_db"] += sum(
                    con.execute("SELECT 1 FROM transfers WHERE line = ?", (r.line,)).fetchone()
                    is not None
                    for r in rows
                )
                n = con.execute(
                    "SELECT count(*) FROM transfers WHERE (sender = ? OR receiver = ?) "
                    "AND block <= ?",
                    (lk, lk, c),
                ).fetchone()[0]
                rows_seen[side].append(n)
    finally:
        con.close()
    out: dict[str, Any] = {"scan_used_this_manifest": scanned == manifest.sha256}
    for side, a in acc.items():
        n = a["candidates"]
        out[side] = {
            "candidates": n,
            "targeted_share": round(a["targeted_address"] / n, 4) if n else None,
            "old_subset_targeted_share": round(a["targeted_in_old_subset"] / n, 4) if n else None,
            "planting_rows_in_graph_db_share": (
                round(a["planting_rows_in_graph_db"] / a["planting_rows"], 4)
                if a["planting_rows"]
                else None
            ),
            "planting_txs_targeted_share": (
                round(a["planting_txs_targeted"] / a["planting_rows"], 4)
                if a["planting_rows"]
                else None
            ),
            "archive_rows_at_cutoff_median": (
                statistics.median(rows_seen[side]) if rows_seen[side] else None
            ),
        }
    out["symmetric"] = bool(
        out["scan_used_this_manifest"]
        and all(out[s]["targeted_share"] == 1.0 for s in acc)
        and all(out[s]["planting_rows_in_graph_db_share"] == 1.0 for s in acc)
    )
    return out


# --- the study ------------------------------------------------------------------------------


def run(poisoning_dir: Path) -> dict[str, Any]:
    t_start = time.perf_counter()
    episodes, exclusions = lr.load_episodes(poisoning_dir)
    gpath = poisoning_dir / lr.RESEARCH_DIR / lr.GRAPH_DB
    # Rows touching a frozen review wallet never enter the graph (protocol section 3).
    blind = lr.protected_wallets(poisoning_dir)
    graph = lr.sqlite_graph(gpath, exclude=blind)
    tokens = lr.TokenIndex.build(episodes)
    grp, linkage = lr.protocol_groups(episodes)
    split = lr.temporal_split(episodes, grp)
    ms = methods()
    t0 = time.perf_counter()
    feats = [lr.candidate_features(e, lr.View(), graph, tokens) for e in episodes]
    feature_seconds = time.perf_counter() - t0
    # Eligibility guarantees every episode is evaluable at the primary cutoff, so result
    # lists and episode indices align.
    if any(f is None for f in feats):
        raise RuntimeError("an eligible episode is not evaluable at the primary cutoff")
    res = _score(feats, episodes, ms)
    test_idx = [i for i, s in enumerate(split) if s == "test"]
    dev_idx = [i for i, s in enumerate(split) if s == "dev"]
    report: dict[str, Any] = {
        "task": lr.TASK,
        "protocol": lr.PROTOCOL,
        "study_version": STUDY_VERSION,
        "feature_version": lr.FEATURE_VERSION,
        "episodes": len(episodes),
        "exclusions": exclusions,
        "groups": {
            "linkage": linkage,
            "count": len(set(grp)),
            "largest": max(Counter(grp).values()),
            "by_tx_count": len(set(lr.groups(episodes, by_tx=True))),
        },
        "split": {
            s: {
                "episodes": sum(1 for x in split if x == s),
                "groups": len({g for g, x in zip(grp, split, strict=True) if x == s}),
            }
            for s in ("dev", "test")
        },
        "k": {
            "mean": round(statistics.fmean(len(f) for f in feats if f), 2),
            "median": statistics.median(len(f) for f in feats if f),
        },
    }

    report["coverage_symmetry"] = coverage_symmetry(episodes, poisoning_dir, gpath)
    overlap = lr.protected_overlap(episodes, *lr.protected_entities(poisoning_dir))
    report["protected_overlap"] = {
        "episodes_linked": sum(overlap),
        "test_episodes_linked": sum(overlap[i] for i in test_idx),
        "dev_episodes_linked": sum(overlap[i] for i in dev_idx),
    }

    # Primary (confirmatory): paired top-1 differences against B0 on the test split.
    g_test = [grp[i] for i in test_idx]
    prim: dict[str, Any] = {}
    for test, m in PRIMARY.items():
        d = [res[m]["top1"][i] - res["B0"]["top1"][i] for i in test_idx]
        prim[test] = {"method": m, "baseline": "B0", **lr.paired(d, g_test, seed=SEED)}
    adj = lr.holm({k: v["p"] for k, v in prim.items()})
    for k, v in prim.items():
        v["p_holm"] = adj[k]
        v["decision"] = lr.decision(v, adj[k])
    report["primary"] = prim

    # Sensitivity (deviation D1): the same tests without episodes that share an entity or a
    # linkage group with a frozen review item.
    clean = [i for i in test_idx if not overlap[i]]
    sens: dict[str, Any] = {}
    for test, m in PRIMARY.items():
        d = [res[m]["top1"][i] - res["B0"]["top1"][i] for i in clean]
        sens[test] = lr.paired(d, [grp[i] for i in clean], seed=SEED)
    adj_s = lr.holm({k: v["p"] for k, v in sens.items()})
    for k, v in sens.items():
        v["p_holm"] = adj_s[k]
        v["decision"] = lr.decision(v, adj_s[k])
    report["primary_without_protected_overlap"] = sens

    # Exploratory: every method by split, and against random on all episodes.
    report["methods"] = {
        m: {
            s: _summary(_subset(res[m], idx))
            for s, idx in (
                ("dev", dev_idx),
                ("test", test_idx),
                ("all", list(range(len(episodes)))),
            )
        }
        for m in ms
    }
    report["vs_random_all"] = {
        m: lr.paired(
            [a - b for a, b in zip(res[m]["top1"], res["random"]["top1"], strict=True)],
            grp,
            seed=SEED,
            n_perm=2_000,
        )
        for m in KEY_METHODS
        if m != "random"
    }
    report["vs_B0_all"] = {
        m: lr.paired(
            [a - b for a, b in zip(res[m]["top1"], res["B0"]["top1"], strict=True)],
            grp,
            seed=SEED,
            n_perm=2_000,
        )
        for m in ("B1", "B2", "T1", "T2", "T3", "T4", "G2", "G3", "NC")
    }

    # Exploratory: strata.
    strata: dict[str, dict[str, Any]] = {}
    keys: tuple[tuple[str, Callable[[lr.Episode, Feats], str]], ...] = (
        ("year", lambda e, f: _year(e.payoff_block)),
        ("paid_subtype", lambda e, f: subtype(e)),
        ("k", lambda e, f: _kbin(len(f))),
    )
    for name, key in keys:
        buckets: defaultdict[str, list[int]] = defaultdict(list)
        for i, (e, f) in enumerate(zip(episodes, feats, strict=True)):
            if f is not None:
                buckets[key(e, f)].append(i)
        strata[name] = {
            b: {m: _summary(_subset(res[m], idx))["top1"] for m in KEY_METHODS}
            | {"episodes": len(idx)}
            for b, idx in sorted(buckets.items())
        }
    report["strata"] = strata

    # Exploratory: hybrid ablations and the learned model (test split).
    abl: dict[str, Any] = {"H": _summary(_subset(res["H"], test_idx))["top1"]}
    for drop in lr.HYBRID:
        rest = tuple(c for c in lr.HYBRID if c != drop)
        r = _score(
            [feats[i] for i in test_idx], [episodes[i] for i in test_idx], {"h": lr.hybrid(rest)}
        )["h"]
        abl[f"H_without_{drop}"] = _summary(r)["top1"]
    report["ablations_test"] = abl
    learned_out: dict[str, Any] = {}
    for ind in (True, False):
        # Deviation D1: development episodes linked to a frozen item are not fitted on.
        fit_split = ["overlap" if o else s for s, o in zip(split, overlap, strict=True)]
        score, info = learned(feats, episodes, fit_split, indicators=ind)
        r = _score([feats[i] for i in test_idx], [episodes[i] for i in test_idx], {"m": score})["m"]
        d = [a - res["B0"]["top1"][i] for a, i in zip(r["top1"], test_idx, strict=True)]
        learned_out["with_indicators" if ind else "without_indicators"] = {
            **info,
            "test": _summary(r),
            "vs_B0_test": lr.paired(d, g_test, seed=SEED, n_perm=2_000),
        }
    report["learned_exploratory"] = learned_out

    # Exploratory: robustness. Changes are measured on the episodes evaluable in both.
    base_top = {m: res[m]["top"] for m in KEY_METHODS}
    rob: dict[str, Any] = {}
    variants: list[tuple[str, lr.View, Any, int | None]] = [
        ("lag_300", lr.View(lag=300), graph, None),
        ("lag_7200", lr.View(lag=7_200), graph, None),
        ("victim_lookback_7d", lr.View(victim_lookback=50_400), graph, None),
        ("victim_lookback_30d", lr.View(victim_lookback=216_000), graph, None),
        ("victim_drop_50", lr.View(victim_drop=0.5, seed=0), graph, None),
        ("graph_lookback_30d", lr.View(), graph, 216_000),
        (
            "graph_drop_50",
            lr.View(),
            lr.sqlite_graph(gpath, keep=lr.graph_keep(0.5, 0), exclude=blind),
            None,
        ),
    ]
    evaluable = [i for i, f in enumerate(feats) if f is not None]
    for name, view, g, glb in variants:
        vf = [lr.candidate_features(e, view, g, tokens, graph_lookback=glb) for e in episodes]
        vr = _score(vf, episodes, {m: ms[m] for m in KEY_METHODS})
        keep = [i for i in evaluable if vf[i] is not None]
        pos = {i: n for n, i in enumerate(i for i in range(len(episodes)) if vf[i] is not None)}
        entry: dict[str, Any] = {"evaluable": len(keep)}
        for m in KEY_METHODS:
            same_set = [i for i in keep if set(vf[i] or {}) == set(feats[i] or {})]
            changed = sum(1 for i in same_set if vr[m]["top"][pos[i]] != base_top[m][i])
            entry[m] = {
                **_summary(vr[m]),
                "top_set_changed_share": round(changed / len(same_set), 4) if same_set else None,
            }
        rob[name] = entry
    report["robustness"] = rob

    # Exploratory: leakage and randomization controls.
    rng = random.Random(SEED)  # noqa: S311 - seeded research sampling, not security
    sample = rng.sample(range(len(episodes)), min(100, len(episodes)))
    mismatches = 0
    for i in sample:
        c = episodes[i].payoff_block - 1
        g_cut = lr.sqlite_graph(gpath, keep=_before(c), exclude=blind)
        if lr.candidate_features(episodes[i], lr.View(), g_cut, tokens) != feats[i]:
            mismatches += 1
    shuffled_within, shuffled_global = [], []
    pool = [v["G1"] for fs in feats if fs for v in fs.values()]
    rng.shuffle(pool)
    it = iter(pool)
    for f, e in zip(feats, episodes, strict=True):
        if f is None:
            continue
        vals = [v["G1"] for v in f.values()]
        rng.shuffle(vals)
        within: Feats = {c: {"G1": v} for c, v in zip(f, vals, strict=True)}
        glob: Feats = {c: {"G1": next(it)} for c in f}
        shuffled_within.append(lr.top1(lr.single("G1")(within), e.paid, len(f)))
        shuffled_global.append(lr.top1(lr.single("G1")(glob), e.paid, len(f)))
    public = sum(1 for e in episodes for r in e.plantings if r.token in PUBLIC_TOKENS)
    report["controls"] = {
        "future_rows_cut_graph_mismatches": f"{mismatches}/{len(sample)}",
        "G1_within_episode_shuffle_top1": round(statistics.fmean(shuffled_within), 4),
        "G1_global_shuffle_top1": round(statistics.fmean(shuffled_global), 4),
        "random_top1": report["methods"]["random"]["all"]["top1"],
        "NC_top1": report["methods"]["NC"]["all"]["top1"],
        "plantings_in_public_tokens_share": round(
            public / sum(len(e.plantings) for e in episodes), 4
        ),
    }

    # Exploratory: source shift (paid vs rival, by year) and availability.
    shift: dict[str, Any] = {}
    for name in ("B0", "B1", "B3", "T0", "T1", "G1", "G2", "G3", "NC"):
        paid_v: list[float] = [
            x
            for f, e in zip(feats, episodes, strict=True)
            if f
            for x in (f[e.paid][name],)
            if x is not None
        ]
        rival_v: list[float] = [
            x
            for f, e in zip(feats, episodes, strict=True)
            if f
            for c, v in f.items()
            if c != e.paid
            for x in (v[name],)
            if x is not None
        ]
        avail: dict[str, float | None] = {}
        for y in ("2022", "2023", "2024+"):
            seen = [
                f[e.paid][name] is not None
                for f, e in zip(feats, episodes, strict=True)
                if f and _year(e.payoff_block) == y
            ]
            avail[y] = round(sum(seen) / len(seen), 3) if seen else None
        shift[name] = {
            "paid_median": statistics.median(paid_v) if paid_v else None,
            "rival_median": statistics.median(rival_v) if rival_v else None,
            "available_share_by_year": avail,
        }
    report["source_shift"] = shift

    # Exploratory: errors of H on test.
    errors: Counter[str] = Counter()
    for i in test_idx:
        f, e = feats[i], episodes[i]
        if f is None or res["H"]["top1"][i] == 1.0:
            continue
        errors["miss_or_tie"] += 1
        if res["H"]["top1"][i] > 0:
            errors["paid_tied_at_top"] += 1
        for m, label in (
            ("T0", "paid_not_most_recent"),
            ("B1", "paid_not_most_similar"),
            ("G1", "paid_not_most_reused"),
            ("B3", "paid_reference_not_most_used"),
        ):
            if e.paid not in res[m]["top"][i]:
                errors[label] += 1
        if f[e.paid]["B0"] is None:
            errors["no_victim_payment_history_observed"] += 1
        if res["B1"]["abstain"][i]:
            errors["source_intended_missing"] += 1
    report["errors_test_H"] = dict(errors)

    report["coverage_task1"] = coverage(poisoning_dir, lr.protected_wallets(poisoning_dir))
    report["availability"] = availability()
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    peak = peak_rss_bytes()
    report["resources"] = {
        "feature_seconds_primary": round(feature_seconds, 2),
        "total_seconds": round(time.perf_counter() - t_start, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
        "rpc_requests": 0,
    }
    return report

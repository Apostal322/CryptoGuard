"""Generalization audit of a trained run (Phase 11.1). Offline only: no RPC calls.

Everything here reads stored artifacts (feature table, splits, collected chain records, a
run's model) and recomputes evidence independently of ``train.py``:

- metrics recomputed with this module's own NumPy implementations;
- Wilson intervals for proportions and a *cluster* bootstrap (rows from one account
  component are resampled together: PTXPhish draws up to 200 benign transactions per
  account and up to 50 per scammer address, so rows are not independent);
- low-prevalence alert arithmetic (scenarios, not deployment measurements);
- shortcut experiments: fixed hyperparameters on restricted feature sets, no per-subset
  tuning;
- sensitivity of split sizes and scores to the hub policy (reported, never used to choose);
- exact feature-vector duplicates across splits; calibration bins; per-error features.

The old test split has been looked at during development (see ML_GENERALIZATION_AUDIT.md),
so every number on it is a *development benchmark*, never an untouched holdout.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.ml.features import FEATURES, SELECTORS, parties

if TYPE_CHECKING:
    import numpy as np
    import pandas as pd

SEED = 20261101
PREVALENCES = (0.0001, 0.001, 0.01, 0.05)

# Restricted feature sets for the shortcut experiments (fixed before running them).
SELECTOR = (*(f"fn_{n}" for n in SELECTORS), "fn_other", "input_is_bare_selector")
TX_TYPE = ("is_typed_fee", "is_contract_creation", "is_zero_value", "input_bytes_log")
INTERACTION = (
    "to_is_contract",
    "to_code_size_log",
    "to_is_delegated_eoa",
    "gas_used_ratio",
    "status_success",
)
HISTORY = ("sender_prior_txs_log",)
SIMILARITY = ("max_party_affix_match", "to_vanity_zero_nibbles", "from_vanity_zero_nibbles")
LOG_STRUCTURE = (
    "n_logs",
    "n_log_emitters",
    "n_transfers",
    "n_zero_value_transfers",
    "n_transfers_not_from_sender",
    "n_transfers_from_sender",
    "n_transfers_to_sender",
    "n_transfer_recipients",
    "n_approvals",
    "n_unlimited_approvals",
    "n_approval_for_all_granted",
)
ERA_PROXIES = ("is_typed_fee", "gas_price_gwei_log", "gas_limit_log")


def _minus(*groups: tuple[str, ...]) -> tuple[str, ...]:
    drop = {f for g in groups for f in g}
    return tuple(f for f in FEATURES if f not in drop)


ABLATIONS: dict[str, tuple[str, ...]] = {
    "full": FEATURES,
    "selector_only": SELECTOR,
    "tx_type_only": TX_TYPE,
    "interaction_only": INTERACTION,
    "history_only": HISTORY,
    "similarity_only": SIMILARITY,
    "log_structure_only": LOG_STRUCTURE,
    "all_minus_selector": _minus(SELECTOR),
    "all_minus_history": _minus(HISTORY),
    "all_minus_identity": _minus(HISTORY, SIMILARITY[1:]),
    "all_minus_era_proxies": _minus(ERA_PROXIES),
    "all_minus_shortcuts": _minus(SELECTOR, HISTORY, SIMILARITY[1:], ERA_PROXIES),
}
FIXED_LIGHTGBM = {"num_leaves": 7, "min_child_samples": 5}  # the Phase 11 selection
FIXED_LOGREG = {"C": 1.0}


# --- metrics (independent of sklearn) -------------------------------------------------------


def roc_auc(y: np.ndarray, score: np.ndarray) -> float | None:
    """Mann-Whitney AUC with average ranks for ties."""
    import pandas as pd

    pos, neg = int(y.sum()), int(len(y) - y.sum())
    if pos == 0 or neg == 0:
        return None
    ranks = pd.Series(score).rank(method="average").to_numpy()
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def confusion(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, int]:
    pred = score >= threshold  # a score equal to the threshold counts as positive
    return {
        "tp": int(((y == 1) & pred).sum()),
        "fp": int(((y == 0) & pred).sum()),
        "fn": int(((y == 1) & ~pred).sum()),
        "tn": int(((y == 0) & ~pred).sum()),
    }


def wilson(k: int, n: int, z: float = 1.959964) -> list[float] | None:
    """Wilson score interval for k successes in n trials."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    # The analytic endpoints at k = 0 and k = n are exactly 0 and 1 (avoid 0.9999999999999999).
    lo = 0.0 if k == 0 else max(0.0, centre - half)
    hi = 1.0 if k == n else min(1.0, centre + half)
    return [lo, hi]


def evaluate(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    import numpy as np

    from cryptoguard.ml.train import fast_average_precision

    c = confusion(y, score, threshold)
    pos, neg = c["tp"] + c["fn"], c["fp"] + c["tn"]
    flagged = c["tp"] + c["fp"]
    prevalence = pos / len(y) if len(y) else 0.0
    ap = fast_average_precision(y, score) if pos and neg else None
    clipped = np.clip(score, 1e-6, 1 - 1e-6)
    return {
        "rows": len(y),
        "positives": pos,
        "negatives": neg,
        "prevalence": prevalence,
        "confusion": c,
        "recall": c["tp"] / pos if pos else None,
        "recall_wilson": wilson(c["tp"], pos),
        "false_positive_rate": c["fp"] / neg if neg else None,
        "fpr_wilson": wilson(c["fp"], neg),
        "precision": c["tp"] / flagged if flagged else None,
        "precision_wilson": wilson(c["tp"], flagged),
        "f1": 2 * c["tp"] / (2 * c["tp"] + c["fp"] + c["fn"]) if pos else None,
        "balanced_accuracy": (c["tp"] / pos + c["tn"] / neg) / 2 if pos and neg else None,
        "average_precision": ap,
        "ap_above_prevalence": None if ap is None else ap - prevalence,
        "ap_lift": None if ap is None or prevalence >= 1 else (ap - prevalence) / (1 - prevalence),
        "roc_auc": roc_auc(y, score),
        "log_loss": float(-np.mean(y * np.log(clipped) + (1 - y) * np.log(1 - clipped))),
        "brier": float(np.mean((score - y) ** 2)),
    }


def cluster_bootstrap(
    y: np.ndarray, score: np.ndarray, threshold: float, clusters: np.ndarray, n: int = 2000
) -> dict[str, Any]:
    """Percentile intervals from resampling whole clusters (account components)."""
    import numpy as np

    from cryptoguard.ml.train import fast_average_precision

    rng = np.random.default_rng(SEED)
    ids = np.unique(clusters)
    members = [np.flatnonzero(clusters == c) for c in ids]
    ap, rec, fpr = [], [], []
    for _ in range(n):
        idx = np.concatenate([members[i] for i in rng.integers(0, len(ids), len(ids))])
        yi, si = y[idx], score[idx]
        if yi.sum() in (0, len(yi)):
            continue
        pred = si >= threshold
        ap.append(fast_average_precision(yi, si))
        rec.append(float(pred[yi == 1].mean()))
        fpr.append(float(pred[yi == 0].mean()))

    def q(v: list[float]) -> list[float]:
        return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]

    return {
        "clusters": len(ids),
        "positive_clusters": len(np.unique(clusters[y == 1])),
        "negative_clusters": len(np.unique(clusters[y == 0])),
        "resamples_used": len(ap),
        "average_precision": q(ap),
        "recall": q(rec),
        "false_positive_rate": q(fpr),
    }


def prevalence_scenarios(
    recall: float, fpr: float, fpr_interval: list[float]
) -> list[dict[str, Any]]:
    """Alerts per 10,000 transactions at assumed base rates (arithmetic, not measurement)."""
    out = []
    for p in PREVALENCES:
        tp, fp = 10_000 * p * recall, 10_000 * (1 - p) * fpr
        lo_fp, hi_fp = (10_000 * (1 - p) * f for f in fpr_interval)
        out.append(
            {
                "prevalence": p,
                "true_alerts": tp,
                "false_alerts": fp,
                "alerts": tp + fp,
                "precision": tp / (tp + fp) if tp + fp else None,
                "false_alerts_range": [lo_fp, hi_fp],
                "precision_range": [
                    tp / (tp + hi_fp) if tp + hi_fp else None,
                    tp / (tp + lo_fp) if tp + lo_fp else None,
                ],
            }
        )
    return out


def negatives_needed(target_fpr: float, confidence: float = 0.95) -> int:
    """Benign rows needed so that observing zero false positives bounds the FPR below the
    target at this confidence (exact binomial; about 3 / target at 95%)."""
    return math.ceil(math.log(1 - confidence) / math.log(1 - target_fpr))


# --- data helpers ---------------------------------------------------------------------------


def degree_hub_policy(records: dict[str, dict[str, Any]]) -> set[str]:
    """The Phase 11 policy that was replaced (kept for the sensitivity audit only)."""
    senders: dict[str, set[str]] = defaultdict(set)
    emitters: dict[str, set[str]] = defaultdict(set)
    for rec in records.values():
        sender = (rec["tx"].get("from") or "").lower()
        for account in parties(rec):
            senders[account].add(sender)
        for log in (rec.get("receipt") or {}).get("logs") or []:
            emitters[log["address"].lower()].add(sender)
    return {a for a, s in senders.items() if len(s) >= 10} | {
        a for a, s in emitters.items() if len(s) >= 2
    }


def no_hub_policy(records: dict[str, dict[str, Any]]) -> set[str]:
    return set()


def account_clusters(
    table: pd.DataFrame, records: dict[str, dict[str, Any]], index: Any
) -> np.ndarray:
    """Union-find components over sender/target/spender/recipient (registry hubs excluded)
    for the given rows only: the unit of resampling."""
    import numpy as np

    from cryptoguard.ml.dataset import _UnionFind, hubs

    rows = table.loc[index, "tx_hash"].tolist()
    sub = {h: records[h] for h in rows}
    hub_set = hubs(sub)
    uf = _UnionFind()
    for h in rows:
        uf.find(h)
        for account in sorted(parties(sub[h]) - hub_set):
            uf.union(h, "acct:" + account)
    return np.array([uf.find(h) for h in rows])


def _fit_predict(
    name: str, params: dict[str, Any], train: pd.DataFrame, cols: list[str], *others: pd.DataFrame
) -> list[np.ndarray]:
    from cryptoguard.ml.train import make_model

    model = make_model(name, params).fit(train[cols], train["label"].to_numpy())
    return [model.predict_proba(o[cols])[:, 1] for o in others]


# --- the audit ------------------------------------------------------------------------------


def run_audit(
    table: pd.DataFrame,
    split: pd.Series,
    records: dict[str, dict[str, Any]],
    run_dir: Path,
) -> dict[str, Any]:
    import numpy as np

    from cryptoguard.ml.registry import _verified_model
    from cryptoguard.ml.splits import make_splits
    from cryptoguard.ml.train import best_threshold

    train, val, test = (table[split == s] for s in ("train", "validation", "test"))
    y_va, y_te = val["label"].to_numpy(), test["label"].to_numpy()
    out: dict[str, Any] = {"seed": SEED}

    # 1. Recompute the run's selected-model metrics from its stored artifact.
    card, model = _verified_model(run_dir)
    cols = card["feature_columns"]
    thr = float(card["threshold"])
    s_va, s_te = (model.predict_proba(p[cols])[:, 1] for p in (val, test))
    recorded = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    mine_va, mine_te = evaluate(y_va, s_va, thr), evaluate(y_te, s_te, thr)
    out["baseline"] = {
        "run_id": card["run_id"],
        "model_sha256": card["model_sha256"],
        "threshold": thr,
        "threshold_from_validation_only": abs(best_threshold(y_va, s_va) - thr) < 1e-12,
        "validation": mine_va,
        "test": mine_te,
        "matches_recorded": {
            k: abs((mine_te[k] or 0) - (recorded["test"][k] or 0)) < 1e-9
            for k in (
                "average_precision",
                "roc_auc",
                "recall",
                "false_positive_rate",
                "precision",
                "balanced_accuracy",
                "brier",
            )
        }
        | {"confusion": mine_te["confusion"] == recorded["test"]["confusion"]},
    }
    clusters = account_clusters(table, records, test.index)
    out["baseline"]["test_cluster_bootstrap"] = cluster_bootstrap(y_te, s_te, thr, clusters)
    senders = np.array([records[h]["tx"]["from"].lower() for h in test["tx_hash"]])
    out["baseline"]["test_distinct_senders"] = {
        "benign": len(set(senders[y_te == 0])),
        "phishing": len(set(senders[y_te == 1])),
    }

    # 2. Operating-point arithmetic and sample-size requirements.
    out["prevalence_scenarios"] = prevalence_scenarios(
        mine_te["recall"], mine_te["false_positive_rate"], mine_te["fpr_wilson"]
    )
    out["negatives_needed"] = {str(t): negatives_needed(t) for t in (0.05, 0.01, 0.001)}

    # 3. Errors on the development test split.
    flagged = s_te >= thr
    err = test.assign(score=s_te)
    keep = [
        "tx_hash",
        "family",
        "subtype",
        "score",
        *[
            f
            for f in (
                "fn_transfer",
                "fn_transfer_from",
                "fn_other",
                "n_logs",
                "n_transfers",
                "n_zero_value_transfers",
                "to_vanity_zero_nibbles",
                "sender_prior_txs_log",
                "is_zero_value",
            )
            if f in err
        ],
    ]
    out["errors"] = {
        "false_positives": err[(y_te == 0) & flagged][keep].sort_values("score").to_dict("records"),
        "false_negatives": err[(y_te == 1) & ~flagged][keep]
        .sort_values("score")
        .to_dict("records"),
    }

    # 4. Shortcut experiments: fixed hyperparameters, threshold from validation.
    ablations = []
    for name, feats in ABLATIONS.items():
        for family, params in (("lightgbm", FIXED_LIGHTGBM), ("logistic_regression", FIXED_LOGREG)):
            pv, pt = _fit_predict(family, params, train, list(feats), val, test)
            t = best_threshold(y_va, pv)
            ev_va, ev_te = evaluate(y_va, pv, t), evaluate(y_te, pt, t)
            ablations.append(
                {
                    "features": name,
                    "n_features": len(feats),
                    "model": family,
                    "validation": ev_va,
                    "test": ev_te,
                }
            )
    out["ablations"] = ablations

    # 5. Hub-policy sensitivity (descriptive; the production split never changes).
    sens = []
    for policy_name, policy in (
        ("registry (used)", None),
        ("degree rule (replaced)", degree_hub_policy),
        ("no exemptions", no_hub_policy),
    ):
        alt_split = split if policy is None else make_splits(table, records, hub_policy=policy)[0]
        a_tr, a_va, a_te = (table[alt_split == s] for s in ("train", "validation", "test"))
        row: dict[str, Any] = {
            "policy": policy_name,
            "counts": {
                s: {
                    "benign": int((p["label"] == 0).sum()),
                    "phishing": int((p["label"] == 1).sum()),
                }
                for s, p in (("train", a_tr), ("validation", a_va), ("test", a_te))
            },
        }
        if (
            len(a_va)
            and len(a_te)
            and a_te["label"].nunique() == 2
            and a_va["label"].nunique() == 2
        ):
            pv, pt = _fit_predict("lightgbm", FIXED_LIGHTGBM, a_tr, list(FEATURES), a_va, a_te)
            row["test"] = evaluate(
                a_te["label"].to_numpy(), pt, best_threshold(a_va["label"].to_numpy(), pv)
            )
        sens.append(row)
    out["hub_policy_sensitivity"] = sens

    # 6. Exact feature-vector duplicates between training and evaluation rows.
    def vectors(p: pd.DataFrame) -> dict[tuple[float, ...], set[int]]:
        d: dict[tuple[float, ...], set[int]] = defaultdict(set)
        for vec, lab in zip(map(tuple, p[list(FEATURES)].to_numpy()), p["label"], strict=True):
            d[vec].add(int(lab))
        return d

    train_vecs = vectors(train)
    out["duplicate_vectors"] = {
        name: {
            "rows": len(p),
            "same_vector_in_train": int(
                sum(tuple(v) in train_vecs for v in p[list(FEATURES)].to_numpy())
            ),
            "same_vector_and_label_in_train": int(
                sum(
                    lab in train_vecs.get(tuple(v), set())
                    for v, lab in zip(p[list(FEATURES)].to_numpy(), p["label"], strict=True)
                )
            ),
        }
        for name, p in (("validation", val), ("test", test))
    }

    # 7. Calibration bins (descriptive: too few benign rows to fit a calibrator).
    def bins(y: np.ndarray, s: np.ndarray) -> list[dict[str, Any]]:
        edges = np.linspace(0, 1, 6)
        rows = []
        for lo, hi in itertools.pairwise(edges):
            m = (s >= lo) & ((s < hi) if hi < 1 else (s <= hi))
            rows.append(
                {
                    "bin": [float(lo), float(hi)],
                    "rows": int(m.sum()),
                    "mean_score": float(s[m].mean()) if m.any() else None,
                    "phishing_share": float(y[m].mean()) if m.any() else None,
                }
            )
        return rows

    out["calibration"] = {
        "validation": bins(y_va, s_va),
        "test": bins(y_te, s_te),
        "train_phishing_share": float(train["label"].mean()),
    }

    # 8. Class description inside the study window (training + evaluation rows).
    used = table[split.isin(["train", "validation", "test"])]
    sel = used[list(SELECTOR)].idxmax(axis=1).where(used[list(SELECTOR)].max(axis=1) > 0, "none")
    out["class_profile"] = {
        str(lab): {
            "rows": len(g),
            "function_family": {k: int(v) for k, v in sel[g.index].value_counts().items()},
            "share_typed_fee": float(g["is_typed_fee"].mean()),
            "share_zero_value": float(g["is_zero_value"].mean()),
            "share_contract_target": float(g["to_is_contract"].mean()),
            "share_vanity_target": float((g["to_vanity_zero_nibbles"] >= 4).mean()),
            "share_failed": float(1 - g["status_success"].mean()),
            "median_sender_prior_txs": float(np.expm1(g["sender_prior_txs_log"].median())),
            "median_logs": float(g["n_logs"].median()),
        }
        for lab, g in used.groupby("label")
    }
    return out


def audit_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[
        :12
    ]


def _p(x: float | None, d: int = 3) -> str:
    return "—" if x is None else f"{x:.{d}f}"


def _iv(v: list[float] | None, d: int = 3) -> str:
    return "—" if not v else f"[{v[0]:.{d}f}, {v[1]:.{d}f}]"


def _row(*cells: object) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _head(*cells: str) -> list[str]:
    return [_row(*cells), _row(*("---" for _ in cells))]


def render_tables(a: dict[str, Any], ident: str) -> str:
    """ML_AUDIT_TABLES.md: every number traceable to audit-<id>.json (generated)."""
    b = a["baseline"]
    te, va = b["test"], b["validation"]
    c = te["confusion"]
    boot = b["test_cluster_bootstrap"]
    inp = a["inputs"]
    out: list[str] = ["# ML audit tables (generated)\n"]
    add = out.append
    add(
        f"Generated by `cryptoguard ml audit`; do not edit by hand. Audit `{ident}` of run "
        f"`{b['run_id']}` (model sha256 `{b['model_sha256'][:16]}…`), table sha256 "
        f"`{inp['table_sha256'][:16]}…`, splits sha256 `{inp['splits_sha256'][:16]}…`, seed "
        f"{a['seed']}, {a['seconds']} s. Offline: no RPC calls. Narrative and caveats: "
        "ML_GENERALIZATION_AUDIT.md.\n"
    )
    add(
        "**The test split below is a development benchmark** (examined while the method was "
        "still changing), not an untouched holdout.\n"
    )

    add("## 1. Recomputed baseline metrics\n")
    add(
        "Recomputed from the stored model with this module's own implementations and compared "
        "with the values recorded at training time.\n"
    )
    out += _head("Quantity", "Validation", "Test (dev benchmark)", "Matches recorded")
    m = b["matches_recorded"]
    for key, label in (
        ("average_precision", "AP"),
        ("roc_auc", "ROC-AUC"),
        ("recall", "Recall"),
        ("false_positive_rate", "False-positive rate"),
        ("precision", "Precision"),
        ("balanced_accuracy", "Balanced accuracy"),
        ("brier", "Brier score"),
    ):
        add(_row(label, _p(va[key]), _p(te[key]), m.get(key)))
    add(_row("Log loss", _p(va["log_loss"]), _p(te["log_loss"]), "—"))
    cm = f"{c['tp']}/{c['fp']}/{c['fn']}/{c['tn']}"
    add(_row("Confusion (tp/fp/fn/tn)", "—", cm, m["confusion"]))
    add(_row("Prevalence (phishing share)", _p(va["prevalence"]), _p(te["prevalence"]), "—"))
    add(
        _row(
            "AP above prevalence",
            _p(va["ap_above_prevalence"]),
            _p(te["ap_above_prevalence"]),
            "—",
        )
    )
    add(
        f"\nThreshold {b['threshold']:.4f}; reproduced from validation scores alone: "
        f"**{b['threshold_from_validation_only']}**.\n"
    )

    add("## 2. Uncertainty on the development test split\n")
    s = b["test_distinct_senders"]
    add(
        f"Test rows: {te['positives']} phishing from {s['phishing']} distinct senders, "
        f"{te['negatives']} benign from **{s['benign']} distinct senders**. Account clusters "
        f"(union-find over sender, target, spender, recipient): {boot['clusters']} "
        f"({boot['positive_clusters']} with phishing rows, {boot['negative_clusters']} with "
        "benign rows).\n"
    )
    out += _head("Quantity", "Estimate", "Wilson 95% (rows independent)", "Cluster bootstrap 95%")
    flagged = c["tp"] + c["fp"]
    add(
        _row(
            "Recall",
            f"{c['tp']}/{te['positives']} = {_p(te['recall'])}",
            _iv(te["recall_wilson"]),
            _iv(boot["recall"]),
        )
    )
    add(
        _row(
            "False-positive rate",
            f"{c['fp']}/{te['negatives']} = {_p(te['false_positive_rate'])}",
            _iv(te["fpr_wilson"]),
            _iv(boot["false_positive_rate"]),
        )
    )
    add(
        _row(
            "Precision",
            f"{c['tp']}/{flagged} = {_p(te['precision'])}",
            _iv(te["precision_wilson"]),
            "—",
        )
    )
    add(_row("AP", _p(te["average_precision"]), "—", _iv(boot["average_precision"])))
    add(f"\nBootstrap: {boot['resamples_used']} resamples containing both classes.\n")
    add(
        "Benign rows needed to bound the false-positive rate below a target with 95% "
        "confidence when **zero** false positives are observed:\n"
    )
    out += _head("Target FPR", "Benign rows needed")
    for t, n in a["negatives_needed"].items():
        add(_row(f"{float(t):.1%}", f"{n:,}"))
    add("")

    add("## 3. Low-prevalence scenarios (arithmetic, not measurement)\n")
    add(
        f"Using the development-test recall {_p(te['recall'])} and false-positive rate "
        f"{_p(te['false_positive_rate'])} (Wilson range {_iv(te['fpr_wilson'])}), per 10,000 "
        "transactions:\n"
    )
    out += _head(
        "Assumed phishing prevalence",
        "True alerts",
        "False alerts (range)",
        "Alerts",
        "Precision (range)",
    )
    for r in a["prevalence_scenarios"]:
        fr, pr = r["false_alerts_range"], r["precision_range"]
        add(
            _row(
                f"{r['prevalence']:.2%}",
                f"{r['true_alerts']:.1f}",
                f"{r['false_alerts']:.0f} ({fr[0]:.0f} to {fr[1]:.0f})",
                f"{r['alerts']:.0f}",
                f"{_p(r['precision'])} ({_p(pr[0])} to {_p(pr[1])})",
            )
        )
    add("")

    add("## 4. Shortcut experiments\n")
    add(
        "Fixed hyperparameters (LightGBM: the Phase 11 selection; logistic regression: C=1), "
        "threshold from validation, no tuning per feature set. Test = development benchmark.\n"
    )
    out += _head(
        "Features", "n", "Model", "Val AP", "Test AP", "Test ROC-AUC", "Test recall", "Test FPR"
    )
    for r in a["ablations"]:
        v, t = r["validation"], r["test"]
        add(
            _row(
                r["features"],
                r["n_features"],
                r["model"],
                _p(v["average_precision"]),
                _p(t["average_precision"]),
                _p(t["roc_auc"]),
                _p(t["recall"]),
                _p(t["false_positive_rate"]),
            )
        )
    add("")

    add("## 5. Sensitivity to the hub policy (descriptive; the split is not chosen by this)\n")
    out += _head(
        "Policy", "Train b/p", "Validation b/p", "Test b/p", "Test AP", "Test ROC-AUC", "Test FPR"
    )
    for r in a["hub_policy_sensitivity"]:
        k, t = r["counts"], r.get("test") or {}
        add(
            _row(
                r["policy"],
                f"{k['train']['benign']}/{k['train']['phishing']}",
                f"{k['validation']['benign']}/{k['validation']['phishing']}",
                f"{k['test']['benign']}/{k['test']['phishing']}",
                _p(t.get("average_precision")),
                _p(t.get("roc_auc")),
                _p(t.get("false_positive_rate")),
            )
        )
    add("")

    add("## 6. Identical feature vectors across splits\n")
    out += _head("Split", "Rows", "Same vector in train", "Same vector and label in train")
    for name, d in a["duplicate_vectors"].items():
        add(_row(name, d["rows"], d["same_vector_in_train"], d["same_vector_and_label_in_train"]))
    add("")

    add("## 7. Calibration (descriptive)\n")
    add(f"Training data were {a['calibration']['train_phishing_share']:.0%} phishing.\n")
    out += _head(
        "Score bin",
        "Val rows",
        "Val mean score",
        "Val phishing share",
        "Test rows",
        "Test mean score",
        "Test phishing share",
    )
    for bv, bt in zip(a["calibration"]["validation"], a["calibration"]["test"], strict=True):
        add(
            _row(
                f"{bv['bin'][0]:.1f} to {bv['bin'][1]:.1f}",
                bv["rows"],
                _p(bv["mean_score"]),
                _p(bv["phishing_share"]),
                bt["rows"],
                _p(bt["mean_score"]),
                _p(bt["phishing_share"]),
            )
        )
    add("")

    add("## 8. Class profile inside the study window (train, validation and test rows)\n")
    prof = a["class_profile"]
    out += _head("Property", "Benign", "Phishing")
    for key, label in (
        ("rows", "Rows"),
        ("share_typed_fee", "EIP-1559 fee fields present"),
        ("share_zero_value", "Zero ETH value"),
        ("share_contract_target", "Target is a contract"),
        ("share_vanity_target", "Target has 4+ vanity zero nibbles"),
        ("share_failed", "Reverted"),
        ("median_sender_prior_txs", "Median sender prior transactions"),
        ("median_logs", "Median logs"),
    ):
        add(_row(label, f"{prof['0'][key]:.3g}", f"{prof['1'][key]:.3g}"))
    families = sorted(set(prof["0"]["function_family"]) | set(prof["1"]["function_family"]))
    for f in families:
        add(
            _row(
                f"Function family `{f}`",
                prof["0"]["function_family"].get(f, 0),
                prof["1"]["function_family"].get(f, 0),
            )
        )
    add("")

    add("## 9. Errors on the development test split\n")
    for kind in ("false_positives", "false_negatives"):
        add(f"**{kind.replace('_', ' ').capitalize()}** ({len(a['errors'][kind])}):\n")
        out += _head(
            "Transaction",
            "Subtype",
            "Score",
            "transfer()",
            "transferFrom()",
            "Other fn",
            "Logs",
            "Transfers",
            "Vanity nibbles",
            "Zero ETH",
        )
        for e in a["errors"][kind]:
            add(
                _row(
                    f"`{e['tx_hash'][:18]}…`",
                    e["subtype"],
                    f"{e['score']:.3f}",
                    f"{e['fn_transfer']:.0f}",
                    f"{e['fn_transfer_from']:.0f}",
                    f"{e['fn_other']:.0f}",
                    f"{e['n_logs']:.0f}",
                    f"{e['n_transfers']:.0f}",
                    f"{e['to_vanity_zero_nibbles']:.0f}",
                    f"{e['is_zero_value']:.0f}",
                )
            )
        add("")
    return "\n".join(out)

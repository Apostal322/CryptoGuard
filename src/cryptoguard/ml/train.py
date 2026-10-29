"""Train, select and evaluate phishing-transaction classifiers (CPU, seconds).

Protocol: every choice (hyperparameters, decision threshold, feature set, which model is
"selected") is made on the validation split. The test split is scored once, at the end,
for every model family, so baselines and models are compared on identical rows.

Baselines:

- ``majority`` and ``stratified``: trivial (sklearn ``DummyClassifier``);
- ``rule_phishing_shape``: a hand-written heuristic ("delegated transfer, permit, operator
  grant, upgrade, bare-selector call with value, or zero-value transfer");
- ``rule_cryptoguard_signals``: the transaction-level signals CryptoGuard's detectors use
  (unlimited allowance, operator grant, zero-value transfer, lookalike affix >= 7). This is a
  proxy: CryptoGuard's detectors are wallet-centric and need the wallet's history, which
  this dataset does not contain, so the real detector cannot be run on it.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.ml import FEATURE_SET_VERSION, ML_VERSION
from cryptoguard.ml.features import FEATURES

if TYPE_CHECKING:
    import numpy as np
    import pandas as pd

SEED = 20261029

# Features that describe *who* rather than *what*: long sender histories (the benign class
# is "KOL" and developer accounts) and vanity-mined addresses. Real signals, but also the
# likeliest dataset-construction artefacts, so every model is also trained without them.
IDENTITY_FEATURES = ("sender_prior_txs_log", "from_vanity_zero_nibbles", "to_vanity_zero_nibbles")
FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "full": FEATURES,
    "no_identity": tuple(f for f in FEATURES if f not in IDENTITY_FEATURES),
}


@dataclass
class ModelResult:
    name: str
    kind: str  # "trivial" | "rule" | "learned"
    feature_set: str | None
    params: dict[str, Any]
    validation: dict[str, Any]
    test: dict[str, Any] = field(default_factory=dict)
    threshold: float = 0.5


def _git_sha() -> str:
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _versions() -> dict[str, str]:
    import importlib.metadata as md

    out = {"python": platform.python_version()}
    for pkg in ("cryptoguard", "numpy", "pandas", "scikit-learn", "lightgbm", "pandera"):
        try:
            out[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            out[pkg] = "missing"
    return out


def rule_scores(frame: pd.DataFrame, rule: str) -> np.ndarray:
    import numpy as np

    if rule == "rule_phishing_shape":
        hit = (
            (frame["fn_transfer_from"] > 0)
            | (frame["fn_permit"] > 0)
            | (frame["fn_set_approval_for_all"] > 0)
            | (frame["fn_upgrade"] > 0)
            | ((frame["input_is_bare_selector"] > 0) & (frame["is_zero_value"] == 0))
            | (frame["n_zero_value_transfers"] > 0)
        )
    elif rule == "rule_cryptoguard_signals":
        hit = (
            (frame["n_unlimited_approvals"] > 0)
            | (frame["n_approval_for_all_granted"] > 0)
            | (frame["n_zero_value_transfers"] > 0)
            | (frame["max_party_affix_match"] >= 7)
        )
    else:
        raise ValueError(rule)
    return np.asarray(hit, dtype=float)


def metrics(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    import numpy as np
    from sklearn.metrics import (
        average_precision_score,
        balanced_accuracy_score,
        brier_score_loss,
        confusion_matrix,
        f1_score,
        log_loss,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    pred = (score >= threshold).astype(int)
    both = len(np.unique(y)) == 2
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    prevalence = float(y.mean()) if len(y) else 0.0
    ap = float(average_precision_score(y, score)) if both else None
    return {
        "rows": len(y),
        "positives": int(y.sum()),
        "prevalence": prevalence,
        "average_precision": ap,
        # AP is at least the positive share; lift = share of the remaining room achieved.
        "ap_lift": None if ap is None or prevalence >= 1 else (ap - prevalence) / (1 - prevalence),
        "roc_auc": float(roc_auc_score(y, score)) if both else None,
        "log_loss": float(log_loss(y, np.clip(score, 1e-6, 1 - 1e-6), labels=[0, 1])),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)) if both else None,
        "brier": float(brier_score_loss(y, np.clip(score, 0, 1))),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def best_threshold(y: np.ndarray, score: np.ndarray) -> float:
    """Threshold maximising F1 on the given (validation) rows."""
    import numpy as np
    from sklearn.metrics import f1_score

    candidates = np.unique(score)
    if len(candidates) > 200:
        candidates = np.quantile(score, np.linspace(0, 1, 201))
    f1s = [f1_score(y, (score >= t).astype(int), zero_division=0) for t in candidates]
    return float(candidates[int(np.argmax(f1s))])


def bootstrap_ci(
    y: np.ndarray, score: np.ndarray, threshold: float, n: int = 1000
) -> dict[str, list[float]]:
    """95% percentile intervals for test AP, recall and false-positive rate (seeded
    resamples of rows)."""
    import numpy as np
    from sklearn.metrics import average_precision_score, recall_score

    rng = np.random.default_rng(SEED)
    ap, rec, fpr = [], [], []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if len(np.unique(y[idx])) < 2:
            continue
        pred = (score[idx] >= threshold).astype(int)
        ap.append(average_precision_score(y[idx], score[idx]))
        rec.append(recall_score(y[idx], pred, zero_division=0))
        neg = y[idx] == 0
        fpr.append(float(pred[neg].mean()))

    def q(values: list[float]) -> list[float]:
        return [float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))]

    return {"average_precision": q(ap), "recall": q(rec), "false_positive_rate": q(fpr)}


def _candidates() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    out += [("logistic_regression", {"C": c}) for c in (0.01, 0.1, 1.0, 10.0)]
    out += [("random_forest", {"min_samples_leaf": m}) for m in (1, 3, 10)]
    out += [
        ("lightgbm", {"num_leaves": nl, "min_child_samples": mc})
        for nl in (7, 15)
        for mc in (5, 20)
    ]
    return out


def make_model(name: str, params: dict[str, Any]):  # type: ignore[no-untyped-def]
    if name == "logistic_regression":
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler

        return make_pipeline(
            StandardScaler(),
            LogisticRegression(
                C=params["C"], class_weight="balanced", max_iter=2_000, random_state=SEED
            ),
        )
    if name == "random_forest":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=params["min_samples_leaf"],
            class_weight="balanced_subsample",
            n_jobs=2,
            random_state=SEED,
        )
    if name == "lightgbm":
        from lightgbm import LGBMClassifier

        return LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=params["num_leaves"],
            min_child_samples=params["min_child_samples"],
            subsample=0.8,
            subsample_freq=1,
            colsample_bytree=0.8,
            class_weight="balanced",
            n_jobs=2,
            random_state=SEED,
            deterministic=True,
            force_col_wise=True,
            verbose=-1,
        )
    raise ValueError(name)


def run_training(table: pd.DataFrame, split: pd.Series) -> dict[str, Any]:
    """Fit everything, select on validation, score test once. Returns the full result."""
    import numpy as np
    from sklearn.dummy import DummyClassifier
    from sklearn.inspection import permutation_importance

    started = time.perf_counter()
    train, val, test = (table[split == s] for s in ("train", "validation", "test"))
    y_tr, y_va, y_te = (part["label"].to_numpy() for part in (train, val, test))
    results: list[ModelResult] = []
    fitted: dict[tuple[str, str], Any] = {}

    for strategy in ("most_frequent", "stratified"):
        dummy = DummyClassifier(strategy=strategy, random_state=SEED).fit(
            train[list(FEATURES)], y_tr
        )
        s_va = dummy.predict_proba(val[list(FEATURES)])[:, 1]
        res = ModelResult(
            "majority" if strategy == "most_frequent" else "stratified",
            "trivial",
            None,
            {"strategy": strategy},
            metrics(y_va, s_va, 0.5),
        )
        res.test = metrics(y_te, dummy.predict_proba(test[list(FEATURES)])[:, 1], 0.5)
        results.append(res)
    for rule in ("rule_phishing_shape", "rule_cryptoguard_signals"):
        res = ModelResult(rule, "rule", None, {}, metrics(y_va, rule_scores(val, rule), 0.5))
        res.test = metrics(y_te, rule_scores(test, rule), 0.5)
        res.test["ci95"] = bootstrap_ci(y_te, rule_scores(test, rule), 0.5)
        results.append(res)

    # Learned models: every candidate scored on validation; best per (family, feature set) by
    # validation log loss (a proper scoring rule: AP saturates near 1 on this data).
    best: dict[tuple[str, str], tuple[float, dict[str, Any], Any, np.ndarray]] = {}
    for fs_name, fs_tuple in FEATURE_SETS.items():
        for name, params in _candidates():
            model = make_model(name, params).fit(train[list(fs_tuple)], y_tr)
            s_va = model.predict_proba(val[list(fs_tuple)])[:, 1]
            loss = metrics(y_va, s_va, 0.5)["log_loss"]
            key = (name, fs_name)
            if key not in best or loss < best[key][0]:
                best[key] = (loss, params, model, s_va)
    for (name, fs_name), (_, params, model, s_va) in sorted(best.items()):
        fs_cols = list(FEATURE_SETS[fs_name])
        thr = best_threshold(y_va, s_va)
        res = ModelResult(name, "learned", fs_name, params, metrics(y_va, s_va, thr), threshold=thr)
        s_te = model.predict_proba(test[fs_cols])[:, 1]
        res.test = metrics(y_te, s_te, thr)
        res.test["ci95"] = bootstrap_ci(y_te, s_te, thr)
        res.test["recall_by_family"] = {
            fam: float(
                ((s_te >= thr) & (test["family"] == fam).to_numpy()).sum()
                / max((test["family"] == fam).sum(), 1)
            )
            for fam in sorted(test.loc[test["label"] == 1, "family"].unique())
        }
        fitted[(name, fs_name)] = model
        results.append(res)

    learned = [r for r in results if r.kind == "learned"]
    selected = min(learned, key=lambda r: r.validation["log_loss"])
    model = fitted[(selected.name, selected.feature_set or "full")]
    cols = list(FEATURE_SETS[selected.feature_set or "full"])
    imp = permutation_importance(
        model, val[cols], y_va, scoring="neg_log_loss", n_repeats=5, random_state=SEED, n_jobs=1
    )
    importance: list[dict[str, Any]] = sorted(
        (
            {"feature": c, "mean": float(m), "std": float(s)}
            for c, m, s in zip(cols, imp.importances_mean, imp.importances_std, strict=True)
        ),
        key=lambda d: -float(d["mean"]),
    )
    s_te = model.predict_proba(test[cols])[:, 1]
    errors = test.assign(score=s_te)
    fn = errors[(errors["label"] == 1) & (errors["score"] < selected.threshold)]
    fp = errors[(errors["label"] == 0) & (errors["score"] >= selected.threshold)]
    return {
        "results": results,
        "selected": selected,
        "model": model,
        "feature_columns": cols,
        "importance": importance,
        "errors": {
            "false_negatives": fn.sort_values("score")[["tx_hash", "family", "subtype", "score"]]
            .head(15)
            .to_dict("records"),
            "false_positives": fp.sort_values("score", ascending=False)[
                ["tx_hash", "subtype", "score"]
            ]
            .head(15)
            .to_dict("records"),
        },
        "seconds": round(time.perf_counter() - started, 1),
        "reference": {
            c: [float(q) for q in np.quantile(train[c], np.linspace(0, 1, 11))] for c in cols
        },
    }


GATE_GAP_REDUCTION = 0.5


def promotion_gate(results: list[ModelResult], selected: ModelResult) -> dict[str, Any]:
    """A model is validated for shadow mode only if (1) on validation it closes at least half
    of the AP gap between the best non-learned baseline and a perfect ranking, and (2) its
    test AP interval lies entirely above the best baseline's test AP.

    Revised before the final run: the first version demanded "+0.05 AP over the best
    baseline", which cannot be met when that baseline already exceeds 0.95 (as on a
    partial-data dry run). Documented in ML.md.
    """
    baselines = [r for r in results if r.kind != "learned"]
    base_val = max(r.validation["average_precision"] or 0.0 for r in baselines)
    base_test = max(r.test["average_precision"] or 0.0 for r in baselines)
    model_val = selected.validation["average_precision"] or 0.0
    gap_closed = (model_val - base_val) / (1 - base_val) if base_val < 1 else 0.0
    val_ok = gap_closed >= GATE_GAP_REDUCTION
    test_ok = selected.test["ci95"]["average_precision"][0] > base_test
    return {
        "best_baseline_validation_ap": base_val,
        "best_baseline_test_ap": base_test,
        "validation_gap_closed": gap_closed,
        "required_gap_reduction": GATE_GAP_REDUCTION,
        "validation_beats_baselines": bool(val_ok),
        "test_interval_above_best_baseline": bool(test_ok),
        "validated_for_shadow": bool(val_ok and test_ok),
    }


def ledger_entry(
    run_id: str,
    config: dict[str, Any],
    out: dict[str, Any],
    gate: dict[str, Any],
    manifest_sha: str,
) -> dict[str, Any]:
    sel: ModelResult = out["selected"]
    return {
        "run_id": run_id,
        "ml_version": ML_VERSION,
        "feature_set_version": FEATURE_SET_VERSION,
        "git": _git_sha(),
        "versions": _versions(),
        "config": config,
        "dataset_manifest_sha256": manifest_sha,
        "selected": {
            "name": sel.name,
            "feature_set": sel.feature_set,
            "params": sel.params,
            "threshold": sel.threshold,
        },
        "validation": sel.validation,
        "test": sel.test,
        "gate": gate,
        "seconds": out["seconds"],
        "results": [asdict(r) for r in out["results"]],
    }


def save_run(run_dir: Path, entry: dict[str, Any], out: dict[str, Any]) -> Path:
    """Persist the selected model with a hash-pinned card (``registry.load_model`` checks it)."""
    import hashlib

    import joblib

    run_dir.mkdir(parents=True, exist_ok=True)
    model_path = run_dir / "model.joblib"
    joblib.dump(out["model"], model_path)
    card = {
        "run_id": entry["run_id"],
        "ml_version": ML_VERSION,
        "feature_set_version": FEATURE_SET_VERSION,
        "feature_columns": out["feature_columns"],
        "threshold": entry["selected"]["threshold"],
        "selected": entry["selected"],
        "gate": entry["gate"],
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "reference_quantiles": out["reference"],
        "trained_on": entry["config"],
    }
    (run_dir / "model_card.json").write_text(json.dumps(card, indent=1), encoding="utf-8")
    (run_dir / "run.json").write_text(json.dumps(entry, indent=1, default=str), encoding="utf-8")
    return run_dir

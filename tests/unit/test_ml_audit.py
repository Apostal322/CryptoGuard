"""Audit statistics are correct (they decide what the generalization report claims)."""

from __future__ import annotations

import pytest

pytest.importorskip("sklearn")

import numpy as np

from cryptoguard.ml.audit import (
    cluster_bootstrap,
    confusion,
    evaluate,
    negatives_needed,
    prevalence_scenarios,
    roc_auc,
    wilson,
)


def test_wilson_matches_reference_values() -> None:
    # Reference: Wilson score interval, z = 1.96 (e.g. statsmodels proportion_confint).
    lo, hi = wilson(7, 43)
    assert lo == pytest.approx(0.0810, abs=5e-4)
    assert hi == pytest.approx(0.2999, abs=5e-4)
    assert wilson(0, 10)[0] == 0.0
    assert wilson(10, 10)[1] == 1.0
    assert wilson(0, 0) is None


def test_auc_matches_sklearn_with_ties() -> None:
    from sklearn.metrics import roc_auc_score

    rng = np.random.default_rng(1)
    for _ in range(30):
        y = rng.integers(0, 2, 50)
        y[:2] = [0, 1]
        s = rng.integers(0, 4, 50) / 3
        assert roc_auc(y, s) == pytest.approx(roc_auc_score(y, s), abs=1e-12)
    assert roc_auc(np.ones(5), np.arange(5.0)) is None


def test_threshold_boundary_counts_as_flagged() -> None:
    y = np.array([1, 0, 1, 0])
    s = np.array([0.5, 0.5, 0.49, 0.1])
    assert confusion(y, s, 0.5) == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}


def test_evaluate_reports_prevalence_and_handles_one_class() -> None:
    y = np.array([1, 1, 1, 0])
    e = evaluate(y, np.array([0.9, 0.8, 0.7, 0.1]), 0.5)
    assert e["prevalence"] == 0.75
    assert e["average_precision"] == 1.0
    assert e["ap_above_prevalence"] == pytest.approx(0.25)
    one = evaluate(np.ones(3, dtype=int), np.array([0.2, 0.3, 0.9]), 0.5)
    assert one["average_precision"] is None
    assert one["false_positive_rate"] is None
    assert one["fpr_wilson"] is None


def test_cluster_bootstrap_is_wider_than_pretending_rows_are_independent() -> None:
    rng = np.random.default_rng(3)
    clusters = np.repeat(np.arange(12), 10)  # 12 accounts x 10 rows
    y = np.tile([0, 1], 60)
    # Whole clusters err together: cluster-level dependence.
    noisy = np.isin(clusters, [0, 1, 2])
    s = np.where(noisy, 1 - y, y) * 0.8 + rng.uniform(0, 0.2, 120)
    by_cluster = cluster_bootstrap(y, s, 0.5, clusters, n=500)
    by_row = cluster_bootstrap(y, s, 0.5, np.arange(120), n=500)
    width = lambda iv: iv[1] - iv[0]  # noqa: E731
    assert width(by_cluster["false_positive_rate"]) > width(by_row["false_positive_rate"])
    assert by_cluster["clusters"] == 12


def test_negatives_needed_follows_the_rule_of_three() -> None:
    assert negatives_needed(0.01) == 299
    assert negatives_needed(0.001) == 2_995
    assert negatives_needed(0.05) == 59


def test_prevalence_scenarios_arithmetic() -> None:
    rows = prevalence_scenarios(recall=1.0, fpr=0.1, fpr_interval=[0.05, 0.2])
    one_percent = next(r for r in rows if r["prevalence"] == 0.01)
    assert one_percent["true_alerts"] == pytest.approx(100)
    assert one_percent["false_alerts"] == pytest.approx(990)
    assert one_percent["precision"] == pytest.approx(100 / 1090)
    assert one_percent["false_alerts_range"] == pytest.approx([495, 1980])

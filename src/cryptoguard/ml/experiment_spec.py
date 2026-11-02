"""Pre-registered specification of the first supervised ``poisoning-attempt/1`` experiment
(Phase 11.6). It stays **inactive** until ``activation_check`` passes on real, independently
reviewed labels. Synthetic labels may exercise the code but never activate it.

Everything a result depends on is fixed here, before any label exists:
- the prediction unit, cutoff, target and eligibility;
- the split, threshold rule, metrics and calibration;
- the baselines, feature groups and resource budget.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptoguard.ml.label_policy import POLICY_VERSION

SPEC_VERSION = "poisoning-attempt-supervised/1"
MIN_PER_CLASS = 30  # events.quality_gates gate B
MIN_GROUPS_PER_CLASS = 5  # gate D
FORBIDDEN_COLUMN_WORDS = (
    "label",
    "source",
    "dataset",
    "cohort",
    "frame",
    "row",
    "line",
    "file",
    "outcome",
    "payoff",
    "loss",
    "score",
    "screen",
)

FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "similarity_only": (
        "prefix_to_imitated",
        "suffix_to_imitated",
        "plausible_impersonated",
        "recipient_lookalike_of_known",
        "recipient_max_affix_to_known",
    ),
    "transaction_only": (
        "value_is_zero",
        "token_trusted",
        "subtype_dust",
        "subtype_fake_token",
        "subtype_other",
        "subtype_spoofed_transfer_from",
        "subtype_zero_value",
    ),
    "wallet_history_only": (
        "prior_payments_to_recipient",
        "prior_interactions_with_recipient",
        "distinct_prior_recipients",
        "recent_new_recipient_share",
        "unsolicited_events_with_recipient",
        "history_available",
        "history_partial",
        "observed_blocks",
    ),
    "temporal_only": (
        "blocks_since_first_interaction",
        "blocks_since_last_interaction",
        "blocks_since_imitated_chosen",
        "recent_unsolicited_in",
    ),
    "graph_context_only": (
        "lookalike_victims_before",
        "signer_victims_before",
        "lookalike_plantings_observed",
    ),
}
FEATURE_GROUPS["combined"] = tuple(c for g in list(FEATURE_GROUPS.values()) for c in g)

SPEC: dict[str, Any] = {
    "version": SPEC_VERSION,
    "status": "inactive",
    "prediction_unit": "victim-event: one candidate transfer to or from one wallet",
    "cutoff": "after the candidate's transaction executes, before anything later in its block",
    "target": f"{POLICY_VERSION} strict binary: reviewed_attack=1, reviewed_legitimate=0",
    "eligibility": "candidates/2 outputs with complete or partial recorded history; "
    "known-positive overlaps never serve as negatives",
    "populations": {
        "train": "reviewed items outside both frozen review cohorts",
        "validation": "grouped-temporal split of the training population",
        "test": "a later, untouched set; the frozen cohorts count only if never used in "
        "development (benchmark.Holdout)",
    },
    "split": "grouped-temporal/1 with typed-groups/1 entities (victim, lookalike, planting "
    "tx, signer, imitated, counterfeit token); public tokens and routers never link",
    "threshold": "chosen on validation only: the highest recall with FPR <= 5%",
    "primary_metric": "average precision on test, reported with recall at FPR <= 5%",
    "secondary_metrics": [
        "precision",
        "recall",
        "FPR",
        "ROC-AUC",
        "precision at review capacity 50",
        "candidate recall (separately)",
        "latency",
    ],
    "calibration": "reliability curve and Brier score only with >= 100 reviewed items per class",
    "baselines": [
        "detectors.poisoning (production rule)",
        "similarity heuristic (candidates.similar)",
        "transaction-shape heuristic (subtype)",
        "wallet-history heuristic (no prior payment to the recipient)",
        "logistic regression",
        "LightGBM",
    ],
    "feature_groups": FEATURE_GROUPS,
    "resource_budget": "CPU only, < 2 GB RAM, < 2 minutes per fit (larger needs approval)",
    "no_gnn": "graph context enters as tabular features; no GNN without a new hypothesis",
}


def forbidden_columns(columns: tuple[str, ...]) -> list[str]:
    return [c for c in columns if any(w in c.lower() for w in FORBIDDEN_COLUMN_WORDS)]


def activation_check(labels: Mapping[str, int], groups: Mapping[str, str]) -> dict[str, Any]:
    """``labels``: strict binary labels from ``label_policy.strict_benchmark``; ``groups``:
    campaign group per event. Returns ``active`` and every unmet requirement."""
    reasons = []
    pos = [e for e, y in labels.items() if y == 1]
    neg = [e for e, y in labels.items() if y == 0]
    for name, ids in (("reviewed_attack", pos), ("reviewed_legitimate", neg)):
        if len(ids) < MIN_PER_CLASS:
            reasons.append(f"{len(ids)} {name} labels; need {MIN_PER_CLASS}")
        n_groups = len({groups.get(e, e) for e in ids})
        if n_groups < MIN_GROUPS_PER_CLASS:
            reasons.append(f"{n_groups} {name} campaign groups; need {MIN_GROUPS_PER_CLASS}")
    bad = forbidden_columns(FEATURE_GROUPS["combined"])
    if bad:
        reasons.append(f"forbidden feature columns: {bad}")
    return {"spec": SPEC_VERSION, "active": not reasons, "unmet": reasons}

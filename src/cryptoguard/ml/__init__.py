"""Experimental machine-learning subsystem (needs the ``ml`` extra).

Phishing-transaction classification trained on independently labelled public data
(PTXPhish, NDSS 2025), with point-in-time features read from the chain. Shadow mode only:
scores are context for a human reviewer and never create, change or resolve findings.
See ML.md for data, method, results and limitations.

Heavy libraries (pandas, scikit-learn, LightGBM) are imported inside the functions that
need them, never at module import.
"""

from __future__ import annotations

ML_VERSION = "cg-ml/0.1.0"
FEATURE_SET_VERSION = "ptx-features/1"
# The Phase 11 model's task: is a mined transaction part of a phishing operation? Cards
# without a task field predate it and belong to this task.
TRANSACTION_TASK_ID = "ptxphish-transaction-phishing/1"


def ml_available() -> bool:
    import importlib.util

    return all(
        importlib.util.find_spec(name) is not None
        for name in ("pandas", "pandera", "sklearn", "lightgbm", "openpyxl")
    )

"""Feature-distribution monitoring for shadow scoring (population stability index).

The model card stores training deciles for every feature. Each shadow-scored feature vector
is appended to a local log; ``drift_report`` compares the logged values with the training
deciles. PSI below 0.1 is usually read as stable, 0.1-0.25 as a moderate shift, above 0.25
as a large one: the model is then scoring data unlike what it was trained on.
"""

from __future__ import annotations

import bisect
import json
import math
from pathlib import Path
from typing import Any

DEFAULT_LOG = Path("data") / "ml" / "shadow_scores.jsonl"
MIN_ROWS = 30


def reference_bins(train_values: list[float]) -> dict[str, list[float]]:
    """Bin edges (distinct interior training deciles) and the training share per bin.
    Shares are counted, not assumed equal: binary and count features have tied deciles."""
    ordered = sorted(train_values)
    n = len(ordered)
    deciles = [ordered[min(int(n * q / 10), n - 1)] for q in range(1, 10)]
    edges = sorted(set(deciles))
    counts = [0] * (len(edges) + 1)
    for v in ordered:
        counts[bisect.bisect_right(edges, v)] += 1
    return {"edges": edges, "expected": [c / n for c in counts]}


def psi(reference: dict[str, list[float]], values: list[float]) -> float:
    """Population stability index of ``values`` against the training bins."""
    edges, expected = reference["edges"], reference["expected"]
    counts = [0] * len(expected)
    for v in values:
        counts[bisect.bisect_right(edges, v)] += 1
    total = len(values) or 1
    eps = 1e-4
    return sum(
        (max(c / total, eps) - max(e, eps)) * math.log(max(c / total, eps) / max(e, eps))
        for c, e in zip(counts, expected, strict=True)
    )


def log_score(entry: dict[str, Any], path: Path = DEFAULT_LOG) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


def drift_report(card: dict[str, Any], path: Path = DEFAULT_LOG) -> dict[str, Any]:
    rows = []
    if path.exists():
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    rows = [r for r in rows if r.get("run_id") == card["run_id"]]
    if len(rows) < MIN_ROWS:
        return {"status": "insufficient_data", "rows": len(rows), "min_rows": MIN_ROWS}
    reference = card["reference_bins"]
    scores = {
        feature: psi(reference[feature], [float(r["features"][feature]) for r in rows])
        for feature in card["feature_columns"]
    }
    worst = sorted(scores.items(), key=lambda kv: -kv[1])
    return {
        "status": "ok",
        "rows": len(rows),
        "psi": dict(worst),
        "shifted": [f for f, v in worst if v > 0.25],
        "moderate": [f for f, v in worst if 0.1 < v <= 0.25],
    }

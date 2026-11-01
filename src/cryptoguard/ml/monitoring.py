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


MAX_LOG_ROWS = 10_000  # only the most recent scores are read (the log is append-only)


def _quantiles(values: list[float], qs: tuple[float, ...]) -> dict[str, float] | None:
    if not values:
        return None
    ordered = sorted(values)
    return {f"p{round(q * 100)}": ordered[min(int(q * len(ordered)), len(ordered) - 1)] for q in qs}


def drift_report(card: dict[str, Any], path: Path = DEFAULT_LOG) -> dict[str, Any]:
    """Input drift of recent shadow scores against the training reference.

    This measures *data* drift (PSI per feature) and *prediction* drift (score
    distribution), plus coverage failures and latency. Without labels it cannot show that
    accuracy degraded (concept drift or performance loss): a stable PSI is not evidence of
    a working model."""
    lines: list[str] = []
    if path.exists():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line][
            -MAX_LOG_ROWS:
        ]
    rows: list[dict[str, Any]] = []
    unreadable = 0
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if row.get("run_id") == card["run_id"]:
            rows.append(row)
    columns = list(card["feature_columns"])
    scored = [r for r in rows if r.get("status", "scored") == "scored" and "features" in r]
    valid = [r for r in scored if sorted(r["features"]) == sorted(columns)]
    statuses: dict[str, int] = {}
    for r in rows:
        statuses[r.get("status", "scored")] = statuses.get(r.get("status", "scored"), 0) + 1
    latencies = [float(r["latency_ms"]) for r in rows if "latency_ms" in r]
    summary: dict[str, Any] = {
        "rows": len(rows),
        "status_counts": statuses,
        "schema_mismatches": len(scored) - len(valid),
        "unreadable_lines": unreadable,
        "latency_ms": _quantiles(latencies, (0.5, 0.95)),
        "scores": _quantiles([float(r["score"]) for r in valid], (0.1, 0.5, 0.9)),
        "share_above_threshold": (
            sum(float(r["score"]) >= float(card["threshold"]) for r in valid) / len(valid)
            if valid
            else None
        ),
        "note": "Data and prediction drift only; without labels, accuracy cannot be monitored.",
    }
    if len(valid) < MIN_ROWS:
        return {"status": "insufficient_data", "min_rows": MIN_ROWS, **summary}
    reference = card["reference_bins"]
    scores = {
        feature: psi(reference[feature], [float(r["features"][feature]) for r in valid])
        for feature in columns
    }
    worst = sorted(scores.items(), key=lambda kv: -kv[1])
    return {
        "status": "ok",
        **summary,
        "psi": dict(worst),
        "shifted": [f for f, v in worst if v > 0.25],
        "moderate": [f for f, v in worst if 0.1 < v <= 0.25],
    }

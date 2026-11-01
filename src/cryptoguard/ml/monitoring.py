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


def _bin(edges: list[float], value: float, closed: str) -> int:
    # "right": a value equal to an edge goes to the upper bin (Phase 11 cards, bisect_right).
    # "left": a value equal to an edge stays in the lower bin, so a tied decile (e.g. a
    # mostly-zero count feature) keeps its own bin and a shift away from it is visible.
    if closed == "left":
        return bisect.bisect_left(edges, value)
    return bisect.bisect_right(edges, value)


def reference_bins(train_values: list[float]) -> dict[str, Any]:
    """Bin edges (distinct interior training deciles) and the training share per bin.
    Shares are counted, not assumed equal: binary and count features have tied deciles.

    New references use ``closed="left"``. Phase 11 cards have no ``closed`` key and keep
    their original ``bisect_right`` binning, with which a feature that is mostly one value
    falls into a single bin (its shifts are invisible); see ML.md."""
    ordered = sorted(train_values)
    n = len(ordered)
    deciles = [ordered[min(int(n * q / 10), n - 1)] for q in range(1, 10)]
    edges = sorted(set(deciles))
    counts = [0] * (len(edges) + 1)
    for v in ordered:
        counts[_bin(edges, v, "left")] += 1
    return {"edges": edges, "expected": [c / n for c in counts], "closed": "left"}


def _present(values: list[float | None]) -> list[float]:
    return [v for v in values if v is not None and not math.isnan(v)]


def missing_share(values: list[float | None]) -> float | None:
    """Share of missing (None or NaN) values; None for an empty batch."""
    return None if not values else 1 - len(_present(values)) / len(values)


def psi(reference: dict[str, Any], values: list[float | None]) -> float | None:
    """Population stability index of the present ``values`` against the training bins.

    Missing values are excluded (report them with ``missing_share``; NaN would otherwise
    fall into the first bin silently) and an empty batch has no PSI (None, not 0 or a large
    number). Zero-frequency bins are floored at 1e-4 on both sides."""
    present = _present(values)
    if not present:
        return None
    edges, expected = reference["edges"], reference["expected"]
    counts = [0] * len(expected)
    closed = reference.get("closed", "right")
    for v in present:
        counts[_bin(edges, v, closed)] += 1
    total = len(present)
    eps = 1e-4
    return float(
        sum(
            (max(c / total, eps) - max(e, eps)) * math.log(max(c / total, eps) / max(e, eps))
            for c, e in zip(counts, expected, strict=True)
        )
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
    values = {feature: [_as_float(r["features"][feature]) for r in valid] for feature in columns}
    scores = {feature: psi(reference[feature], values[feature]) for feature in columns}
    worst = sorted(scores.items(), key=lambda kv: -(kv[1] if kv[1] is not None else -1.0))
    return {
        "status": "ok",
        **summary,
        "psi": dict(worst),
        "missing_share": {f: missing_share(values[f]) for f in columns},
        "shifted": [f for f, v in worst if v is not None and v > 0.25],
        "moderate": [f for f, v in worst if v is not None and 0.1 < v <= 0.25],
    }


def _as_float(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None

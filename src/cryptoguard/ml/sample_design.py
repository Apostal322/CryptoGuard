"""Design-based analysis of the frozen review sample (``review-sample/1``), offline.

Units, kept distinct:

- *attempt*: one packet of the payoff-linked queue (1,469);
- *campaign group*: attempts linked by victim, lookalike, planting transaction or imitated
  address (1,395);
- *representative*: the one attempt per group with the lowest ``rank("rep", id)``;
- *item*: a representative drawn into the sample (60).

The implemented design is (1) one representative per group, then (2) stratified simple
random sampling without replacement of representatives: ``n_c`` of ``N_c`` in stratum
``c``, lowest ``rank("select", id)`` first. The ranks are SHA-256 of fixed strings and are
treated as a pseudo-random permutation. Given the representatives, an item's inclusion
probability is exactly ``n_c / N_c``.

- The *campaign* estimand (each group represented by its fixed representative) is
  therefore design-estimable.
- The *attempt* estimand is not. Under the fixed hash, non-representative attempts have
  inclusion probability zero, so it is reported only as bounds (``attempt_bounds``).
- *Victim-level* rates are not estimated. Victims are nested in groups, and 12 groups hold
  two victims.

Everything here is aggregate: no address or event id leaves these functions except the
ids the caller passes in.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.review import ReviewPacket

DESIGN_VERSION = "sample-design/1"
Z95 = 1.959963984540054  # two-sided 95%


@dataclass(frozen=True)
class Cell:
    name: str
    subtype: str
    year: int
    rival: bool
    groups: int  # N_c: representatives in the stratum
    selected: int  # n_c
    packets: int  # attempts whose own stratum is c (descriptive only)

    @property
    def census(self) -> bool:
        return self.selected == self.groups


@dataclass(frozen=True)
class Design:
    cells: dict[str, Cell]
    item_cell: dict[str, str]  # victim_event_id -> stratum name
    group_size: dict[str, int]
    queue_packets: int

    @property
    def population(self) -> int:
        return sum(c.groups for c in self.cells.values())

    def inclusion(self, event_id: str) -> Fraction:
        """Exact inclusion probability of a selected representative, given the
        representatives."""
        c = self.cells[self.item_cell[event_id]]
        return Fraction(c.selected, c.groups)

    def weight(self, event_id: str) -> Fraction:
        return 1 / self.inclusion(event_id)


def parse_stratum(name: str) -> tuple[str, int, bool]:
    # The flag is rival/no_rival (Phase 11.4 sample) or yes/no (later cohorts; its meaning
    # is in the manifest's design["strata"]).
    subtype, year, flag = name.split("|")
    if flag not in ("rival", "no_rival", "yes", "no"):
        raise ValueError(f"bad stratum name {name!r}")
    return subtype, int(year), flag in ("rival", "yes")


def design(manifest: Mapping[str, Any]) -> Design:
    """Rebuild the design from a frozen manifest; checks the manifest is self-consistent."""
    cells: dict[str, Cell] = {}
    for row in manifest["strata_table"]:
        subtype, year, rival = parse_stratum(row["stratum"])
        cells[row["stratum"]] = Cell(
            row["stratum"], subtype, year, rival, row["groups"], row["selected"], row["packets"]
        )
    item_cell = {r["victim_event_id"]: r["stratum"] for r in manifest["selected"]}
    if len(item_cell) != len(manifest["selected"]):
        raise rs.ReviewSampleError("manifest repeats a selected item")
    per_cell = Counter(item_cell.values())
    for name, c in cells.items():
        if per_cell[name] != c.selected or not 0 <= c.selected <= c.groups:
            raise rs.ReviewSampleError(f"{name}: selected count inconsistent with the items")
    if set(per_cell) - set(cells):
        raise rs.ReviewSampleError("an item belongs to an unknown stratum")
    return Design(
        cells,
        item_cell,
        {r["victim_event_id"]: r["group_size"] for r in manifest["selected"]},
        manifest["queue_packets"],
    )


# --- intervals -------------------------------------------------------------------------


def wilson(p: float, n: float, z: float = Z95) -> tuple[float, float] | None:
    """Two-sided Wilson score interval for a proportion ``p`` with (effective) size ``n``."""
    if n <= 0:
        return None
    z2 = z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def kish_deff(weights: Sequence[float]) -> float:
    return len(weights) * sum(w * w for w in weights) / sum(weights) ** 2


# --- the stratified estimator -----------------------------------------------------------


def collapse_partners(cells: Sequence[Cell], responded: Mapping[str, int]) -> dict[str, str]:
    """Pre-specified collapse rule for variance estimation (fixed before any review).

    A stratum with one respondent and no census is pooled with another stratum of the
    same subtype that has respondents. The partner is chosen in this order:
    1. the same rival status, nearest year, earlier year on ties;
    2. otherwise the largest stratum.
    Returns ``stratum -> collapsed group name``."""
    parent = {c.name: c.name for c in cells}

    def find(x: str) -> str:
        while parent[x] != x:
            x = parent[x]
        return x

    for c in sorted(cells, key=lambda c: c.name):
        if responded.get(c.name, 0) != 1 or responded[c.name] >= c.groups:
            continue
        others = [o for o in cells if o.subtype == c.subtype and o.name != c.name]
        others = [o for o in others if responded.get(o.name, 0) >= 1]
        same = [o for o in others if o.rival == c.rival]
        if same:
            partner = min(same, key=lambda o: (abs(o.year - c.year), o.year))
        elif others:
            partner = max(others, key=lambda o: (o.groups, o.name))
        else:
            continue
        a, b = find(c.name), find(partner.name)
        if a != b:
            parent[max(a, b)] = min(a, b)
    return {c.name: find(c.name) for c in cells}


def subtype_scope(subtype: str) -> Callable[[Cell], bool]:
    return lambda c: c.subtype == subtype


def estimate(
    d: Design,
    outcomes: Mapping[str, bool | None],
    *,
    scope: Callable[[Cell], bool] = lambda c: True,
) -> dict[str, Any]:
    """Campaign-level proportion of ``True`` in the strata selected by ``scope``.

    Missing outcomes (``None``, or an item absent from ``outcomes``) are nonresponse. The
    point estimate assumes they are missing at random within the stratum. ``bounds`` set
    them all to False and all to True instead. An undefined quantity is ``None`` with a
    reason, never zero."""
    cells = [c for c in d.cells.values() if scope(c) and c.selected]
    population = sum(c.groups for c in d.cells.values() if scope(c))
    items = [e for e, s in d.item_cell.items() if s in {c.name for c in cells}]
    ys: dict[str, list[bool]] = defaultdict(list)
    missing: Counter[str] = Counter()
    for e in items:
        y = outcomes.get(e)
        if y is None:
            missing[d.item_cell[e]] += 1
        else:
            ys[d.item_cell[e]].append(bool(y))
    responded = {c.name: len(ys[c.name]) for c in cells}
    n, r = len(items), sum(responded.values())
    positives = sum(sum(v) for v in ys.values())
    out: dict[str, Any] = {
        "population_groups": population,
        "strata": len(cells),
        "census": bool(cells) and all(c.census for c in cells),
        "items": n,
        "responded": r,
        "missing": n - r,
        "positives": positives,
        "unweighted": {
            "proportion": positives / r if r else None,
            "wilson95": wilson(positives / r, r) if r else None,
            "note": "illustrative only: treats the items as a simple random sample",
        },
    }
    if not cells:
        return out | {"estimate": None, "reason": "no sampled stratum in scope"}

    def strat(fill: bool | None) -> float | None:
        total = Fraction(0)  # exact, so a unanimous sample gives exactly 1.0
        for c in cells:
            vals = ys[c.name] + ([fill] * missing[c.name] if fill is not None else [])
            if not vals:
                return None
            total += Fraction(c.groups, population) * Fraction(sum(vals), len(vals))
        return float(total)

    out["bounds_missing_as_false_true"] = (strat(False), strat(True))
    p = strat(None)
    if p is None:
        return out | {"estimate": None, "reason": "a sampled stratum has no responses"}
    weights = [c.groups / responded[c.name] for c in cells for _ in ys[c.name]]
    deff = kish_deff(weights)
    var, reason = _variance(cells, ys, responded, population)
    if var is not None and var > 0 and 0 < p < 1:
        n_eff = min(r, p * (1 - p) / var)
        basis = "variance (collapsed strata, finite-population correction)"
    else:
        n_eff = r / deff
        basis = "Kish weighting effect only" + (f" ({reason})" if reason else "")
    if out["census"] and not missing:
        interval: tuple[float, float] | None = (p, p)
        basis = "census of the frame: no sampling error (review error remains)"
    else:
        interval = wilson(p, n_eff)
    return out | {
        "estimate": p,
        "variance": var,
        "variance_note": reason,
        "kish_deff": deff,
        "effective_n": n_eff,
        "wilson95_design": interval,
        "interval_basis": basis,
    }


def _variance(
    cells: Sequence[Cell],
    ys: Mapping[str, list[bool]],
    responded: Mapping[str, int],
    population: int,
) -> tuple[float | None, str | None]:
    group = collapse_partners(cells, responded)
    pooled: dict[str, list[bool]] = defaultdict(list)
    for c in cells:
        pooled[group[c.name]] += ys[c.name]
    var = 0.0
    for c in cells:
        r = responded[c.name]
        fpc = 1 - r / c.groups
        if fpc <= 0:
            continue
        vals = pooled[group[c.name]]
        if len(vals) < 2:
            return None, f"{c.name}: one response and no stratum to pool with"
        mean = sum(vals) / len(vals)
        s2 = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
        var += (c.groups / population) ** 2 * fpc * s2 / r
    collapsed = sum(1 for c in cells if group[c.name] != c.name)
    return var, f"{collapsed} strata pooled for variance" if collapsed else None


def attempt_bounds(
    campaign_interval: tuple[float, float] | None, groups: int, attempts: int
) -> tuple[float, float] | None:
    """Bounds on the attempt-level share from a campaign-level interval. The
    ``attempts - groups`` non-representative attempts were never eligible for selection,
    so they are bounded at 0 and 1."""
    if campaign_interval is None:
        return None
    lo, hi = campaign_interval
    extra = attempts - groups
    return lo * groups / attempts, (hi * groups + extra) / attempts


# --- audit of the frozen design -----------------------------------------------------------


def _groups_with(packets: Sequence[ReviewPacket], keys: Sequence[str]) -> dict[str, str]:
    from cryptoguard.ml.events import _UnionFind

    uf = _UnionFind()
    for p in packets:
        node = "e:" + p.victim_event_id
        uf.find(node)
        for k in keys:
            value = getattr(p, k)
            if value:
                uf.union(node, f"{k}:{value.lower()}")
    return {p.victim_event_id: uf.find("e:" + p.victim_event_id) for p in packets}


def audit(packets: Sequence[ReviewPacket], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute the frozen design from the queue and check it. Aggregate output only."""
    by_id = {p.victim_event_id: p for p in packets}
    root = rs.groups(packets)
    members: dict[str, list[str]] = defaultdict(list)
    for e, g in root.items():
        members[g].append(e)
    reps = {min(ids, key=lambda e: rs.rank("rep", e)) for ids in members.values()}
    exploratory = _groups_with(packets, ("victim", "lookalike", "planting_tx"))
    merged: dict[str, set[str]] = defaultdict(set)
    for e, g in root.items():
        merged[g].add(exploratory[e])
    merges = [s for s in merged.values() if len(s) > 1]
    d = design(manifest)
    selected = list(d.item_cell)
    reserves = [e for ids in manifest["reserves"].values() for e in ids]
    sizes = Counter(len(ids) for ids in members.values())

    # Allocation recomputed from representative counts per stratum.
    cell_reps = Counter(rs.stratum_name(rs.stratum(by_id[e])) for e in reps)
    realloc: dict[str, int] = {}
    ideal: dict[str, float] = {}
    for subtype in sorted({c.subtype for c in d.cells.values()}):
        names = {(n,): cell_reps[n] for n, c in d.cells.items() if c.subtype == subtype}
        quota = rs.SUBTYPE_QUOTA.get(subtype, 0)
        total = sum(names.values())
        got = rs.allocate(names, quota) if quota else dict.fromkeys(names, 0)
        realloc |= {k[0]: v for k, v in got.items()}
        ideal |= {k[0]: (quota * v / total if quota < total else v) for k, v in names.items()}

    weights = [float(d.weight(e)) for e in selected]
    recorded = {r["victim_event_id"]: r["weight"] for r in manifest["selected"]}
    blocks = sorted(p.observation_block for p in packets)

    def near(boundary: int, k: int) -> int:
        return sum(1 for b in blocks if abs(b - boundary) <= k)

    checks = {
        "items_unique": len(set(selected)) == len(selected),
        "one_item_per_group": len({root[e] for e in selected}) == len(selected),
        "one_item_per_victim": len({by_id[e].victim for e in selected}) == len(selected),
        "items_are_representatives": set(selected) <= reps,
        "strata_partition_representatives": sum(c.groups for c in d.cells.values()) == len(reps),
        "strata_counts_match_queue": all(cell_reps[n] == c.groups for n, c in d.cells.items()),
        "allocation_reproduced": all(realloc[n] == c.selected for n, c in d.cells.items()),
        "reserves_disjoint_and_complete": not set(reserves) & set(selected)
        and len(reserves) + len(selected) == len(reps),
        "reserves_in_rank_order": all(
            ids == sorted(ids, key=lambda e: rs.rank("select", e))
            for ids in manifest["reserves"].values()
        ),
        "recorded_weights_match_exact": max(abs(recorded[e] - float(d.weight(e))) for e in selected)
        < 1e-6,
        "weights_sum_to_groups": abs(sum(weights) - len(reps)) < 1e-9,
    }
    return {
        "design_version": DESIGN_VERSION,
        "sample_version": manifest["sample_version"],
        "selection_sha256": manifest["selection_sha256"],
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "units": {
            "attempts": len(packets),
            "campaign_groups": len(members),
            "representatives": len(reps),
            "non_representative_attempts": len(packets) - len(reps),
            "multi_attempt_groups": sum(v for k, v in sizes.items() if k > 1),
            "attempts_in_multi_attempt_groups": sum(k * v for k, v in sizes.items() if k > 1),
            "multi_stratum_groups": sum(
                1 for ids in members.values() if len({rs.stratum(by_id[e]) for e in ids}) > 1
            ),
            "largest_group": max(sizes),
            "victims": len({p.victim for p in packets}),
            "groups_with_two_or_more_victims": sum(
                1 for ids in members.values() if len({by_id[e].victim for e in ids}) > 1
            ),
            "selected_items": len(selected),
            "selected_from_multi_attempt_groups": sum(
                1 for e in selected if len(members[root[e]]) > 1
            ),
        },
        "grouping_discrepancy": {
            "groups_victim_lookalike_tx": len(set(exploratory.values())),
            "groups_frozen_links_with_imitated": len(members),
            "frozen_groups_merging_several": len(merges),
            "exploratory_groups_absorbed": sum(len(s) for s in merges),
        },
        "strata": [
            {
                "stratum": c.name,
                "attempts": c.packets,
                "groups": c.groups,
                "ideal_share": round(ideal[c.name], 3),
                "selected": c.selected,
                "census": c.census,
                "inclusion_probability": f"{c.selected}/{c.groups}",
                "weight": round(c.groups / c.selected, 4) if c.selected else None,
                "reserves": len(manifest["reserves"].get(c.name, [])),
            }
            for c in sorted(d.cells.values(), key=lambda c: c.name)
        ],
        "weights": {
            "kish_deff_all": kish_deff(weights),
            "kish_deff_by_subtype": {
                s: kish_deff(
                    [float(d.weight(e)) for e in selected if d.item_cell[e].startswith(s + "|")]
                )
                for s in sorted({c.subtype for c in d.cells.values() if c.selected})
            },
            "max_recorded_rounding_error": max(
                abs(recorded[e] - float(d.weight(e))) for e in selected
            ),
        },
        "year_boundaries": {
            str(y): {
                "block": b,
                "attempts_within_7200": near(b, 7_200),
                "attempts_within_50400": near(b, 50_400),
            }
            for y, b in rs.YEAR_STARTS
        },
        "protocol_bounds_if_all_confirmed": {
            "unweighted_wilson95_lower_60": wilson(1.0, 60)[0],  # type: ignore[index]
            "unweighted_wilson95_lower_24": wilson(1.0, 24)[0],  # type: ignore[index]
            "design_wilson95_lower_all": estimate(d, dict.fromkeys(selected, True))[
                "wilson95_design"
            ][0],
            "design_wilson95_lower_by_subtype": {
                s: estimate(d, dict.fromkeys(selected, True), scope=subtype_scope(s))[
                    "wilson95_design"
                ][0]
                for s in sorted({c.subtype for c in d.cells.values() if c.selected})
            },
        },
        "rpc_requests": 0,
    }

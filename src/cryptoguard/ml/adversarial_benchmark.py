"""Phase 12.7 offline study (protocol 12.7): adversarial candidate exposure.

Populations are kept apart and labelled in the output:

- ``synthetic``: the 16 pre-registered scenario families (controlled adversarial
  robustness; synthetic Exposure@K is not real-world recall);
- ``archive_dev``: the 12.1 lookalike-prioritization development split (source-conditional
  development evaluation; its test split is never used);
- ``development_cases``: the pilot and the ScamSniffer windows (development-case analysis,
  not independent validation).

No RPC requests. Protected wallets are excluded exactly as in 12.1, and the frozen cohort
files are never opened for writing.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
import tracemalloc
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cryptoguard.ml import adversarial_ranking as ar
from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_evidence as ce
from cryptoguard.ml import reliability_study as rs

STUDY_VERSION = "adversarial-ranking-study/1"
W, USDT, FAKE, END = rs.WALLET, rs.USDT, rs.FAKE, rs.END
ATTACKER = rs.ATTACKER
M_GRID = (0, 10, 100, 1_000, 10_000)
K_GRID = (1, 3, 5, 10, 20, 50)
SEEDS = tuple(range(10))
GAS = {"native": 21_000, "zero_value_erc20": 40_000, "fake_token": 45_000}  # illustrative


# --- references and families ----------------------------------------------------------------


def references(*, overlap: bool = False) -> list[str]:
    """R1 (the builder's USDT payment) and R2-R5 (wallet-signed native payments). With
    ``overlap``, R2 shares exactly a 3-character prefix and suffix with R1."""
    refs = [rs.REF] + [
        "0x" + hashlib.sha256(f"cg127-ref-{i}".encode()).hexdigest()[:40] for i in range(2, 6)
    ]
    if overlap:
        r1 = rs.REF[2:]
        body = hashlib.sha256(b"cg127-overlap").hexdigest()
        fourth = "0" if r1[3] != "0" else "1"
        before_suffix = "0" if r1[-4] != "0" else "1"
        refs[1] = "0x" + r1[:3] + fourth + body[:32] + before_suffix + r1[-3:]
    return refs


def _fixture(
    refs: Sequence[str],
    *,
    transfers: Sequence[Any] = (),
    native: Sequence[Any] = (),
    refs_complete: bool = True,
) -> Any:
    return rs.wallet_fixture(
        transfers=list(transfers),
        native=list(native),
        wallet_txs=[(r, 10**15, 1_100 + 100 * i) for i, r in enumerate(refs[1:], start=1)],
        refs_complete=refs_complete,
    )


@dataclass(frozen=True)
class Scenario:
    family: str
    m: int
    fixture: Any
    relevant: tuple[str, ...]  # the oracle targets: scoring only, never a feature
    target_ref: str  # the reference the (first) target imitates


def _decoys(m: int, p: int, s: int, refs: Sequence[str], start: int = 1_000) -> list[str]:
    return [rs.lookalike(start + i, prefix=p, suffix=s, ref=refs[i % len(refs)]) for i in range(m)]


def _block(i: int) -> int:
    return 3_000 + i % 5_000  # decoys are newer than every target (blocks 2,000-2,200)


def scenario(family: str, m: int) -> Scenario:
    refs = references(overlap=family == "F8_reference_overlap")
    r1 = refs[0]
    t = rs.lookalike(0, prefix=4, suffix=4, ref=r1)
    spoof = (W, t, 0, 2_000, ATTACKER, USDT, 0)

    def native_dust(ds: Sequence[str]) -> list[Any]:
        return [(d, 1, _block(i), True) for i, d in enumerate(ds)]

    others = refs[1:]
    rel: tuple[str, ...] = (t,)
    tr: list[Any] = [spoof]
    nat: list[Any] = []
    complete = True
    if family == "F1_native_dust_flood":
        nat = native_dust(_decoys(m, 3, 3, refs))
    elif family == "F2_fake_token_flood":
        tr += [
            (d, W, 10**18, _block(i), None, FAKE, 0) for i, d in enumerate(_decoys(m, 3, 3, refs))
        ]
    elif family == "F3_zero_value_flood":
        tr += [(d, W, 0, _block(i), None, USDT, 0) for i, d in enumerate(_decoys(m, 3, 3, refs))]
    elif family == "F4_repetition_one_address":
        strong = rs.lookalike(999, prefix=5, suffix=5, ref=refs[1])
        nat = [(strong, 1, _block(i), True) for i in range(m)]
    elif family == "F5_distinct_equal_lookalikes":
        nat = native_dust(_decoys(m, 4, 4, refs))
    elif family == "F6_equal_similarity_same_reference":
        nat = native_dust(_decoys(m, 4, 4, [r1]))
    elif family in ("F7_recent_decoys_other_references", "F10_unknown_signer"):
        nat = native_dust(_decoys(m, 4, 4, others))
        if family == "F10_unknown_signer":
            tr = [(W, t, 0, 2_000, None, USDT, 0)]
    elif family == "F8_reference_overlap":
        nat = native_dust(_decoys(m, 4, 4, [refs[1]]))
    elif family == "F9_mixed_mechanisms":
        tr += [(t, W, 0, 2_100, None, USDT, 0)]
        nat = [(t, 1, 2_050, True)]
        for i, d in enumerate(_decoys(m, 4, 4, others)):
            kind = i % 3
            if kind == 0:
                nat.append((d, 1, _block(i), True))
            elif kind == 1:
                tr.append((d, W, 10**18, _block(i), None, FAKE, 0))
            else:
                tr.append((d, W, 0, _block(i), None, USDT, 0))
    elif family == "F11_missing_receipt":
        tr = []
        nat = [(t, 1, 2_000, None), *native_dust(_decoys(m, 4, 4, others))]
    elif family == "F12_partial_history":
        tr = [(W, t, 0, 2_000, None, USDT, 0)]
        nat = native_dust(_decoys(m, 4, 4, others))
        complete = False
    elif family == "F13_contract_mediated":
        tr = [(W, t, 10**6, 2_000, ATTACKER, USDT, 0)]
        nat = native_dust(_decoys(m, 4, 4, others))
    elif family == "F14_one_campaign_several_relevant":
        ts = [rs.lookalike(j, prefix=5, suffix=5, ref=r1) for j in range(3)]
        rel = tuple(ts)
        tr = [(W, x, 0, 2_000 + 10 * j, ATTACKER, USDT, j) for j, x in enumerate(ts)]
        nat = native_dust(_decoys(m, 4, 4, others))
    elif family == "F15_one_among_unrelated":
        t = rs.lookalike(0, prefix=3, suffix=3, ref=r1)
        rel = (t,)
        tr = [(W, t, 0, 2_000, ATTACKER, USDT, 0)]
        strangers = ["0x" + f"{0x5000000 + i:040x}" for i in range(m)]
        half = m // 2
        nat = [(s, 1, _block(i), True) for i, s in enumerate(strangers[:half])]
        tr += [(s, W, 0, _block(i), None, USDT, 0) for i, s in enumerate(strangers[half:])]
    elif family == "F16_several_relevant_compete":
        t2 = rs.lookalike(0, prefix=4, suffix=4, ref=refs[1])
        t3 = rs.lookalike(0, prefix=3, suffix=3, ref=refs[2])
        rel = (t, t2, t3)
        tr = [spoof, (t3, W, 0, 2_200, None, USDT, 0)]
        nat = [(t2, 1, 2_100, True), *native_dust(_decoys(m, 4, 4, [r1]))]
    else:
        raise ValueError(family)
    fx = _fixture(refs, transfers=tr, native=nat, refs_complete=complete)
    return Scenario(family, m, fx, tuple(x.lower() for x in rel), r1.lower())


FAMILIES = (
    "F1_native_dust_flood",
    "F2_fake_token_flood",
    "F3_zero_value_flood",
    "F4_repetition_one_address",
    "F5_distinct_equal_lookalikes",
    "F6_equal_similarity_same_reference",
    "F7_recent_decoys_other_references",
    "F8_reference_overlap",
    "F9_mixed_mechanisms",
    "F10_unknown_signer",
    "F11_missing_receipt",
    "F12_partial_history",
    "F13_contract_mediated",
    "F14_one_campaign_several_relevant",
    "F15_one_among_unrelated",
    "F16_several_relevant_compete",
)

# decoy cost per family: (decoy bits, references used, gas kind); None: no decoys / strangers
DECOY_COST: dict[str, tuple[int, int, str] | None] = {
    "F1_native_dust_flood": (24, 5, "native"),
    "F2_fake_token_flood": (24, 5, "fake_token"),
    "F3_zero_value_flood": (24, 5, "zero_value_erc20"),
    "F4_repetition_one_address": (40, 1, "native"),  # one address, m repeats
    "F5_distinct_equal_lookalikes": (32, 5, "native"),
    "F6_equal_similarity_same_reference": (32, 1, "native"),
    "F7_recent_decoys_other_references": (32, 4, "native"),
    "F8_reference_overlap": (32, 1, "native"),
    "F9_mixed_mechanisms": (32, 4, "native"),
    "F10_unknown_signer": (32, 4, "native"),
    "F11_missing_receipt": (32, 4, "native"),
    "F12_partial_history": (32, 4, "native"),
    "F13_contract_mediated": (32, 4, "native"),
    "F14_one_campaign_several_relevant": (32, 4, "native"),
    "F15_one_among_unrelated": None,
    "F16_several_relevant_compete": (32, 1, "native"),
}


def attack_cost(family: str, m: int) -> dict[str, Any] | None:
    """Illustrative cost of m decoys: expected key trials (log2) and gas units."""
    c = DECOY_COST[family]
    if c is None or m == 0:
        return None
    b, _refs, kind = c
    addresses = 1 if family == "F4_repetition_one_address" else m
    trials = addresses * 2.0**b
    return {
        "decoy_bits": b,
        "addresses": addresses,
        "log2_key_trials": round(math.log2(trials), 2),
        "gas": m * GAS[kind],
    }


# --- methods ----------------------------------------------------------------------------------


def selectors(seed: int) -> dict[str, ar.Selector]:
    s = ar.Selector
    return {
        "B0": s("B0"),
        "B1": s("B1"),
        "B2": s("B2"),
        "B3": s("B3"),
        "B4": s("B4"),
        "B5": s("B5"),
        "B6": s("B6", seed=seed),
        "P1": s("P1", seed=seed),
        "P1b": s("P1", seed=seed, bucket_tie=True),  # post hoc: bucket-level ties
        "A-nosim": s("P1", seed=seed, nosim=True),
        "A-rec": s("P1", seed=seed, tie="recency"),
        "A-lam2": s("P1", seed=seed, lam=2.0),
        "A-lam8": s("P1", seed=seed, lam=8.0),
        "A-laminf": s("P1", seed=seed, lam=math.inf),
        "A-nomech": s("P1", seed=seed, nomech=True),
        "NC-random": s("random", seed=seed),
        "NC-revrec": s("revrec"),
    }


SEEDED = frozenset(
    {"B6", "P1", "P1b", "A-nosim", "A-rec", "A-lam2", "A-lam8", "A-laminf", "A-nomech", "NC-random"}
)
# A-lam0 is B6 by definition (lambda = 0: no group discount); it is reported under B6.

Scorer = Callable[[ce.CandidateGroup, int], float]  # (group, cutoff block) -> score


def score_order(
    groups: Sequence[ce.CandidateGroup], score: Scorer, cutoff_block: int
) -> list[ce.CandidateGroup]:
    return sorted(groups, key=lambda g: (-score(g, cutoff_block), g.lookalike))


# --- the grid ---------------------------------------------------------------------------------


def _ranks(
    ordered: Sequence[ce.CandidateGroup], relevant: Sequence[str], target_ref: str
) -> tuple[list[int | None], int | None]:
    pos = {g.lookalike: i + 1 for i, g in enumerate(ordered)}
    first_bucket = next(
        (i + 1 for i, g in enumerate(ordered) if ce.bucket_of(g) == target_ref), None
    )
    return [pos.get(r) for r in relevant], first_bucket


def _exposure(ranks: Sequence[int | None], k: int) -> float:
    return sum(1 for r in ranks if r is not None and r <= k) / len(ranks)


def run_cell(
    sc: Scenario, extra: dict[str, Scorer] | None = None, seeds: Sequence[int] = SEEDS
) -> dict[str, Any]:
    t0 = time.perf_counter()
    res = ce.build(sc.fixture, cutoff=END)
    build_s = time.perf_counter() - t0
    groups = list(res.groups)
    out: dict[str, Any] = {
        "groups": len(groups),
        "evidence_records": res.evidence_records,
        "build_seconds": round(build_s, 3),
        "relevant_found": [r in {g.lookalike for g in groups} for r in sc.relevant],
        "methods": {},
    }
    target_bucket = sc.target_ref
    rows: dict[str, list[tuple[list[int | None], int | None]]] = {}
    bound_violations: dict[str, int] = {}
    for seed in seeds:
        for name, sel in selectors(seed).items():
            if seed != seeds[0] and name not in SEEDED:
                continue
            ordered = ar.order(groups, sel)
            if len(ordered) != len(groups):
                raise AssertionError("not a permutation")
            ranks, fb = _ranks(ordered, sc.relevant, target_bucket)
            rows.setdefault(name, []).append((ranks, fb))
            if sel.method == "P1" and not sel.nosim and sel.lam > 0:
                bound = ar.displacement_bound(groups, target_bucket, sel.lam, nomech=sel.nomech)
                if bound is not None and fb is not None and fb > bound:
                    bound_violations[name] = bound_violations.get(name, 0) + 1
    for name, score in (extra or {}).items():
        ordered = score_order(groups, score, END[0])
        rows[name] = [_ranks(ordered, sc.relevant, target_bucket)]
    for name, rr in rows.items():
        out["methods"][name] = {
            "ranks": [r for r, _ in rr] if name in SEEDED else rr[0][0],
            "bucket_first": [f for _, f in rr] if name in SEEDED else rr[0][1],
            "exposure": {
                k: round(sum(_exposure(r, k) for r, _ in rr) / len(rr), 4) for k in K_GRID
            },
            "tgc": {
                k: round(sum(1 for _, f in rr if f is not None and f <= k) / len(rr), 4)
                for k in K_GRID
            },
        }
    out["bound_violations"] = bound_violations
    if res.groups:
        out["digest_repeat_equal"] = ce.digest(res) == ce.digest(ce.build(sc.fixture, cutoff=END))
    return out


def grid(
    m_grid: Sequence[int] = M_GRID,
    extra: dict[str, Scorer] | None = None,
    families: Sequence[str] = FAMILIES,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fam in families:
        out[fam] = {}
        for m in m_grid:
            cell = run_cell(scenario(fam, m), extra)
            cell["attack_cost"] = attack_cost(fam, m)
            out[fam][str(m)] = cell
    return out


def summarize_grid(g: dict[str, Any], methods: Sequence[str]) -> dict[str, Any]:
    """Mean Exposure@K / TGC@K per method, overall and per family, and the H1 verdict."""
    per_family: dict[str, dict[str, float]] = {}
    overall: dict[str, list[float]] = {m: [] for m in methods}
    tgc_all: dict[str, list[float]] = {m: [] for m in methods}
    by_k: dict[str, dict[int, list[float]]] = {m: {k: [] for k in K_GRID} for m in methods}
    for fam, cells in g.items():
        per_family[fam] = {}
        for meth in methods:
            vals = []
            for cell in cells.values():
                if meth not in cell["methods"]:
                    continue
                for k in K_GRID:
                    v = cell["methods"][meth]["exposure"][k]
                    vals.append(v)
                    by_k[meth][k].append(v)
                    tgc_all[meth].append(cell["methods"][meth]["tgc"][k])
            if vals:
                per_family[fam][meth] = round(sum(vals) / len(vals), 4)
                overall[meth] += vals
    mean = {m: round(sum(v) / len(v), 4) for m, v in overall.items() if v}
    out: dict[str, Any] = {
        "mean_exposure": mean,
        "mean_tgc": {m: round(sum(v) / len(v), 4) for m, v in tgc_all.items() if v},
        "mean_exposure_by_k": {
            m: {k: round(sum(v) / len(v), 4) for k, v in ks.items() if v} for m, ks in by_k.items()
        },
        "per_family": per_family,
    }
    if "P1" in mean and "B0" in mean:
        diffs = {f: per_family[f]["P1"] - per_family[f]["B0"] for f in per_family}
        ge = sum(1 for d in diffs.values() if d >= -1e-9)
        worst = min(diffs.values())
        c1, c2, c3 = mean["P1"] > mean["B0"], ge >= 12, worst >= -0.10
        out["H1"] = {
            "P1_minus_B0": round(mean["P1"] - mean["B0"], 4),
            "families_P1_ge_B0": ge,
            "worst_family_difference": round(worst, 4),
            "verdict": "supported"
            if c1 and c2 and c3
            else "partially supported"
            if c1
            else "failed",
        }
    return out


def cell_tgc_check(g: dict[str, Any]) -> dict[str, Any]:
    """H2: P1's target-group coverage is never below B0's, cell by cell."""
    worse = []
    for fam, cells in g.items():
        for m, cell in cells.items():
            for k in K_GRID:
                p, b = cell["methods"]["P1"]["tgc"][k], cell["methods"]["B0"]["tgc"][k]
                if p < b - 1e-9:
                    worse.append([fam, int(m), k, p, b])
    violations = sum(
        sum(c["bound_violations"].values()) for cells in g.values() for c in cells.values()
    )
    return {"cells_P1_below_B0": len(worse), "examples": worse[:10], "bound_violations": violations}


def h3_check(g: dict[str, Any]) -> dict[str, Any]:
    fams = ("F1_native_dust_flood", "F2_fake_token_flood", "F3_zero_value_flood")
    out: dict[str, Any] = {}
    for fam in fams:
        rows = []
        for m, cell in g[fam].items():
            b0 = cell["methods"]["B0"]["ranks"][0]
            p1 = max(r[0] or 10**9 for r in cell["methods"]["P1"]["ranks"])
            b1 = cell["methods"]["B1"]["ranks"][0]
            b1_ok = all(cell["methods"]["B1"]["exposure"][k] == 0 for k in K_GRID if int(m) >= k)
            rows.append(
                {
                    "m": int(m),
                    "B0_rank": b0,
                    "P1_worst_rank": p1,
                    "B1_rank": b1,
                    "B1_zero_when_m_ge_K": b1_ok,
                }
            )
        out[fam] = rows
    return out


def h4_check(g: dict[str, Any]) -> dict[str, Any]:
    cells = g["F6_equal_similarity_same_reference"]
    rows = []
    for m, cell in cells.items():
        m_i = int(m)
        for k in K_GRID:
            if m_i < k:
                continue
            theory = min(1.0, k / (m_i + 1))
            rows.append(
                {
                    "m": m_i,
                    "K": k,
                    "theory": round(theory, 4),
                    "B0": cell["methods"]["B0"]["exposure"][k],
                    "B6": cell["methods"]["B6"]["exposure"][k],
                    "P1": cell["methods"]["P1"]["exposure"][k],
                    "P1_within_0.10": abs(cell["methods"]["P1"]["exposure"][k] - theory) <= 0.10,
                }
            )
    return {"rows": rows, "all_within": all(r["P1_within_0.10"] for r in rows)}


def attack_curves(
    g: dict[str, Any], methods: Sequence[str] = ("B0", "B1", "B6", "P1")
) -> dict[str, Any]:
    """Smallest m in the grid at which the (median-seed) first relevant rank exceeds K."""
    out: dict[str, Any] = {}
    for fam, cells in g.items():
        out[fam] = {}
        for meth in methods:
            row = {}
            for k in K_GRID:
                hit = None
                for m in sorted(cells, key=int):
                    r = cells[m]["methods"][meth]["ranks"]
                    if meth in SEEDED:
                        firsts = sorted((x[0] if x[0] is not None else 10**9) for x in r)
                        rank = firsts[len(firsts) // 2]
                    else:
                        rank = r[0] if r[0] is not None else 10**9
                    if rank > k:
                        hit = int(m)
                        break
                row[k] = hit
            out[fam][meth] = row
    return out


# --- negative controls ------------------------------------------------------------------------


def _relabel(groups: Sequence[ce.CandidateGroup], what: str, seed: int) -> list[ce.CandidateGroup]:
    rng = random.Random(seed)  # noqa: S311 - reproducible research permutation
    gs = list(groups)
    if what == "time":
        pos = [(g.first_position, g.last_position) for g in gs]
        rng.shuffle(pos)
        return [
            replace(g, first_position=f, last_position=lp)
            for g, (f, lp) in zip(gs, pos, strict=True)
        ]
    if what == "mech":
        idx = [i for i, g in enumerate(gs) if g.references]
        mechs = [gs[i].mechanisms for i in idx]
        rng.shuffle(mechs)
        for i, mech in zip(idx, mechs, strict=True):
            gs[i] = replace(gs[i], mechanisms=mech)
        return gs
    raise ValueError(what)


def negative_controls(m: int = 1_000) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fam in FAMILIES:
        sc = scenario(fam, m)
        res = ce.build(sc.fixture, cutoff=END)
        groups = list(res.groups)
        shuffled = list(groups)
        random.Random(7).shuffle(shuffled)  # noqa: S311 - reproducible research permutation
        serial_ok = all(
            [g.lookalike for g in ar.order(groups, s)]
            == [g.lookalike for g in ar.order(shuffled, s)]
            for s in selectors(0).values()
        )
        p1 = ar.Selector("P1")
        base = [g.lookalike for g in ar.order(groups, p1)]
        time_ok = base == [g.lookalike for g in ar.order(_relabel(groups, "time", 3), p1)]
        mech_ok = base == [g.lookalike for g in ar.order(_relabel(groups, "mech", 3), p1)]
        out[fam] = {
            "serialization_invariant": serial_ok,
            "P1_time_invariant": time_ok,
            "P1_mechanism_invariant": mech_ok,
        }
    # NC-signer and NC-public-token: add unrelated activity to F7 and compare target ranks
    sc = scenario("F7_recent_decoys_other_references", m)
    strangers = ["0x" + f"{0x7000000 + i:040x}" for i in range(1_000)]
    signer_fx = sc.fixture.model_copy(
        update={
            "transfers": list(sc.fixture.transfers)
            + [_row(W, s, 10**6, 8_000 + i % 900, ATTACKER, i) for i, s in enumerate(strangers)]
        }
    )
    public_fx = sc.fixture.model_copy(
        update={
            "transfers": list(sc.fixture.transfers)
            + [_row(s, W, 0, 8_000 + i % 900, None, i) for i, s in enumerate(strangers)]
        }
    )
    for name, fx in (
        ("NC_signer_unrelated_links", signer_fx),
        ("NC_public_token_strangers", public_fx),
    ):
        before = run_cell(sc, seeds=(0,))
        after = run_cell(replace(sc, fixture=fx), seeds=(0,))
        out[name] = {
            meth: {
                "rank_before": before["methods"][meth]["ranks"][0]
                if meth not in SEEDED
                else before["methods"][meth]["ranks"][0][0],
                "rank_after": after["methods"][meth]["ranks"][0]
                if meth not in SEEDED
                else after["methods"][meth]["ranks"][0][0],
            }
            for meth in ("B0", "B1", "P1", "B6")
        } | {"groups_added": after["groups"] - before["groups"]}
    return out


def _row(sender: str, recipient: str, value: int, block: int, signer: str | None, i: int) -> Any:
    from cryptoguard.replay.models import RecordedTransfer

    h = "0x" + hashlib.sha256(f"nc:{sender}:{recipient}:{value}:{block}:{i}".encode()).hexdigest()
    return RecordedTransfer(
        token=USDT,
        sender=sender,
        recipient=recipient,
        value=str(value),
        block_number=block,
        block_hash="0x" + hashlib.sha256(f"b{block}".encode()).hexdigest(),
        transaction_hash=h,
        transaction_index=5,
        log_index=10_000 + i,
        tx_sender=signer,
    )


# --- learning to rank (archive development split only) --------------------------------------

LTR_FEATURES = ("S", "R", "N")


def _vec(f: Mapping[str, Any], names: Sequence[str]) -> list[float]:
    out: list[float] = []
    for n in names:
        if n == "S":
            out += [0.0 if f["B0"] is None else float(f["B0"]), 1.0 if f["B0"] is None else 0.0]
        elif n == "R":
            age = -float(f["T0"]) if f["T0"] is not None else 0.0
            out.append(-math.log1p(max(age, 0.0)))
        elif n == "N":
            out.append(math.log1p(float(f["T1"] or 0.0)))
    return out


def _fit(
    rows: Sequence[tuple[dict[str, dict[str, Any]], Any]], names: Sequence[str]
) -> tuple[Any, Any, Any]:
    import numpy as np
    from sklearn.linear_model import LogisticRegression

    raw = np.array([_vec(v, names) for f, _ in rows for v in f.values()])
    mu, sd = raw.mean(axis=0), raw.std(axis=0)
    sd[sd == 0] = 1.0
    xs, ys = [], []
    for f, e in rows:
        z = {c: (np.array(_vec(v, names)) - mu) / sd for c, v in f.items()}
        for c in f:
            if c != e.paid:
                xs += [z[e.paid] - z[c], z[c] - z[e.paid]]
                ys += [1, 0]
    model = LogisticRegression(C=1.0, fit_intercept=False, max_iter=2_000, random_state=0)
    model.fit(np.array(xs), np.array(ys))
    return model.coef_[0], mu, sd


def ltr_study(poisoning_dir: Path) -> tuple[dict[str, Any], dict[str, Scorer]]:
    """Pairwise conditional logit on the 12.1 development split (internal temporal 70/30).
    The 12.1 test split is dropped before any feature is computed."""
    import numpy as np

    from cryptoguard.ml import lookalike_ranking as lr

    t0 = time.perf_counter()
    episodes, excluded = lr.load_episodes(poisoning_dir)
    addrs, txs = lr.protected_entities(poisoning_dir)
    overlap = lr.protected_overlap(episodes, addrs, txs)
    kept = [e for e, o in zip(episodes, overlap, strict=True) if not o]
    grp, mode = lr.protocol_groups(kept)
    split = lr.temporal_split(kept, grp)
    dev = [(e, g) for e, g, s in zip(kept, grp, split, strict=True) if s == "dev"]
    load_s = time.perf_counter() - t0
    computed = [(lr.candidate_features(e, lr.View(), None, None), e, g) for e, g in dev]
    feats: list[tuple[dict[str, dict[str, Any]], Any, int]] = [
        (f, e, g) for f, e, g in computed if f is not None
    ]
    start: dict[int, int] = {}
    size: dict[int, int] = {}
    for _, e, g in feats:
        start[g] = min(start.get(g, e.payoff_block), e.payoff_block)
        size[g] = size.get(g, 0) + 1
    fit_groups: set[int] = set()
    n = 0
    for g in sorted(start, key=lambda g: (start[g], g)):
        if n >= 0.7 * len(feats):
            break
        fit_groups.add(g)
        n += size[g]
    fit = [(f, e) for f, e, g in feats if g in fit_groups]
    val = [(f, e, g) for f, e, g in feats if g not in fit_groups]
    models: dict[str, Any] = {}
    for name, names in (("M-LTR", LTR_FEATURES), ("M-LTR-noR", ("S", "N"))):
        w, mu, sd = _fit(fit, names)
        models[name] = (names, w, mu, sd)

    def scores(f: dict[str, dict[str, Any]], method: str) -> dict[str, float] | None:
        if method == "random":
            return None
        if method in ("S", "S_then_R"):
            if any(v["B0"] is None for v in f.values()):
                return None
            if method == "S":
                return {c: float(v["B0"]) for c, v in f.items()}
            return {c: float(v["B0"]) * 1e9 + float(v["T0"]) for c, v in f.items()}
        if method == "R":
            return {c: float(v["T0"]) for c, v in f.items()}
        names, w, mu, sd = models[method]
        return {c: float(((np.array(_vec(v, names)) - mu) / sd) @ w) for c, v in f.items()}

    methods = ("random", "S", "R", "S_then_R", "M-LTR", "M-LTR-noR")
    per: dict[str, list[float]] = {m: [] for m in methods}
    per_mrr: dict[str, list[float]] = {m: [] for m in methods}
    for f, e, _ in val:
        for m in methods:
            sc = scores(f, m)
            per[m].append(lr.top1(sc, e.paid, len(f)))
            per_mrr[m].append(lr.mrr(sc, e.paid, len(f)))
    gv = [g for _, _, g in val]
    comparisons = {}
    for m in ("R", "M-LTR", "M-LTR-noR"):
        d = [a - b for a, b in zip(per[m], per["S_then_R"], strict=True)]
        comparisons[f"{m}_vs_S_then_R"] = lr.paired(d, gv)
    d = [a - b for a, b in zip(per["M-LTR"], per["R"], strict=True)]
    comparisons["M-LTR_vs_R"] = lr.paired(d, gv)

    def q(xs: list[float]) -> list[float]:
        if not xs:
            return []
        s = sorted(xs)
        return [round(s[int(p * (len(s) - 1))], 3) for p in (0.1, 0.5, 0.9)]

    def dist(rows: Sequence[tuple[dict[str, dict[str, Any]], Any]]) -> dict[str, Any]:
        s_vals = [float(v["B0"]) for f, _ in rows for v in f.values() if v["B0"] is not None]
        ages = [-float(v["T0"]) for f, _ in rows for v in f.values() if v["T0"] is not None]
        n_vals = [float(v["T1"] or 0) for f, _ in rows for v in f.values()]
        ks = [float(len(f)) for f, _ in rows]
        return {
            "S_q10_50_90": q(s_vals),
            "age_blocks_q10_50_90": q(ages),
            "N_q10_50_90": q(n_vals),
            "candidates_q10_50_90": q(ks),
            "S_missing_share": round(
                sum(1 for f, _ in rows for v in f.values() if v["B0"] is None)
                / max(1, sum(len(f) for f, _ in rows)),
                4,
            ),
        }

    by_k: dict[str, dict[str, Any]] = {}
    for (f, _ep, _), i in zip(val, range(len(val)), strict=True):
        kb = "2" if len(f) == 2 else "3-5" if len(f) <= 5 else "6+"
        row = by_k.setdefault(kb, {"episodes": 0, **{m: 0.0 for m in methods}})
        row["episodes"] += 1
        for m in methods:
            row[m] += per[m][i]
    for row in by_k.values():
        for m in methods:
            row[m] = round(row[m] / row["episodes"], 4)
    report = {
        "population": "12.1 lookalike-prioritization development split only (source-conditional)",
        "group_mode": mode,
        "dev_episodes_evaluable": len(feats),
        "fit_episodes": len(fit),
        "val_episodes": len(val),
        "val_groups": len(set(gv)),
        "excluded_before": excluded,
        "excluded_protected_overlap": sum(overlap),
        "test_split_used": False,
        "weights": {
            name: {
                "features": list(names),
                "w": [round(float(x), 4) for x in w],
            }
            for name, (names, w, _, _) in models.items()
        },
        "val_top1": {m: round(sum(v) / len(v), 4) for m, v in per.items()},
        "val_mrr": {m: round(sum(v) / len(v), 4) for m, v in per_mrr.items()},
        "comparisons": comparisons,
        "shift": {"fit": dist(fit), "val": dist([(f, e) for f, e, _ in val])},
        "val_top1_by_candidate_count": by_k,
        "seconds": {"load": round(load_s, 1), "total": round(time.perf_counter() - t0, 1)},
    }

    def make(name: str) -> Scorer:
        names, w, mu, sd = models[name]

        def score(g: ce.CandidateGroup, cutoff_block: int) -> float:
            f = {
                "B0": float(g.affix or 0),
                "T0": -float(cutoff_block - g.last_position[0]),
                "T1": float(len({r.identity.split(":")[1] for r in g.evidence})),
            }
            return float(((np.array(_vec(f, names)) - mu) / sd) @ w)

        return score

    return report, {name: make(name) for name in models}


# --- development cases (not independent validation) -----------------------------------------


def development_cases(
    poisoning_dir: Path, extra: dict[str, Scorer] | None = None
) -> dict[str, Any]:
    from cryptoguard.ml import incident_benchmark as ib

    paid = {
        c.manifest.case_id: c.manifest.harm.recipient.lower()
        for c in ib.load_new_cases()
        if c.fixture is not None
    }
    out: dict[str, Any] = {}
    for name, fx, cut in rs.eligible_windows(poisoning_dir):
        key = (
            name
            if name in paid
            else ("scamsniffer-763k-2025-02-20" if "scamsniffer" in name else None)
        )
        if key is None or key not in paid:
            continue
        target = paid[key]
        res = ce.build(fx, cutoff=cut)
        groups = list(res.groups)
        row: dict[str, Any] = {
            "label": "development-case analysis, not independent validation",
            "groups": len(groups),
            "paid_is_candidate": target in {g.lookalike for g in groups},
            "missing_categories": sorted(k for k, v in res.coverage.items() if v != "complete"),
            "abstain": res.abstain,
            "ranks": {},
        }
        for meth, sel in selectors(0).items():
            if meth.startswith("NC"):
                continue
            ranks = [
                next(
                    (
                        i + 1
                        for i, g in enumerate(ar.order(groups, replace(sel, seed=s)))
                        if g.lookalike == target
                    ),
                    None,
                )
                for s in (SEEDS if meth in SEEDED else (0,))
            ]
            row["ranks"][meth] = (
                ranks[0]
                if len(ranks) == 1
                else {
                    "seed0": ranks[0],
                    "min": min(r or 10**9 for r in ranks),
                    "max": max(r or 0 for r in ranks),
                }
            )
        for meth, score in (extra or {}).items():
            ordered = score_order(groups, score, cut[0])
            row["ranks"][meth] = next(
                (i + 1 for i, g in enumerate(ordered) if g.lookalike == target), None
            )
        c2 = cd.discover(fx, cutoff=cut, variant="C2").candidates
        row["c2_list_rank"] = next((i + 1 for i, c in enumerate(c2) if c.lookalike == target), None)
        row["c2_candidates"] = len(c2)
        row["c2_note"] = "C2's own candidate set and list order; not the same set as the groups"
        out[name] = row
    return out


# --- performance ------------------------------------------------------------------------------


def performance(sizes: Sequence[int]) -> list[dict[str, Any]]:
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    refs = references()
    base_fx = _fixture(refs)
    base = cd.observations(base_fx)
    out = []
    for n in sizes:
        obs = base + [
            cd.Observation(
                "native",
                "in",
                rs.lookalike(i + 1, ref=refs[i % 5]),
                1,
                2_000 + i // 20,
                i % 20,
                -1,
                "0x" + f"{0xB0000000 + i:064x}",
                rs.lookalike(i + 1, ref=refs[i % 5]),
                False,
                None,
                True,
            )
            for i in range(n)
        ]
        res = ce.build(base_fx, cutoff=END, observations=obs)
        row: dict[str, Any] = {"candidates": n, "groups": len(res.groups)}
        for meth in ("B0", "P1"):
            sel = ar.Selector(meth)
            tracemalloc.start()
            t0 = time.perf_counter()
            selected = ar.select(res, sel)
            sec = time.perf_counter() - t0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            t1 = time.perf_counter()
            summary = ce.summarize(selected, 10)
            s_sec = time.perf_counter() - t1
            t2 = time.perf_counter()
            pg = ce.page(selected, offset=n // 2, limit=10)
            p_sec = time.perf_counter() - t2
            row[meth] = {
                "select_seconds": round(sec, 3),
                "groups_per_second": round(len(res.groups) / sec) if sec else None,
                "select_peak_traced_mib": round(peak / 2**20, 2),
                "summary_seconds": round(s_sec, 3),
                "summary_bytes": len(json.dumps(summary)),
                "page_seconds": round(p_sec, 3),
                "page_bytes": len(json.dumps(pg)),
            }
        peak_rss = peak_rss_bytes()
        row["process_peak_rss_mib"] = None if peak_rss is None else round(peak_rss / 2**20, 1)
        out.append(row)
        del obs, res
    return out


def free_ram_bytes() -> int | None:
    import ctypes
    import sys

    if sys.platform == "win32":  # mypy understands this guard on every platform

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MemoryStatus()
        st.dwLength = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return int(st.ullAvailPhys)
        return None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


# --- entry point ------------------------------------------------------------------------------


def main(
    poisoning_dir: Path, out: Path, *, ltr: bool = True, perf_max: int = 100_000
) -> dict[str, Any]:
    import subprocess

    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    t0 = time.perf_counter()
    free = free_ram_bytes()
    try:
        git = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        git = None
    ltr_report: dict[str, Any] | str = "not run"
    scorers: dict[str, Scorer] = {}
    if ltr and (poisoning_dir / "archive_subset.sqlite").exists():
        ltr_report, scorers = ltr_study(poisoning_dir)
    elif ltr:
        ltr_report = "archive subset missing: not trained"
    g = grid(extra=scorers)
    methods = list(selectors(0)) + list(scorers)
    result: dict[str, Any] = {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.7",
        "selector_version": ar.SELECTOR_VERSION,
        "evidence_version": ce.EVIDENCE_VERSION,
        "git": git,
        "rpc_requests": 0,
        "preflight_free_ram_mib": None if free is None else round(free / 2**20),
        "seeds": list(SEEDS),
        "m_grid": list(M_GRID),
        "k_grid": list(K_GRID),
        "config_hashes": {n: ar.config_hash(s) for n, s in selectors(0).items()},
        "population_labels": {
            "grid": "synthetic, controlled adversarial robustness (not real-world recall)",
            "ltr": "archive development split, source-conditional",
            "development_cases": "development-case analysis, not independent validation",
        },
        "summary": summarize_grid(g, methods),
        "H2": cell_tgc_check(g),
        "H3": h3_check(g),
        "H4": h4_check(g),
        "attack_curves": attack_curves(g),
        "negative_controls": negative_controls(),
        "ltr": ltr_report,
        "development_cases": development_cases(poisoning_dir, scorers),
        "grid": g,
    }
    sizes = [n for n in (100, 1_000, 10_000, 100_000) if n <= perf_max]
    result["performance"] = performance(sizes)
    peak = peak_rss_bytes()
    result["resources"] = {
        "seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "adversarial-ranking.json").write_text(
        json.dumps(result, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result


# --- post-hoc checks (added after the negative controls flagged benchmark design bias) -------

POSTHOC_METHODS = ("B0", "B3", "B4", "B5", "B6", "P1", "P1b", "A-laminf", "A-nomech", "NC-revrec")


def adaptive_scenario(
    m: int,
    *,
    same_reference: bool = False,
    decoy_time: str = "newer",
    decoy_mechanism: str = "native",
    target_reference: int = 0,
    target_index: int = 0,
) -> Scenario:
    """F7 (decoys on the other references) or F6 (``same_reference``) with the design
    choices the pre-registered grid fixed now varied by an adaptive attacker: decoys older
    than the target, decoys sharing the target's mechanism (zero-value spoofs), the target
    on any of the five references, and a target address that does not sort first."""
    refs = references()
    r_t = refs[target_reference]
    t = rs.lookalike(target_index, prefix=4, suffix=4, ref=r_t)
    pool = [r_t] if same_reference else [r for r in refs if r != r_t]
    decoys = _decoys(m, 4, 4, pool, start=5_000)

    def blk(i: int) -> int:
        return 1_600 + i % 400 if decoy_time == "older" else _block(i)

    tr: list[Any] = [(W, t, 0, 2_000, ATTACKER, USDT, 0)]
    nat: list[Any] = []
    for i, d in enumerate(decoys):
        if decoy_mechanism == "spoof":
            tr.append((W, d, 0, blk(i), ATTACKER, USDT, 1 + i % 50))
        else:
            nat.append((d, 1, blk(i), True))
    fx = _fixture(refs, transfers=tr, native=nat)
    return Scenario("adaptive", m, fx, (t.lower(),), r_t.lower())


def _mean_exposure(cell: dict[str, Any], meth: str) -> float:
    vals: dict[int, float] = cell["methods"][meth]["exposure"]
    return round(sum(vals.values()) / len(vals), 4)


def posthoc_checks(m_grid: Sequence[int] = (10, 100, 1_000)) -> dict[str, Any]:
    """Exploratory and post hoc: each variant is averaged over m and K like the grid."""
    variants: dict[str, dict[str, Any]] = {
        "F7_as_registered": {},
        "F7_decoys_older": {"decoy_time": "older"},
        "F7_decoys_share_mechanism": {"decoy_mechanism": "spoof"},
        "F7_target_address_not_first": {"target_index": 0x7_777_777},
        "F6_target_address_not_first": {"same_reference": True, "target_index": 0x7_777_777},
        **{f"F7_target_on_R{j + 1}": {"target_reference": j} for j in range(5)},
    }
    out: dict[str, Any] = {}
    for name, kw in variants.items():
        acc: dict[str, list[float]] = {m: [] for m in POSTHOC_METHODS}
        for m in m_grid:
            cell = run_cell(adaptive_scenario(m, **kw))
            for meth in POSTHOC_METHODS:
                acc[meth].append(_mean_exposure(cell, meth))
        out[name] = {meth: round(sum(v) / len(v), 4) for meth, v in acc.items()}
    refs_avg = {
        meth: round(sum(out[f"F7_target_on_R{j + 1}"][meth] for j in range(5)) / 5, 4)
        for meth in POSTHOC_METHODS
    }
    out["F7_averaged_over_target_reference"] = refs_avg
    # H4 with 200 seeds: is the 10-seed deviation sampling noise?
    seeds = tuple(range(200))
    h4 = []
    for m in (10, 100):
        sc = scenario("F6_equal_similarity_same_reference", m)
        groups = list(ce.build(sc.fixture, cutoff=END).groups)
        t = sc.relevant[0]
        ranks = [
            next(
                i + 1
                for i, g in enumerate(ar.order(groups, ar.Selector("P1", seed=s)))
                if g.lookalike == t
            )
            for s in seeds
        ]
        for k in K_GRID:
            if m < k:
                continue
            p = sum(1 for r in ranks if r <= k) / len(ranks)
            theory = min(1.0, k / (m + 1))
            se = math.sqrt(theory * (1 - theory) / len(ranks))
            h4.append(
                {
                    "m": m,
                    "K": k,
                    "theory": round(theory, 4),
                    "observed_200_seeds": round(p, 4),
                    "se": round(se, 4),
                }
            )
    out["H4_200_seeds"] = h4
    out["label"] = "post hoc, exploratory: added after NC-revrec and B3 scored unexpectedly high"
    return out

"""Phase 12.2 (``cryptoguard ml recency-validation``), as pre-registered in
docs/ml/protocol-12.2.md. Aggregate output only; 0 RPC requests.

Every archive analysis here re-examines the Phase 12.1 episodes. It is retrospective
sensitivity analysis, never independent validation. H1 and H2 are the confirmatory tests,
H3 is descriptive, and everything else is exploratory and labelled so.
"""

from __future__ import annotations

import math
import random
import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptoguard.ml import lookalike_ranking as lr

STUDY_VERSION = "recency-validation/1"
PROTOCOL = "protocol-12.2/1"
SEED = 20261103
DAY = lr.DAY
PUBLIC_TOKENS = frozenset(
    {
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    }
)
Feats = Mapping[str, Mapping[str, lr.Value]]
Scores = dict[str, float]


# --- the symmetric confirmation rule (protocol section 3) ---------------------------------


def _intended_rows(ep: lr.Episode, c: int) -> dict[str, list[int]]:
    """Blocks of the victim's source-flagged intended rows at or before ``c``, by receiver."""
    from cryptoguard.ml.tsuchiya_archive import INTENDED

    out: defaultdict[str, list[int]] = defaultdict(list)
    for r in ep.victim_out:
        if r.flags & INTENDED and r.block <= c:
            out[r.receiver].append(r.block)
    return out


def confirmation_rule(ep: lr.Episode, c: int) -> dict[str, tuple[bool | None, bool | None]]:
    """Per candidate at ``c``: ``(SR_any, SR_latest)``, both ``None`` when no planting of it
    names an intended address. SR_any: some planting with intended address ``a`` comes
    strictly after an intended row to ``a``. SR_latest: its latest planting comes after
    the victim's latest intended row to any of its intended addresses."""
    intended = _intended_rows(ep, c)
    by_l: defaultdict[str, list[lr.Row]] = defaultdict(list)
    for r in ep.plantings:
        if r.block <= c:
            by_l[lr.lookalike_of(r, ep.victim)].append(r)
    out: dict[str, tuple[bool | None, bool | None]] = {}
    for lk, rows in by_l.items():
        named = [r for r in rows if r.intended and r.intended != lk]
        if not named:
            out[lk] = (None, None)
            continue
        sr_any = any(any(b < r.block for b in intended.get(r.intended or "", [])) for r in named)
        latest = max(r.block for r in rows)
        last_intended = max(
            (max(intended[a]) for a in {r.intended for r in named} if a and a in intended),
            default=None,
        )
        out[lk] = (sr_any, last_intended is not None and latest > last_intended)
    return out


# --- scoring helpers ----------------------------------------------------------------------


def _top1(scores: Mapping[str, float] | None, paid: str, cands: Iterable[str]) -> float:
    keys = list(cands)
    if scores is None:
        return 1.0 / len(keys)
    return lr.top1({k: scores[k] for k in keys}, paid, len(keys))


def _single(f: Feats, name: str, keep: Iterable[str] | None = None) -> Scores | None:
    keys = list(f) if keep is None else list(keep)
    vals = {k: f[k][name] for k in keys}
    if any(v is None for v in vals.values()):
        return None
    return {k: float(v) for k, v in vals.items() if v is not None}


def _mean(xs: Sequence[float]) -> float | None:
    return round(statistics.fmean(xs), 4) if xs else None


def _cmp(
    t0: Sequence[float], b0: Sequence[float], grp: Sequence[int], *, n_perm: int = 10_000
) -> dict[str, Any]:
    d = [a - b for a, b in zip(t0, b0, strict=True)]
    if not d:
        return {"episodes": 0}
    out = lr.paired(d, grp, seed=SEED, n_perm=n_perm)
    out["T0_top1"] = _mean(t0)
    out["B0_top1"] = _mean(b0)
    return out


# --- archive-observation replay of the production detector (H2, E13) ---------------------


def production_cases(ep: lr.Episode, c: int) -> list[Any]:
    """Run the unchanged production detector on the victim's archive rows at or before ``c``.

    The archive has no signers, no raw values and no in-block order, so:
    - signers are unknown (``None``);
    - the value is 0 for zero-value rows and 1 otherwise;
    - the archive line stands in for the log index."""
    from cryptoguard.blockchain.erc20 import TransferEvent
    from cryptoguard.core.address import to_checksum_address
    from cryptoguard.detectors.poisoning import detect_poisoning
    from cryptoguard.ml.tsuchiya_archive import ZERO

    rows = sorted(
        {r for r in (*ep.plantings, *ep.victim_out) if r.block <= c},
        key=lambda r: (r.block, r.line),
    )
    events = [
        TransferEvent(
            token=to_checksum_address(r.token),
            sender=to_checksum_address(r.sender),
            recipient=to_checksum_address(r.receiver),
            value=0 if r.flags & ZERO else 1,
            block_number=r.block,
            block_hash="",
            transaction_hash=r.tx,
            transaction_index=0,
            log_index=r.line,
            tx_sender=None,
        )
        for r in rows
    ]
    return detect_poisoning(ep.victim, events, chain_id=1, wallet_is_plain_eoa=None)


def _op_top1(cases: Sequence[Any], paid: str, c: int) -> tuple[float, float]:
    from cryptoguard.ml.warning_rank import baseline_score, recency_score

    k = len(cases)
    # Exact integers: a float would lose the block resolution of the packed key.
    s0: dict[str, float] = {x.suspect.lower(): _pack(baseline_score(x)) for x in cases}
    s1: dict[str, float] = {x.suspect.lower(): _pack(recency_score(x, c)) for x in cases}
    return lr.top1(s0, paid, k), lr.top1(s1, paid, k)


def _pack(t: tuple[int, ...]) -> int:
    """Lexicographic tuple as one integer (each field < 10**10)."""
    out = 0
    for x in t:
        out = out * 10**10 + int(x)
    return out


# --- recorded incidents (H3) and background windows (E14) ---------------------------------


Blind = tuple[frozenset[str], frozenset[str]]  # frozen-cohort (addresses, transactions)


def touches_frozen(fixture: Any, blind: Blind) -> bool:
    """A recorded window that holds a frozen review item: its wallet, or any transfer whose
    party or transaction is a frozen address or transaction. Such a window never enters a
    computation (protocol 12.1 section 3; amendment 12.2-cohort-overlap)."""
    addrs, txs = blind
    if fixture.wallet.lower() in addrs:
        return True
    return any(
        t.sender.lower() in addrs
        or t.recipient.lower() in addrs
        or t.transaction_hash.lower() in txs
        for t in fixture.transfers
    )


def incidents(blind: Blind) -> list[dict[str, Any]]:
    from cryptoguard.detectors.poisoning import PoisoningConfig
    from cryptoguard.ml.warning_rank import rank_warnings
    from cryptoguard.replay.engine import Visibility, detector_outputs
    from cryptoguard.replay.models import load_cases

    out = []
    for case in load_cases():
        if case.fixture is None:
            continue
        m = case.manifest
        if touches_frozen(case.fixture, blind):
            out.append({"case": m.case_id, "excluded": "holds a frozen review item"})
            continue
        c = m.harm.block_number - 1
        cases, _ = detector_outputs(
            case.fixture, c, Visibility.ERC20_PLUS_WALLET_TRANSACTIONS, PoisoningConfig()
        )
        paid = m.harm.recipient.lower()
        entry: dict[str, Any] = {"case": m.case_id, "warnings": len(cases)}
        warned = [x for x in cases if x.suspect.lower() == paid]
        entry["paid_warned"] = bool(warned)
        if warned and len(cases) >= 2:
            t0, t1 = _op_top1(cases, paid, c)
            entry |= {"OP0_top1": round(t0, 4), "OP1_top1": round(t1, 4), "random": 1 / len(cases)}
            ranked = rank_warnings(cases, c)
            entry["OP1_display_rank"] = next(r.rank for r in ranked if r.suspect.lower() == paid)
            entry["paid_basis"] = next(r.basis for r in ranked if r.suspect.lower() == paid)
        out.append(entry)
    return out


def background(blind: Blind) -> dict[str, Any]:
    from cryptoguard.detectors.poisoning import PoisoningConfig
    from cryptoguard.ml.warning_rank import baseline_score, rank_warnings
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.engine import Visibility, detector_outputs

    t = time.perf_counter()
    windows = multi = changed = preserved = no_basis = n = excluded = 0
    for b in load_background():
        if b.fixture is None:
            continue
        if touches_frozen(b.fixture, blind):
            excluded += 1
            continue
        windows += 1
        c = b.fixture.to_block
        cases, _ = detector_outputs(
            b.fixture, c, Visibility.ERC20_PLUS_WALLET_TRANSACTIONS, PoisoningConfig()
        )
        n += len(cases)
        ranked = rank_warnings(cases, c)
        preserved += sorted(r.suspect for r in ranked) == sorted(x.suspect for x in cases)
        no_basis += sum(r.basis == "no_recency_basis" for r in ranked)
        if len(cases) >= 2:
            multi += 1
            base = sorted(cases, key=lambda x: (baseline_score(x), x.suspect.lower()), reverse=True)
            changed += [x.suspect for x in base] != [r.suspect for r in ranked]
    return {
        "windows": windows,
        "warnings": n,
        "windows_with_2plus_warnings": multi,
        "windows_order_changed": changed,
        "windows_warning_set_preserved": preserved,
        "warnings_without_recency_basis": no_basis,
        "windows_excluded_frozen_cohort": excluded,
        "seconds": round(time.perf_counter() - t, 3),
    }


# --- the study ------------------------------------------------------------------------------


def _strata(
    keys: Sequence[str],
    grp: Sequence[int],
    t0: Sequence[float],
    b0: Sequence[float],
    rnd: Sequence[float],
) -> dict[str, Any]:
    by: defaultdict[str, list[int]] = defaultdict(list)
    for i, k in enumerate(keys):
        by[k].append(i)
    return {
        k: {
            "episodes": len(ix),
            "groups": len({grp[i] for i in ix}),
            "T0": _mean([t0[i] for i in ix]),
            "B0": _mean([b0[i] for i in ix]),
            "random": _mean([rnd[i] for i in ix]),
        }
        for k, ix in sorted(by.items())
    }


def _restricted(
    eps: Sequence[lr.Episode],
    feats: Sequence[Feats],
    grp: Sequence[int],
    keep: Callable[[int, str], bool],
) -> dict[str, Any]:
    """T0 vs B0 on candidate sets restricted by ``keep(episode index, candidate)``; an
    episode counts when the paid candidate survives and k >= 2."""
    t0, b0, rnd, g = [], [], [], []
    dropped_paid = small = 0
    for i, (e, f) in enumerate(zip(eps, feats, strict=True)):
        ks = [c for c in f if keep(i, c)]
        if e.paid not in ks:
            dropped_paid += 1
            continue
        if len(ks) < 2:
            small += 1
            continue
        t0.append(_top1(_single(f, "T0", ks), e.paid, ks))
        b0.append(_top1(_single(f, "B0", ks), e.paid, ks))
        rnd.append(1 / len(ks))
        g.append(grp[i])
    out = _cmp(t0, b0, g, n_perm=2_000)
    out |= {"random_top1": _mean(rnd), "paid_removed": dropped_paid, "fewer_than_2": small}
    return out


def run(poisoning_dir: Path) -> dict[str, Any]:
    t_start = time.perf_counter()
    episodes, exclusions = lr.load_episodes(poisoning_dir)
    tokens = lr.TokenIndex.build(episodes)
    grp, linkage = lr.protocol_groups(episodes)
    feats: list[Feats] = []
    for e in episodes:
        fe = lr.candidate_features(e, lr.View(), None, tokens)
        if fe is None:
            raise RuntimeError("an eligible episode is not evaluable at the primary cutoff")
        feats.append(fe)
    n = len(episodes)
    cut = [e.payoff_block - 1 for e in episodes]
    t0 = [_top1(_single(f, "T0"), e.paid, f) for f, e in zip(feats, episodes, strict=True)]
    b0 = [_top1(_single(f, "B0"), e.paid, f) for f, e in zip(feats, episodes, strict=True)]
    rnd = [1 / len(f) for f in feats]
    report: dict[str, Any] = {
        "task": STUDY_VERSION,
        "protocol": PROTOCOL,
        "classification": "retrospective internal sensitivity analysis (previously examined)",
        "episodes": n,
        "distinct_victims": len({e.victim for e in episodes}),
        "exclusions": exclusions,
        "groups": {
            "linkage": linkage,
            "count": len(set(grp)),
            "largest": max(Counter(grp).values()),
        },
        "k": {
            "mean": round(statistics.fmean(len(f) for f in feats), 2),
            "median": statistics.median(len(f) for f in feats),
            "bins": dict(Counter(_kbin(len(f)) for f in feats)),
        },
        "R_all": _cmp(t0, b0, grp, n_perm=2_000) | {"random_top1": _mean(rnd)},
    }

    # Protected overlap (protocol section 7).
    overlap = lr.protected_overlap(episodes, *lr.protected_entities(poisoning_dir))
    report["protected_overlap"] = {"episodes_linked": sum(overlap)}

    # H1: the symmetric confirmation rule.
    sr = [confirmation_rule(e, cc) for e, cc in zip(episodes, cut, strict=True)]
    manip: dict[str, Counter[str]] = {"paid": Counter(), "rival": Counter()}
    for e, rule in zip(episodes, sr, strict=True):
        for lk, (any_, lt) in rule.items():
            side = manip["paid" if lk == e.paid else "rival"]
            side["candidates"] += 1
            side["any_true"] += any_ is True
            side["any_none"] += any_ is None
            side["latest_true"] += lt is True
    report["manipulation_check"] = {
        side: {
            "candidates": m["candidates"],
            "SR_any_true_share": round(m["any_true"] / m["candidates"], 4),
            "SR_none_share": round(m["any_none"] / m["candidates"], 4),
            "SR_latest_true_share": round(m["latest_true"] / m["candidates"], 4),
        }
        for side, m in manip.items()
    }
    h1_idx = [
        i
        for i, (e, s) in enumerate(zip(episodes, sr, strict=True))
        if s[e.paid][0] is True and sum(1 for v in s.values() if v[0] is True) >= 2
    ]

    def sr_keep(i: int, c: str) -> bool:
        return sr[i][c][0] is True

    h1_t0, h1_b0, h1_rnd, h1_full_t0, h1_full_b0 = [], [], [], [], []
    for i in h1_idx:
        e, f = episodes[i], feats[i]
        ks = [c for c in f if sr_keep(i, c)]
        h1_t0.append(_top1(_single(f, "T0", ks), e.paid, ks))
        h1_b0.append(_top1(_single(f, "B0", ks), e.paid, ks))
        h1_rnd.append(1 / len(ks))
        h1_full_t0.append(t0[i])
        h1_full_b0.append(b0[i])
    h1g = [grp[i] for i in h1_idx]
    h1 = _cmp(h1_t0, h1_b0, h1g) | {"random_top1": _mean(h1_rnd)}
    full = _cmp(h1_full_t0, h1_full_b0, h1g, n_perm=2_000)
    h1["delta_same_episodes_full_sets"] = round(full["mean"], 4) if h1_idx else None
    h1["attenuation"] = (
        round((full["mean"] - h1["mean"]) / full["mean"], 4) if h1_idx and full["mean"] else None
    )
    h1["excluded"] = {
        "paid_SR_not_true": sum(
            1 for e, s in zip(episodes, sr, strict=True) if s[e.paid][0] is not True
        ),
        "fewer_than_2_SR_candidates": sum(
            1
            for e, s in zip(episodes, sr, strict=True)
            if s[e.paid][0] is True and sum(1 for v in s.values() if v[0] is True) < 2
        ),
    }

    # H2: production warnings, archive observation.
    t = time.perf_counter()
    h2_op0, h2_op1, h2_g, h2_idx = [], [], [], []
    warned: dict[str, Counter[str]] = {"paid": Counter(), "rival": Counter()}
    for i, e in enumerate(episodes):
        cases = production_cases(e, cut[i])
        sus = {x.suspect.lower() for x in cases}
        for c in feats[i]:
            w = warned["paid" if c == e.paid else "rival"]
            w["candidates"] += 1
            w["warned"] += c in sus
        if e.paid in sus and len(cases) >= 2:
            op0, op1 = _op_top1(cases, e.paid, cut[i])
            h2_op0.append(op0)
            h2_op1.append(op1)
            h2_g.append(grp[i])
            h2_idx.append(i)
    h2 = _cmp(h2_op1, h2_op0, h2_g)
    h2 = {
        **{k: v for k, v in h2.items() if k not in ("T0_top1", "B0_top1")},
        "OP1_top1": h2.get("T0_top1"),
        "OP0_top1": h2.get("B0_top1"),
    }
    report["production_replay_seconds"] = round(time.perf_counter() - t, 1)
    report["E13_operational_coverage"] = {
        side: {
            "candidates": w["candidates"],
            "warned_share": round(w["warned"] / w["candidates"], 4),
        }
        for side, w in warned.items()
    } | {"H2_eligible_episodes": len(h2_idx)}

    adj = lr.holm({"H1": h1["p"], "H2": h2["p"]}) if h1_idx and h2_idx else {}
    for name, res in (("H1", h1), ("H2", h2)):
        if name in adj:
            res["p_holm"] = adj[name]
            res["decision"] = _decision(res, adj[name])
    report["H1_symmetric_confirmation"] = h1
    report["H2_production_warnings"] = h2

    # Sensitivity: H1 and H2 without protected overlap; H1 with SR_latest and with SR None.
    clean = [i for i in range(n) if not overlap[i]]
    report["H1_without_overlap"] = _restricted(
        [episodes[i] for i in clean],
        [feats[i] for i in clean],
        [grp[i] for i in clean],
        lambda j, c: sr[clean[j]][c][0] is True,
    )
    report["H1_SR_latest"] = _restricted(episodes, feats, grp, lambda i, c: sr[i][c][1] is True)
    report["H1_SR_none_included"] = _restricted(
        episodes, feats, grp, lambda i, c: sr[i][c][0] is not False
    )
    blind = lr.protected_entities(poisoning_dir)
    report["H3_incidents"] = incidents(blind)

    # E1 within-episode permutation of T0; E2 reversed time.
    rng = random.Random(SEED)  # noqa: S311 - seeded research sampling, not security
    perm: list[float] = []
    for f, e in zip(feats, episodes, strict=True):
        t0_vals = [f[c]["T0"] for c in f]
        acc = 0.0
        for _ in range(200):
            rng.shuffle(t0_vals)
            shuffled = {c: float(v or 0.0) for c, v in zip(f, t0_vals, strict=True)}
            acc += lr.top1(shuffled, e.paid, len(f))
        perm.append(acc / 200)
    rev = [
        _top1({c: -float(f[c]["T0"] or 0.0) for c in f}, e.paid, f)
        for f, e in zip(feats, episodes, strict=True)
    ]
    report["E1_within_episode_permutation_top1"] = _mean(perm)
    report["E2_oldest_first_top1"] = _mean(rev)
    report["random_top1"] = _mean(rnd)

    # E3 timing jitter; E4 coarsening.
    def gaps(e: lr.Episode, c: int, shift: Callable[[lr.Row], int]) -> dict[str, float]:
        g: dict[str, int] = {}
        for r in e.plantings:
            if r.block <= c:
                lk = lr.lookalike_of(r, e.victim)
                b = min(c, r.block + shift(r))
                g[lk] = min(g.get(lk, 1 << 62), c - b)
        return {k: float(v) for k, v in g.items()}

    jit: dict[str, float | None] = {}
    for days in (1, 7):
        j = days * DAY
        vals: list[float] = []
        for e, cc in zip(episodes, cut, strict=True):
            r2 = random.Random(f"{SEED}:{e.victim}:{days}")  # noqa: S311 - seeded research
            shifts: dict[int, int] = {}

            def shift(
                r: lr.Row, s: dict[int, int] = shifts, rr: random.Random = r2, j: int = j
            ) -> int:
                return s.setdefault(r.line, rr.randint(-j, j))

            gp = gaps(e, cc, shift)
            vals.append(_top1({k: -v for k, v in gp.items()}, e.paid, gp))
        jit[f"jitter_{days}d"] = _mean(vals)
    for days in (1, 7):
        vals = []
        for e, cc in zip(episodes, cut, strict=True):
            gp = gaps(e, cc, lambda _r: 0)
            vals.append(
                _top1({k: -math.floor(v / (days * DAY)) for k, v in gp.items()}, e.paid, gp)
            )
        jit[f"coarsened_{days}d"] = _mean(vals)
    report["E3_E4_timing"] = jit

    # E5 token class; E6 k bins; E9 strata.
    def last_token(e: lr.Episode, lk: str, c: int) -> str:
        rows = [r for r in e.plantings if r.block <= c and lr.lookalike_of(r, e.victim) == lk]
        return max(rows, key=lambda r: (r.block, r.line)).token

    paid_cls = [
        "public_stablecoin" if last_token(e, e.paid, cc) in PUBLIC_TOKENS else "other"
        for e, cc in zip(episodes, cut, strict=True)
    ]
    report["E5_paid_token_class"] = _strata(paid_cls, grp, t0, b0, rnd)
    report["E5_public_token_candidates_only"] = _restricted(
        episodes, feats, grp, lambda i, c: last_token(episodes[i], c, cut[i]) in PUBLIC_TOKENS
    )
    report["E6_k"] = _strata([_kbin(len(f)) for f in feats], grp, t0, b0, rnd)

    # E7 symmetric maximum lookback; E8 no immediate copies.
    def within(days: int) -> Callable[[int, str], bool]:
        return lambda i, c: -(feats[i][c]["T0"] or 0) <= days * DAY

    report["E7_symmetric_lookback"] = {
        f"{w}d": _restricted(episodes, feats, grp, within(w)) for w in (30, 90, 180)
    }
    non_imm = [i for i in range(n) if -(feats[i][episodes[i].paid]["T0"] or 0) >= 300]
    report["E8_paid_gap_at_least_300_blocks"] = _cmp(
        [t0[i] for i in non_imm], [b0[i] for i in non_imm], [grp[i] for i in non_imm], n_perm=2_000
    ) | {
        "random_top1": _mean([rnd[i] for i in non_imm]),
        "label": "stratified on an outcome attribute",
    }

    from cryptoguard.ml.lookalike_study import _year, subtype

    activity = [
        sum(1 for r in e.victim_out if r.block <= cc) for e, cc in zip(episodes, cut, strict=True)
    ]
    q1, q2 = statistics.quantiles(activity, n=3)
    newest = [min(-(v["T0"] or 0) for v in f.values()) for f in feats]
    largest_share = max(Counter(grp).values()) / n
    report["E9_strata"] = {
        "year": _strata([_year(e.payoff_block) for e in episodes], grp, t0, b0, rnd),
        "paid_subtype": _strata([subtype(e) for e in episodes], grp, t0, b0, rnd),
        "victim_activity_tertile": _strata(
            ["low" if a <= q1 else "mid" if a <= q2 else "high" for a in activity], grp, t0, b0, rnd
        ),
        "newest_candidate_age": _strata([_agebin(x) for x in newest], grp, t0, b0, rnd),
        "largest_group_share": round(largest_share, 4),
    }

    # E10 negative control.
    nc = [_top1(_single(f, "NC"), e.paid, f) for f, e in zip(feats, episodes, strict=True)]
    rho = []
    for f in feats:
        if len(f) >= 3:
            r_ = _spearman([f[c]["NC"] or 0.0 for c in f], [f[c]["T0"] or 0.0 for c in f])
            if r_ is not None:
                rho.append(r_)
    same_cls = [
        i
        for i, (e, f) in enumerate(zip(episodes, feats, strict=True))
        if len({last_token(e, c, cut[i]) in PUBLIC_TOKENS for c in f}) == 1
    ]
    report["E10_negative_control"] = {
        "NC_top1": _mean(nc),
        "random_top1": _mean(rnd),
        "by_paid_token_class": {
            k: {
                "episodes": len(ix),
                "NC": _mean([nc[i] for i in ix]),
                "random": _mean([rnd[i] for i in ix]),
            }
            for k in ("public_stablecoin", "other")
            for ix in ([i for i in range(n) if paid_cls[i] == k],)
        },
        "within_episode_spearman_NC_T0": {
            "episodes": len(rho),
            "mean": _mean(rho),
            "median": round(statistics.median(rho), 4) if rho else None,
        },
        "candidates_share_token_class": {
            "episodes": len(same_cls),
            "NC": _mean([nc[i] for i in same_cls]),
            "random": _mean([rnd[i] for i in same_cls]),
        },
    }

    # E11 history perturbations.
    def t0_on(eps: Sequence[lr.Episode]) -> tuple[float | None, int]:
        vals = []
        for e in eps:
            f = lr.candidate_features(e, lr.View(), None, None)
            if f is not None:
                vals.append(_top1(_single(f, "T0"), e.paid, f))
        return _mean(vals), len(vals)

    def drop_latest(e: lr.Episode) -> lr.Episode:
        latest: dict[str, lr.Row] = {}
        for r in e.plantings:
            lk = lr.lookalike_of(r, e.victim)
            if lk not in latest or (r.block, r.line) > (latest[lk].block, latest[lk].line):
                latest[lk] = r
        gone = set(latest.values())
        return replace(e, plantings=tuple(r for r in e.plantings if r not in gone))

    def duplicate(e: lr.Episode) -> lr.Episode:
        return replace(
            e, plantings=e.plantings + tuple(replace(r, line=r.line + 10**9) for r in e.plantings)
        )

    def reorder(e: lr.Episode) -> lr.Episode:
        rr = random.Random(f"{SEED}:{e.victim}:reorder")  # noqa: S311 - seeded research
        by_b: defaultdict[int, list[lr.Row]] = defaultdict(list)
        for r in e.plantings:
            by_b[r.block].append(r)
        out = []
        for _b, rows in by_b.items():
            lines = [r.line for r in rows]
            rr.shuffle(lines)
            out += [replace(r, line=ln) for r, ln in zip(rows, lines, strict=True)]
        return replace(e, plantings=tuple(out))

    base_t0 = _mean(t0)
    e11: dict[str, Any] = {"primary_T0_top1": base_t0}
    for name, fn in (
        ("drop_latest_planting", drop_latest),
        ("duplicate_rows", duplicate),
        ("reorder_within_block", reorder),
    ):
        v, k = t0_on([fn(e) for e in episodes])
        e11[name] = {"T0_top1": v, "evaluable": k}
    report["E11_history_perturbations"] = e11

    # E12 errors (top-1 == 1 means the paid candidate alone at the top).
    cells: Counter[str] = Counter()
    cats: dict[str, Counter[str]] = defaultdict(Counter)
    for i, (e, f) in enumerate(zip(episodes, feats, strict=True)):
        cell = f"T0_{'hit' if t0[i] == 1.0 else 'miss'}__B0_{'hit' if b0[i] == 1.0 else 'miss'}"
        cells[cell] += 1
        cat = cats[cell]
        gap = -(f[e.paid]["T0"] or 0)
        cat["paid_gap_over_30d"] += gap > 30 * DAY
        cat["two_plus_candidates_within_1d"] += (
            sum(1 for v in f.values() if -(v["T0"] or 0) <= DAY) >= 2
        )
        cat["paid_planted_more_than_once"] += (f[e.paid]["T1"] or 0) >= 2
        cat["k_6_plus"] += len(f) >= 6
        cat["B0_tied_at_top"] += 0 < b0[i] < 1
    report["E12_errors"] = {k: {"episodes": v, **cats[k]} for k, v in sorted(cells.items())}

    report["E14_background"] = background(blind)
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    peak = peak_rss_bytes()
    report["resources"] = {
        "total_seconds": round(time.perf_counter() - t_start, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
        "rpc_requests": 0,
        "graph_used": False,
    }
    return report


def _decision(diff: Mapping[str, Any], p_holm: float, margin: float = 0.05) -> str:
    """Protocol 12.2 section 4."""
    lo, hi = diff["ci95"]
    if p_holm < 0.05 and lo > 0 and diff["mean"] >= margin:
        return "survives"
    if (-margin < lo and hi < margin) or (diff["mean"] <= 0 and hi < margin):
        return "explained_or_null"
    return "inconclusive"


def _kbin(k: int) -> str:
    return "2" if k == 2 else "3-5" if k <= 5 else "6+"


def _agebin(gap: float) -> str:
    if gap < 300:
        return "a_under_1h"
    if gap < DAY:
        return "b_1h_to_1d"
    if gap < 7 * DAY:
        return "c_1d_to_7d"
    return "d_over_7d"


def _spearman(x: Sequence[float], y: Sequence[float]) -> float | None:
    def ranks(v: Sequence[float]) -> list[float]:
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for m in range(i, j + 1):
                r[order[m]] = (i + j) / 2
            i = j + 1
        return r

    rx, ry = ranks(x), ranks(y)
    mx, my = statistics.fmean(rx), statistics.fmean(ry)
    sx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    sy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if sx == 0 or sy == 0:
        return None
    return sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True)) / (sx * sy)

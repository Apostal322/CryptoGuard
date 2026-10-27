"""Evaluation of the experimental analyses against the existing detector and simple baselines.

Subjects are the recorded incident cases (positives, scored with their manifests) and the
randomly sampled background wallets (unlabelled). Every method is run point in time: at the
end of each ``BIN_BLOCKS`` bin it sees ``ObservationSet.at(bin end)`` and nothing later.

Wallet-level alert methods compared per bin:

- ``A_existing``    a new CG-POI-001/003 suspect appears (the production detector);
- ``F_count_rule``  >= 3 zero-value or unsolicited incoming transfers in the bin (no history);
- ``D_temporal``    robust-z burst on any activity series (``analytics.temporal``);
- ``D_ewma``        the same series scored against an EWMA baseline;
- ``C_spectral``    robust-z of the spectral distance between consecutive window graphs;
- ``C_structural``  robust-z of the change in counterparties / edges between window graphs.

Graph propagation (``B``) produces no wallet-level alerts; it enriches A's warnings with
related addresses and is evaluated by what it surfaces and by how its rankings differ from
hop distance and neighbour aggregation.

Positives are scored against the address that later received the funds (from the manifest,
used only here): A is on target when it names that address as a warned suspect before the
harmful block; the anomaly methods, which name no address, when they fire in a bin in which
that address is active. ``onset`` is that address's first appearance in the data, the
earliest block at which any method could possibly relate an alert to it.
"""

from __future__ import annotations

import itertools
import statistics
import time
import tracemalloc
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from pydantic import BaseModel

from cryptoguard.analytics.diffusion import Seed, propagate
from cryptoguard.analytics.graph import GraphScope, build_graph
from cryptoguard.analytics.hawkes import fit, log_likelihood, poisson_log_likelihood
from cryptoguard.analytics.observations import BlockRange, ObservationSet
from cryptoguard.analytics.spectral import (
    StructuralFeatures,
    spectral_distance,
    structural_features,
)
from cryptoguard.analytics.temporal import SERIES, activity_bins, detect_bursts, ewma_scores
from cryptoguard.core.address import to_checksum_address
from cryptoguard.detectors.poisoning import detect_poisoning
from cryptoguard.replay.engine import WARNING_RULES
from cryptoguard.replay.models import ReplayFixture

BIN_BLOCKS = 300  # ~1 hour
WINDOW_BLOCKS = 1_800  # graph window for structural comparison (~6 hours)
THRESHOLD = 4.0
MIN_HISTORY = 12
BLOCKS_PER_DAY = 7_200
METHODS = ("A_existing", "F_count_rule", "D_temporal", "D_ewma", "C_spectral", "C_structural")
COMBINATIONS = (
    ("A_existing", "F_count_rule"),
    ("A_existing", "D_temporal"),
    ("A_existing", "C_spectral"),
    ("A_existing", "C_structural"),
    ("A_existing", "D_temporal", "C_spectral"),
)


@dataclass(frozen=True)
class Subject:
    case_id: str
    kind: str  # "positive" | "background"
    fixture: ReplayFixture
    harm_block: int | None = None
    target: str | None = None  # harm recipient (positives only; scoring only)


def observations_of(fixture: ReplayFixture) -> ObservationSet:
    full = [BlockRange(fixture.from_block, fixture.to_block)]
    return ObservationSet.build(
        chain_id=fixture.chain_id,
        wallet=fixture.wallet,
        cutoff_block=fixture.to_block,
        transfers=[t.as_event() for t in fixture.transfers],
        native_sends=[s for t in fixture.wallet_transactions if (s := t.as_native_send())],
        transfer_ranges=full if fixture.transfer_scan_complete else [],
        wallet_tx_ranges=full,
        signer_lookups_skipped=fixture.sender_lookups_skipped,
    )


def _plain(fixture: ReplayFixture, cutoff: int) -> bool | None:
    known = {int(b): c for b, c in fixture.wallet_code_hex.items() if int(b) <= cutoff}
    return known[max(known)] == "0x" if known else None


def _warnings(fixture: ReplayFixture, o: ObservationSet) -> dict[str, str]:
    cases = detect_poisoning(
        o.wallet,
        list(o.transfers),
        chain_id=o.chain_id,
        wallet_is_plain_eoa=_plain(fixture, o.cutoff_block),
        native_sends=list(o.native_sends),
    )
    return {c.suspect: c.rule_id for c in cases if c.rule_id in WARNING_RULES}


def _robust_flags(values: Sequence[float | None]) -> list[bool]:
    """Robust z of each value against strictly earlier non-missing values."""
    out: list[bool] = []
    past: list[float] = []
    for v in values:
        if v is None:
            out.append(False)
            continue
        if len(past) >= MIN_HISTORY:
            med = statistics.median(past)
            mad = statistics.median(abs(x - med) for x in past)
            scale = max(1.4826 * mad, 0.05 if max(past) <= 2 else 1.0)
            out.append((v - med) / scale >= THRESHOLD)
        else:
            out.append(False)
        past.append(v)
    return out


class MethodResult(BaseModel):
    alerts: int
    alert_blocks: list[int]
    first_alert_before_harm: int | None = None
    on_target: bool | None = None
    lead_blocks: int | None = None
    seconds: float = 0.0


class SubjectResult(BaseModel):
    case_id: str
    kind: str
    wallet_days: float
    transfers: int
    native_sends: int
    bins: int
    onset_block: int | None
    harm_block: int | None
    methods: dict[str, MethodResult]
    graph: dict[str, object] = {}
    peak_memory_kib: int = 0


@dataclass
class _Timer:
    seconds: dict[str, float] = field(default_factory=dict)

    def run(self, name: str, fn: Callable[[], list[bool]]) -> list[bool]:
        t = time.perf_counter()
        out = fn()
        self.seconds[name] = self.seconds.get(name, 0.0) + time.perf_counter() - t
        return out


def evaluate_subject(subject: Subject) -> SubjectResult:
    fx = subject.fixture
    full = observations_of(fx)
    end = (subject.harm_block - 1) if subject.harm_block is not None else fx.to_block
    pre = full.at(end)  # positives: everything strictly before the harmful block
    bins = activity_bins(pre, bin_blocks=BIN_BLOCKS)
    cutoffs = [b.to_block for b in bins]
    timer = _Timer()
    tracemalloc.start()

    target = to_checksum_address(subject.target) if subject.target else None
    existing_on_target: list[int] = []  # bins where the eventual recipient is a warned suspect

    def existing() -> list[bool]:
        seen: set[str] = set()
        flags = []
        for i, c in enumerate(cutoffs):
            now = set(_warnings(fx, pre.at(c)))
            flags.append(bool(now - seen))
            if target in now - seen:
                existing_on_target.append(i)
            seen |= now
        return flags

    def count_rule() -> list[bool]:
        return [
            b.observed
            and b.counts.get("zero_value", 0) + b.counts.get("unsolicited_incoming", 0) >= 3
            for b in bins
        ]

    def temporal() -> list[bool]:
        flags = []
        for c in cutoffs:  # recomputed per cutoff: no later data can enter
            found, _ = detect_bursts(
                pre.at(c),
                bin_blocks=BIN_BLOCKS,
                threshold=THRESHOLD,
                min_history=MIN_HISTORY,
                last_bins=1,
            )
            flags.append(bool(found))
        return flags

    def ewma() -> list[bool]:
        per_series = [ewma_scores(bins, s, min_history=MIN_HISTORY) for s in SERIES]
        return [
            any(
                (v[i] or 0) >= THRESHOLD and bins[i].counts.get(s, 0) >= 3
                for v, s in zip(per_series, SERIES, strict=True)
            )
            for i in range(len(bins))
        ]

    window_features: list[StructuralFeatures | None] = []
    for c in cutoffs:
        start = c - WINDOW_BLOCKS + 1
        if not pre.coverage.both_cover(max(start, fx.from_block), c) or start < fx.from_block:
            window_features.append(None)
            continue
        window_features.append(
            structural_features(build_graph(pre.at(c), GraphScope(from_block=start)))
        )

    def spectral() -> list[bool]:
        dists: list[float | None] = [None]
        for prev, cur in itertools.pairwise(window_features):
            dists.append(
                spectral_distance(prev.eigenvalues, cur.eigenvalues) if prev and cur else None
            )
        return _robust_flags(dists)

    def structural() -> list[bool]:
        a: list[float | None] = [None]
        b: list[float | None] = [None]
        for prev, cur in itertools.pairwise(window_features):
            a.append(abs(cur.counterparties - prev.counterparties) if prev and cur else None)
            b.append(abs(cur.edges - prev.edges) if prev and cur else None)
        return [x or y for x, y in zip(_robust_flags(a), _robust_flags(b), strict=True)]

    flags = {
        "A_existing": timer.run("A_existing", existing),
        "F_count_rule": timer.run("F_count_rule", count_rule),
        "D_temporal": timer.run("D_temporal", temporal),
        "D_ewma": timer.run("D_ewma", ewma),
        "C_spectral": timer.run("C_spectral", spectral),
        "C_structural": timer.run("C_structural", structural),
    }

    onset = None
    target_bins: set[int] = set()  # bins containing activity of the eventual recipient
    if target is not None:
        origin = bins[0].from_block if bins else 0
        for e in pre.all_events():
            if target in (e.sender, e.recipient):
                onset = e.block_number if onset is None else onset
                if bins and e.block_number >= origin:
                    target_bins.add((e.block_number - origin) // BIN_BLOCKS)
    methods: dict[str, MethodResult] = {}
    for name, f in flags.items():
        blocks = [cutoffs[i] for i, hit in enumerate(f) if hit]
        r = MethodResult(
            alerts=len(blocks), alert_blocks=blocks, seconds=round(timer.seconds[name], 4)
        )
        if subject.harm_block is not None:
            r.first_alert_before_harm = blocks[0] if blocks else None
            # A names its suspect, so it must name the eventual recipient. The anomaly methods
            # name no address: they are on target when they fire in a bin where it is active.
            hits = (
                existing_on_target
                if name == "A_existing"
                else [i for i, hit in enumerate(f) if hit and i in target_bins]
            )
            r.on_target = bool(hits)
            r.lead_blocks = subject.harm_block - cutoffs[hits[0]] if hits else None
            if name == "A_existing" and hits:
                # A needs no bins: it can fire at the very block the data appears. Use the
                # exact block (as the replay engine does) so binning does not shorten its lead.
                lo = bins[hits[0]].from_block
                exact = next(
                    b
                    for b in sorted(
                        {e.block_number for e in pre.all_events() if e.block_number >= lo}
                    )
                    if target in _warnings(fx, pre.at(b))
                )
                r.lead_blocks = subject.harm_block - exact
        methods[name] = r

    graph = _graph_enrichment(fx, pre)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    span = (end - fx.from_block + 1) / BLOCKS_PER_DAY
    return SubjectResult(
        case_id=subject.case_id,
        kind=subject.kind,
        wallet_days=round(span, 3),
        transfers=len(pre.transfers),
        native_sends=len(pre.native_sends),
        bins=len(bins),
        onset_block=onset,
        harm_block=subject.harm_block,
        methods=methods,
        graph=graph,
        peak_memory_kib=peak // 1024,
    )


def _graph_enrichment(fx: ReplayFixture, o: ObservationSet) -> dict[str, object]:
    """Seeds = warnings at the cutoff (point in time). What does propagation add?"""
    warnings = _warnings(fx, o)
    g = build_graph(o)
    all_cases = detect_poisoning(
        o.wallet,
        list(o.transfers),
        chain_id=o.chain_id,
        wallet_is_plain_eoa=_plain(fx, o.cutoff_block),
        native_sends=list(o.native_sends),
    )
    informational = {c.suspect for c in all_cases if c.rule_id == "CG-POI-002"}
    seeds = [
        Seed(a, f"{rule} at block {o.cutoff_block}", o.cutoff_block)
        for a, rule in sorted(warnings.items())
    ]
    t = time.perf_counter()
    result = propagate(g, seeds, top_k=10_000) if seeds else None
    seconds = time.perf_counter() - t
    a, nodes = g.matrix(exclude_wallet=True)
    out: dict[str, object] = {
        "nodes": len(nodes),
        "edges": int(a.nnz // 2),
        "seeds": len(seeds),
        "propagation_seconds": round(seconds, 4),
    }
    if result is None or result.status != "ok":
        out["status"] = "no_seeds" if result is None else result.status
        return out
    related = result.related
    out["status"] = "ok"
    out["related"] = len(related)
    out["related_signers"] = sum("signer" in r.roles for r in related)
    out["related_counterparties_non_token"] = sum(
        "counterparty" in r.roles and "token" not in r.roles for r in related
    )
    out["informational_lookalikes_linked"] = sum(r.address in informational for r in related)
    out["hops_histogram"] = {
        str(h): sum(r.hops == h for r in related) for h in sorted({r.hops for r in related})
    }
    out["top_related"] = [
        {
            "address": r.address,
            "roles": list(r.roles),
            "hops": r.hops,
            "via": [s.kind for s in r.path],
        }
        for r in related[:5]
    ]

    # Do the rankings differ? Spearman-free check: top-5 overlap between heat and each baseline.
    def top(key: str) -> list[str]:
        return [r.address for r in sorted(related, key=lambda r: (-r.scores[key], r.address))[:5]]

    def by_hops() -> list[str]:
        return [r.address for r in sorted(related, key=lambda r: (r.hops, r.address))[:5]]

    heat = top("heat_tau_1")
    out["top5_overlap_heat_vs"] = {
        "ppr_reverse": len(set(heat) & set(top("ppr_reverse"))),
        "neighbour": len(set(heat) & set(top("neighbour"))),
        "hop_distance": len(set(heat) & set(by_hops())),
    }
    return out


# --- Hawkes vs Poisson on held-out data ----------------------------------------------------


class HawkesComparison(BaseModel):
    case_id: str
    events_train: int
    events_test: int
    status: str
    branching_ratio: float | None = None
    heldout_ll_per_event_hawkes: float | None = None
    heldout_ll_per_event_poisson: float | None = None
    fit_seconds: float | None = None


def hawkes_comparison(subject: Subject, *, min_train: int = 10) -> HawkesComparison:
    fx = subject.fixture
    end = (subject.harm_block - 1) if subject.harm_block is not None else fx.to_block
    o = observations_of(fx).at(end)
    times = sorted({e.block_number - fx.from_block + 0.5 for e in o.all_events()})  # one per block
    horizon = float(end - fx.from_block + 1)
    split = horizon * 2 / 3
    train = [t for t in times if t < split]
    test = [t for t in times if t >= split]
    base = HawkesComparison(
        case_id=subject.case_id, events_train=len(train), events_test=len(test), status="ok"
    )
    if len(train) < min_train or not test:
        base.status = "insufficient_events"
        return base
    t0 = time.perf_counter()
    f = fit(train, split)
    base.fit_seconds = round(time.perf_counter() - t0, 3)
    hawkes_test = log_likelihood(times, horizon, f.mu, f.alpha, f.beta) - log_likelihood(
        train, split, f.mu, f.alpha, f.beta
    )
    rate = len(train) / split
    poisson_test = poisson_log_likelihood(len(test), horizon - split, rate=rate)
    base.branching_ratio = round(f.branching_ratio, 4)
    base.heldout_ll_per_event_hawkes = round(hawkes_test / len(test), 4)
    base.heldout_ll_per_event_poisson = round(poisson_test / len(test), 4)
    return base


# --- Synthetic scaling benchmark ---------------------------------------------------------


class ScalingPoint(BaseModel):
    target_nodes: int
    nodes: int
    edges: int
    build_seconds: float
    propagation_seconds: float | None
    propagation_status: str
    spectral_seconds: float | None
    spectral_status: str
    peak_memory_kib: int


def scaling_benchmark(
    sizes: Sequence[int] = (100, 1_000, 10_000), *, seed: int = 7
) -> list[ScalingPoint]:
    """SYNTHETIC graphs shaped like a wallet neighbourhood (counterparties, shared signers and
    token contracts). Measures cost only; says nothing about detection quality."""
    import random

    from cryptoguard.blockchain.erc20 import TransferEvent

    rng = random.Random(seed)  # noqa: S311 - reproducible synthetic data, not cryptography
    wallet = to_checksum_address("0x" + "aa" * 20)
    out: list[ScalingPoint] = []
    for n in sizes:
        parties = [to_checksum_address(f"0x{0x1000 + i:040x}") for i in range(int(n * 0.7))]
        signers = [to_checksum_address(f"0x{0x900000 + i:040x}") for i in range(max(1, n // 10))]
        tokens = [to_checksum_address(f"0x{0xA00000 + i:040x}") for i in range(max(1, n // 5))]
        events = []
        for i, p in enumerate(parties):
            for k in range(2):
                outgoing = rng.random() < 0.5
                events.append(
                    TransferEvent(
                        token=rng.choice(tokens),
                        sender=wallet if outgoing else p,
                        recipient=p if outgoing else wallet,
                        value=rng.choice([0, 1, 10]),
                        block_number=1 + i * 2 + k,
                        block_hash="0x" + "00" * 32,
                        transaction_hash=f"0x{i * 2 + k:064x}",
                        transaction_index=0,
                        log_index=k,
                        tx_sender=rng.choice(signers) if outgoing else None,
                    )
                )
        o = ObservationSet.build(
            chain_id=1,
            wallet=wallet,
            cutoff_block=10**7,
            transfers=events,
            native_sends=[],
            transfer_ranges=[BlockRange(0, 10**7)],
            wallet_tx_ranges=[BlockRange(0, 10**7)],
        )
        tracemalloc.start()
        t = time.perf_counter()
        g = build_graph(o, GraphScope(max_nodes=20_000, max_edges=200_000))
        build = time.perf_counter() - t
        t = time.perf_counter()
        prop = propagate(g, [Seed(parties[0], "synthetic", 1)], top_k=50, max_nodes=20_000)
        prop_s = time.perf_counter() - t
        t = time.perf_counter()
        feats = structural_features(g)
        spec_s = time.perf_counter() - t
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        a, nodes = g.matrix()
        out.append(
            ScalingPoint(
                target_nodes=n,
                nodes=len(nodes),
                edges=int(a.nnz // 2),
                build_seconds=round(build, 3),
                propagation_seconds=round(prop_s, 3),
                propagation_status=prop.status,
                spectral_seconds=round(spec_s, 3),
                spectral_status=feats.spectral_status,
                peak_memory_kib=peak // 1024,
            )
        )
    return out


# --- Aggregation and report ----------------------------------------------------------------


class AnalyticsEvaluation(BaseModel):
    subjects: list[SubjectResult]
    hawkes: list[HawkesComparison]
    scaling: list[ScalingPoint]
    parameters: dict[str, object]
    notes: list[str] = []


def run_evaluation(
    subjects: Sequence[Subject], *, scaling: bool = True, notes: Sequence[str] = ()
) -> AnalyticsEvaluation:
    return AnalyticsEvaluation(
        notes=list(notes),
        subjects=[evaluate_subject(s) for s in subjects],
        hawkes=[hawkes_comparison(s) for s in subjects],
        scaling=scaling_benchmark() if scaling else [],
        parameters={
            "bin_blocks": BIN_BLOCKS,
            "graph_window_blocks": WINDOW_BLOCKS,
            "robust_z_threshold": THRESHOLD,
            "min_history_bins": MIN_HISTORY,
            "count_rule_min_events": 3,
        },
    )


def render_analytics(ev: AnalyticsEvaluation) -> str:
    pos = [s for s in ev.subjects if s.kind == "positive"]
    bg = [s for s in ev.subjects if s.kind == "background"]
    days = sum(s.wallet_days for s in bg)
    out = [
        "## Experimental analyses (graph, spectral, temporal)",
        "",
        "Generated by `cryptoguard replay run --analytics`. Every method runs point in time at "
        f"the end of each {BIN_BLOCKS}-block bin (~1 h) and sees only data up to that block; for "
        "incident cases evaluation stops one block before the harmful transaction. Parameters: "
        + ", ".join(f"{k}={v}" for k, v in ev.parameters.items())
        + ". Thresholds were fixed before the runs and not tuned.",
        "",
        f"Subjects: {len(pos)} incident cases and {len(bg)} background wallets "
        f"({days:.1f} wallet-days), selected as described in `replay/background.py`. "
        "Background wallets are unlabelled; poisoning attempts are common, so their alerts are "
        "an upper bound on false alarms, not a false-positive rate.",
        "",
        "### Incident cases: on-target alerts before the harm",
        "",
        "Onset = first block where the address that later received the funds appears in the "
        "observable data. On target: for A, the eventual recipient is named as a warned suspect "
        "before the harm (exact block, as in the replay above); for the other methods, which "
        "name no address, an alert fires in a bin in which that address is active. Their lead "
        f"is measured from the end of the bin, so it can be up to {BIN_BLOCKS - 1} blocks "
        "shorter than the underlying event.",
        "",
        "| Case | Onset to harm (blocks) | " + " | ".join(METHODS) + " |",
        "|---|---|" + "---|" * len(METHODS),
    ]
    for s in pos:
        gap = f"{s.harm_block - s.onset_block}" if s.onset_block and s.harm_block else "no onset"
        cells = []
        for m in METHODS:
            r = s.methods[m]
            cells.append(f"yes ({r.lead_blocks})" if r.on_target else f"no [{r.alerts}]")
        out.append(f"| {s.case_id} | {gap} | " + " | ".join(cells) + " |")
    out += [
        "",
        "Cells: `yes (lead blocks)` or `no [alerts elsewhere before the harm]`.",
        "",
        "### Background wallets: alerts per wallet-day",
        "",
        "| Method | Alerts | Wallets with >= 1 alert | Alerts per wallet-day "
        "| Runtime per wallet (s) |",
        "|---|---|---|---|---|",
    ]
    for m in METHODS:
        alerts = sum(s.methods[m].alerts for s in bg)
        wallets = sum(s.methods[m].alerts > 0 for s in bg)
        rate = alerts / days if days else 0.0
        runtime = statistics.mean(s.methods[m].seconds for s in bg) if bg else 0.0
        out.append(f"| {m} | {alerts} | {wallets}/{len(bg)} | {rate:.2f} | {runtime:.3f} |")
    out += [
        "",
        "### Combinations (alert in a bin if any member alerts)",
        "",
        "| Combination | Incident cases on target | Best lead vs A alone | Background alerts "
        "per wallet-day |",
        "|---|---|---|---|",
    ]
    for combo in COMBINATIONS:
        hits = 0
        gains: list[int] = []
        for s in pos:
            leads = [s.methods[m].lead_blocks for m in combo if s.methods[m].on_target]
            if leads:
                hits += 1
                a = s.methods["A_existing"].lead_blocks if s.methods["A_existing"].on_target else 0
                gains.append(max(x for x in leads if x is not None) - (a or 0))
        union = sum(len({b for m in combo for b in s.methods[m].alert_blocks}) for s in bg)
        gain = f"+{max(gains)} blocks" if gains and max(gains) > 0 else "none"
        out.append(
            f"| {' + '.join(combo)} | {hits}/{len(pos)} | {gain} | "
            f"{(union / days if days else 0):.2f} |"
        )
    if ev.notes:
        out += ["", *[f"- {n}" for n in ev.notes]]
    out += ["", "### Graph propagation (enrichment of existing warnings)", ""]
    out.append(
        "| Subject | Nodes / edges | Seeds | Related | Signers | Other lookalikes linked "
        "| Top-5 overlap heat vs PPR / neighbour / hops |"
    )
    out.append("|---|---|---|---|---|---|---|")
    for s in ev.subjects:
        g = s.graph
        if g.get("status") != "ok":
            out.append(
                f"| {s.case_id} | {g.get('nodes')} / {g.get('edges')} | {g.get('seeds')} "
                f"| {g.get('status')} | | | |"
            )
            continue
        ov = g["top5_overlap_heat_vs"]
        assert isinstance(ov, dict)
        out.append(
            f"| {s.case_id} | {g['nodes']} / {g['edges']} | {g['seeds']} | {g['related']} | "
            f"{g['related_signers']} | {g['informational_lookalikes_linked']} | "
            f"{ov['ppr_reverse']} / {ov['neighbour']} / {ov['hop_distance']} |"
        )
    out += ["", "### Hawkes vs homogeneous Poisson (held-out last third, one event per block)", ""]
    out.append(
        "| Subject | Train / test events | Branching ratio "
        "| Held-out log-lik/event Hawkes | Poisson |"
    )
    out.append("|---|---|---|---|---|")
    for h in ev.hawkes:
        if h.status != "ok":
            out.append(f"| {h.case_id} | {h.events_train} / {h.events_test} | {h.status} | | |")
        else:
            out.append(
                f"| {h.case_id} | {h.events_train} / {h.events_test} | {h.branching_ratio} | "
                f"{h.heldout_ll_per_event_hawkes} | {h.heldout_ll_per_event_poisson} |"
            )
    if ev.scaling:
        out += ["", "### Cost on SYNTHETIC graphs (cost only, not detection quality)", ""]
        out.append(
            "| Target nodes | Nodes / edges | Build (s) | Propagation (s) | Spectral (s) "
            "| Peak traced memory (KiB) |"
        )
        out.append("|---|---|---|---|---|---|")
        for p in ev.scaling:
            spec = f"{p.spectral_seconds} ({p.spectral_status})"
            out.append(
                f"| {p.target_nodes} | {p.nodes} / {p.edges} | {p.build_seconds} | "
                f"{p.propagation_seconds} ({p.propagation_status}) | {spec} | {p.peak_memory_kib} |"
            )
    out.append("")
    return "\n".join(out)

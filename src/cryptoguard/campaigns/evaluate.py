"""Offline evaluation of campaign clustering (renders ``CAMPAIGN_EVALUATION.md``).

There are no independent labels saying which attempts share an operator, so no precision,
recall, ARI or NMI is computed: clusters produced by these rules cannot be scored against
themselves. The report is descriptive and diagnostic: what each relationship type and
ablation links, how much over-clustering appears when guards are removed, what the
expansion adds over wallet-level findings, whether the existing graph and spectral methods
add anything, point-in-time behaviour before each incident, and cost.
"""

from __future__ import annotations

import random
import statistics
import time
import tracemalloc
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import replace
from datetime import UTC, datetime

from pydantic import BaseModel

from cryptoguard.campaigns.attempts import PoisoningAttempt, attempt_id, dedupe
from cryptoguard.campaigns.cluster import (
    CLUSTER_ALGORITHM_VERSION,
    CampaignAnalysis,
    Deployer,
    cluster_attempts,
)
from cryptoguard.campaigns.dataset import (
    SubjectAttempts,
    attempts_at,
    canonical_sha256,
    fixture_attempts,
    load_expansion,
)
from cryptoguard.campaigns.expansion import ExpansionResult
from cryptoguard.campaigns.graph import build_campaign_graph, node_id
from cryptoguard.campaigns.relations import (
    COMMON_CONTRACTS,
    RelationConfig,
    Strength,
    temporal_pairs,
)
from cryptoguard.core.address import to_checksum_address
from cryptoguard.replay.models import load_cases

WITH_TENTATIVE: frozenset[Strength] = frozenset(
    {"directly_observed", "strongly_supported", "tentative"}
)
EVERY_STRENGTH: frozenset[Strength] = frozenset(
    {"directly_observed", "strongly_supported", "tentative", "insufficient"}
)
ABLATIONS: dict[str, RelationConfig] = {
    "A_signer_only": RelationConfig(merge_kinds=frozenset({"signer"})),
    "B_lookalike_only": RelationConfig(merge_kinds=frozenset({"lookalike"})),
    "C_transaction_only": RelationConfig(merge_kinds=frozenset({"transaction"})),
    "D_combined (default)": RelationConfig(),
    "E_D_plus_deployer_and_narrow_contract": RelationConfig(
        merge_kinds=frozenset({"transaction", "lookalike", "signer", "deployer", "contract"}),
        merge_strengths=WITH_TENTATIVE,
    ),
    "X_no_guards (common contracts merge, no hub cap)": RelationConfig(
        merge_kinds=frozenset({"transaction", "lookalike", "signer", "contract"}),
        merge_strengths=EVERY_STRENGTH,
        max_lookalikes_per_entity=10**9,
        narrow_contract_max_victims=10**9,
        use_common_contract_list=False,
    ),
}
TEMPORAL_WINDOW_BLOCKS = 25  # ~5 minutes


class ClusterStats(BaseModel):
    attempts: int
    clusters: int
    unclustered: int
    multi_wallet_clusters: int
    largest_cluster_attempts: int
    largest_cluster_wallets: int
    tentative_clusters: int
    hub_entities: int
    seconds: float


class IncidentCheck(BaseModel):
    case_id: str
    cutoff_block: int
    recipient_in_attempts: bool
    recipient_cluster: str | None
    cluster_wallets: int
    cluster_confidence: str | None
    first_multi_wallet_block: int | None
    lead_blocks: int | None
    existing_detector_lead_blocks: int | None
    inputs_after_cutoff: int


class RankingComparison(BaseModel):
    clusters_compared: int
    mean_top5_overlap_heat_vs_hops: float | None
    mean_top5_overlap_heat_vs_ppr: float | None
    mean_top5_overlap_heat_vs_shared_neighbours: float | None
    heat_ranked_outside_cluster: int
    note: str


class SpectralComparison(BaseModel):
    clusters: int
    chained: int
    mean_gap_chained: float | None
    mean_gap_other: float | None
    articulation_separates: bool
    gap_separates: bool
    note: str


class ScalePoint(BaseModel):
    attempts: int
    seconds: float
    peak_kib: int
    clusters: int


class CampaignEvaluation(BaseModel):
    generated_at: str
    algorithm_version: str
    subjects: dict[str, str]
    expansion_sha256: str | None
    expansion: dict[str, object]
    scenarios: dict[str, dict[str, ClusterStats]]
    hub_sensitivity: dict[str, ClusterStats]
    temporal: dict[str, int]
    incidents: list[IncidentCheck]
    added_information: dict[str, int]
    prior_context: dict[str, object]
    ranking: RankingComparison
    spectral: SpectralComparison
    scale: list[ScalePoint]
    real_examples: list[dict[str, object]]


def _stats(analysis: CampaignAnalysis, seconds: float) -> ClusterStats:
    multi = [c for c in analysis.clusters if len(c.victims) > 1]
    largest = max(analysis.clusters, key=lambda c: len(c.attempts), default=None)
    return ClusterStats(
        attempts=len(analysis.attempts),
        clusters=len(analysis.clusters),
        unclustered=len(analysis.unclustered),
        multi_wallet_clusters=len(multi),
        largest_cluster_attempts=len(largest.attempts) if largest else 0,
        largest_cluster_wallets=len(largest.victims) if largest else 0,
        tentative_clusters=sum(c.confidence == "tentative" for c in analysis.clusters),
        hub_entities=len(analysis.hub_entities),
        seconds=round(seconds, 3),
    )


def _run(
    attempts: Sequence[PoisoningAttempt],
    cutoff: int,
    deployers: dict[str, Deployer],
    config: RelationConfig,
) -> tuple[CampaignAnalysis, float]:
    t = time.perf_counter()
    a = cluster_attempts(
        attempts, chain_id=1, cutoff_block=cutoff, deployers=deployers, config=config
    )
    return a, time.perf_counter() - t


def _temporal_merge(analysis: CampaignAnalysis) -> dict[str, int]:
    """Ablation F: what block proximity alone would add on top of D (never used to merge)."""
    pairs = temporal_pairs(list(analysis.attempts), window_blocks=TEMPORAL_WINDOW_BLOCKS)
    owner: dict[str, str] = {}
    for c in analysis.clusters:
        for m in c.attempts:
            owner[m] = c.cluster_id
    new_links = [p for p in pairs if owner.get(p[0]) is None or owner.get(p[0]) != owner.get(p[1])]
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            x = parent[x]
        return x

    for a in analysis.attempts:
        find(owner.get(a.attempt_id, a.attempt_id))
    for x, y in new_links:
        rx, ry = find(owner.get(x, x)), find(owner.get(y, y))
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)
    groups: dict[str, int] = defaultdict(int)
    for a in analysis.attempts:
        groups[find(owner.get(a.attempt_id, a.attempt_id))] += 1
    return {
        "window_blocks": TEMPORAL_WINDOW_BLOCKS,
        "cross_wallet_pairs_within_window": len(pairs),
        "pairs_not_already_linked": len(new_links),
        "groups_if_merged": sum(1 for v in groups.values() if v > 1),
        "largest_group_if_merged": max(groups.values(), default=0),
    }


def _top5(candidates: Sequence[int], score: Iterable[float]) -> set[int]:
    s = list(score)
    return set(sorted(candidates, key=lambda i: (-s[i], i))[:5])


def _ranking(analysis: CampaignAnalysis) -> RankingComparison:
    """Ablation G: does heat-kernel ranking around a cluster find anything hop distance,
    shared-neighbour counts or PPR do not?"""
    import numpy as np

    from cryptoguard.analytics.diffusion import heat_kernel, hop_distances, personalized_pagerank

    graph = build_campaign_graph(list(analysis.attempts))
    common = {node_id("contract", c) for c in COMMON_CONTRACTS[1]} | {
        node_id("signer", h.entity.key) for h in analysis.hub_entities
    }
    a, nodes = graph.propagation_matrix(frozenset(common))
    index = {n: i for i, n in enumerate(nodes)}
    overlaps: dict[str, list[int]] = defaultdict(list)
    outside = 0
    compared = 0
    for c in analysis.clusters[:30]:
        seeds = [index[node_id("attempt", m)] for m in c.attempts if node_id("attempt", m) in index]
        if not seeds:
            continue
        u0 = np.zeros(len(nodes))
        u0[seeds] = 1.0 / len(seeds)
        heat = heat_kernel(a, u0, 1.0)
        ppr, _ = personalized_pagerank(a, u0)
        hops = hop_distances(a, seeds, max_hops=6)
        shared = np.asarray(a @ (a @ u0)).ravel()
        candidates = [
            i for i, n in enumerate(nodes) if n.startswith("attempt:") and i not in set(seeds)
        ]
        if len(candidates) < 5:
            continue
        compared += 1
        hop_score = [-(h if h is not None else 99.0) for h in hops]
        heat_top = _top5(candidates, heat)
        overlaps["hops"].append(len(heat_top & _top5(candidates, hop_score)))
        overlaps["ppr"].append(len(heat_top & _top5(candidates, ppr)))
        overlaps["shared"].append(len(heat_top & _top5(candidates, shared)))
        outside += sum(1 for i in heat_top if heat[i] > 1e-12)

    def mean(key: str) -> float | None:
        return round(statistics.mean(overlaps[key]), 2) if overlaps[key] else None

    return RankingComparison(
        clusters_compared=compared,
        mean_top5_overlap_heat_vs_hops=mean("hops"),
        mean_top5_overlap_heat_vs_ppr=mean("ppr"),
        mean_top5_overlap_heat_vs_shared_neighbours=mean("shared"),
        heat_ranked_outside_cluster=outside,
        note="Top-5 attempts outside each cluster ranked by heat diffusion (tau=1) on the "
        "planting-side graph, compared with hop distance, two-step shared-neighbour counts "
        "and personalized PageRank. Popular contracts and hub signers are removed first.",
    )


def _spectral(analysis: CampaignAnalysis) -> SpectralComparison:
    """Ablation H: does the spectral gap of a cluster's attempt-entity graph tell chained
    (transitively joined) clusters apart better than articulation points already do?"""
    from scipy.sparse import csr_matrix

    from cryptoguard.analytics.spectral import normalized_spectrum

    gaps: dict[bool, list[float]] = {True: [], False: []}
    for c in analysis.clusters:
        if len(c.attempts) > 1_500:
            continue
        nodes = sorted(
            {f"a:{m}" for m in c.attempts} | {f"e:{e.entity.label}" for e in c.merging_evidence}
        )
        idx = {n: i for i, n in enumerate(nodes)}
        rows, cols = [], []
        for e in c.merging_evidence:
            for m in e.attempts:
                rows += [idx[f"a:{m}"], idx[f"e:{e.entity.label}"]]
                cols += [idx[f"e:{e.entity.label}"], idx[f"a:{m}"]]
        mat = csr_matrix(([1.0] * len(rows), (rows, cols)), shape=(len(nodes), len(nodes)))
        mat.data[:] = 1.0
        values = normalized_spectrum(mat)
        gaps[c.structure == "chained"].append(float(values[1]) if len(values) > 1 else 0.0)
    chained, other = gaps[True], gaps[False]
    mean_c = round(statistics.mean(chained), 4) if chained else None
    mean_o = round(statistics.mean(other), 4) if other else None
    separates = bool(chained and other and max(chained) < min(other))
    return SpectralComparison(
        clusters=len(chained) + len(other),
        chained=len(chained),
        mean_gap_chained=mean_c,
        mean_gap_other=mean_o,
        articulation_separates=True,  # by construction: "chained" is defined by them
        gap_separates=separates,
        note="Spectral gap = second-smallest normalized-Laplacian eigenvalue of each cluster's "
        "attempt-entity graph. A small gap indicates a weakly connected group. Articulation "
        "points identify such groups exactly and name the joining attempt or entity.",
    )


def _scale(sizes: Sequence[int] = (100, 1_000, 10_000), seed: int = 11) -> list[ScalePoint]:
    rng = random.Random(seed)  # noqa: S311 - reproducible synthetic data, not cryptography
    out: list[ScalePoint] = []
    for n in sizes:
        signers = [to_checksum_address(f"0x{0x5000000 + i:040x}") for i in range(max(1, n // 20))]
        attempts = []
        for i in range(n):
            victim = to_checksum_address(f"0x{0xA000000 + rng.randrange(n):040x}")
            look = to_checksum_address(f"0x{0xB000000 + rng.randrange(n * 2):040x}")
            tx = f"0x{rng.randrange(n * 3):064x}"
            attempts.append(
                PoisoningAttempt(
                    block_number=i,
                    transaction_index=0,
                    log_index=i,
                    attempt_id=attempt_id(1, tx, i, victim, look),
                    chain_id=1,
                    victim=victim,
                    lookalike=look,
                    imitated=None,
                    imitated_confirmed=False,
                    event_type="zero_value_transfer",
                    transaction_hash=tx,
                    block_hash="0x" + "00" * 32,
                    contract=to_checksum_address(f"0x{0xC000000 + rng.randrange(50):040x}"),
                    log_from=victim,
                    log_to=look,
                    value=0,
                    signer=rng.choice(signers),
                    rule_id="CG-POI-001",
                    source="wallet_scan",
                )
            )
        tracemalloc.start()
        t = time.perf_counter()
        result = cluster_attempts(attempts, chain_id=1, cutoff_block=10**9)
        seconds = time.perf_counter() - t
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        out.append(
            ScalePoint(
                attempts=n,
                seconds=round(seconds, 3),
                peak_kib=peak // 1024,
                clusters=len(result.clusters),
            )
        )
    return out


def run_campaign_evaluation() -> CampaignEvaluation:
    subjects = fixture_attempts()
    wallet_attempts = [a for s in subjects for a in s.attempts]
    loaded = load_expansion()
    expansion: ExpansionResult | None = loaded[0] if loaded else None
    raw = loaded[1] if loaded else None
    global_cutoff = max(s.cutoff_block for s in subjects)
    extra, deployers = expansion.usable_at(global_cutoff) if expansion else ([], {})
    scenarios: dict[str, dict[str, ClusterStats]] = {}
    analyses: dict[str, CampaignAnalysis] = {}
    for label, attempts, deps in (
        ("monitored wallets only", wallet_attempts, {}),
        ("plus expansion", dedupe([*wallet_attempts, *extra]), deployers),
    ):
        scenarios[label] = {}
        for name, config in ABLATIONS.items():
            analysis, seconds = _run(attempts, global_cutoff, deps, config)
            scenarios[label][name] = _stats(analysis, seconds)
            analyses[f"{label}|{name}"] = analysis
    full = analyses["plus expansion|D_combined (default)"]
    hub: dict[str, ClusterStats] = {}
    for cap in (5, 10, 25, 50, 10**9):
        analysis, seconds = _run(
            full.attempts,
            global_cutoff,
            deployers,
            replace(RelationConfig(), max_lookalikes_per_entity=cap),
        )
        hub["no cap" if cap == 10**9 else str(cap)] = _stats(analysis, seconds)

    monitored = {s.wallet for s in subjects}
    added = {
        "attempts_from_monitored_wallets": len(wallet_attempts),
        "verified_attempts_from_expansion": len(extra),
        "new_targeted_wallets_from_expansion": len({a.victim for a in extra} - monitored),
        "unverified_candidates_from_expansion": sum(
            1 for c in (expansion.candidates if expansion else []) if c.status != "verified"
        ),
        "multi_wallet_clusters_monitored_only": scenarios["monitored wallets only"][
            "D_combined (default)"
        ].multi_wallet_clusters,
        "multi_wallet_clusters_with_expansion": scenarios["plus expansion"][
            "D_combined (default)"
        ].multi_wallet_clusters,
        "planting_transactions_targeting_several_wallets": sum(
            1 for e in _transactions(full.attempts) if e > 1
        ),
        "deployers_found": len(deployers),
    }
    return CampaignEvaluation(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        algorithm_version=CLUSTER_ALGORITHM_VERSION,
        subjects={s.subject_id: s.fixture_sha256 for s in subjects},
        expansion_sha256=canonical_sha256(raw) if raw else None,
        expansion=_expansion_info(expansion, raw, len(wallet_attempts)),
        scenarios=scenarios,
        hub_sensitivity=hub,
        temporal=_temporal_merge(full),
        incidents=_incident_checks(subjects, expansion),
        added_information=added,
        prior_context=_prior_context(subjects, expansion),
        ranking=_ranking(full),
        spectral=_spectral(full),
        scale=_scale(),
        real_examples=_examples(full, monitored),
    )


def _transactions(attempts: Iterable[PoisoningAttempt]) -> list[int]:
    victims: dict[str, set[str]] = defaultdict(set)
    for a in attempts:
        victims[a.transaction_hash.lower()].add(a.victim)
    return [len(v) for v in victims.values()]


def _expansion_info(
    expansion: ExpansionResult | None, raw: dict[str, object] | None, seeds: int
) -> dict[str, object]:
    if expansion is None or raw is None:
        return {"status": "not recorded"}
    cov = expansion.coverage()
    return {
        "recorded_at": raw.get("recorded_at"),
        "recorded_with": raw.get("recorded_with"),
        "cutoff_block": expansion.cutoff_block,
        "cutoff_block_hash": raw.get("cutoff_block_hash"),
        "budget": raw.get("budget"),
        "requests": expansion.requests,
        "seconds": expansion.seconds,
        "stopped": expansion.stopped,
        "tasks": cov["tasks"],
        "requests_per_seed_attempt": round(expansion.requests / seeds, 1) if seeds else None,
        "requests_per_verified_attempt": round(
            expansion.requests / max(1, len(expansion.attempts())), 1
        ),
        "by_kind": _by_kind(expansion),
        "truncations": sum(len(o.truncated) for o in expansion.outcomes),
        "not_attempted": cov["not_attempted"],
    }


def _by_kind(expansion: ExpansionResult) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for o in expansion.outcomes:
        out[o.task.kind][o.status] += 1
        out[o.task.kind]["requests"] += o.requests
        out[o.task.kind]["verified"] += sum(c.status == "verified" for c in o.candidates)
    return {k: dict(v) for k, v in out.items()}


_KNOWN_SINCE: dict[int, dict[str, int]] = {}


def known_since(subjects: Sequence[SubjectAttempts]) -> dict[str, int]:
    """First block at which each signer, lookalike and contract appeared in an attempt that
    the detector recognised *at that block* (exhaustive over the blocks where inputs change)."""
    key = id(subjects)
    if key in _KNOWN_SINCE:
        return _KNOWN_SINCE[key]
    first: dict[str, int] = {}
    for s in subjects:
        blocks = sorted({e.block_number for e in s.observations.all_events()})
        for block in blocks:
            for a in s.attempts_at(block):
                for entity in (a.signer, a.lookalike, a.contract):
                    if entity is not None and (entity not in first or block < first[entity]):
                        first[entity] = block
    _KNOWN_SINCE[key] = first
    return first


def _inputs_at(
    subjects: Sequence[SubjectAttempts], expansion: ExpansionResult | None, block: int
) -> tuple[list[PoisoningAttempt], dict[str, Deployer]]:
    """Everything a system running at ``block`` could have known: the detector re-run on
    each wallet's observations cut at ``block``, plus expansion tasks whose seed entity had
    been recognised by then."""
    extra, deps = (
        expansion.usable_at(block, known_since=known_since(subjects)) if expansion else ([], {})
    )
    return dedupe([*attempts_at(list(subjects), block), *extra]), deps


def _existing_leads() -> dict[str, int | None]:
    from cryptoguard.replay.engine import Visibility, replay

    out: dict[str, int | None] = {}
    for case in load_cases():
        if case.fixture is None:
            continue
        result = replay(
            case.manifest, case.fixture, visibilities=(Visibility.ERC20_PLUS_WALLET_TRANSACTIONS,)
        )
        out[case.manifest.case_id] = result.results[0].lead_time_blocks
    return out


def _incident_checks(
    subjects: Sequence[SubjectAttempts], expansion: ExpansionResult | None
) -> list[IncidentCheck]:
    """Before each theft: was its eventual recipient (from the manifest, scoring only) part
    of a multi-wallet cluster, using only what was knowable at each block?"""
    manifests = {c.manifest.case_id: c.manifest for c in load_cases()}
    leads = _existing_leads()
    out: list[IncidentCheck] = []
    for s in subjects:
        if s.kind != "incident":
            continue
        cutoff = s.cutoff_block
        recipient = to_checksum_address(manifests[s.subject_id].harm.recipient)
        inputs, deps = _inputs_at(subjects, expansion, cutoff)
        late = sum(1 for a in inputs if a.block_number > cutoff)
        analysis = cluster_attempts(inputs, chain_id=1, cutoff_block=cutoff, deployers=deps)
        cluster = next((c for c in analysis.clusters if recipient in c.lookalikes), None)
        first_multi = None
        if cluster is not None and len(cluster.victims) > 1:
            # Exhaustive over the blocks where any input can change, from the recipient's
            # first appearance on: attempt blocks and every observed event block.
            start = min(a.block_number for a in inputs if a.lookalike == recipient)
            blocks = {a.block_number for a in inputs if a.block_number >= start}
            for x in subjects:
                blocks |= {
                    e.block_number
                    for e in x.observations.all_events()
                    if start <= e.block_number <= cutoff
                }
            for block in sorted(blocks):
                early, early_deps = _inputs_at(subjects, expansion, block)
                partial = cluster_attempts(
                    early, chain_id=1, cutoff_block=block, deployers=early_deps
                )
                c2 = next((c for c in partial.clusters if recipient in c.lookalikes), None)
                if c2 is not None and len(c2.victims) > 1:
                    first_multi = block
                    break
        out.append(
            IncidentCheck(
                case_id=s.subject_id,
                cutoff_block=cutoff,
                recipient_in_attempts=any(a.lookalike == recipient for a in inputs),
                recipient_cluster=cluster.cluster_id if cluster else None,
                cluster_wallets=len(cluster.victims) if cluster else 0,
                cluster_confidence=cluster.confidence if cluster else None,
                first_multi_wallet_block=first_multi,
                lead_blocks=(cutoff + 1 - first_multi) if first_multi is not None else None,
                existing_detector_lead_blocks=leads.get(s.subject_id),
                inputs_after_cutoff=late,
            )
        )
    return out


def _prior_context(
    subjects: Sequence[SubjectAttempts], expansion: ExpansionResult | None
) -> dict[str, object]:
    """For each attempt on a monitored wallet: was its planting signer or lookalike already
    seen in attempts on a *different* wallet strictly before its block (point in time)?"""
    checked = signer_hits = lookalike_hits = 0
    examples: list[dict[str, object]] = []
    affected: set[str] = set()
    for s in subjects:
        for a in s.attempts_at(s.cutoff_block):
            checked += 1
            earlier, _ = _inputs_at(subjects, expansion, a.block_number - 1)
            others = [x for x in earlier if x.victim != a.victim]
            by_signer = [x for x in others if a.signer and x.signer == a.signer]
            by_look = [x for x in others if x.lookalike == a.lookalike]
            signer_hits += bool(by_signer)
            lookalike_hits += bool(by_look)
            if by_signer or by_look:
                affected.add(s.subject_id)
                if len(examples) < 8:
                    prior = by_signer or by_look
                    examples.append(
                        {
                            "subject": s.subject_id,
                            "block": a.block_number,
                            "shared": "signer" if by_signer else "lookalike",
                            "other_wallets_before": len({x.victim for x in prior}),
                            "first_seen_block": min(x.block_number for x in prior),
                        }
                    )
    return {
        "attempts_checked": checked,
        "signer_already_seen_on_other_wallets": signer_hits,
        "lookalike_already_seen_on_other_wallets": lookalike_hits,
        "monitored_wallets_affected": len(affected),
        "examples": examples,
    }


def _examples(analysis: CampaignAnalysis, monitored: set[str]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for c in analysis.clusters:
        if len(c.victims) < 2:
            continue
        out.append(
            {
                "campaign_id": c.cluster_id,
                "attempts": len(c.attempts),
                "wallets": len(c.victims),
                "monitored_wallets": len(set(c.victims) & monitored),
                "lookalikes": len(c.lookalikes),
                "signers": len(c.signers),
                "blocks": f"{c.first_block}-{c.last_block}",
                "structure": c.structure,
                "confidence": c.confidence,
                "merging": sorted({f"{e.entity.kind}" for e in c.merging_evidence}),
            }
        )
        if len(out) >= 15:
            break
    return out


def render_report(ev: CampaignEvaluation) -> str:
    from cryptoguard.campaigns.report import render

    return render(ev)

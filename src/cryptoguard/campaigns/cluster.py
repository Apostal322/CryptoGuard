"""Candidate campaign clusters (algorithm ``campaign-cluster/1``).

Semantics: a cluster is a set of attempts connected by **merging links** (shared entities
whose kind and strength the configuration allows, by default a planting transaction, a
lookalike or a verified planting signer, minus hub entities). It means "these attempts share
planting infrastructure, as shown", never "one operator did all of this".

Transitive grouping is the main risk: A shares a signer with B, B a lookalike with C, so A,
B and C end up together although A and C share nothing. The algorithm does not hide this:
it works on the bipartite attempt-entity graph and classifies each cluster's structure:

- ``shared_entity``: every member shares at least one common entity (no transitivity);
- ``multiply_connected``: no single attempt or entity holds the cluster together;
- ``chained``: at least one attempt or entity is an articulation point; removing it would
  split the cluster. Such clusters are at most *tentative*, and the points are listed.

Weaker shared entities (narrow contracts, deployers) are attached as context and never
merge by default. IDs are content hashes of the sorted member ids, so an ID always denotes
exactly one membership; lineage across runs is reported explicitly instead.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Literal

from cryptoguard.campaigns.attempts import PoisoningAttempt, at_cutoff, dedupe
from cryptoguard.campaigns.relations import (
    STRENGTH_ORDER,
    Entity,
    EntityEvidence,
    RelationConfig,
    Strength,
    merging,
    shared_entities,
)
from cryptoguard.core.hashing import keccak256

CLUSTER_ALGORITHM_VERSION = "campaign-cluster/1"
Structure = Literal["shared_entity", "multiply_connected", "chained"]


@dataclass(frozen=True)
class Deployer:
    address: str
    creation_block: int
    transaction_hash: str


@dataclass(frozen=True)
class CampaignCluster:
    cluster_id: str
    attempts: tuple[str, ...]
    victims: tuple[str, ...]
    lookalikes: tuple[str, ...]
    signers: tuple[str, ...]
    first_block: int
    last_block: int
    structure: Structure
    confidence: Strength
    merging_evidence: tuple[EntityEvidence, ...]
    context_evidence: tuple[EntityEvidence, ...]
    articulation_entities: tuple[Entity, ...]
    articulation_attempts: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class CampaignAnalysis:
    algorithm_version: str
    chain_id: int
    cutoff_block: int
    input_sha256: str
    attempts: tuple[PoisoningAttempt, ...]
    clusters: tuple[CampaignCluster, ...]
    unclustered: tuple[str, ...]
    hub_entities: tuple[EntityEvidence, ...]
    config: Mapping[str, object]
    notes: tuple[str, ...] = field(default=())


def cluster_id(member_ids: Sequence[str]) -> str:
    material = CLUSTER_ALGORITHM_VERSION + "|" + "|".join(sorted(member_ids))
    return "cmp-" + keccak256(material.encode()).hex()[:24]


class _UnionFind:
    def __init__(self, items: Sequence[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)  # deterministic representative


def articulation_points(adjacency: Mapping[str, Sequence[str]]) -> set[str]:
    """Iterative Tarjan: nodes whose removal disconnects their component."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    points: set[str] = set()
    counter = 0
    for root in sorted(adjacency):
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        children = 0
        stack: list[tuple[str, str | None, int]] = [(root, None, 0)]
        while stack:
            node, parent, i = stack[-1]
            neighbours = adjacency[node]
            if i < len(neighbours):
                stack[-1] = (node, parent, i + 1)
                nxt = neighbours[i]
                if nxt == parent:
                    continue
                if nxt in index:
                    low[node] = min(low[node], index[nxt])
                else:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    if node == root:
                        children += 1
                    stack.append((nxt, node, 0))
            else:
                stack.pop()
                if parent is not None:
                    low[parent] = min(low[parent], low[node])
                    if parent != root and low[node] >= index[parent]:
                        points.add(parent)
        if children > 1:
            points.add(root)
    return points


def _input_hash(
    attempts: Sequence[PoisoningAttempt],
    deployers: Mapping[str, Deployer],
    config: RelationConfig,
    cutoff: int,
) -> str:
    payload = {
        "version": CLUSTER_ALGORITHM_VERSION,
        "cutoff": cutoff,
        "attempts": [asdict(a) for a in attempts],
        "deployers": {k: asdict(v) for k, v in sorted(deployers.items())},
        "config": _config_dict(config),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _config_dict(config: RelationConfig) -> dict[str, object]:
    return {
        "merge_kinds": sorted(config.merge_kinds),
        "merge_strengths": sorted(config.merge_strengths),
        "max_lookalikes_per_entity": config.max_lookalikes_per_entity,
        "narrow_contract_max_victims": config.narrow_contract_max_victims,
        "use_common_contract_list": config.use_common_contract_list,
    }


def cluster_attempts(
    attempts: Sequence[PoisoningAttempt],
    *,
    chain_id: int,
    cutoff_block: int,
    deployers: Mapping[str, Deployer] | None = None,
    config: RelationConfig | None = None,
) -> CampaignAnalysis:
    config = config or RelationConfig()
    # Point in time: attempts and deployer facts after the cutoff do not exist yet.
    visible = dedupe(at_cutoff([a for a in attempts if a.chain_id == chain_id], cutoff_block))
    known = {c: d for c, d in sorted((deployers or {}).items()) if d.creation_block <= cutoff_block}
    evidence = shared_entities(
        visible,
        chain_id=chain_id,
        deployers={c: d.address for c, d in known.items()},
        config=config,
    )
    merge = merging(evidence, config)
    hubs = tuple(e for e in evidence if e.entity.kind == "signer" and e.strength == "insufficient")

    by_id = {a.attempt_id: a for a in visible}
    uf = _UnionFind(sorted(by_id))
    for ev in merge:
        first = ev.attempts[0]
        for other in ev.attempts[1:]:
            uf.union(first, other)
    groups: dict[str, list[str]] = defaultdict(list)
    for aid in sorted(by_id):
        groups[uf.find(aid)].append(aid)

    # Assign each piece of evidence to the clusters it touches once (linear, not
    # clusters x evidence).
    root_of = {aid: uf.find(aid) for aid in by_id}
    merge_ids = {id(e) for e in merge}
    inside_by: dict[str, list[EntityEvidence]] = defaultdict(list)
    context_by: dict[str, list[EntityEvidence]] = defaultdict(list)
    for e in evidence:
        for root in sorted({root_of[a] for a in e.attempts}):
            if id(e) in merge_ids:
                inside_by[root].append(e)
            elif e.strength != "insufficient":
                context_by[root].append(e)
    clusters: list[CampaignCluster] = []
    unclustered: list[str] = []
    for root, members in groups.items():
        if len(members) < 2:
            unclustered.extend(members)
            continue
        clusters.append(_describe(members, by_id, inside_by[root], context_by[root]))
    clusters.sort(key=lambda c: (-len(c.attempts), c.first_block, c.cluster_id))
    return CampaignAnalysis(
        algorithm_version=CLUSTER_ALGORITHM_VERSION,
        chain_id=chain_id,
        cutoff_block=cutoff_block,
        input_sha256=_input_hash(visible, known, config, cutoff_block),
        attempts=tuple(visible),
        clusters=tuple(clusters),
        unclustered=tuple(sorted(unclustered)),
        hub_entities=hubs,
        config=_config_dict(config),
    )


def _describe(
    members: list[str],
    by_id: Mapping[str, PoisoningAttempt],
    inside: Sequence[EntityEvidence],
    context: Sequence[EntityEvidence],
) -> CampaignCluster:
    member_set = set(members)
    # Bipartite attempt-entity graph restricted to this cluster's merging links.
    adjacency: dict[str, list[str]] = defaultdict(list)
    for e in inside:
        node = "entity:" + e.entity.label
        for aid in e.attempts:
            adjacency[node].append("attempt:" + aid)
            adjacency["attempt:" + aid].append(node)
    points = articulation_points({k: sorted(v) for k, v in adjacency.items()})
    entity_points = tuple(e.entity for e in inside if "entity:" + e.entity.label in points)
    attempt_points = tuple(sorted(p.split(":", 1)[1] for p in points if p.startswith("attempt:")))

    covering = [e for e in inside if member_set <= set(e.attempts)]
    if covering:
        # Every member shares this entity directly: no transitivity involved, even if the
        # entity is (trivially) the point holding the group together.
        structure: Structure = "shared_entity"
        confidence: Strength = min(
            (e.strength for e in covering), key=lambda s: STRENGTH_ORDER.index(s)
        )
    elif not points:
        structure, confidence = "multiply_connected", "strongly_supported"
        if all(e.strength == "directly_observed" for e in inside):
            confidence = "directly_observed"
    else:
        structure, confidence = "chained", "tentative"

    attempts = [by_id[m] for m in members]
    victims = sorted({a.victim for a in attempts})
    lookalikes = sorted({a.lookalike for a in attempts})
    signers = sorted({a.signer for a in attempts if a.signer})
    kinds = sorted({e.entity.kind for e in inside})
    explanation = (
        f"{len(attempts)} poisoning attempts on {len(victims)} wallet(s), linked by "
        + ", ".join(f"{_count(inside, k)} shared {k}(s)" for k in kinds)
        + "."
    )
    if structure == "chained":
        explanation += (
            " The group is held together through "
            f"{len(entity_points) + len(attempt_points)} single point(s); attempts on either "
            "side of such a point may share nothing directly, so the grouping is tentative."
        )
    return CampaignCluster(
        cluster_id=cluster_id(members),
        attempts=tuple(sorted(members)),
        victims=tuple(victims),
        lookalikes=tuple(lookalikes),
        signers=tuple(signers),
        first_block=min(a.block_number for a in attempts),
        last_block=max(a.block_number for a in attempts),
        structure=structure,
        confidence=confidence,
        merging_evidence=tuple(inside),
        context_evidence=tuple(context),
        articulation_entities=entity_points,
        articulation_attempts=attempt_points,
        explanation=explanation,
    )


def _count(evidence: Sequence[EntityEvidence], kind: str) -> int:
    return sum(1 for e in evidence if e.entity.kind == kind)


LineageKind = Literal["unchanged", "grown", "shrunk", "merged", "split", "new", "changed"]


def lineage(
    previous: Sequence[CampaignCluster], current: Sequence[CampaignCluster]
) -> dict[str, tuple[LineageKind, tuple[str, ...]]]:
    """How each current cluster relates to the previous run's clusters (by shared members)."""
    prev_sets = {c.cluster_id: set(c.attempts) for c in previous}
    out: dict[str, tuple[LineageKind, tuple[str, ...]]] = {}
    for c in current:
        cur = set(c.attempts)
        overlaps = tuple(sorted(pid for pid, s in prev_sets.items() if s & cur))
        if c.cluster_id in prev_sets:
            kind: LineageKind = "unchanged"
        elif not overlaps:
            kind = "new"
        elif len(overlaps) > 1:
            kind = "merged"
        else:
            p = prev_sets[overlaps[0]]
            split = sum(1 for other in current if set(other.attempts) & p) > 1
            kind = "split" if split else "grown" if p < cur else "shrunk" if cur < p else "changed"
        out[c.cluster_id] = (kind, overlaps)
    return out

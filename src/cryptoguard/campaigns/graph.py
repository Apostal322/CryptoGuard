"""Typed campaign graph with poisoning attempts as first-class nodes.

Representing each attempt as a node avoids inventing address-to-address relationships:
two addresses in one transaction are linked only through the attempt that involved both,
with the edge saying exactly how. Edges (direction from the attempt unless stated):

- ``TARGETED_WALLET``      attempt -> victim wallet
- ``USED_LOOKALIKE``       attempt -> lookalike address
- ``IMITATES_RECIPIENT``   lookalike -> the payee it resembles
- ``PLANTED_BY``           attempt -> verified transaction signer
- ``EMITTED_BY_CONTRACT``  attempt -> contract that emitted the Transfer log
- ``IN_TRANSACTION``       attempt -> planting transaction
- ``DEPLOYED_BY``          contract -> deploying account (top-level creations only)

``propagation_matrix`` projects the planting-side part (no victim or imitated nodes, the
same rule as clustering) onto a symmetric sparse matrix for the existing diffusion code;
the projection drops edge direction, which only distinguishes attempt -> entity here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from cryptoguard.campaigns.attempts import PoisoningAttempt
from cryptoguard.campaigns.cluster import Deployer

if TYPE_CHECKING:
    from scipy.sparse import csr_matrix

NodeKind = Literal[
    "attempt", "victim", "lookalike", "imitated", "signer", "contract", "transaction", "deployer"
]
EdgeKind = Literal[
    "TARGETED_WALLET",
    "USED_LOOKALIKE",
    "IMITATES_RECIPIENT",
    "PLANTED_BY",
    "EMITTED_BY_CONTRACT",
    "IN_TRANSACTION",
    "DEPLOYED_BY",
]
PLANTING_SIDE: frozenset[EdgeKind] = frozenset(
    {"USED_LOOKALIKE", "PLANTED_BY", "EMITTED_BY_CONTRACT", "IN_TRANSACTION", "DEPLOYED_BY"}
)


@dataclass(frozen=True, order=True)
class CampaignEdge:
    source: str
    target: str
    kind: EdgeKind
    block_number: int | None
    transaction_hash: str | None


@dataclass
class CampaignGraph:
    nodes: dict[str, NodeKind]  # node id -> kind; ids are "<kind>:<key>"
    edges: list[CampaignEdge]
    truncated: bool = False

    def propagation_matrix(
        self, common: frozenset[str] = frozenset()
    ) -> tuple[csr_matrix, list[str]]:
        """Symmetric 0/1 adjacency over planting-side edges; ``common`` node ids (popular
        contracts, hub signers) are left out so they cannot carry signal between attempts."""
        import numpy as np
        from scipy.sparse import coo_matrix, csr_matrix

        nodes = sorted(
            n for n, k in self.nodes.items() if k not in ("victim", "imitated") and n not in common
        )
        index = {n: i for i, n in enumerate(nodes)}
        pairs = sorted(
            {
                (index[e.source], index[e.target])
                for e in self.edges
                if e.kind in PLANTING_SIDE and e.source in index and e.target in index
            }
        )
        rows = np.array([p[0] for p in pairs] + [p[1] for p in pairs], dtype=np.int64)
        cols = np.array([p[1] for p in pairs] + [p[0] for p in pairs], dtype=np.int64)
        vals = np.ones(len(rows), dtype=float)
        n = len(nodes)
        return csr_matrix(coo_matrix((vals, (rows, cols)), shape=(n, n))), nodes


def node_id(kind: NodeKind, key: str) -> str:
    return f"{kind}:{key}"


def build_campaign_graph(
    attempts: Sequence[PoisoningAttempt],
    deployers: Mapping[str, Deployer] | None = None,
    *,
    max_attempts: int | None = None,
) -> CampaignGraph:
    ordered = sorted(attempts)
    truncated = max_attempts is not None and len(ordered) > max_attempts
    if truncated and max_attempts is not None:
        ordered = ordered[-max_attempts:]  # keep the most recent; reported as truncated
    nodes: dict[str, NodeKind] = {}
    edges: set[CampaignEdge] = set()

    def add(kind: NodeKind, key: str) -> str:
        nid = node_id(kind, key)
        nodes.setdefault(nid, kind)
        return nid

    for a in ordered:
        att = add("attempt", a.attempt_id)
        blk, tx = a.block_number, a.transaction_hash
        edges.add(CampaignEdge(att, add("victim", a.victim), "TARGETED_WALLET", blk, tx))
        look = add("lookalike", a.lookalike)
        edges.add(CampaignEdge(att, look, "USED_LOOKALIKE", blk, tx))
        if a.imitated:
            edges.add(
                CampaignEdge(look, add("imitated", a.imitated), "IMITATES_RECIPIENT", None, None)
            )
        if a.signer and a.signer not in (a.victim, a.lookalike):
            edges.add(CampaignEdge(att, add("signer", a.signer), "PLANTED_BY", blk, tx))
        contract = add("contract", a.contract)
        edges.add(CampaignEdge(att, contract, "EMITTED_BY_CONTRACT", blk, tx))
        edges.add(CampaignEdge(att, add("transaction", tx.lower()), "IN_TRANSACTION", blk, tx))
        d = (deployers or {}).get(a.contract)
        if d is not None:
            edges.add(
                CampaignEdge(
                    contract,
                    add("deployer", d.address),
                    "DEPLOYED_BY",
                    d.creation_block,
                    d.transaction_hash,
                )
            )
    return CampaignGraph(
        nodes=dict(sorted(nodes.items())), edges=sorted(edges), truncated=truncated
    )

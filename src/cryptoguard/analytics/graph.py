"""Directed, typed interaction graph built from one wallet's observations.

Nodes are addresses (wallet, counterparties, transaction signers) and token contracts.
Edges keep their direction and type and aggregate the chain events behind them:

- ``transfer``         sender -> recipient, ERC-20 Transfer events (any token)
- ``native_transfer``  wallet -> recipient, ETH carried by a wallet-signed transaction
- ``caused``           signer -> recipient, the signer's transaction emitted a transfer
                       "from" the wallet (only when the signer is not the wallet)
- ``token_use``        counterparty -> token contract the transfer happened in

A ``caused`` edge records who paid for the transaction, not who benefits; ``token_use`` only
says two addresses touched the same contract. None of these is a financial relationship
between counterparties, and nothing here marks an address as malicious.

Every edge touches the wallet or one of its counterparties: the graph is the wallet's
*observed neighbourhood*, not a slice of the global transaction graph. In particular every
counterparty is adjacent to the wallet by construction, so analyses that care about links
*between* counterparties exclude the wallet node (``WalletGraph.matrix(exclude_wallet=True)``).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from cryptoguard.analytics.observations import ObservationSet
from cryptoguard.detectors.poisoning import NATIVE_ASSET

if TYPE_CHECKING:
    from scipy.sparse import csr_matrix

EdgeKind = Literal["transfer", "native_transfer", "caused", "token_use"]
NodeRole = Literal["wallet", "counterparty", "signer", "token"]
EDGE_KINDS: tuple[EdgeKind, ...] = ("transfer", "native_transfer", "caused", "token_use")
MAX_SAMPLES = 5

# Default weights for propagation over the undirected projection. Transfers are the only
# value-carrying edges; a shared signer is strong evidence of common control of a
# transaction; a shared token contract is weak (popular tokens connect everyone).
DEFAULT_WEIGHTS: Mapping[EdgeKind, float] = {
    "transfer": 1.0,
    "native_transfer": 1.0,
    "caused": 1.0,
    "token_use": 0.25,
}


@dataclass
class EdgeAggregate:
    source: str
    target: str
    kind: EdgeKind
    count: int = 0
    zero_value: int = 0
    first_block: int | None = None
    last_block: int | None = None
    tokens: set[str] = field(default_factory=set)
    samples: list[tuple[int, str]] = field(default_factory=list)  # (block, tx hash)

    def add(self, block: int, tx_hash: str, value: int, token: str | None) -> None:
        self.count += 1
        self.zero_value += value == 0
        self.first_block = block if self.first_block is None else min(self.first_block, block)
        self.last_block = block if self.last_block is None else max(self.last_block, block)
        if token is not None:
            self.tokens.add(token)
        if len(self.samples) < MAX_SAMPLES and (block, tx_hash) not in self.samples:
            self.samples.append((block, tx_hash))


@dataclass(frozen=True)
class GraphScope:
    """Bounds that keep the graph small enough for interactive analysis."""

    max_nodes: int = 2_000
    max_edges: int = 20_000
    from_block: int | None = None  # inclusive; None = everything observed


@dataclass
class WalletGraph:
    wallet: str
    cutoff_block: int
    nodes: list[str]  # deterministic order (sorted), wallet included
    roles: dict[str, set[NodeRole]]
    edges: dict[tuple[str, str, EdgeKind], EdgeAggregate]
    truncated_nodes: int = 0
    truncated_edges: int = 0

    @property
    def index(self) -> dict[str, int]:
        return {n: i for i, n in enumerate(self.nodes)}

    def edges_of(self, kinds: tuple[EdgeKind, ...] = EDGE_KINDS) -> list[EdgeAggregate]:
        return [e for key, e in sorted(self.edges.items()) if key[2] in kinds]

    def matrix(
        self,
        *,
        weights: Mapping[EdgeKind, float] = DEFAULT_WEIGHTS,
        directed: bool = False,
        exclude_wallet: bool = True,
    ) -> tuple[csr_matrix, list[str]]:
        """Sparse weighted adjacency over the node order returned alongside it.

        Parallel edges of different kinds between one pair add their weights (each kind counts
        once per pair, however many events it aggregates, so volume cannot dominate). The
        undirected projection is ``W + W.T``; it loses who-sent-to-whom, which is why
        direction-aware methods take ``directed=True``. Self-loops are dropped.
        """
        import numpy as np
        from scipy.sparse import coo_matrix, csr_matrix

        nodes = [n for n in self.nodes if not (exclude_wallet and n == self.wallet)]
        index = {n: i for i, n in enumerate(nodes)}
        rows: list[int] = []
        cols: list[int] = []
        vals: list[float] = []
        for (src, dst, kind), _ in sorted(self.edges.items()):
            w = float(weights.get(kind, 0.0))
            if w <= 0 or src == dst or src not in index or dst not in index:
                continue
            rows.append(index[src])
            cols.append(index[dst])
            vals.append(w)
        n = len(nodes)
        a = csr_matrix(
            coo_matrix(
                (
                    np.asarray(vals, dtype=float),
                    (np.asarray(rows, dtype=np.int64), np.asarray(cols, dtype=np.int64)),
                ),
                shape=(n, n),
            )
        )
        if not directed:
            a = csr_matrix(a + a.T)
        a.sum_duplicates()
        return a, nodes

    def degree_stats(self, *, exclude_wallet: bool = True) -> dict[str, int]:
        neighbours: dict[str, set[str]] = defaultdict(set)
        for src, dst, _ in self.edges:
            if exclude_wallet and self.wallet in (src, dst):
                continue
            neighbours[src].add(dst)
            neighbours[dst].add(src)
        degrees = [len(v) for v in neighbours.values()]
        return {
            "nodes": len(self.nodes) - (1 if exclude_wallet else 0),
            "edges": sum(
                1 for s, d, _ in self.edges if not (exclude_wallet and self.wallet in (s, d))
            ),
            "max_degree": max(degrees, default=0),
            "counterparties": sum(1 for r in self.roles.values() if "counterparty" in r),
        }


def build_graph(observations: ObservationSet, scope: GraphScope | None = None) -> WalletGraph:
    scope = scope or GraphScope()
    wallet = observations.wallet
    roles: dict[str, set[NodeRole]] = defaultdict(set)
    roles[wallet].add("wallet")
    edges: dict[tuple[str, str, EdgeKind], EdgeAggregate] = {}

    def edge(src: str, dst: str, kind: EdgeKind) -> EdgeAggregate:
        key = (src, dst, kind)
        if key not in edges:
            edges[key] = EdgeAggregate(src, dst, kind)
        return edges[key]

    for e in observations.all_events():
        if scope.from_block is not None and e.block_number < scope.from_block:
            continue
        native = e.token == NATIVE_ASSET
        token = None if native else e.token
        edge(e.sender, e.recipient, "native_transfer" if native else "transfer").add(
            e.block_number, e.transaction_hash, e.value, token
        )
        for party in (e.sender, e.recipient):
            if party != wallet:
                roles[party].add("counterparty")
                if token is not None:
                    roles[token].add("token")
                    edge(party, token, "token_use").add(
                        e.block_number, e.transaction_hash, e.value, token
                    )
        if e.sender == wallet and e.tx_sender is not None and e.tx_sender != wallet:
            roles[e.tx_sender].add("signer")
            edge(e.tx_sender, e.recipient, "caused").add(
                e.block_number, e.transaction_hash, e.value, token
            )

    truncated_nodes = 0
    if len(roles) > scope.max_nodes:
        # Keep the wallet and the most recently active nodes; report what was dropped.
        last: dict[str, int] = defaultdict(lambda: -1)
        for (src, dst, _), agg in edges.items():
            for n in (src, dst):
                last[n] = max(last[n], agg.last_block or -1)
        ranked = sorted((n for n in roles if n != wallet), key=lambda n: (-last[n], n))
        keep = {wallet, *ranked[: scope.max_nodes - 1]}
        truncated_nodes = len(roles) - len(keep)
        roles = defaultdict(set, {n: r for n, r in roles.items() if n in keep})
        edges = {k: v for k, v in edges.items() if k[0] in keep and k[1] in keep}
    truncated_edges = 0
    if len(edges) > scope.max_edges:
        ranked_edges = sorted(edges, key=lambda k: (-(edges[k].last_block or -1), k))
        truncated_edges = len(edges) - scope.max_edges
        edges = {k: edges[k] for k in ranked_edges[: scope.max_edges]}

    return WalletGraph(
        wallet=wallet,
        cutoff_block=observations.cutoff_block,
        nodes=sorted(roles),
        roles=dict(roles),
        edges=edges,
        truncated_nodes=truncated_nodes,
        truncated_edges=truncated_edges,
    )

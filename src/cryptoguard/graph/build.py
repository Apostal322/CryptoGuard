"""Build the wallet's relationship graph from its latest snapshot and stored transfers.

Every edge is either an **observed fact** with evidence (an allowance read at a block, a
balance, account code, Transfer events with transaction hashes) or, for ``RESEMBLES``, a
clearly labelled **heuristic** (address similarity computed by the poisoning detector). No
edge asserts that an address is criminal: suspicion lives in node annotations (findings).

Edge types:

- ``APPROVED_SPENDER`` wallet → spender (one per token; allowance from the snapshot)
- ``HOLDS_TOKEN`` wallet → token (nonzero balance observed at the snapshot block)
- ``DELEGATES_TO`` wallet → EIP-7702 delegation target
- ``TRANSFERRED_TO`` wallet → counterparty (Transfer events *from* the wallet, aggregated;
  ``wallet_signed`` says how many the wallet actually signed)
- ``RECEIVED_FROM`` counterparty → wallet (Transfer events to the wallet, aggregated)
- ``RESEMBLES`` lookalike → imitated address (heuristic, from the poisoning detector)

The graph is capped at ``max_nodes``; lower-priority counterparties are folded into one
explicit summary node, never silently dropped.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.core.known_contracts import lookup_known_contract
from cryptoguard.detectors.poisoning import NATIVE_ASSET, PoisoningCase
from cryptoguard.history.state import WalletState
from cryptoguard.services.approvals import AllowanceLevel

GRAPH_SCHEMA_VERSION = "wallet-graph/1"
MAX_SAMPLE_TXS = 5

NodeKind = Literal["wallet", "token", "spender", "delegation_target", "counterparty", "summary"]
EdgeType = Literal[
    "APPROVED_SPENDER",
    "HOLDS_TOKEN",
    "DELEGATES_TO",
    "TRANSFERRED_TO",
    "RECEIVED_FROM",
    "RESEMBLES",
    "OTHER_COUNTERPARTIES",
]


class EvidenceItem(BaseModel):
    kind: Literal[
        "allowance_read",
        "balance_read",
        "account_code",
        "transfer_event",
        "approval_event",
        "similarity",
    ]
    description: str
    block_number: int | None
    transaction_hash: str | None = None


class FindingRef(BaseModel):
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    status: str
    title: str


class GraphNode(BaseModel):
    id: str
    address: str | None
    kinds: list[NodeKind]
    label: str | None
    label_source: Literal["known_contract", "token_symbol_untrusted", "summary"] | None
    code_kind: CodeKind | None
    findings: list[FindingRef]
    hidden_count: int | None = None


class GraphEdge(BaseModel):
    id: str
    type: EdgeType
    source: str
    target: str
    evidence_class: Literal["observed_fact", "heuristic_signal"]
    explanation: str
    attributes: dict[str, Any]
    evidence: list[EvidenceItem]


class GraphLimits(BaseModel):
    max_nodes: int
    nodes_before_limit: int
    hidden_counterparties: int
    hidden_approvals: int


class WalletGraph(BaseModel):
    schema_version: str = GRAPH_SCHEMA_VERSION
    wallet: str
    chain_id: int
    simulated: bool
    snapshot_id: int
    snapshot_block: int
    coverage: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    limits: GraphLimits
    limitations: list[str]


@dataclass(frozen=True)
class OpenFinding:
    finding_id: str
    rule_id: str
    severity: str
    confidence: str
    status: str
    title: str
    subject: str


@dataclass
class _Flow:
    count: int = 0
    zero_value: int = 0
    wallet_signed: int = 0
    other_signed: int = 0
    unknown_signer: int = 0
    tokens: set[str] = field(default_factory=set)
    first_block: int | None = None
    last_block: int | None = None
    samples: list[TransferEvent] = field(default_factory=list)

    def add(self, event: TransferEvent, wallet: str) -> None:
        self.count += 1
        self.zero_value += event.value == 0
        self.tokens.add(event.token)
        if event.sender == wallet:
            if event.tx_sender is None:
                self.unknown_signer += 1
            elif event.tx_sender == wallet:
                self.wallet_signed += 1
            else:
                self.other_signed += 1
        self.first_block = event.block_number if self.first_block is None else self.first_block
        self.last_block = event.block_number
        self.samples.append(event)


_LEVEL_RANK = {
    AllowanceLevel.UNLIMITED: 0,
    AllowanceLevel.EFFECTIVELY_UNLIMITED: 1,
    AllowanceLevel.UNKNOWN: 2,
    AllowanceLevel.LIMITED: 3,
    AllowanceLevel.NONE: 4,
}


def _subject_address(subject: str) -> str | None:
    """Map a finding subject to the node it concerns."""
    if subject.startswith(("poisoning:", "delegation:")):
        return subject.split(":", 1)[1]
    if ":" in subject:  # approval pair token:spender
        return subject.split(":", 1)[1]
    return None


def build_wallet_graph(
    *,
    wallet: str,
    chain_id: int,
    simulated: bool,
    snapshot_id: int,
    snapshot_block: int,
    state: WalletState,
    transfers: Sequence[TransferEvent],
    cases: Sequence[PoisoningCase],
    open_findings: Sequence[OpenFinding],
    coverage: str,
    max_nodes: int = 60,
    include_inactive: bool = False,
) -> WalletGraph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}

    def node(address: str, kind: NodeKind) -> GraphNode:
        existing = nodes.get(address)
        if existing is None:
            known = lookup_known_contract(chain_id, address) if kind != "wallet" else None
            existing = GraphNode(
                id=address,
                address=address,
                kinds=[],
                label=known.label if known else None,
                label_source="known_contract" if known else None,
                code_kind=None,
                findings=[],
            )
            nodes[address] = existing
        if kind not in existing.kinds:
            existing.kinds.append(kind)
        return existing

    def edge(e: GraphEdge) -> None:
        edges[e.id] = e

    center = node(wallet, "wallet")
    center.code_kind = state.account.code_kind

    # Approvals and balances (observed at the snapshot block). Riskier ones first.
    flagged = {_subject_address(f.subject) for f in open_findings}
    candidates = [
        a
        for a in state.approvals.values()
        if a.verified_at_block == snapshot_block  # carried-forward pairs make no claim here
        and (include_inactive or a.active is not False)
    ]
    candidates.sort(
        key=lambda a: (
            a.spender not in flagged,
            _LEVEL_RANK[a.level],
            a.latest_event.block_number * -1,
            a.key,
        )
    )
    approval_budget = max(1, max_nodes // 2)
    hidden_approvals = max(0, len(candidates) - approval_budget)
    for approval in candidates[:approval_budget]:
        spender = node(approval.spender, "spender")
        spender.code_kind = approval.spender_code_kind
        token = node(approval.token, "token")
        if token.label is None and approval.token_symbol:
            token.label, token.label_source = approval.token_symbol, "token_symbol_untrusted"
        level = approval.level.value
        allowance = approval.allowance if approval.allowance is not None else "unknown"
        edge(
            GraphEdge(
                id=f"APPROVED_SPENDER:{wallet}:{approval.spender}:{approval.token}",
                type="APPROVED_SPENDER",
                source=wallet,
                target=approval.spender,
                evidence_class="observed_fact",
                explanation=f"The wallet allows {approval.spender} to transfer its "
                f"{approval.token_symbol or 'token'} ({approval.token}); allowance {allowance} "
                f"base units ({level}) at block {snapshot_block}.",
                attributes={
                    "token": approval.token,
                    "token_symbol": approval.token_symbol,
                    "allowance": approval.allowance,
                    "allowance_level": level,
                    "active": approval.active,
                    "exposure": approval.exposure,
                },
                evidence=[
                    EvidenceItem(
                        kind="allowance_read",
                        block_number=snapshot_block,
                        description=f"allowance(wallet, {approval.spender}) = {allowance}",
                    ),
                    EvidenceItem(
                        kind="approval_event",
                        block_number=approval.latest_event.block_number,
                        transaction_hash=approval.latest_event.transaction_hash,
                        description=f"Latest Approval event set {approval.latest_event.value}.",
                    ),
                ],
            )
        )
        if approval.balance is not None and int(approval.balance) > 0:
            edge(
                GraphEdge(
                    id=f"HOLDS_TOKEN:{wallet}:{approval.token}",
                    type="HOLDS_TOKEN",
                    source=wallet,
                    target=approval.token,
                    evidence_class="observed_fact",
                    explanation=f"balanceOf(wallet) = {approval.balance} base units at block "
                    f"{snapshot_block}.",
                    attributes={"balance": approval.balance, "token_symbol": approval.token_symbol},
                    evidence=[
                        EvidenceItem(
                            kind="balance_read",
                            block_number=snapshot_block,
                            description=f"balanceOf(wallet) = {approval.balance}",
                        )
                    ],
                )
            )

    # Delegation.
    account = state.account
    if account.code_kind is CodeKind.EIP7702_DELEGATION and account.target:
        target = node(account.target, "delegation_target")
        target.code_kind = account.target_code_kind
        edge(
            GraphEdge(
                id=f"DELEGATES_TO:{wallet}:{account.target}",
                type="DELEGATES_TO",
                source=wallet,
                target=account.target,
                evidence_class="observed_fact",
                explanation=f"The wallet's code is an EIP-7702 delegation indicator pointing to "
                f"{account.target} at block {snapshot_block}.",
                attributes={"target_code_kind": account.target_code_kind},
                evidence=[
                    EvidenceItem(
                        kind="account_code",
                        block_number=snapshot_block,
                        description=f"eth_getCode(wallet), code hash {account.code_hash}",
                    )
                ],
            )
        )

    # Transfers, aggregated per counterparty and direction.
    flows: dict[tuple[str, str], _Flow] = defaultdict(_Flow)
    for event in sorted(transfers, key=lambda e: e.position):
        if event.sender == wallet and event.recipient != wallet:
            flows[("out", event.recipient)].add(event, wallet)
        elif event.recipient == wallet and event.sender != wallet:
            flows[("in", event.sender)].add(event, wallet)

    suspects = {c.suspect for c in cases}
    references = {c.reference for c in cases}
    finding_nodes: dict[str, list[FindingRef]] = defaultdict(list)
    for f in open_findings:
        address = _subject_address(f.subject)
        finding_nodes[address or wallet].append(
            FindingRef(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                severity=f.severity,
                confidence=f.confidence,
                status=f.status,
                title=f.title,
            )
        )

    # Rank counterparties: involved in poisoning, then flagged, then wallet-paid, then volume.
    parties: dict[str, int] = defaultdict(int)
    for (_, address), flow in flows.items():
        parties[address] += flow.count

    def priority(address: str) -> tuple[int, int, int, int, str]:
        paid = flows.get(("out", address))
        return (
            0 if address in suspects or address in references else 1,
            0 if address in finding_nodes else 1,
            0 if paid and paid.wallet_signed else 1,
            -parties[address],
            address,
        )

    budget = max(0, max_nodes - len(nodes) - 1)  # keep room for a summary node
    ranked = sorted((a for a in parties if a not in nodes), key=priority)
    shown = set(ranked[:budget]) | {a for a in parties if a in nodes}
    hidden = ranked[budget:]

    for (direction, address), flow in sorted(flows.items()):
        if address not in shown:
            continue
        node(address, "counterparty")
        etype: EdgeType = "TRANSFERRED_TO" if direction == "out" else "RECEIVED_FROM"
        src, dst = (wallet, address) if direction == "out" else (address, wallet)
        signer_note = (
            f" Signed by the wallet: {flow.wallet_signed}; by others: {flow.other_signed}; "
            f"unknown: {flow.unknown_signer}."
            if direction == "out"
            else ""
        )
        edge(
            GraphEdge(
                id=f"{etype}:{src}:{dst}",
                type=etype,
                source=src,
                target=dst,
                evidence_class="observed_fact",
                explanation=f"{flow.count} ERC-20 Transfer event(s) "
                f"{'from the wallet to' if direction == 'out' else 'to the wallet from'} "
                f"{address} "
                f"in blocks {flow.first_block}-{flow.last_block}, "
                f"{flow.zero_value} with zero value." + signer_note,
                attributes={
                    "count": flow.count,
                    "zero_value": flow.zero_value,
                    "wallet_signed": flow.wallet_signed,
                    "other_signed": flow.other_signed,
                    "unknown_signer": flow.unknown_signer,
                    "tokens": sorted(flow.tokens),
                    "first_block": flow.first_block,
                    "last_block": flow.last_block,
                },
                evidence=[
                    EvidenceItem(
                        kind="transfer_event",
                        block_number=e.block_number,
                        transaction_hash=e.transaction_hash,
                        description=(
                            f"Native ETH payment of {e.value} wei"
                            if e.token == NATIVE_ASSET
                            else f"Transfer of {e.value} base units of {e.token}"
                        )
                        + (f", tx signed by {e.tx_sender}" if e.tx_sender else ""),
                    )
                    for e in flow.samples[-MAX_SAMPLE_TXS:]
                ],
            )
        )

    for case in cases:
        if case.suspect not in nodes or case.reference not in nodes:
            continue
        edge(
            GraphEdge(
                id=f"RESEMBLES:{case.suspect}:{case.reference}",
                type="RESEMBLES",
                source=case.suspect,
                target=case.reference,
                evidence_class="heuristic_signal",
                explanation="Inferred, not an observed interaction: "
                f"{case.suspect} shares its first "
                f"{case.prefix_match} and last {case.suffix_match} hex characters with "
                f"{case.reference} (random odds {case.random_match_odds}).",
                attributes={
                    "prefix_match": case.prefix_match,
                    "suffix_match": case.suffix_match,
                    "rule_id": case.rule_id,
                    "severity": case.severity.value,
                },
                evidence=[
                    EvidenceItem(
                        kind="similarity",
                        block_number=case.first_seen_block,
                        description=f"Full-address comparison: displayed as {case.displayed_as}.",
                    )
                ],
            )
        )

    if hidden:
        summary_id = "summary:other-counterparties"
        nodes[summary_id] = GraphNode(
            id=summary_id,
            address=None,
            kinds=["summary"],
            label=f"{len(hidden)} other counterparties",
            label_source="summary",
            code_kind=None,
            findings=[],
            hidden_count=len(hidden),
        )
        edge(
            GraphEdge(
                id=f"OTHER_COUNTERPARTIES:{wallet}",
                type="OTHER_COUNTERPARTIES",
                source=wallet,
                target=summary_id,
                evidence_class="observed_fact",
                explanation=f"{len(hidden)} lower-priority counterparties with "
                f"{sum(parties[a] for a in hidden)} transfer(s) are summarized to keep the graph "
                "readable. None of them is involved in an open finding or poisoning case.",
                attributes={"hidden": len(hidden), "transfers": sum(parties[a] for a in hidden)},
                evidence=[],
            )
        )

    for address, refs in finding_nodes.items():
        if address in nodes:
            nodes[address].findings = refs

    limitations = [
        f"Built from the snapshot at block {snapshot_block} and the transfers stored for this "
        "wallet; it shows nothing outside that coverage.",
        "Native ETH transfers and NFT approvals are not included.",
        "RESEMBLES edges are inferred from address similarity; all other edges are observed.",
    ]
    if hidden:
        limitations.append(
            f"{len(hidden)} counterparties are summarized (limit {max_nodes} nodes)."
        )
    if hidden_approvals:
        limitations.append(
            f"{hidden_approvals} lower-priority approvals are not drawn; see the Permissions view."
        )
    if simulated:
        limitations.insert(0, "SIMULATED DATA: fictional demo fixture, not Ethereum state.")
    return WalletGraph(
        wallet=wallet,
        chain_id=chain_id,
        simulated=simulated,
        snapshot_id=snapshot_id,
        snapshot_block=snapshot_block,
        coverage=coverage,
        nodes=sorted(nodes.values(), key=lambda n: (n.kinds[0] != "wallet", n.id)),
        edges=sorted(edges.values(), key=lambda e: e.id),
        limits=GraphLimits(
            max_nodes=max_nodes,
            nodes_before_limit=len(nodes) - (1 if hidden else 0) + len(hidden),
            hidden_counterparties=len(hidden),
            hidden_approvals=hidden_approvals,
        ),
        limitations=limitations,
    )

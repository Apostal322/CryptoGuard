"""Assemble a wallet's threat graph from stored data (no chain reads)."""

from __future__ import annotations

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.provider import DataSource
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import NoSnapshotError
from cryptoguard.database.history import HistoryRepository
from cryptoguard.detectors.poisoning import detect_poisoning
from cryptoguard.graph.build import OpenFinding, WalletGraph, build_wallet_graph
from cryptoguard.risk.lifecycle import OPEN_STATUSES
from cryptoguard.services.snapshots import DetectionOptions


def wallet_graph(
    repo: HistoryRepository,
    address: str,
    *,
    chain_id: int,
    data_source: DataSource,
    options: DetectionOptions,
    max_nodes: int,
    include_inactive: bool,
) -> WalletGraph:
    wallet = to_checksum_address(address)
    latest = repo.recent_snapshots(chain_id, wallet, data_source, limit=1)
    if not latest:
        raise NoSnapshotError(
            "No snapshot exists for this wallet yet. Take a snapshot first; the graph is built "
            "only from stored, block-anchored observations."
        )
    snapshot = latest[0]
    transfers = repo.load_transfers(chain_id, wallet, data_source, options.history_limit)
    natives = [
        send
        for tx in repo.load_wallet_transactions(
            chain_id, wallet, data_source, options.history_limit
        )
        if (send := tx.as_native_send()) is not None
    ]
    cases = detect_poisoning(
        wallet,
        transfers,
        chain_id=chain_id,
        wallet_is_plain_eoa=snapshot.state.account.code_kind is CodeKind.NO_CODE,
        config=options.poisoning,
        native_sends=natives,
    )
    # Native payments appear as transfer edges too (asset shown as native ETH).
    transfers = [*transfers, *(n.as_transfer(wallet) for n in natives)]
    findings = [
        OpenFinding(
            f.fingerprint, f.rule_id, f.severity, f.confidence, f.status, f.title, f.subject
        )
        for f in repo.list_findings(chain_id, wallet, [s.value for s in OPEN_STATUSES])
        if f.data_source == data_source
    ]
    return build_wallet_graph(
        wallet=wallet,
        chain_id=chain_id,
        simulated=data_source == "demo_fixture",
        snapshot_id=snapshot.id,
        snapshot_block=snapshot.block_number,
        state=snapshot.state,
        transfers=transfers,
        cases=cases,
        open_findings=findings,
        coverage=str(snapshot.coverage.get("description", "")),
        max_nodes=max_nodes,
        include_inactive=include_inactive,
    )

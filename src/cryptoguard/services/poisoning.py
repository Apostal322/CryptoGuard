"""One-off address-poisoning scan over a bounded window (no history is stored).

For continuous monitoring, use snapshots: they keep the transfer history, so the detector
sees everything observed since the wallet's first snapshot.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from cryptoguard.blockchain.eip7702 import CodeKind, classify_code
from cryptoguard.blockchain.provider import DataSource, EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import ChainInfo
from cryptoguard.core.errors import ReorgDetectedError
from cryptoguard.detectors.poisoning import DETECTOR_VERSION, PoisoningCase, detect_poisoning
from cryptoguard.services.approvals import ScanLimits, normalize_token_scope
from cryptoguard.services.snapshots import DetectionOptions
from cryptoguard.services.transfers import discover_transfers
from cryptoguard.services.wallet_txs import locate_wallet_transactions


class PoisoningReport(BaseModel):
    detector_version: str = DETECTOR_VERSION
    data_source: DataSource
    simulated: bool
    owner: str
    chain_id: int
    block_number: int
    block_hash: str
    observed_at: datetime
    wallet_is_plain_eoa: bool
    scanned_from_block: int
    complete_for_requested_range: bool
    token_scope: list[str] | None
    transfers_analyzed: int
    sender_lookups: int
    sender_lookups_skipped: int
    wallet_transactions_located: int
    wallet_transactions_unlocated: int | None = Field(
        description="Signed in the window but not located; null if the count is unknown."
    )
    cases: list[PoisoningCase]
    limitations: list[str]


async def scan_poisoning(
    provider: EthereumProvider,
    owner: str,
    *,
    chain: ChainInfo,
    limits: ScanLimits,
    options: DetectionOptions,
    lookback_blocks: int | None = None,
    tokens: list[str] | None = None,
) -> PoisoningReport:
    owner = to_checksum_address(owner)
    scope = normalize_token_scope(tokens)
    await provider.verify_chain()
    header = await provider.get_block(await provider.block_number())
    lookback = min(lookback_blocks or limits.lookback_blocks, limits.max_scan_blocks)
    from_block = max(0, header.number - lookback + 1)
    plain = classify_code(await provider.get_code(owner, header.number)).kind is CodeKind.NO_CODE
    discovery = await discover_transfers(
        provider,
        owner,
        from_block=from_block,
        to_block=header.number,
        limits=limits,
        token_scope=scope,
        max_sender_lookups=options.max_sender_lookups,
    )
    wallet_txs = await locate_wallet_transactions(
        provider,
        owner,
        from_block=from_block,
        to_block=header.number,
        max_transactions=options.max_wallet_transactions,
    )
    if (await provider.get_block(header.number)).hash != header.hash:
        raise ReorgDetectedError("The chain reorganized during the scan; try again.")
    natives = [s for t in wallet_txs.transactions if (s := t.as_native_send()) is not None]
    cases = detect_poisoning(
        owner,
        discovery.transfers,
        native_sends=natives,
        chain_id=chain.chain_id,
        wallet_is_plain_eoa=plain,
        config=options.poisoning,
    )
    simulated = provider.source == "demo_fixture"
    limitations = [
        f"ERC-20 transfers were scanned in blocks {discovery.scanned_from} to {header.number}"
        + ("" if discovery.complete else " (the request budget ended the scan early)")
        + ". Lookalikes of addresses used before this window cannot be recognized.",
        "Native ETH the wallet sent is covered through its own signed transactions; native ETH "
        "it received (e.g. ETH dust from a lookalike) is not visible over standard JSON-RPC.",
        "Every case is a warning based on address similarity and transfer context, not proof "
        "of fraud.",
    ]
    if scope:
        limitations.append(f"Only these token contracts were scanned: {', '.join(scope)}.")
    if discovery.sender_lookups_skipped:
        limitations.append(
            f"{discovery.sender_lookups_skipped} outgoing transaction signer(s) were not looked "
            "up (budget), so spoofed transfers among them are not distinguished."
        )
    if wallet_txs.note:
        limitations.append(wallet_txs.note)
    if not plain:
        limitations.append(
            "The wallet has code (smart account or EIP-7702 delegation): a relayer may sign its "
            "transactions, so foreign signers are not treated as spoofing."
        )
    if simulated:
        limitations.insert(0, "SIMULATED DATA: fictional demo fixture, not Ethereum state.")
    return PoisoningReport(
        data_source=provider.source,
        simulated=simulated,
        owner=owner,
        chain_id=chain.chain_id,
        block_number=header.number,
        block_hash=header.hash,
        observed_at=datetime.now(UTC),
        wallet_is_plain_eoa=plain,
        scanned_from_block=discovery.scanned_from,
        complete_for_requested_range=discovery.complete,
        token_scope=scope,
        transfers_analyzed=len(discovery.transfers),
        sender_lookups=discovery.sender_lookups,
        sender_lookups_skipped=discovery.sender_lookups_skipped,
        wallet_transactions_located=len(wallet_txs.transactions),
        wallet_transactions_unlocated=(
            wallet_txs.unlocated if wallet_txs.signed_in_window is not None else None
        ),
        cases=cases,
        limitations=limitations,
    )

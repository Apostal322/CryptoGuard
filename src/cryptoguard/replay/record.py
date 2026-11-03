"""Record a replay fixture from an RPC provider (requires historical log and state access).

Collected without using the answer:

- every ERC-20 Transfer to or from the wallet in the window (all tokens, both directions);
- the signer of each outgoing transfer's transaction (``eth_getTransactionByHash``);
- every transaction the wallet signed in the window, found by bisecting its nonce
  (``eth_getTransactionCount``) — complete by construction, so native-ETH sends are not
  searched for "where the answer is";
- the wallet's code at the window start and just before the end;
- timestamps of every block referenced.

The manifest supplies only the wallet and the window; its ground truth is never consulted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cryptoguard.blockchain.abi import TRANSFER_TOPIC
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import RpcInvalidResponseError
from cryptoguard.replay.models import (
    IncidentManifest,
    RecordedTransaction,
    RecordedTransfer,
    ReplayFixture,
)
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.transfers import discover_transfers
from cryptoguard.services.wallet_txs import locate_wallet_transactions

METHOD = [
    "ERC-20 Transfer logs to and from the wallet, all tokens, the whole window (eth_getLogs).",
    "Signer (tx.from) of every outgoing transfer's transaction (eth_getTransactionByHash).",
    "Every wallet-signed transaction in the window, located by nonce bisection "
    "(eth_getTransactionCount) and read from its block (eth_getBlockByNumber).",
    "Wallet code at the window start and one block before the harmful block (eth_getCode).",
    "Timestamps of all referenced blocks (eth_getBlockByNumber).",
]


async def record_fixture(
    provider: RpcEthereumProvider,
    manifest: IncidentManifest,
    *,
    chunk_blocks: int = 100,
    max_log_requests: int = 2_000,
    max_sender_lookups: int = 500,
) -> ReplayFixture:
    return await record_window(
        provider,
        case_id=manifest.case_id,
        chain_id=manifest.chain_id,
        wallet=manifest.victim,
        start=manifest.evaluation.from_block,
        end=manifest.evaluation.to_block,
        chunk_blocks=chunk_blocks,
        max_log_requests=max_log_requests,
        max_sender_lookups=max_sender_lookups,
    )


async def record_window(
    provider: RpcEthereumProvider,
    *,
    case_id: str,
    chain_id: int,
    wallet: str,
    start: int,
    end: int,
    chunk_blocks: int = 100,
    max_log_requests: int = 2_000,
    max_sender_lookups: int = 500,
    all_timestamps: bool = True,
    max_wallet_transactions: int = 10_000,
) -> ReplayFixture:
    """Record one wallet's observations in ``[start, end]``. With ``all_timestamps=False``
    only the window's first and last block timestamps are read (analyses use block time)."""
    wallet = to_checksum_address(wallet)
    await provider.verify_chain()

    limits = ScanLimits(
        lookback_blocks=0,
        max_scan_blocks=end - start + 1,
        chunk_blocks=chunk_blocks,
        max_log_requests=max_log_requests,
        max_pairs=0,
    )
    transfers = await discover_transfers(
        provider,
        wallet,
        from_block=start,
        to_block=end,
        limits=limits,
        token_scope=None,
        max_sender_lookups=max_sender_lookups,
    )
    located = await locate_wallet_transactions(
        provider, wallet, from_block=start, to_block=end, max_transactions=max_wallet_transactions
    )
    if not located.complete:
        raise RpcInvalidResponseError(
            "Cannot record a complete fixture: " + (located.note or "wallet transactions missing.")
        )
    transactions = [
        RecordedTransaction(
            transaction_hash=t.transaction_hash,
            block_number=t.block_number,
            transaction_index=t.transaction_index,
            nonce=t.nonce,
            to=t.to,
            value=str(t.value),
            succeeded=t.succeeded,
        )
        for t in located.transactions
    ]
    code = {
        str(block): "0x" + (await provider.get_code(wallet, block)).hex()
        for block in (start, end - 1)
    }
    blocks = sorted(
        (
            {t.block_number for t in transfers.transfers} | {t.block_number for t in transactions}
            if all_timestamps
            else set()
        )
        | {start, end}
    )
    timestamps = {str(b): (await provider.get_block(b)).timestamp for b in blocks}

    return ReplayFixture(
        case_id=case_id,
        chain_id=chain_id,
        wallet=wallet,
        from_block=start,
        to_block=end,
        recorded_at=datetime.now(UTC),
        recorded_with=provider.endpoint_display,
        rpc_requests=provider.client.metrics.requests,
        transfer_scan_complete=transfers.complete,
        sender_lookups_skipped=transfers.sender_lookups_skipped,
        method=METHOD,
        wallet_code_hex=code,
        block_timestamps=timestamps,
        transfers=[RecordedTransfer.from_event(t) for t in transfers.transfers],
        wallet_transactions=transactions,
    )


async def locate_transaction(provider: RpcEthereumProvider, tx_hash: str) -> dict[str, Any]:
    """One receipt read: the block, sender, recipient, status and ERC-20 Transfer logs of a
    publicly reported transaction. Used to fix a pre-registered case's window from its
    harmful block and to check its reported identifiers; the recorder never receives it."""
    receipt = await provider.get_transaction_receipt(tx_hash)
    if receipt is None:
        return {"transaction_hash": tx_hash, "found": False}

    def word_address(topic: str) -> str:
        return to_checksum_address("0x" + topic[-40:])

    transfers = [
        {
            "token": to_checksum_address(log["address"]),
            "from": word_address(log["topics"][1]),
            "to": word_address(log["topics"][2]),
            "value_base_units": str(int(log.get("data") or "0x0", 16)),
        }
        for log in receipt.get("logs") or []
        if len(log.get("topics") or []) == 3 and log["topics"][0].lower() == TRANSFER_TOPIC
    ]
    return {
        "transaction_hash": tx_hash,
        "found": True,
        "block_number": int(receipt["blockNumber"], 16),
        "from": to_checksum_address(receipt["from"]) if receipt.get("from") else None,
        "to": to_checksum_address(receipt["to"]) if receipt.get("to") else None,
        "succeeded": receipt.get("status") == "0x1",
        "transfers": transfers,
    }

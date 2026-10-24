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

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import RpcInvalidResponseError
from cryptoguard.core.hexutil import parse_hash32, parse_quantity, to_quantity
from cryptoguard.replay.models import (
    IncidentManifest,
    RecordedTransaction,
    RecordedTransfer,
    ReplayFixture,
)
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.transfers import discover_transfers

METHOD = [
    "ERC-20 Transfer logs to and from the wallet, all tokens, the whole window (eth_getLogs).",
    "Signer (tx.from) of every outgoing transfer's transaction (eth_getTransactionByHash).",
    "Every wallet-signed transaction in the window, located by nonce bisection "
    "(eth_getTransactionCount) and read from its block (eth_getBlockByNumber).",
    "Wallet code at the window start and one block before the harmful block (eth_getCode).",
    "Timestamps of all referenced blocks (eth_getBlockByNumber).",
]


async def _nonce(provider: RpcEthereumProvider, wallet: str, block: int) -> int:
    raw = await provider.client.call("eth_getTransactionCount", [wallet, to_quantity(block)])
    try:
        return parse_quantity(raw)
    except ValueError:
        raise RpcInvalidResponseError("Provider returned an invalid nonce.") from None


async def _block_with_txs(provider: RpcEthereumProvider, block: int) -> list[dict[str, Any]]:
    raw = await provider.client.call("eth_getBlockByNumber", [to_quantity(block), True])
    if not isinstance(raw, dict) or not isinstance(raw.get("transactions"), list):
        raise RpcInvalidResponseError(f"Provider returned an invalid block {block}.")
    return [tx for tx in raw["transactions"] if isinstance(tx, dict)]


async def _wallet_transactions(
    provider: RpcEthereumProvider, wallet: str, from_block: int, to_block: int
) -> list[RecordedTransaction]:
    first = await _nonce(provider, wallet, from_block - 1)
    last = await _nonce(provider, wallet, to_block)
    found: list[RecordedTransaction] = []
    for nonce in range(first, last):
        lo, hi = from_block, to_block  # smallest block whose post-state nonce exceeds ``nonce``
        while lo < hi:
            mid = (lo + hi) // 2
            if await _nonce(provider, wallet, mid) > nonce:
                hi = mid
            else:
                lo = mid + 1
        for tx in await _block_with_txs(provider, lo):
            sender = str(tx.get("from", "")).lower()
            if sender == wallet.lower() and parse_quantity(tx.get("nonce")) == nonce:
                found.append(
                    RecordedTransaction(
                        transaction_hash=parse_hash32(tx.get("hash")),
                        block_number=lo,
                        transaction_index=parse_quantity(tx.get("transactionIndex")),
                        nonce=nonce,
                        to=to_checksum_address(tx["to"]) if tx.get("to") else None,
                        value=str(parse_quantity(tx.get("value"))),
                    )
                )
                break
        else:
            raise RpcInvalidResponseError(
                f"Transaction with nonce {nonce} not found in block {lo}."
            )
    return found


async def record_fixture(
    provider: RpcEthereumProvider,
    manifest: IncidentManifest,
    *,
    chunk_blocks: int = 100,
    max_log_requests: int = 2_000,
    max_sender_lookups: int = 500,
) -> ReplayFixture:
    wallet = to_checksum_address(manifest.victim)
    start, end = manifest.evaluation.from_block, manifest.evaluation.to_block
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
    transactions = await _wallet_transactions(provider, wallet, start, end)
    code = {
        str(block): "0x" + (await provider.get_code(wallet, block)).hex()
        for block in (start, end - 1)
    }
    blocks = sorted(
        {t.block_number for t in transfers.transfers}
        | {t.block_number for t in transactions}
        | {start, end}
    )
    timestamps = {str(b): (await provider.get_block(b)).timestamp for b in blocks}

    return ReplayFixture(
        case_id=manifest.case_id,
        chain_id=manifest.chain_id,
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

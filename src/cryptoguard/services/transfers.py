"""Discover a wallet's ERC-20 transfers in a bounded block window.

Two scans, sharing the request budget: ``Transfer(owner, *)`` (outgoing) and
``Transfer(*, owner)`` (incoming). Coverage is the range both scans completed. For outgoing
transfers, the transaction's signer is looked up (bounded; newest first), because a Transfer
"from" the wallet proves nothing about who caused it.

Native ETH transfers are not visible here: standard JSON-RPC has no per-address index.
"""

from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass

from cryptoguard.blockchain.abi import TRANSFER_TOPIC, address_topic
from cryptoguard.blockchain.erc20 import LogShape, TransferEvent, classify_transfer_log
from cryptoguard.blockchain.logscan import scan_logs
from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import InvalidAddressError, RpcError
from cryptoguard.services.approvals import ScanLimits


@dataclass(frozen=True)
class TransferDiscovery:
    transfers: list[TransferEvent]
    from_block: int
    to_block: int
    scanned_from: int
    complete: bool
    log_requests: int
    log_counts: dict[str, int]
    sender_lookups: int
    sender_lookups_skipped: int


async def _tx_sender(provider: EthereumProvider, tx_hash: str) -> str | None:
    try:
        tx = await provider.get_transaction(tx_hash)
    except RpcError:
        return None
    if not tx:
        return None
    try:
        return to_checksum_address(tx.get("from"))
    except InvalidAddressError:
        return None


async def discover_transfers(
    provider: EthereumProvider,
    owner: str,
    *,
    from_block: int,
    to_block: int,
    limits: ScanLimits,
    token_scope: list[str] | None,
    max_sender_lookups: int,
) -> TransferDiscovery:
    owner = to_checksum_address(owner)
    owner_topic = address_topic(owner)
    budget = max(1, limits.max_log_requests // 2)
    outgoing, incoming = await asyncio.gather(
        scan_logs(
            provider,
            topics=[TRANSFER_TOPIC, owner_topic],
            from_block=from_block,
            to_block=to_block,
            chunk_blocks=limits.chunk_blocks,
            max_requests=budget,
            address=token_scope,
        ),
        scan_logs(
            provider,
            topics=[TRANSFER_TOPIC, None, owner_topic],
            from_block=from_block,
            to_block=to_block,
            chunk_blocks=limits.chunk_blocks,
            max_requests=budget,
            address=token_scope,
        ),
    )
    counts = dict.fromkeys((s.value for s in LogShape), 0)
    seen: set[tuple[str, str]] = set()
    events: list[TransferEvent] = []
    for log in [*outgoing.logs, *incoming.logs]:
        shape, event = classify_transfer_log(log)
        identity = (str(log.get("blockHash")), str(log.get("logIndex")))
        if identity in seen:  # a self-transfer matches both scans
            continue
        seen.add(identity)
        counts[shape.value] += 1
        if event is not None and owner in (event.sender, event.recipient):
            events.append(event)
    events.sort(key=lambda e: e.position)

    outgoing_txs = list(
        dict.fromkeys(e.transaction_hash for e in reversed(events) if e.sender == owner)
    )
    looked_up = outgoing_txs[:max_sender_lookups]
    senders = dict(
        zip(
            looked_up,
            await asyncio.gather(*(_tx_sender(provider, tx) for tx in looked_up)),
            strict=True,
        )
    )
    events = [dataclasses.replace(e, tx_sender=senders.get(e.transaction_hash)) for e in events]
    scanned_from = max(outgoing.scanned_from, incoming.scanned_from)
    return TransferDiscovery(
        transfers=events,
        from_block=from_block,
        to_block=to_block,
        scanned_from=scanned_from,
        complete=outgoing.complete and incoming.complete,
        log_requests=outgoing.requests + incoming.requests,
        log_counts=counts,
        sender_lookups=len(looked_up),
        sender_lookups_skipped=len(outgoing_txs) - len(looked_up),
    )

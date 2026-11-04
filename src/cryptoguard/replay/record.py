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
METHOD_V2 = [
    *METHOD,
    "observation/2: ERC-721-shaped Transfer logs from the same scans, kept as records; "
    "malformed Transfer-topic logs counted.",
    "observation/2: native ETH received, by balance bisection (eth_getBalance) over runs "
    "without own transactions, senders read from the increase blocks (eth_getBlockByNumber), "
    "unexplained increases kept as unattributed; see services/native_inbound.py.",
]


async def record_fixture(
    provider: RpcEthereumProvider,
    manifest: IncidentManifest,
    *,
    chunk_blocks: int = 100,
    max_log_requests: int = 2_000,
    max_sender_lookups: int = 500,
    observation: int = 1,
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
        observation=observation,
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
    observation: int = 1,
) -> ReplayFixture:
    """Record one wallet's observations in ``[start, end]``. With ``all_timestamps=False``
    only the window's first and last block timestamps are read (analyses use block time).
    ``observation=2`` also records native ETH received, ERC-721-shaped transfers and a
    per-category coverage (``replay.observation``); 1, the default, records exactly what
    every existing fixture holds."""
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
    extension = (
        await _observation_v2(provider, wallet, start, end, transfers, transactions, code)
        if observation == 2
        else {}
    )
    extra_blocks = {r.block_number for r in extension.get("native_inbound") or []} | {
        r.block_number for r in extension.get("nft_transfers") or []
    }
    blocks = sorted(
        (
            {t.block_number for t in transfers.transfers}
            | {t.block_number for t in transactions}
            | extra_blocks
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
        method=METHOD_V2 if observation == 2 else METHOD,
        wallet_code_hex=code,
        block_timestamps=timestamps,
        transfers=[RecordedTransfer.from_event(t) for t in transfers.transfers],
        wallet_transactions=transactions,
        **extension,
    )


async def _observation_v2(
    provider: RpcEthereumProvider,
    wallet: str,
    start: int,
    end: int,
    transfers: Any,
    transactions: list[RecordedTransaction],
    code: dict[str, str],
) -> dict[str, Any]:
    """The ``observation/2`` fields: native ETH received, ERC-721-shaped transfers kept as
    records, discarded-log counts, and the coverage of every category."""
    from cryptoguard.core.hexutil import parse_hash32, parse_quantity
    from cryptoguard.replay.models import (
        RecordedNativeInbound,
        RecordedNftTransfer,
        UnattributedInbound,
    )
    from cryptoguard.replay.observation import (
        OBSERVATION_V2,
        CategoryCoverage,
        ObservationCoverage,
        Status,
        legacy_coverage,
    )
    from cryptoguard.services.native_inbound import locate_native_inbound

    plain = all(v == "0x" for v in code.values()) if code else None
    found = await locate_native_inbound(
        provider,
        wallet,
        from_block=start,
        to_block=end,
        own_tx_blocks=[t.block_number for t in transactions],
        wallet_is_plain_eoa=plain,
    )
    nfts = []
    for log in transfers.erc721_logs:
        topics = log["topics"]
        nfts.append(
            RecordedNftTransfer(
                token=to_checksum_address(log["address"]),
                sender=to_checksum_address("0x" + topics[1][-40:]),
                recipient=to_checksum_address("0x" + topics[2][-40:]),
                token_id=str(int(topics[3], 16)),
                block_number=parse_quantity(log["blockNumber"]),
                block_hash=parse_hash32(log["blockHash"]),
                transaction_hash=parse_hash32(log["transactionHash"]),
                transaction_index=parse_quantity(log["transactionIndex"]),
                log_index=parse_quantity(log["logIndex"]),
            )
        )
    scan: Status = "complete" if transfers.complete else "partial"
    counts = dict(transfers.log_counts)
    nonzero = [x for x in found.inbound if x.value > 0]
    zero = [x for x in found.inbound if x.value == 0]
    native: Status = found.status  # type: ignore[assignment]
    unattributed: Status = found.unattributed_status  # type: ignore[assignment]
    categories = dict(legacy_coverage(_Counts(transfers, transactions)).categories)
    categories |= {
        "erc721_transfer_logs": CategoryCoverage(status=scan, count=len(nfts)),
        "malformed_transfer_logs": CategoryCoverage(
            status=scan, count=counts.get("malformed", 0), note="counted, not decoded"
        ),
        "native_inbound_external": CategoryCoverage(
            status=native, count=len(nonzero), note=found.note
        ),
        "native_inbound_zero_value": CategoryCoverage(
            status="unsupported" if native == "unsupported" else "partial",
            count=len(zero),
            note="moves no balance: seen only in blocks read for other reasons",
        ),
        "native_inbound_unattributed": CategoryCoverage(
            status=unattributed, count=len(found.unattributed), note="sender unknown without traces"
        ),
    }
    return {
        "observation": ObservationCoverage(schema_version=OBSERVATION_V2, categories=categories),
        "native_inbound": [
            RecordedNativeInbound(
                transaction_hash=x.transaction_hash,
                block_number=x.block_number,
                transaction_index=x.transaction_index,
                sender=x.sender,
                value=str(x.value),
                succeeded=x.succeeded,
            )
            for x in found.inbound
        ],
        "unattributed_inbound": [
            UnattributedInbound(block_number=u.block_number, value=str(u.value))
            for u in found.unattributed
        ],
        "nft_transfers": nfts,
        "discarded_log_counts": {k: v for k, v in counts.items() if k != "erc20"},
    }


class _Counts:
    """The fields ``legacy_coverage`` reads, from a recording in progress."""

    def __init__(self, transfers: Any, transactions: list[RecordedTransaction]) -> None:
        self.transfer_scan_complete = transfers.complete
        self.sender_lookups_skipped = transfers.sender_lookups_skipped
        self.transfers = transfers.transfers
        self.wallet_transactions = transactions


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


async def block_at_time(provider: RpcEthereumProvider, ts: int, *, after: bool) -> int:
    """By bisection on header timestamps: the first block with timestamp >= ``ts`` (``after``)
    or the last block with timestamp <= ``ts``. About log2(head) block reads."""
    lo, hi = 0, await provider.block_number()
    while lo < hi:
        mid = (lo + hi + (0 if after else 1)) // 2
        stamp = (await provider.get_block(mid)).timestamp
        if after:
            lo, hi = (mid + 1, hi) if stamp < ts else (lo, mid)
        else:
            lo, hi = (mid, hi) if stamp <= ts else (lo, mid - 1)
    return lo


async def find_transfers(
    provider: RpcEthereumProvider,
    *,
    sender: str,
    since: int,
    until: int,
    recipient: str | None = None,
    recipient_prefixes: tuple[str, ...] = (),
    token: str | None = None,
    chunk_blocks: int = 100,
    max_log_requests: int = 500,
    locate_first: int = 10,
) -> dict[str, Any]:
    """ERC-20 Transfer logs from ``sender`` (to ``recipient``, if given) between two UTC
    timestamps, filtered to nonzero values and to the given recipient prefixes, oldest first;
    the first ``locate_first`` matches are read with ``locate_transaction``. Resolves a
    pre-registered Stage 2 case's harmful transaction from the identifiers a source gave; it
    never scores similarity, and the detector never sees its output."""
    from cryptoguard.blockchain.abi import address_topic
    from cryptoguard.blockchain.logscan import scan_logs

    await provider.verify_chain()
    start = await block_at_time(provider, since, after=True)
    end = await block_at_time(provider, until, after=False)
    topics: list[str | list[str] | None] = [TRANSFER_TOPIC, address_topic(sender)]
    if recipient is not None:
        topics.append(address_topic(recipient))
    scan = await scan_logs(
        provider,
        topics=topics,
        from_block=start,
        to_block=end,
        chunk_blocks=chunk_blocks,
        max_requests=max_log_requests,
        address=[token] if token else None,
    )
    prefixes = tuple(p.lower() for p in recipient_prefixes)
    matches: list[dict[str, Any]] = []
    for log in scan.logs:
        if len(log.get("topics") or []) != 3:
            continue
        to = "0x" + log["topics"][2][-40:].lower()
        value = int(log.get("data") or "0x0", 16)
        if value == 0 or (prefixes and not to.startswith(prefixes)):
            continue
        matches.append(
            {
                "transaction_hash": str(log["transactionHash"]).lower(),
                "block_number": int(log["blockNumber"], 16),
                "log_index": int(log["logIndex"], 16),
                "token": to_checksum_address(log["address"]),
                "from": to_checksum_address(sender),
                "to": to_checksum_address(to),
                "value_base_units": str(value),
            }
        )
    matches.sort(key=lambda m: (m["block_number"], m["log_index"]))
    hashes = list(dict.fromkeys(m["transaction_hash"] for m in matches))[:locate_first]
    return {
        "query": {
            "sender": sender.lower(),
            "recipient": recipient.lower() if recipient else None,
            "recipient_prefixes": list(prefixes),
            "token": token.lower() if token else None,
            "since": since,
            "until": until,
        },
        "from_block": start,
        "to_block": end,
        "scan_complete": scan.complete,
        "log_requests": scan.requests,
        "transfers": matches,
        "located": [await locate_transaction(provider, h) for h in hashes],
    }

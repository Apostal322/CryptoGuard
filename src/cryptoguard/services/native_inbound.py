"""Locate native ETH a plain-EOA wallet received in a block window, by balance bisection.

Standard JSON-RPC has no per-address index for native transfers, but it has historical
balances. An externally owned account without code can lose ETH only through transactions
it signs (value plus fee). So between two of its own transactions its balance never falls,
and where it rises, ETH arrived. Bisecting ``eth_getBalance`` over each run of blocks
without an own transaction finds every block whose balance increased; that block's
transaction list then names the external senders (``tx.to == wallet``, nonzero value).

Exact accounting per increase block: the successful external inbound values must sum to
the increase. With ``read_receipts`` (what ``observation/2`` uses) every nonzero inbound
transaction's receipt is read, so success is observed, never inferred. Without it, success
is inferred from an exact sum, which a reverted inbound plus an internal credit of exactly
the same value in the same block would fool. Any remainder is **unattributed** (an
internal transfer from contract execution, a validator withdrawal, a fee-recipient credit):
its sender is unknown without traces, and it is recorded as such, never as a transfer from
anyone.

What this cannot see, stated in the coverage:

- **zero-value native transactions** to the wallet move no balance. They are recorded only
  when they happen to sit in a block that was read anyway.
- **blocks holding the wallet's own transactions**: their external inbound transactions
  are read from the block, but internal credits there cannot be separated from the fee
  without more reads, so ``unattributed`` is partial whenever the window holds own
  transactions.
- **wallets with code** (contracts, EIP-7702 delegations): the balance can fall without
  a wallet-signed transaction, so the method does not apply (``unsupported``).

It never uses an outcome address: it is wallet-centric by construction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import InvalidAddressError, RpcError
from cryptoguard.core.hexutil import parse_hash32, parse_quantity

DEFAULT_MAX_CHANGE_BLOCKS = 200


@dataclass(frozen=True)
class NativeInbound:
    transaction_hash: str
    block_number: int
    transaction_index: int
    sender: str
    value: int
    succeeded: bool | None  # receipt status; None when it could not be read


@dataclass(frozen=True)
class Unattributed:
    block_number: int
    value: int


@dataclass(frozen=True)
class NativeInboundDiscovery:
    inbound: list[NativeInbound]
    unattributed: list[Unattributed]
    status: str  # "complete", "truncated", "partial" or "unsupported"
    unattributed_status: str
    note: str | None
    balance_reads: int
    block_reads: int
    receipt_reads: int
    change_blocks: list[int] = field(default_factory=list)


async def locate_native_inbound(
    provider: EthereumProvider,
    wallet: str,
    *,
    from_block: int,
    to_block: int,
    own_tx_blocks: Sequence[int],
    wallet_is_plain_eoa: bool | None,
    max_change_blocks: int = DEFAULT_MAX_CHANGE_BLOCKS,
    read_receipts: bool = False,
) -> NativeInboundDiscovery:
    wallet = to_checksum_address(wallet)
    if wallet_is_plain_eoa is not True:
        return NativeInboundDiscovery(
            [],
            [],
            "unsupported",
            "unsupported",
            "balance accounting needs a plain EOA (the wallet has code, or it is unknown)",
            0,
            0,
            0,
        )
    balances: dict[int, int] = {}
    counts = {"balance": 0, "block": 0, "receipt": 0}

    async def balance(block: int) -> int:
        if block not in balances:
            counts["balance"] += 1
            balances[block] = await provider.get_balance(wallet, block)
        return balances[block]

    own = sorted({b for b in own_tx_blocks if from_block <= b <= to_block})
    runs: list[tuple[int, int]] = []
    start = from_block
    for b in [*own, to_block + 1]:
        if start <= b - 1:
            runs.append((start, b - 1))
        start = b + 1
    increases: list[tuple[int, int]] = []
    anomalies: list[str] = []
    truncated = False

    async def bisect(lo: int, hi: int, before: int, after: int) -> None:
        nonlocal truncated
        if after == before or truncated:
            return
        if after < before:  # impossible for a plain EOA without own transactions
            anomalies.append(f"balance fell in blocks {lo}..{hi} without an own transaction")
            return
        if lo == hi:
            if len(increases) >= max_change_blocks:
                truncated = True
                return
            increases.append((lo, after - before))
            return
        mid = (lo + hi) // 2
        at_mid = await balance(mid)
        await bisect(lo, mid, before, at_mid)
        await bisect(mid + 1, hi, at_mid, after)

    for lo, hi in runs:
        await bisect(lo, hi, await balance(lo - 1), await balance(hi))

    inbound: list[NativeInbound] = []
    unattributed: list[Unattributed] = []
    for block, delta in sorted(increases):
        txs = await _inbound_txs(provider, wallet, block, counts)
        paid = [t for t in txs if t.value > 0]
        if read_receipts or sum(t.value for t in paid) != delta:  # observe, or resolve a gap
            paid = [await _with_status(provider, t, counts) for t in paid]
            txs = [t for t in txs if t.value == 0] + paid
        explained = sum(t.value for t in paid if t.succeeded is not False)
        if explained > delta:
            anomalies.append(f"block {block}: inbound transactions exceed the balance increase")
        elif explained < delta:
            unattributed.append(Unattributed(block, delta - explained))
        inbound.extend(
            t if t.succeeded is not None or t.value == 0 else _ok(t) for t in txs
        )  # an exact sum shows every nonzero one executed
    for block in own:  # external inbound beside the wallet's own transactions
        for t in await _inbound_txs(provider, wallet, block, counts):
            inbound.append(await _with_status(provider, t, counts) if t.value else t)

    status = "truncated" if truncated else "partial" if anomalies else "complete"
    unattributed_status = status if status != "complete" else "partial" if own else "complete"
    notes = anomalies + (
        [f"{len(own)} block(s) with own transactions: internal credits there not separated"]
        if own
        else []
    )
    return NativeInboundDiscovery(
        sorted(inbound, key=lambda t: (t.block_number, t.transaction_index)),
        unattributed,
        status,
        unattributed_status,
        "; ".join(notes) or None,
        counts["balance"],
        counts["block"],
        counts["receipt"],
        [b for b, _ in sorted(increases)],
    )


def _ok(t: NativeInbound) -> NativeInbound:
    return NativeInbound(
        t.transaction_hash, t.block_number, t.transaction_index, t.sender, t.value, True
    )


async def _inbound_txs(
    provider: EthereumProvider, wallet: str, block: int, counts: dict[str, int]
) -> list[NativeInbound]:
    counts["block"] += 1
    out: list[NativeInbound] = []
    for tx in await provider.get_block_transactions(block):
        try:
            to, sender = tx.get("to"), tx.get("from")
            if not to or str(to).lower() != wallet.lower() or not sender:
                continue
            if str(sender).lower() == wallet.lower():
                continue  # the wallet's own (self-)transaction: not inbound
            out.append(
                NativeInbound(
                    transaction_hash=parse_hash32(tx.get("hash")),
                    block_number=block,
                    transaction_index=parse_quantity(tx.get("transactionIndex")),
                    sender=to_checksum_address(sender),
                    value=parse_quantity(tx.get("value")),
                    succeeded=None,
                )
            )
        except (ValueError, KeyError, InvalidAddressError):
            continue  # a malformed entry is skipped, never guessed
    return out


async def _with_status(
    provider: EthereumProvider, t: NativeInbound, counts: dict[str, int]
) -> NativeInbound:
    counts["receipt"] += 1
    try:
        receipt = await provider.get_transaction_receipt(t.transaction_hash)
    except RpcError:
        return t
    status = (receipt or {}).get("status")
    ok = True if status == "0x1" else False if status == "0x0" else None
    return NativeInbound(
        t.transaction_hash, t.block_number, t.transaction_index, t.sender, t.value, ok
    )

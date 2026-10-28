"""Locate every transaction a wallet signed in a block window, by nonce bisection.

An externally owned account's nonce increases by exactly one per transaction it signs, so the
block of the transaction with nonce ``k`` is the first block whose post-state nonce exceeds
``k``. Bisection on ``eth_getTransactionCount`` finds it; the block's transaction list then
gives the transaction. This is complete by construction (no transaction is missed) and needs
no address index — but it needs historical state for every probed block.

On providers that serve only recent state, probing older blocks fails; the result then says
how many transactions could not be located instead of guessing. Contract wallets do not sign
transactions themselves (relayers and bundlers do), so their native payments are not found.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import (
    HistoricalStateUnavailableError,
    InvalidAddressError,
    RpcError,
    RpcInvalidResponseError,
)
from cryptoguard.core.hexutil import parse_hash32, parse_quantity
from cryptoguard.detectors.poisoning import NativeSend

DEFAULT_MAX_TRANSACTIONS = 200


@dataclass(frozen=True)
class WalletTransaction:
    transaction_hash: str
    block_number: int
    block_hash: str
    transaction_index: int
    nonce: int
    to: str | None
    value: int
    # Receipt status for ETH-carrying transactions: True = executed, False = reverted (no ETH
    # moved, although the nonce was used), None = not read or unknown.
    succeeded: bool | None = None

    def as_native_send(self) -> NativeSend | None:
        if self.to is None or self.value == 0:
            return None
        return NativeSend(
            to=self.to,
            value=self.value,
            block_number=self.block_number,
            transaction_hash=self.transaction_hash,
            transaction_index=self.transaction_index,
            succeeded=self.succeeded,
        )


@dataclass(frozen=True)
class WalletTxDiscovery:
    transactions: list[WalletTransaction]
    from_block: int
    to_block: int
    signed_in_window: int | None  # None when the start or end nonce could not be read
    unlocated: int  # signed in the window but not located (history unavailable or capped)
    note: str | None
    nonce_at_end: int | None = None

    @property
    def complete(self) -> bool:
        return self.signed_in_window is not None and self.unlocated == 0


async def locate_wallet_transactions(
    provider: EthereumProvider,
    wallet: str,
    *,
    from_block: int,
    to_block: int,
    start_nonce: int | None = None,
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
) -> WalletTxDiscovery:
    """Transactions signed by ``wallet`` in ``[from_block, to_block]``, each ETH-carrying one
    with its receipt status (a reverted transaction consumes a nonce but moves no ETH)."""
    found = await _locate(
        provider,
        wallet,
        from_block=from_block,
        to_block=to_block,
        start_nonce=start_nonce,
        max_transactions=max_transactions,
    )
    if not found.transactions:
        return found
    return dataclasses.replace(
        found, transactions=[await _with_status(provider, t) for t in found.transactions]
    )


async def _with_status(provider: EthereumProvider, tx: WalletTransaction) -> WalletTransaction:
    if tx.value == 0:
        return tx  # nothing to verify: no ETH could move either way
    try:
        receipt = await provider.get_transaction_receipt(tx.transaction_hash)
    except RpcError:
        return tx  # unknown, not failed: the status stays None
    if not receipt or str(receipt.get("blockHash", "")).lower() != tx.block_hash.lower():
        return tx  # missing, or from another (reorganized) block: unknown
    status = receipt.get("status")
    succeeded = True if status == "0x1" else False if status == "0x0" else None
    return dataclasses.replace(tx, succeeded=succeeded)


async def _locate(
    provider: EthereumProvider,
    wallet: str,
    *,
    from_block: int,
    to_block: int,
    start_nonce: int | None,
    max_transactions: int,
) -> WalletTxDiscovery:
    """Transactions signed by ``wallet`` in ``[from_block, to_block]``.

    ``start_nonce`` is the nonce at ``from_block - 1`` when already known (e.g. stored with the
    previous snapshot), which avoids a historical-state read at the window start.
    """
    wallet = to_checksum_address(wallet)
    cache: dict[int, int] = {}

    async def nonce_at(block: int) -> int:
        if block not in cache:
            cache[block] = await provider.get_transaction_count(wallet, block)
        return cache[block]

    def result(
        found: list[WalletTransaction], signed: int | None, unlocated: int, note: str | None
    ) -> WalletTxDiscovery:
        return WalletTxDiscovery(
            sorted(found, key=lambda t: t.nonce),
            from_block,
            to_block,
            signed,
            unlocated,
            note,
            cache.get(to_block),
        )

    try:
        last = await nonce_at(to_block)
        if start_nonce is not None:
            first = start_nonce
        else:  # before genesis every account's nonce is 0
            first = 0 if from_block == 0 else await nonce_at(from_block - 1)
    except HistoricalStateUnavailableError:
        return result(
            [],
            None,
            0,
            "The provider cannot serve the wallet's nonce at the window "
            "boundaries (historical state), so its own transactions are unknown.",
        )
    signed = max(0, last - first)
    if signed == 0:
        return result([], 0, 0, None)

    newest_first = range(last - 1, max(first, last - max_transactions) - 1, -1)
    capped = signed - len(newest_first)
    cache[from_block - 1] = first  # known: no read needed at the window start
    found: list[WalletTransaction] = []
    upper = to_block  # nonce_at(upper) > nonce for the nonce being searched
    try:
        for nonce in newest_first:
            # Gallop down from ``upper`` (1, 2, 4, ... blocks) to a block whose nonce is <= the
            # one sought, so only recent blocks are read when the transaction is recent; then
            # bisect that bracket for the first block whose post-state nonce exceeds it.
            hi, step = upper, 1
            while True:
                probe = max(from_block - 1, hi - step)
                if await nonce_at(probe) <= nonce:
                    break
                hi, step = probe, step * 2
            lo = probe + 1
            while lo < hi:
                mid = (lo + hi) // 2
                if await nonce_at(mid) > nonce:
                    hi = mid
                else:
                    lo = mid + 1
            found.append(await _read_transaction(provider, wallet, lo, nonce))
            upper = lo  # older nonces were mined at or before this block
    except HistoricalStateUnavailableError:
        missing = signed - len(found)
        return result(
            found,
            signed,
            missing,
            f"{missing} older transaction(s) signed in the window could not be located: "
            "the provider does not serve historical state for those blocks.",
        )
    note = (
        f"Only the newest {len(found)} of {signed} transactions were located (limit)."
        if capped
        else None
    )
    return result(found, signed, capped, note)


async def _read_transaction(
    provider: EthereumProvider, wallet: str, block: int, nonce: int
) -> WalletTransaction:
    for tx in await provider.get_block_transactions(block):
        try:
            if (
                str(tx.get("from", "")).lower() != wallet.lower()
                or parse_quantity(tx.get("nonce")) != nonce
            ):
                continue
            return WalletTransaction(
                transaction_hash=parse_hash32(tx.get("hash")),
                block_number=block,
                block_hash=parse_hash32(tx.get("blockHash")),
                transaction_index=parse_quantity(tx.get("transactionIndex")),
                nonce=nonce,
                to=to_checksum_address(tx["to"]) if tx.get("to") else None,
                value=parse_quantity(tx.get("value")),
            )
        except (ValueError, KeyError, InvalidAddressError) as exc:
            raise RpcInvalidResponseError(f"Invalid transaction in block {block}.") from exc
    raise RpcInvalidResponseError(f"Transaction with nonce {nonce} not found in block {block}.")

"""Coverage-aware, point-in-time view of what CryptoGuard observed for one wallet.

The analyses never read the chain. They take the transfers and wallet-signed transactions
already stored (or recorded in a replay fixture) plus the block ranges in which those were
completely scanned, and cut everything at an explicit block. Activity outside the covered
ranges is *unknown*, never zero.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.core.address import to_checksum_address
from cryptoguard.detectors.poisoning import NativeSend


@dataclass(frozen=True, order=True)
class BlockRange:
    from_block: int
    to_block: int

    def contains(self, block: int) -> bool:
        return self.from_block <= block <= self.to_block

    def covers(self, start: int, end: int) -> bool:
        return self.from_block <= start and end <= self.to_block


def _merge(ranges: Iterable[BlockRange]) -> tuple[BlockRange, ...]:
    merged: list[BlockRange] = []
    for r in sorted(ranges):
        if merged and r.from_block <= merged[-1].to_block + 1:
            merged[-1] = BlockRange(merged[-1].from_block, max(merged[-1].to_block, r.to_block))
        else:
            merged.append(r)
    return tuple(merged)


def _clip(ranges: Iterable[BlockRange], cutoff: int) -> tuple[BlockRange, ...]:
    return tuple(
        BlockRange(r.from_block, min(r.to_block, cutoff)) for r in ranges if r.from_block <= cutoff
    )


@dataclass(frozen=True)
class ObservedCoverage:
    """Where each kind of observation is complete. Unknown ranges are simply absent."""

    transfers: tuple[BlockRange, ...]
    wallet_transactions: tuple[BlockRange, ...]
    signer_lookups_skipped: int = 0
    wallet_transactions_unlocated: int = 0
    # Categories CryptoGuard cannot see at all; reported with every result.
    unsupported: tuple[str, ...] = (
        "native ETH received by the wallet",
        "internal (contract-mediated) ETH transfers",
        "transactions of counterparties that do not involve the wallet",
        "signers of incoming transfers",
    )

    def transfers_cover(self, start: int, end: int) -> bool:
        return any(r.covers(start, end) for r in self.transfers)

    def both_cover(self, start: int, end: int) -> bool:
        return self.transfers_cover(start, end) and any(
            r.covers(start, end) for r in self.wallet_transactions
        )

    def describe(self) -> list[str]:
        notes = [
            "ERC-20 transfers observed in blocks "
            + (", ".join(f"{r.from_block}-{r.to_block}" for r in self.transfers) or "none")
            + "; wallet-signed transactions in "
            + (
                ", ".join(f"{r.from_block}-{r.to_block}" for r in self.wallet_transactions)
                or "none"
            )
            + "."
        ]
        if self.signer_lookups_skipped:
            notes.append(
                f"{self.signer_lookups_skipped} outgoing transfer(s) have no known signer "
                "(lookup limit)."
            )
        if self.wallet_transactions_unlocated:
            notes.append(
                f"{self.wallet_transactions_unlocated} wallet-signed transaction(s) could not "
                "be located."
            )
        notes.append("Not visible: " + "; ".join(self.unsupported) + ".")
        return notes


@dataclass(frozen=True)
class ObservationSet:
    """All observations for ``wallet`` with block <= ``cutoff_block``, deduplicated."""

    chain_id: int
    wallet: str
    cutoff_block: int
    transfers: tuple[TransferEvent, ...]
    native_sends: tuple[NativeSend, ...]
    coverage: ObservedCoverage
    duplicates_dropped: int = 0
    notes: tuple[str, ...] = field(default=())

    @classmethod
    def build(
        cls,
        *,
        chain_id: int,
        wallet: str,
        cutoff_block: int,
        transfers: Sequence[TransferEvent],
        native_sends: Sequence[NativeSend],
        transfer_ranges: Iterable[BlockRange],
        wallet_tx_ranges: Iterable[BlockRange],
        signer_lookups_skipped: int = 0,
        wallet_transactions_unlocated: int = 0,
    ) -> ObservationSet:
        """Cut at ``cutoff_block`` and drop repeated observations of the same chain event.

        A transfer is identified by (transaction hash, log index) and a native send by its
        transaction hash, so ingesting the same log twice (overlapping scans, re-recorded
        snapshots) never counts as two transfers.
        """
        wallet = to_checksum_address(wallet)
        seen: set[tuple[str, int]] = set()
        kept: list[TransferEvent] = []
        dropped = 0
        for t in sorted(transfers, key=lambda e: (e.position, e.transaction_hash)):
            if t.block_number > cutoff_block:
                continue
            key = (t.transaction_hash.lower(), t.log_index)
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            kept.append(t)
        seen_tx: set[str] = set()
        natives: list[NativeSend] = []
        for n in sorted(native_sends, key=lambda s: (s.block_number, s.transaction_index)):
            if n.block_number > cutoff_block:
                continue
            if n.transaction_hash.lower() in seen_tx:
                dropped += 1
                continue
            seen_tx.add(n.transaction_hash.lower())
            natives.append(n)
        return cls(
            chain_id=chain_id,
            wallet=wallet,
            cutoff_block=cutoff_block,
            transfers=tuple(kept),
            native_sends=tuple(natives),
            coverage=ObservedCoverage(
                transfers=_clip(_merge(transfer_ranges), cutoff_block),
                wallet_transactions=_clip(_merge(wallet_tx_ranges), cutoff_block),
                signer_lookups_skipped=signer_lookups_skipped,
                wallet_transactions_unlocated=wallet_transactions_unlocated,
            ),
            duplicates_dropped=dropped,
        )

    def at(self, cutoff_block: int) -> ObservationSet:
        """The same observations as they were known at an earlier block."""
        if cutoff_block > self.cutoff_block:
            raise ValueError("cannot move a cutoff forward: later data was never observed")
        return ObservationSet.build(
            chain_id=self.chain_id,
            wallet=self.wallet,
            cutoff_block=cutoff_block,
            transfers=self.transfers,
            native_sends=self.native_sends,
            transfer_ranges=self.coverage.transfers,
            wallet_tx_ranges=self.coverage.wallet_transactions,
            signer_lookups_skipped=self.coverage.signer_lookups_skipped,
            wallet_transactions_unlocated=self.coverage.wallet_transactions_unlocated,
        )

    def all_events(self) -> list[TransferEvent]:
        """Transfers plus native sends (as transfer-shaped events), in chain order."""
        return sorted(
            [*self.transfers, *(n.as_transfer(self.wallet) for n in self.native_sends)],
            key=lambda e: e.position,
        )

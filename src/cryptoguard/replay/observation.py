"""What a recorded window observed, per event category (``observation/2``).

A complete ERC-20 log scan says nothing about native ETH, a receipt says nothing about
internal value transfers, and a complete window says nothing about history before it. So
completeness is stated per category, and a category that was never collected is
``not_collected`` (or ``unsupported``), never an observed zero.

Statuses:

- ``complete``: every event of the category in the window was observed (``count`` of them,
  possibly 0: a real zero).
- ``partial`` / ``truncated``: some were observed; how many were missed is unknown.
- ``interrupted`` / ``rejected``: collection stopped on an error or a provider refusal.
- ``not_collected``: the recorder did not look. Absence of records means nothing.
- ``unsupported``: the data source cannot provide the category (e.g. no trace access).
- ``unknown``: completeness cannot be determined.

Fixtures recorded before ``observation/2`` carry no coverage; ``coverage_of`` derives what
``observation/1`` actually did from the recorder's documented method.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

OBSERVATION_V1 = "observation/1"
OBSERVATION_V2 = "observation/2"

Status = Literal[
    "complete",
    "partial",
    "truncated",
    "interrupted",
    "rejected",
    "not_collected",
    "unsupported",
    "unknown",
]
CATEGORIES = (
    "erc20_transfer_logs",  # Transfer, 3 topics and 32 data bytes, to or from the wallet
    "erc20_outgoing_signers",  # tx.from of every outgoing ERC-20 transfer's transaction
    "erc721_transfer_logs",  # Transfer, 4 topics and no data (same topic0 as ERC-20)
    "malformed_transfer_logs",  # Transfer topic0 in any other shape (counted, not decoded)
    "erc1155_transfer_logs",  # TransferSingle / TransferBatch (different topic0)
    "wallet_signed_transactions",  # every transaction the wallet signed (nonce bisection)
    "native_inbound_external",  # nonzero ETH in top-level transactions to the wallet
    "native_inbound_zero_value",  # 0-ETH top-level transactions to the wallet
    "native_inbound_unattributed",  # balance increases no external transaction explains
    "internal_value_transfers",  # value moved by contract execution (needs traces)
)


class CategoryCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status
    count: int | None = None  # records observed; None when nothing was collected
    note: str | None = None


class ObservationCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    categories: dict[str, CategoryCoverage]

    def status(self, category: str) -> Status:
        c = self.categories.get(category)
        return "unknown" if c is None else c.status

    def complete(self, *categories: str) -> bool:
        return all(self.status(c) == "complete" for c in categories)


_V1_NOT_KEPT = (
    "fetched by the log scan but discarded by observation/1; not even counts were persisted"
)


def legacy_coverage(fixture: Any) -> ObservationCoverage:
    """What an ``observation/1`` recording observed, from its stored fields and the
    recorder's method (see ``replay.record.METHOD``)."""
    scan = "complete" if fixture.transfer_scan_complete else "partial"
    return ObservationCoverage(
        schema_version=OBSERVATION_V1,
        categories={
            "erc20_transfer_logs": CategoryCoverage(status=scan, count=len(fixture.transfers)),
            "erc20_outgoing_signers": CategoryCoverage(
                status="complete" if fixture.sender_lookups_skipped == 0 else "partial",
                note=f"{fixture.sender_lookups_skipped} lookups skipped",
            ),
            "erc721_transfer_logs": CategoryCoverage(status="not_collected", note=_V1_NOT_KEPT),
            "malformed_transfer_logs": CategoryCoverage(status="not_collected", note=_V1_NOT_KEPT),
            "erc1155_transfer_logs": CategoryCoverage(status="not_collected", note="not queried"),
            "wallet_signed_transactions": CategoryCoverage(
                status="complete",  # the recorder refuses an incomplete nonce bisection
                count=len(fixture.wallet_transactions),
            ),
            "native_inbound_external": CategoryCoverage(
                status="not_collected", note="no per-address index for native transfers"
            ),
            "native_inbound_zero_value": CategoryCoverage(status="not_collected"),
            "native_inbound_unattributed": CategoryCoverage(status="not_collected"),
            "internal_value_transfers": CategoryCoverage(
                status="unsupported", note="the RPC layer has no trace access"
            ),
        },
    )


def coverage_of(fixture: Any) -> ObservationCoverage:
    """The fixture's stated coverage (``observation/2``), else the derived legacy one."""
    stated = getattr(fixture, "observation", None)
    return stated if stated is not None else legacy_coverage(fixture)

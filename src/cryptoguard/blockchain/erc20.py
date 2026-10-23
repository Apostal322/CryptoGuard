"""Decoding of ERC-20 ``Approval`` and ``Transfer`` logs with explicit standard disambiguation.

ERC-20 and ERC-721 declare ``Approval`` and ``Transfer`` with identical signatures, so they
share topic0. They differ only in how many fields are indexed:

- ERC-20: 3 topics (signature, two addresses), 32 bytes of data (the amount)
- ERC-721: 4 topics (tokenId indexed too), empty data

Only the exact ERC-20 shape is decoded as a fungible event. ERC-721-shaped logs are counted
separately (NFTs are not supported yet), and anything else is malformed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptoguard.blockchain.abi import APPROVAL_TOPIC, TRANSFER_TOPIC, decode_address_word
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import InvalidAddressError
from cryptoguard.core.hexutil import parse_data, parse_hash32, parse_quantity


class LogShape(StrEnum):
    ERC20 = "erc20"
    ERC721_SHAPED = "erc721_shaped"
    REMOVED = "removed"  # reorged out; the provider flagged it with removed=true
    MALFORMED = "malformed"


ApprovalLogShape = LogShape


@dataclass(frozen=True, order=True)
class LogPosition:
    block_number: int
    log_index: int


@dataclass(frozen=True)
class ApprovalEvent:
    token: str
    owner: str
    spender: str
    value: int
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int

    @property
    def position(self) -> LogPosition:
        return LogPosition(self.block_number, self.log_index)


@dataclass(frozen=True)
class TransferEvent:
    token: str
    sender: str
    recipient: str
    value: int
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int
    # The transaction's signer (``tx.from``), when looked up; None means unknown. A Transfer
    # *from* a wallet in a transaction the wallet did not sign was not necessarily its doing:
    # anyone can call transferFrom(wallet, x, 0) on many tokens, and fake tokens emit anything.
    tx_sender: str | None = None

    @property
    def position(self) -> LogPosition:
        return LogPosition(self.block_number, self.log_index)


@dataclass(frozen=True)
class _Fields:
    token: str
    first: str
    second: str
    value: int
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int


def _decode(log: dict[str, Any], topic0: str) -> tuple[LogShape, _Fields | None]:
    if log.get("removed") is True:
        return LogShape.REMOVED, None
    try:
        topics = [parse_hash32(t) for t in log["topics"]]
        data = parse_data(log["data"], max_bytes=4096)
        if not topics or topics[0] != topic0:
            return LogShape.MALFORMED, None
        if len(topics) == 4 and not data:
            return LogShape.ERC721_SHAPED, None
        if len(topics) != 3 or len(data) != 32:
            return LogShape.MALFORMED, None
        fields = _Fields(
            token=to_checksum_address(log["address"]),
            first=decode_address_word(bytes.fromhex(topics[1][2:])),
            second=decode_address_word(bytes.fromhex(topics[2][2:])),
            value=int.from_bytes(data, "big"),
            block_number=parse_quantity(log["blockNumber"]),
            block_hash=parse_hash32(log["blockHash"]),
            transaction_hash=parse_hash32(log["transactionHash"]),
            transaction_index=parse_quantity(log["transactionIndex"]),
            log_index=parse_quantity(log["logIndex"]),
        )
    except (KeyError, TypeError, ValueError, InvalidAddressError):
        return LogShape.MALFORMED, None
    return LogShape.ERC20, fields


def classify_approval_log(log: dict[str, Any]) -> tuple[LogShape, ApprovalEvent | None]:
    shape, f = _decode(log, APPROVAL_TOPIC)
    if f is None:
        return shape, None
    return shape, ApprovalEvent(
        f.token,
        f.first,
        f.second,
        f.value,
        f.block_number,
        f.block_hash,
        f.transaction_hash,
        f.transaction_index,
        f.log_index,
    )


def classify_transfer_log(log: dict[str, Any]) -> tuple[LogShape, TransferEvent | None]:
    shape, f = _decode(log, TRANSFER_TOPIC)
    if f is None:
        return shape, None
    return shape, TransferEvent(
        f.token,
        f.first,
        f.second,
        f.value,
        f.block_number,
        f.block_hash,
        f.transaction_hash,
        f.transaction_index,
        f.log_index,
    )

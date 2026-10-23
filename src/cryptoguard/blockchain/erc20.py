"""Decoding of ``Approval`` event logs with explicit token-standard disambiguation.

ERC-20 ``Approval(address indexed owner, address indexed spender, uint256 value)`` and
ERC-721 ``Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)``
have the same topic0. They differ only in how many fields are indexed:

- ERC-20: 3 topics, 32 bytes of data (the value)
- ERC-721: 4 topics, empty data

Only the exact ERC-20 shape is decoded as a fungible allowance. ERC-721-shaped logs are
counted separately (NFT approvals are not supported yet), and anything else is malformed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from cryptoguard.blockchain.abi import APPROVAL_TOPIC, decode_address_word
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import InvalidAddressError
from cryptoguard.core.hexutil import parse_data, parse_hash32, parse_quantity


class ApprovalLogShape(StrEnum):
    ERC20 = "erc20"
    ERC721_SHAPED = "erc721_shaped"
    REMOVED = "removed"  # reorged out; the provider flagged it with removed=true
    MALFORMED = "malformed"


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


def classify_approval_log(log: dict[str, Any]) -> tuple[ApprovalLogShape, ApprovalEvent | None]:
    if log.get("removed") is True:
        return ApprovalLogShape.REMOVED, None
    try:
        topics = [parse_hash32(t) for t in log["topics"]]
        data = parse_data(log["data"], max_bytes=4096)
        if not topics or topics[0] != APPROVAL_TOPIC:
            return ApprovalLogShape.MALFORMED, None
        if len(topics) == 4 and not data:
            return ApprovalLogShape.ERC721_SHAPED, None
        if len(topics) != 3 or len(data) != 32:
            return ApprovalLogShape.MALFORMED, None
        event = ApprovalEvent(
            token=to_checksum_address(log["address"]),
            owner=decode_address_word(bytes.fromhex(topics[1][2:])),
            spender=decode_address_word(bytes.fromhex(topics[2][2:])),
            value=int.from_bytes(data, "big"),
            block_number=parse_quantity(log["blockNumber"]),
            block_hash=parse_hash32(log["blockHash"]),
            transaction_hash=parse_hash32(log["transactionHash"]),
            transaction_index=parse_quantity(log["transactionIndex"]),
            log_index=parse_quantity(log["logIndex"]),
        )
    except (KeyError, TypeError, ValueError, InvalidAddressError):
        return ApprovalLogShape.MALFORMED, None
    return ApprovalLogShape.ERC20, event

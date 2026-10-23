"""Demo mode: a provider backed by deterministic, clearly fictional fixtures.

Fixture addresses and block hashes are derived from keccak256 of descriptive labels, so they
look like real values but are not taken from Ethereum. Every inspection served from this
provider is marked ``data_source="demo_fixture"`` and ``simulated=true``. Addresses that are
not fixtures are rejected rather than answered with invented state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    SEL_BALANCE_OF,
    SEL_DECIMALS,
    SEL_SYMBOL,
    TRANSFER_TOPIC,
    UINT256_MAX,
    address_topic,
    decode_address_word,
)
from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX
from cryptoguard.blockchain.provider import BlockHeader, BlockRef, DataSource
from cryptoguard.core.address import address_from_bytes, to_checksum_address
from cryptoguard.core.errors import (
    ContractCallFailedError,
    NotInDemoFixturesError,
    RpcUnsupportedMethodError,
)
from cryptoguard.core.hashing import keccak256

DEMO_HEAD_BLOCK = 1_000_000
DEMO_FINALIZED_BLOCK = DEMO_HEAD_BLOCK - 64
DEMO_GENESIS_TIMESTAMP = 1_767_225_600  # 2026-01-01T00:00:00Z, fictional chain timeline
DEMO_BLOCK_TIME = 12


def _demo_address(label: str) -> str:
    return address_from_bytes(keccak256(f"cryptoguard-demo-address:{label}".encode())[-20:])


def _demo_block_hash(number: int) -> str:
    return "0x" + keccak256(f"cryptoguard-demo-block:{number}".encode()).hex()


def _lookalike(address: str) -> str:
    """Same first and last 5 hex characters, a different middle (an attacker's vanity copy)."""
    middle = keccak256(f"cryptoguard-demo-lookalike:{address}".encode()).hex()[:30]
    body = address[2:7].lower() + middle + address[-5:].lower()
    return to_checksum_address("0x" + body)


@dataclass(frozen=True)
class DemoAccount:
    label: str
    description: str
    address: str
    balance_wei: int
    code: bytes


_DELEGATE = _demo_address("delegate-contract")
# Short, syntactically ordinary bytecode; it is a fixture, not a deployed contract.
_DELEGATE_CODE = bytes.fromhex("6080604052348015600f57600080fd5b50600436106100365760003560e01c00")

DEMO_ACCOUNTS: tuple[DemoAccount, ...] = (
    DemoAccount(
        "plain-wallet",
        "Externally owned account with no code.",
        _demo_address("plain-wallet"),
        2_750_000_000_000_000_000,
        b"",
    ),
    DemoAccount(
        "delegated-wallet",
        "EOA with an EIP-7702 delegation to a fixture contract.",
        _demo_address("delegated-wallet"),
        400_000_000_000_000_000,
        DELEGATION_PREFIX + bytes.fromhex(_DELEGATE[2:]),
    ),
    DemoAccount(
        "delegate-contract",
        "Contract that the delegated wallet points to.",
        _DELEGATE,
        0,
        _DELEGATE_CODE,
    ),
    DemoAccount(
        "demo-token",
        "Fictional ERC-20 token (symbol DEMO, 18 decimals).",
        _demo_address("demo-token"),
        0,
        _DELEGATE_CODE,
    ),
    DemoAccount(
        "demo-router",
        "Fictional contract spender.",
        _demo_address("demo-router"),
        0,
        _DELEGATE_CODE,
    ),
    DemoAccount(
        "demo-old-router",
        "Fictional contract spender whose approval was later revoked.",
        _demo_address("demo-old-router"),
        0,
        _DELEGATE_CODE,
    ),
    DemoAccount(
        "demo-unknown-eoa",
        "Fictional plain account that received a token approval.",
        _demo_address("demo-unknown-eoa"),
        0,
        b"",
    ),
    DemoAccount(
        "demo-friend",
        "Fictional account the plain wallet paid.",
        _demo_address("demo-friend"),
        0,
        b"",
    ),
    DemoAccount(
        "demo-lookalike",
        "Fictional vanity lookalike of demo-friend (same first and last 5 hex characters).",
        _lookalike(_demo_address("demo-friend")),
        0,
        b"",
    ),
)

_BY_ADDRESS = {account.address: account for account in DEMO_ACCOUNTS}
_BY_LABEL = {account.label: account.address for account in DEMO_ACCOUNTS}

_UNIT = 10**18
DEMO_TOKEN = _BY_LABEL["demo-token"]
DEMO_TOKEN_BALANCES = {_BY_LABEL["plain-wallet"]: 1_200 * _UNIT}


@dataclass(frozen=True)
class DemoApproval:
    """A fixture Approval log; ``current`` is the allowance the token reports now."""

    owner: str
    spender: str
    value: int
    current: int
    block_number: int
    log_index: int


DEMO_APPROVALS: tuple[DemoApproval, ...] = (
    DemoApproval(
        _BY_LABEL["plain-wallet"],
        _BY_LABEL["demo-router"],
        UINT256_MAX,
        UINT256_MAX,
        DEMO_HEAD_BLOCK - 7_000,
        3,
    ),
    DemoApproval(
        _BY_LABEL["plain-wallet"],
        _BY_LABEL["demo-old-router"],
        50 * _UNIT,
        0,
        DEMO_HEAD_BLOCK - 6_000,
        1,
    ),
    DemoApproval(
        _BY_LABEL["plain-wallet"], _BY_LABEL["demo-old-router"], 0, 0, DEMO_HEAD_BLOCK - 2_000, 5
    ),
    DemoApproval(
        _BY_LABEL["plain-wallet"],
        _BY_LABEL["demo-unknown-eoa"],
        500 * _UNIT,
        350 * _UNIT,
        DEMO_HEAD_BLOCK - 300,
        0,
    ),
)


@dataclass(frozen=True)
class DemoTransfer:
    """A fixture Transfer log and the account that signed its transaction."""

    sender: str
    recipient: str
    value: int
    signer: str
    block_number: int
    log_index: int

    @property
    def tx_hash(self) -> str:
        material = f"cryptoguard-demo-transfer-tx:{self.block_number}:{self.log_index}"
        return "0x" + keccak256(material.encode()).hex()


_WALLET, _FRIEND, _LOOKALIKE = (
    _BY_LABEL["plain-wallet"],
    _BY_LABEL["demo-friend"],
    _BY_LABEL["demo-lookalike"],
)
DEMO_TRANSFERS: tuple[DemoTransfer, ...] = (
    # The wallet pays a friend (signed by the wallet)...
    DemoTransfer(_WALLET, _FRIEND, 250 * _UNIT, _WALLET, DEMO_HEAD_BLOCK - 5_000, 2),
    # ...then the lookalike calls transferFrom(wallet, lookalike, 0): no allowance needed.
    DemoTransfer(_WALLET, _LOOKALIKE, 0, _LOOKALIKE, DEMO_HEAD_BLOCK - 4_990, 4),
    # ...and sends dust so it shows up as an incoming sender too.
    DemoTransfer(_LOOKALIKE, _WALLET, 1, _LOOKALIKE, DEMO_HEAD_BLOCK - 4_985, 1),
)
_DEMO_TX_SIGNERS = {t.tx_hash: t.signer for t in DEMO_TRANSFERS}


def _demo_transfer_log(transfer: DemoTransfer) -> dict[str, Any]:
    return {
        "address": DEMO_TOKEN,
        "topics": [
            TRANSFER_TOPIC,
            address_topic(transfer.sender),
            address_topic(transfer.recipient),
        ],
        "data": "0x" + transfer.value.to_bytes(32, "big").hex(),
        "blockNumber": hex(transfer.block_number),
        "blockHash": _demo_block_hash(transfer.block_number),
        "transactionHash": transfer.tx_hash,
        "transactionIndex": "0x0",
        "logIndex": hex(transfer.log_index),
        "removed": False,
    }


def _demo_log(approval: DemoApproval) -> dict[str, Any]:
    tx_hash = (
        "0x"
        + keccak256(
            f"cryptoguard-demo-tx:{approval.block_number}:{approval.log_index}".encode()
        ).hex()
    )
    return {
        "address": DEMO_TOKEN,
        "topics": [APPROVAL_TOPIC, address_topic(approval.owner), address_topic(approval.spender)],
        "data": "0x" + approval.value.to_bytes(32, "big").hex(),
        "blockNumber": hex(approval.block_number),
        "blockHash": _demo_block_hash(approval.block_number),
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "logIndex": hex(approval.log_index),
        "removed": False,
    }


class DemoProvider:
    def __init__(self, chain_id: int) -> None:
        self._chain_id = chain_id

    @property
    def source(self) -> DataSource:
        return "demo_fixture"

    @property
    def endpoint_display(self) -> str:
        return "demo fixtures (simulated)"

    async def aclose(self) -> None:
        return None

    async def chain_id(self) -> int:
        return self._chain_id

    async def verify_chain(self) -> int:
        return self._chain_id

    async def block_number(self) -> int:
        return DEMO_HEAD_BLOCK

    async def get_block(self, block: BlockRef) -> BlockHeader:
        if block == "finalized":
            number = DEMO_FINALIZED_BLOCK
        elif block in ("latest", "safe"):
            number = DEMO_HEAD_BLOCK
        elif block == "earliest":
            number = 0
        else:
            assert isinstance(block, int)
            number = block
        if not 0 <= number <= DEMO_HEAD_BLOCK:
            raise NotInDemoFixturesError(f"Block {number} is outside the demo fixture range.")
        return BlockHeader(
            number=number,
            hash=_demo_block_hash(number),
            parent_hash=_demo_block_hash(number - 1) if number else "0x" + "00" * 32,
            timestamp=DEMO_GENESIS_TIMESTAMP + number * DEMO_BLOCK_TIME,
        )

    def _account(self, address: str) -> DemoAccount:
        account = _BY_ADDRESS.get(to_checksum_address(address))
        if account is None:
            raise NotInDemoFixturesError(
                "Demo mode only answers for fixture addresses (see /api/v1/demo/addresses). "
                "Configure an RPC endpoint and use real mode to inspect other addresses."
            )
        return account

    async def get_balance(self, address: str, block: BlockRef) -> int:
        return self._account(address).balance_wei

    async def get_code(self, address: str, block: BlockRef) -> bytes:
        return self._account(address).code

    async def call(self, to: str, data: bytes, block: BlockRef) -> bytes:
        """Answer the fixture token's ERC-20 view functions; every other call reverts."""
        self._account(to)
        if to_checksum_address(to) != DEMO_TOKEN:
            raise ContractCallFailedError("Fixture contract does not implement this call.")
        sel, args = data[:4], data[4:]
        words = [args[i : i + 32] for i in range(0, len(args), 32)]
        if sel == SEL_DECIMALS:
            return (18).to_bytes(32, "big")
        if sel == SEL_SYMBOL:
            text = b"DEMO"
            return (32).to_bytes(32, "big") + len(text).to_bytes(32, "big") + text.ljust(32, b"\0")
        if sel == SEL_BALANCE_OF and len(words) == 1:
            owner = decode_address_word(words[0])
            return DEMO_TOKEN_BALANCES.get(owner, 0).to_bytes(32, "big")
        if sel == SEL_ALLOWANCE and len(words) == 2:
            owner, spender = (decode_address_word(w) for w in words)
            current = 0
            for approval in DEMO_APPROVALS:  # last fixture for the pair wins
                if (approval.owner, approval.spender) == (owner, spender):
                    current = approval.current
            return current.to_bytes(32, "big")
        raise ContractCallFailedError("Fixture token does not implement this call.")

    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        """Only the fixture transfers' transactions exist, and only their signer is given."""
        signer = _DEMO_TX_SIGNERS.get(tx_hash.lower())
        return {"hash": tx_hash.lower(), "from": signer} if signer else None

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        raise RpcUnsupportedMethodError("Receipts are not part of the demo fixtures.")

    async def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        address: str | list[str] | None = None,
        topics: list[str | list[str] | None] | None = None,
    ) -> list[dict[str, Any]]:
        logs = [_demo_log(a) for a in DEMO_APPROVALS if from_block <= a.block_number <= to_block]
        logs += [
            _demo_transfer_log(t)
            for t in DEMO_TRANSFERS
            if from_block <= t.block_number <= to_block
        ]
        wanted = None
        if address is not None:
            wanted = {
                to_checksum_address(a) for a in ([address] if isinstance(address, str) else address)
            }
        return [
            log
            for log in logs
            if (wanted is None or log["address"] in wanted) and topics_match(log["topics"], topics)
        ]


def topics_match(log_topics: list[str], wanted: list[str | list[str] | None] | None) -> bool:
    """``eth_getLogs`` topic filter semantics: position-wise, None is a wildcard, lists are OR."""
    if not wanted:
        return True
    if len(wanted) > len(log_topics):
        return False
    for actual, expected in zip(log_topics, wanted, strict=False):
        if expected is None:
            continue
        options = expected if isinstance(expected, list) else [expected]
        if actual.lower() not in {o.lower() for o in options}:
            return False
    return True

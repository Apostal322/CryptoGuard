"""Demo mode: a provider backed by deterministic, clearly fictional fixtures.

Fixture addresses and block hashes are derived from keccak256 of descriptive labels, so they
look like real values but are not taken from Ethereum. Every inspection served from this
provider is marked ``data_source="demo_fixture"`` and ``simulated=true``. Addresses that are
not fixtures are rejected rather than answered with invented state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX
from cryptoguard.blockchain.provider import BlockHeader, BlockRef, DataSource
from cryptoguard.core.address import address_from_bytes, to_checksum_address
from cryptoguard.core.errors import NotInDemoFixturesError, RpcUnsupportedMethodError
from cryptoguard.core.hashing import keccak256

DEMO_HEAD_BLOCK = 1_000_000
DEMO_FINALIZED_BLOCK = DEMO_HEAD_BLOCK - 64
DEMO_GENESIS_TIMESTAMP = 1_767_225_600  # 2026-01-01T00:00:00Z, fictional chain timeline
DEMO_BLOCK_TIME = 12


def _demo_address(label: str) -> str:
    return address_from_bytes(keccak256(f"cryptoguard-demo-address:{label}".encode())[-20:])


def _demo_block_hash(number: int) -> str:
    return "0x" + keccak256(f"cryptoguard-demo-block:{number}".encode()).hex()


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
)

_BY_ADDRESS = {account.address: account for account in DEMO_ACCOUNTS}


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
        raise RpcUnsupportedMethodError("Contract calls are not part of the demo fixtures.")

    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        raise RpcUnsupportedMethodError("Transactions are not part of the demo fixtures.")

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        raise RpcUnsupportedMethodError("Receipts are not part of the demo fixtures.")

    async def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        address: str | None = None,
        topics: list[str | list[str] | None] | None = None,
    ) -> list[dict[str, Any]]:
        raise RpcUnsupportedMethodError("Event logs are not part of the demo fixtures.")

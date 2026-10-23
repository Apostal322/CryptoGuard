"""Provider abstraction over Ethereum state access.

``EthereumProvider`` is what services depend on. ``RpcEthereumProvider`` implements it over
standard JSON-RPC; the demo provider (``cryptoguard.services.demo``) implements it over
fictional fixtures. All RPC values are validated; invalid data raises instead of being guessed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import (
    BlockNotAvailableError,
    BlockRangeTooLargeError,
    ChainMismatchError,
    RpcInvalidResponseError,
)
from cryptoguard.core.hexutil import parse_data, parse_hash32, parse_quantity, to_quantity

DataSource = Literal["rpc", "demo_fixture"]
NamedBlockTag = Literal["latest", "safe", "finalized", "earliest"]
BlockRef = int | NamedBlockTag

_NAMED_TAGS: frozenset[str] = frozenset({"latest", "safe", "finalized", "earliest"})
_MAX_CODE_BYTES = 128 * 1024


@dataclass(frozen=True)
class BlockHeader:
    number: int
    hash: str
    parent_hash: str
    timestamp: int

    @property
    def timestamp_utc(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, UTC)


class EthereumProvider(Protocol):
    @property
    def source(self) -> DataSource: ...

    @property
    def endpoint_display(self) -> str: ...

    async def verify_chain(self) -> int: ...
    async def chain_id(self) -> int: ...
    async def block_number(self) -> int: ...
    async def get_block(self, block: BlockRef) -> BlockHeader: ...
    async def get_balance(self, address: str, block: BlockRef) -> int: ...
    async def get_code(self, address: str, block: BlockRef) -> bytes: ...
    async def call(self, to: str, data: bytes, block: BlockRef) -> bytes: ...
    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None: ...
    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None: ...
    async def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        address: str | list[str] | None = None,
        topics: list[str | list[str] | None] | None = None,
    ) -> list[dict[str, Any]]: ...
    async def aclose(self) -> None: ...


def _block_param(block: BlockRef) -> str:
    if isinstance(block, bool):
        raise ValueError("invalid block reference")
    if isinstance(block, int):
        return to_quantity(block)
    if block in _NAMED_TAGS:
        return block
    raise ValueError(f"invalid block tag: {block!r}")


def _expect[T](parser: Callable[[object], T], value: object, what: str) -> T:
    try:
        return parser(value)
    except ValueError:
        raise RpcInvalidResponseError(f"Provider returned an invalid {what}.") from None


def parse_block_header(raw: object) -> BlockHeader:
    if not isinstance(raw, dict):
        raise RpcInvalidResponseError("Provider returned an invalid block object.")
    return BlockHeader(
        number=_expect(parse_quantity, raw.get("number"), "block number"),
        hash=_expect(parse_hash32, raw.get("hash"), "block hash"),
        parent_hash=_expect(parse_hash32, raw.get("parentHash"), "parent hash"),
        timestamp=_expect(parse_quantity, raw.get("timestamp"), "block timestamp"),
    )


class RpcEthereumProvider:
    """Read-only provider over standard Ethereum JSON-RPC. It has no signing or send methods."""

    def __init__(
        self,
        client: JsonRpcClient,
        *,
        expected_chain_id: int,
        endpoint_display: str,
        max_log_block_range: int = 1000,
    ) -> None:
        self._client = client
        self._expected_chain_id = expected_chain_id
        self._endpoint_display = endpoint_display
        self._max_log_block_range = max_log_block_range
        self._chain_verified = False

    @property
    def source(self) -> DataSource:
        return "rpc"

    @property
    def endpoint_display(self) -> str:
        return self._endpoint_display

    @property
    def client(self) -> JsonRpcClient:
        return self._client

    async def aclose(self) -> None:
        await self._client.aclose()

    async def chain_id(self) -> int:
        return _expect(parse_quantity, await self._client.call("eth_chainId", []), "chain id")

    async def verify_chain(self) -> int:
        """Confirm the endpoint serves the configured chain. Cached after the first success."""
        if self._chain_verified:
            return self._expected_chain_id
        actual = await self.chain_id()
        if actual != self._expected_chain_id:
            raise ChainMismatchError(
                f"The RPC endpoint reports chain id {actual}, but CryptoGuard is configured for "
                f"chain id {self._expected_chain_id}. Refusing to read state from the wrong chain.",
                details={"expected": self._expected_chain_id, "actual": actual},
            )
        self._chain_verified = True
        return actual

    async def block_number(self) -> int:
        await self.verify_chain()
        raw = await self._client.call("eth_blockNumber", [])
        return _expect(parse_quantity, raw, "block number")

    async def get_block(self, block: BlockRef) -> BlockHeader:
        await self.verify_chain()
        raw = await self._client.call("eth_getBlockByNumber", [_block_param(block), False])
        if raw is None:
            raise BlockNotAvailableError(f"The RPC provider returned no block for {block!r}.")
        return parse_block_header(raw)

    async def get_balance(self, address: str, block: BlockRef) -> int:
        await self.verify_chain()
        raw = await self._client.call(
            "eth_getBalance", [to_checksum_address(address), _block_param(block)]
        )
        return _expect(parse_quantity, raw, "balance")

    async def get_code(self, address: str, block: BlockRef) -> bytes:
        await self.verify_chain()
        raw = await self._client.call(
            "eth_getCode", [to_checksum_address(address), _block_param(block)]
        )
        return _expect(lambda v: parse_data(v, max_bytes=_MAX_CODE_BYTES), raw, "account code")

    async def call(self, to: str, data: bytes, block: BlockRef) -> bytes:
        """``eth_call`` вЂ” a local, read-only execution. Nothing is signed or broadcast."""
        await self.verify_chain()
        tx = {"to": to_checksum_address(to), "data": "0x" + data.hex()}
        raw = await self._client.call("eth_call", [tx, _block_param(block)])
        return _expect(parse_data, raw, "call result")

    async def get_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        await self.verify_chain()
        raw = await self._client.call("eth_getTransactionByHash", [parse_hash32(tx_hash)])
        if raw is not None and not isinstance(raw, dict):
            raise RpcInvalidResponseError("Provider returned an invalid transaction object.")
        return raw

    async def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        await self.verify_chain()
        raw = await self._client.call("eth_getTransactionReceipt", [parse_hash32(tx_hash)])
        if raw is not None and not isinstance(raw, dict):
            raise RpcInvalidResponseError("Provider returned an invalid receipt object.")
        return raw

    async def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        address: str | list[str] | None = None,
        topics: list[str | list[str] | None] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch logs for an explicit, bounded block range (never open-ended)."""
        if from_block < 0 or to_block < from_block:
            raise BlockRangeTooLargeError("Invalid block range: from_block must be <= to_block.")
        span = to_block - from_block + 1
        if span > self._max_log_block_range:
            raise BlockRangeTooLargeError(
                f"Requested {span} blocks; the configured maximum per request is "
                f"{self._max_log_block_range}."
            )
        await self.verify_chain()
        query: dict[str, Any] = {
            "fromBlock": to_quantity(from_block),
            "toBlock": to_quantity(to_block),
        }
        if isinstance(address, list):
            query["address"] = [to_checksum_address(a) for a in address]
        elif address is not None:
            query["address"] = to_checksum_address(address)
        if topics is not None:
            query["topics"] = topics
        raw = await self._client.call("eth_getLogs", [query])
        if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
            raise RpcInvalidResponseError("Provider returned an invalid log list.")
        return raw


def build_rpc_provider(settings: Settings, **client_kwargs: Any) -> RpcEthereumProvider:
    assert settings.rpc_url is not None
    client = JsonRpcClient(
        settings.rpc_url.get_secret_value(),
        timeout=settings.rpc_timeout_seconds,
        retry=RetryPolicy(
            max_retries=settings.rpc_max_retries,
            base_delay=settings.rpc_backoff_base_seconds,
            max_delay=settings.rpc_backoff_max_seconds,
        ),
        max_concurrency=settings.rpc_max_concurrency,
        max_response_bytes=settings.rpc_max_response_bytes,
        **client_kwargs,
    )
    return RpcEthereumProvider(
        client,
        expected_chain_id=settings.chain_id,
        endpoint_display=settings.rpc_endpoint_display or "unknown",
        max_log_block_range=settings.max_log_block_range,
    )

"""Registry of supported chains and safe block-explorer link construction."""

from __future__ import annotations

from dataclasses import dataclass

from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import UnsupportedChainError
from cryptoguard.core.hexutil import parse_hash32


@dataclass(frozen=True)
class ChainInfo:
    chain_id: int
    name: str
    native_symbol: str
    native_decimals: int
    explorer_base_url: str


SUPPORTED_CHAINS: dict[int, ChainInfo] = {
    1: ChainInfo(1, "Ethereum Mainnet", "ETH", 18, "https://etherscan.io"),
    11155111: ChainInfo(11155111, "Sepolia", "ETH", 18, "https://sepolia.etherscan.io"),
}


def get_chain(chain_id: int) -> ChainInfo:
    try:
        return SUPPORTED_CHAINS[chain_id]
    except KeyError:
        supported = ", ".join(str(cid) for cid in SUPPORTED_CHAINS)
        raise UnsupportedChainError(
            f"Chain id {chain_id} is not supported. Supported chain ids: {supported}."
        ) from None


# Explorer links are only ever built from validated values, never from raw user/RPC strings.


def explorer_address_url(chain: ChainInfo, address: str) -> str:
    return f"{chain.explorer_base_url}/address/{to_checksum_address(address)}"


def explorer_block_url(chain: ChainInfo, block_number: int) -> str:
    if block_number < 0:
        raise ValueError("block numbers are non-negative")
    return f"{chain.explorer_base_url}/block/{block_number}"


def explorer_tx_url(chain: ChainInfo, tx_hash: str) -> str:
    return f"{chain.explorer_base_url}/tx/{parse_hash32(tx_hash)}"

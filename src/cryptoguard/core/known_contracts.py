"""Small curated registry of well-known contract addresses, used only as display labels.

A label identifies a contract; it is **not** a safety verdict. A well-known spender can still
be misused (for example through a malicious Permit2 signature), and an unlabelled spender is
not suspicious merely for being unknown.

Each entry cites where the address is published. Addresses are validated (EIP-55) at import.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptoguard.core.address import to_checksum_address


@dataclass(frozen=True)
class KnownContract:
    address: str
    label: str
    source: str


_UNISWAP_DOCS = "Uniswap deployment docs, https://docs.uniswap.org/contracts"

_MAINNET = [
    KnownContract("0x000000000022D473030F116dDEE9F6B43aC78BA3", "Uniswap Permit2", _UNISWAP_DOCS),
    KnownContract(
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Uniswap V2: Router 02", _UNISWAP_DOCS
    ),
    KnownContract(
        "0xE592427A0AEce92De3Edee1F18E0157C05861564", "Uniswap V3: SwapRouter", _UNISWAP_DOCS
    ),
    KnownContract(
        "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "Uniswap V3: SwapRouter02", _UNISWAP_DOCS
    ),
]

KNOWN_CONTRACTS: dict[int, dict[str, KnownContract]] = {
    1: {to_checksum_address(c.address): c for c in _MAINNET},
}


def lookup_known_contract(chain_id: int, address: str) -> KnownContract | None:
    return KNOWN_CONTRACTS.get(chain_id, {}).get(to_checksum_address(address))

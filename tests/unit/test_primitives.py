from __future__ import annotations

import pytest

from cryptoguard.core.address import address_from_bytes, to_checksum_address
from cryptoguard.core.chains import (
    explorer_address_url,
    explorer_tx_url,
    get_chain,
)
from cryptoguard.core.errors import InvalidAddressError, UnsupportedChainError
from cryptoguard.core.hashing import EMPTY_CODE_HASH, keccak256
from cryptoguard.core.hexutil import parse_data, parse_hash32, parse_quantity
from cryptoguard.core.units import format_units

# Test vectors from EIP-55.
EIP55_VECTORS = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


def test_keccak_is_not_sha3() -> None:
    # Known keccak256("") — differs from NIST SHA3-256("").
    assert EMPTY_CODE_HASH == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert (
        keccak256(b"").hex() != "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    )


@pytest.mark.parametrize("address", EIP55_VECTORS)
def test_checksum_vectors(address: str) -> None:
    assert to_checksum_address(address.lower()) == address
    assert to_checksum_address("0x" + address[2:].upper()) == address
    assert to_checksum_address(address) == address


def test_bad_checksum_rejected() -> None:
    good = EIP55_VECTORS[0]
    flipped = good[:3] + good[3].swapcase() + good[4:]  # 'a' -> 'A'
    assert flipped != good
    with pytest.raises(InvalidAddressError, match="checksum"):
        to_checksum_address(flipped)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0x",
        "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",  # 39 hex chars
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed00",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg",
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed\n",
        " 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "vitalik.eth",
        "<script>alert(1)</script>",
        None,
        123,
    ],
)
def test_invalid_addresses_rejected(value: object) -> None:
    with pytest.raises(InvalidAddressError):
        to_checksum_address(value)


def test_address_from_bytes_requires_20_bytes() -> None:
    assert address_from_bytes(bytes(20)) == "0x" + "0" * 40
    with pytest.raises(InvalidAddressError):
        address_from_bytes(bytes(19))


@pytest.mark.parametrize(
    ("value", "decimals", "expected"),
    [
        (0, 18, "0"),
        (1, 18, "0.000000000000000001"),
        (1_500_000_000_000_000_000, 18, "1.5"),
        (10**18, 18, "1"),
        (
            2**256 - 1,
            18,
            "115792089237316195423570985008687907853269984665640564039457.584007913129639935",
        ),
        (123, 0, "123"),
        (-5, 1, "-0.5"),
    ],
)
def test_format_units_is_exact(value: int, decimals: int, expected: str) -> None:
    assert format_units(value, decimals) == expected


def test_hex_parsing_is_strict() -> None:
    assert parse_quantity("0x0") == 0
    assert parse_quantity("0x1b4") == 436
    for bad in ["", "0x", "1b4", "0xzz", "0x" + "f" * 65, 12, None]:
        with pytest.raises(ValueError, match="hex quantity"):
            parse_quantity(bad)
    assert parse_data("0x") == b""
    assert parse_data("0xef01") == b"\xef\x01"
    for bad in ["0xabc", "ef01", "0xgg", None]:
        with pytest.raises(ValueError, match="hex data"):
            parse_data(bad)
    with pytest.raises(ValueError, match="size limit"):
        parse_data("0x" + "00" * 11, max_bytes=10)
    assert parse_hash32("0x" + "AB" * 32) == "0x" + "ab" * 32
    with pytest.raises(ValueError, match="32-byte"):
        parse_hash32("0x" + "ab" * 31)


def test_chain_registry_and_explorer_links() -> None:
    mainnet = get_chain(1)
    assert mainnet.name == "Ethereum Mainnet"
    with pytest.raises(UnsupportedChainError):
        get_chain(56)
    assert explorer_address_url(mainnet, EIP55_VECTORS[0].lower()) == (
        f"https://etherscan.io/address/{EIP55_VECTORS[0]}"
    )
    # Links are only built from validated values — injection attempts fail.
    with pytest.raises(InvalidAddressError):
        explorer_address_url(mainnet, "0x1234/../../evil")
    with pytest.raises(ValueError, match="32-byte"):
        explorer_tx_url(mainnet, "0xabc?x=<script>")

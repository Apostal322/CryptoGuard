"""Minimal, strict ABI encoding/decoding for the ERC-20 surface CryptoGuard reads.

Only what is needed is implemented, and every decoder rejects unexpected shapes instead of
guessing. Token metadata (``symbol``) is untrusted display text and is sanitized.
"""

from __future__ import annotations

from cryptoguard.core.address import address_from_bytes, to_checksum_address
from cryptoguard.core.hashing import keccak256

UINT256_MAX = 2**256 - 1
MAX_SYMBOL_LENGTH = 32


def selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


def event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()


# ERC-20 (https://eips.ethereum.org/EIPS/eip-20)
SEL_ALLOWANCE = selector("allowance(address,address)")
SEL_BALANCE_OF = selector("balanceOf(address)")
SEL_DECIMALS = selector("decimals()")
SEL_SYMBOL = selector("symbol()")

# ERC-20 and ERC-721 share this signature. ERC-20 indexes owner and spender (3 topics, 32-byte
# data); ERC-721 additionally indexes tokenId (4 topics, empty data).
APPROVAL_TOPIC = event_topic("Approval(address,address,uint256)")
# Same ambiguity: ERC-20 Transfer has 3 topics + 32 data bytes; ERC-721 indexes tokenId too.
TRANSFER_TOPIC = event_topic("Transfer(address,address,uint256)")


def encode_address_word(address: str) -> bytes:
    return bytes(12) + bytes.fromhex(to_checksum_address(address)[2:])


def address_topic(address: str) -> str:
    return "0x" + encode_address_word(address).hex()


def encode_call(sel: bytes, *addresses: str) -> bytes:
    return sel + b"".join(encode_address_word(a) for a in addresses)


def decode_address_word(word: bytes) -> str:
    """Decode a 32-byte word holding an address; the 12 high bytes must be zero."""
    if len(word) != 32 or any(word[:12]):
        raise ValueError("not an ABI-encoded address")
    return address_from_bytes(word[12:])


def decode_uint256(data: bytes) -> int:
    """Decode a single ``uint256`` return value (exactly 32 bytes)."""
    if len(data) != 32:
        raise ValueError(f"expected 32 bytes, got {len(data)}")
    return int.from_bytes(data, "big")


def decode_decimals(data: bytes) -> int:
    value = decode_uint256(data)
    if value > 77:  # uint8 by spec; beyond 10**77 no uint256 amount has a whole unit
        raise ValueError("implausible decimals value")
    return value


def _sanitize_symbol(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(ch for ch in text if ch.isprintable() and ch not in "<>&\"'`")
    return cleaned.strip()[:MAX_SYMBOL_LENGTH]


def decode_symbol(data: bytes) -> str:
    """Decode ``symbol()`` returned as ABI ``string`` or legacy ``bytes32`` (e.g. MKR)."""
    if len(data) == 32:
        return _sanitize_symbol(data.rstrip(b"\x00"))
    if len(data) < 64 or len(data) % 32:
        raise ValueError("unrecognized symbol encoding")
    offset = int.from_bytes(data[:32], "big")
    if offset + 32 > len(data):
        raise ValueError("symbol offset out of range")
    length = int.from_bytes(data[offset : offset + 32], "big")
    start = offset + 32
    if length > 256 or start + length > len(data):
        raise ValueError("symbol length out of range")
    return _sanitize_symbol(data[start : start + length])

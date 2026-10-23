"""Ethereum address validation and EIP-55 checksum normalization.

Addresses are always compared in full (all 20 bytes). Mixed-case input must carry a valid
EIP-55 checksum, because a wrong checksum usually means a typo or a tampered address.
"""

from __future__ import annotations

import re

from cryptoguard.core.errors import InvalidAddressError
from cryptoguard.core.hashing import keccak256

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def _apply_checksum(lower_hex: str) -> str:
    digest = keccak256(lower_hex.encode("ascii")).hex()
    return "0x" + "".join(
        char.upper() if int(digest[i], 16) >= 8 else char for i, char in enumerate(lower_hex)
    )


def to_checksum_address(address: object) -> str:
    """Validate ``address`` and return its EIP-55 checksummed form."""
    if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
        raise InvalidAddressError(
            "Expected a 0x-prefixed Ethereum address of exactly 40 hexadecimal characters."
        )
    body = address[2:]
    checksummed = _apply_checksum(body.lower())
    is_single_case = body in (body.lower(), body.upper())
    if not is_single_case and body != checksummed[2:]:
        raise InvalidAddressError("Address has an invalid EIP-55 checksum; it may contain a typo.")
    return checksummed


def address_from_bytes(raw: bytes) -> str:
    if len(raw) != 20:
        raise InvalidAddressError("An address must be exactly 20 bytes.")
    return _apply_checksum(raw.hex())

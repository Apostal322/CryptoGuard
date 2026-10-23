"""Strict parsing of JSON-RPC hex encodings.

RPC responses are untrusted input: every value is validated for shape and size before use.
These helpers raise ``ValueError``; callers translate that into a domain error.
"""

from __future__ import annotations

import re

_QUANTITY_RE = re.compile(r"0x[0-9a-fA-F]{1,64}")
_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_HASH32_RE = re.compile(r"0x[0-9a-fA-F]{64}")

DEFAULT_MAX_DATA_BYTES = 1024 * 1024


def parse_quantity(value: object) -> int:
    """Parse a QUANTITY (unsigned, at most 256 bits)."""
    if not isinstance(value, str) or not _QUANTITY_RE.fullmatch(value):
        raise ValueError("expected a hex quantity")
    return int(value, 16)


def to_quantity(value: int) -> str:
    if value < 0:
        raise ValueError("quantities are unsigned")
    return hex(value)


def parse_data(value: object, *, max_bytes: int = DEFAULT_MAX_DATA_BYTES) -> bytes:
    """Parse unformatted DATA (even-length hex)."""
    if not isinstance(value, str) or len(value) > 2 + 2 * max_bytes:
        raise ValueError("expected hex data within the size limit")
    if not _DATA_RE.fullmatch(value):
        raise ValueError("expected even-length hex data")
    return bytes.fromhex(value[2:])


def parse_hash32(value: object) -> str:
    """Parse a 32-byte hash, returned lower-case."""
    if not isinstance(value, str) or not _HASH32_RE.fullmatch(value):
        raise ValueError("expected a 32-byte hex hash")
    return value.lower()

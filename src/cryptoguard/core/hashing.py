"""Keccak-256 (Ethereum's hash, which is *not* NIST SHA3-256)."""

from __future__ import annotations

from Crypto.Hash import keccak


def keccak256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    result: bytes = digest.digest()
    return result


EMPTY_CODE_HASH = "0x" + keccak256(b"").hex()

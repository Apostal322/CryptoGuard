from __future__ import annotations

import pytest

from cryptoguard.blockchain.eip7702 import (
    DELEGATION_INDICATOR_LENGTH,
    DELEGATION_PREFIX,
    CodeKind,
    classify_code,
    parse_delegation_indicator,
)
from cryptoguard.core.hashing import EMPTY_CODE_HASH, keccak256

TARGET = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
TARGET_BYTES = bytes.fromhex(TARGET[2:])


def test_indicator_constants_match_spec() -> None:
    assert DELEGATION_PREFIX == b"\xef\x01\x00"
    assert DELEGATION_INDICATOR_LENGTH == 23


def test_valid_indicator_is_parsed_with_checksum() -> None:
    code = DELEGATION_PREFIX + TARGET_BYTES
    assert parse_delegation_indicator(code) == TARGET
    result = classify_code(code)
    assert result.kind is CodeKind.EIP7702_DELEGATION
    assert result.delegation_target == TARGET
    assert result.code_size == 23
    assert result.code_hash == "0x" + keccak256(code).hex()


def test_empty_code() -> None:
    result = classify_code(b"")
    assert result.kind is CodeKind.NO_CODE
    assert result.code_hash == EMPTY_CODE_HASH
    assert result.delegation_target is None


@pytest.mark.parametrize(
    "code",
    [
        DELEGATION_PREFIX + TARGET_BYTES[:-1],  # 22 bytes
        DELEGATION_PREFIX + TARGET_BYTES + b"\x00",  # 24 bytes
        DELEGATION_PREFIX,  # prefix only
    ],
)
def test_wrong_length_with_prefix_is_malformed_not_delegation(code: bytes) -> None:
    assert parse_delegation_indicator(code) is None
    assert classify_code(code).kind is CodeKind.MALFORMED_DELEGATION_PREFIX


@pytest.mark.parametrize(
    "code",
    [
        b"\xef\x01\x01" + TARGET_BYTES,  # wrong version byte
        b"\xef\x00\x00" + TARGET_BYTES,
        b"\x60\x80\x60\x40\x52" + TARGET_BYTES,  # ordinary bytecode, 25 bytes
        bytes(23),  # 23 zero bytes
        TARGET_BYTES + DELEGATION_PREFIX,  # prefix in the wrong place
    ],
)
def test_other_bytecode_is_never_a_delegation(code: bytes) -> None:
    assert parse_delegation_indicator(code) is None
    assert classify_code(code).kind is CodeKind.CONTRACT

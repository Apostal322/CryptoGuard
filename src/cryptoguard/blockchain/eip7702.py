"""EIP-7702 delegation-indicator recognition (https://eips.ethereum.org/EIPS/eip-7702).

Per the specification, a delegated EOA's code is exactly ``0xef0100 || address`` (23 bytes).
Only that exact shape is classified as a delegation. Code that starts with ``0xef0100`` but has
any other length is reported as malformed, never as a delegation: under EIP-3541 no contract
can deploy code beginning with ``0xEF``, so such code is anomalous.

Notes from the spec that shape how results are explained:
- Delegating to the zero address clears the code; no indicator is written.
- Indicators are not rolled back if the set-code transaction's execution reverts.
- Clients do not follow delegation chains: if the target is itself delegated, only the first
  hop applies.
- Current code shows the *current* delegation only; it reveals nothing about past ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cryptoguard.core.address import address_from_bytes
from cryptoguard.core.hashing import EMPTY_CODE_HASH, keccak256

DELEGATION_PREFIX = bytes.fromhex("ef0100")
DELEGATION_INDICATOR_LENGTH = len(DELEGATION_PREFIX) + 20
SET_CODE_TX_TYPE = 0x04


class CodeKind(StrEnum):
    NO_CODE = "no_code"
    EIP7702_DELEGATION = "eip7702_delegation"
    CONTRACT = "contract"
    MALFORMED_DELEGATION_PREFIX = "malformed_delegation_prefix"


@dataclass(frozen=True)
class CodeClassification:
    kind: CodeKind
    code_size: int
    code_hash: str
    delegation_target: str | None = None


def parse_delegation_indicator(code: bytes) -> str | None:
    """Return the checksummed delegate address if ``code`` is exactly a delegation indicator."""
    if len(code) != DELEGATION_INDICATOR_LENGTH or not code.startswith(DELEGATION_PREFIX):
        return None
    return address_from_bytes(code[len(DELEGATION_PREFIX) :])


def classify_code(code: bytes) -> CodeClassification:
    code_hash = EMPTY_CODE_HASH if not code else "0x" + keccak256(code).hex()
    if not code:
        return CodeClassification(CodeKind.NO_CODE, 0, code_hash)
    target = parse_delegation_indicator(code)
    if target is not None:
        return CodeClassification(CodeKind.EIP7702_DELEGATION, len(code), code_hash, target)
    if code.startswith(DELEGATION_PREFIX):
        return CodeClassification(CodeKind.MALFORMED_DELEGATION_PREFIX, len(code), code_hash)
    return CodeClassification(CodeKind.CONTRACT, len(code), code_hash)

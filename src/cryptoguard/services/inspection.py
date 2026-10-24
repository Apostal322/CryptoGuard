"""Point-in-time address inspection: chain, block context, native balance, account code.

All reads are pinned to one block number. After reading, the block hash at that height is
fetched again; if it changed, a reorg happened mid-inspection and the reads are retried, so a
result never mixes state from two forks.

Everything returned here is an *observed fact* from the provider at a specific block. No risk
judgement is made in this module.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from cryptoguard.blockchain.eip7702 import CodeKind, classify_code
from cryptoguard.blockchain.provider import BlockHeader, DataSource, EthereumProvider
from cryptoguard.core.address import ZERO_ADDRESS, to_checksum_address
from cryptoguard.core.chains import ChainInfo, explorer_address_url, explorer_block_url
from cryptoguard.core.errors import (
    BlockNotAvailableError,
    ReorgDetectedError,
    RpcInvalidResponseError,
    RpcRequestRejectedError,
    RpcUnsupportedMethodError,
)
from cryptoguard.core.units import format_units

INSPECTION_SCHEMA_VERSION = "address-inspection/1"
OBSERVATION_TYPE = "address_inspection"
_MAX_REORG_RETRIES = 2

Finality = Literal["finalized", "not_finalized", "unknown"]


class BlockContext(BaseModel):
    number: int
    hash: str
    timestamp: datetime = Field(description="Block timestamp (UTC).")
    finality: Finality
    finalized_block_number: int | None
    head_block_number: int


class NativeBalance(BaseModel):
    wei: str = Field(description="Exact integer amount, as a string to avoid float precision loss.")
    formatted: str
    symbol: str


class DelegationObservation(BaseModel):
    target: str
    target_code_kind: CodeKind
    target_code_size: int
    target_code_hash: str
    notes: list[str]


class AccountCodeObservation(BaseModel):
    kind: CodeKind
    code_size: int
    code_hash: str
    delegation: DelegationObservation | None
    explanation: str


class ExplorerLinks(BaseModel):
    address: str
    block: str


class AddressInspection(BaseModel):
    schema_version: str = INSPECTION_SCHEMA_VERSION
    evidence_class: Literal["observed_fact"] = "observed_fact"
    data_source: DataSource
    simulated: bool
    provider: str
    address: str
    chain_id: int
    chain_name: str
    chain_verified: bool
    block: BlockContext
    native_balance: NativeBalance
    account_code: AccountCodeObservation
    observed_at: datetime = Field(description="When CryptoGuard made the observation (UTC).")
    coverage: str
    limitations: list[str]
    explorer: ExplorerLinks | None


_CODE_EXPLANATIONS: dict[CodeKind, str] = {
    CodeKind.NO_CODE: (
        "No code at this block. This matches an externally owned account without an EIP-7702 "
        "delegation, but also an address where no contract has been deployed yet."
    ),
    CodeKind.EIP7702_DELEGATION: (
        "The account's code is an EIP-7702 delegation indicator (0xef0100 || target). Calls to "
        "this account execute the target contract's code in the account's context, so the "
        "target's logic governs what can happen to the account's assets. A delegation is not "
        "malicious by itself; verify that the target is a contract you intended to authorize."
    ),
    CodeKind.CONTRACT: (
        "The address holds smart-contract bytecode. Contract analysis is outside this milestone."
    ),
    CodeKind.MALFORMED_DELEGATION_PREFIX: (
        "The code starts with the EIP-7702 prefix 0xef0100 but is not exactly 23 bytes, so it is "
        "not a valid delegation indicator. EIP-3541 forbids deploying code that starts with 0xEF, "
        "so this state is unexpected and the provider response deserves scrutiny."
    ),
}


def _delegation_notes(target: str, target_kind: CodeKind) -> list[str]:
    notes = [
        "The delegation's history (when it was set, by which transaction) is not shown "
        "by current account code and was not scanned."
    ]
    if target == ZERO_ADDRESS:
        notes.append(
            "The target is the zero address. EIP-7702 clears code instead of writing "
            "such an indicator, so this state is unexpected."
        )
    if target_kind is CodeKind.NO_CODE:
        notes.append(
            "The delegation target has no code at this block, so calls to the account "
            "currently execute no code."
        )
    elif target_kind is CodeKind.EIP7702_DELEGATION:
        notes.append(
            "The target is itself a delegated account. EIP-7702 does not follow "
            "delegation chains; only the first hop's code (an indicator) is loaded."
        )
    return notes


async def _read_finality(
    provider: EthereumProvider, block_number: int
) -> tuple[Finality, int | None]:
    try:
        finalized = await provider.get_block("finalized")
    except (
        BlockNotAvailableError,
        RpcUnsupportedMethodError,
        RpcRequestRejectedError,
        RpcInvalidResponseError,
    ):
        return "unknown", None
    return ("finalized" if block_number <= finalized.number else "not_finalized"), finalized.number


async def inspect_address(
    provider: EthereumProvider,
    address: str,
    *,
    chain: ChainInfo,
    at: BlockHeader | None = None,
) -> AddressInspection:
    """Inspect ``address`` at the head block, or at ``at`` when the caller pins the block.

    With ``at``, a reorg is not retried here: the caller pinned the block and must decide.
    """
    checksummed = to_checksum_address(address)
    await provider.verify_chain()

    attempts = 1 if at is not None else _MAX_REORG_RETRIES + 1
    for attempt in range(attempts):
        head = await provider.block_number()
        header: BlockHeader = at if at is not None else await provider.get_block(head)
        balance, code = await asyncio.gather(
            provider.get_balance(checksummed, header.number),
            provider.get_code(checksummed, header.number),
        )
        classification = classify_code(code)
        delegation: DelegationObservation | None = None
        if classification.delegation_target is not None:
            target_code = classify_code(
                await provider.get_code(classification.delegation_target, header.number)
            )
            delegation = DelegationObservation(
                target=classification.delegation_target,
                target_code_kind=target_code.kind,
                target_code_size=target_code.code_size,
                target_code_hash=target_code.code_hash,
                notes=_delegation_notes(classification.delegation_target, target_code.kind),
            )
        recheck = await provider.get_block(header.number)
        if recheck.hash == header.hash:
            break
        if attempt == attempts - 1:
            raise ReorgDetectedError(
                "The chain reorganized repeatedly during inspection; try again shortly."
            )

    finality, finalized_number = await _read_finality(provider, header.number)
    simulated = provider.source == "demo_fixture"
    limitations = [
        f"Point-in-time state at block {header.number} only. No transaction history, token "
        "approvals or past delegation changes were scanned.",
        "Native balance only; token balances are not included in this milestone.",
    ]
    if finality != "finalized":
        limitations.append(
            "The observed block is not known to be finalized and could still be reorganized."
        )
    if simulated:
        limitations.insert(0, "SIMULATED DATA: fictional demo fixture, not Ethereum state.")

    return AddressInspection(
        data_source=provider.source,
        simulated=simulated,
        provider=provider.endpoint_display,
        address=checksummed,
        chain_id=chain.chain_id,
        chain_name=chain.name,
        # Only an RPC provider verifies the chain (eth_chainId); demo fixtures cannot.
        chain_verified=provider.source == "rpc",
        block=BlockContext(
            number=header.number,
            hash=header.hash,
            timestamp=header.timestamp_utc,
            finality=finality,
            finalized_block_number=finalized_number,
            head_block_number=head,
        ),
        native_balance=NativeBalance(
            wei=str(balance),
            formatted=format_units(balance, chain.native_decimals),
            symbol=chain.native_symbol,
        ),
        account_code=AccountCodeObservation(
            kind=classification.kind,
            code_size=classification.code_size,
            code_hash=classification.code_hash,
            delegation=delegation,
            explanation=_CODE_EXPLANATIONS[classification.kind],
        ),
        observed_at=datetime.now(UTC),
        coverage=f"Single snapshot at block {header.number}.",
        limitations=limitations,
        # Fictional fixtures get no explorer links: they would point at unrelated real pages.
        explorer=None
        if simulated
        else ExplorerLinks(
            address=explorer_address_url(chain, checksummed),
            block=explorer_block_url(chain, header.number),
        ),
    )

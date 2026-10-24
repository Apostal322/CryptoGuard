"""Canonical, hashable wallet security state at one block.

The state holds only what the delta and rules need: verified approvals and the account-code /
delegation observation. It is serialized canonically (sorted keys, no whitespace), so identical
observations always produce the same ``state_hash``.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.erc20 import ApprovalEvent
from cryptoguard.core.hashing import keccak256
from cryptoguard.services.approvals import AllowanceLevel, ApprovalEntry
from cryptoguard.services.inspection import AddressInspection

SNAPSHOT_SCHEMA_VERSION = "wallet-snapshot/2"  # /2 adds the wallet nonce


class EventRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int


class ApprovalState(BaseModel):
    model_config = ConfigDict(frozen=True)

    token: str
    spender: str
    token_symbol: str | None
    token_decimals: int | None
    allowance: str | None
    allowance_status: Literal["known", "unknown"]
    unknown_reason: str | None
    level: AllowanceLevel
    balance: str | None
    exposure: str | None
    spender_code_kind: CodeKind
    spender_label: str | None
    latest_event: EventRef
    verified_at_block: int

    @property
    def key(self) -> str:
        return pair_key(self.token, self.spender)

    @property
    def active(self) -> bool | None:
        """True if a nonzero allowance is known, False if zero, None if unknown."""
        return None if self.allowance is None else int(self.allowance) > 0

    def to_event(self, owner: str) -> ApprovalEvent:
        e = self.latest_event
        return ApprovalEvent(
            token=self.token,
            owner=owner,
            spender=self.spender,
            value=int(e.value),
            block_number=e.block_number,
            block_hash=e.block_hash,
            transaction_hash=e.transaction_hash,
            transaction_index=e.transaction_index,
            log_index=e.log_index,
        )


class DelegationState(BaseModel):
    model_config = ConfigDict(frozen=True)

    code_kind: CodeKind
    code_hash: str
    target: str | None
    target_code_kind: CodeKind | None


class WalletState(BaseModel):
    approvals: dict[str, ApprovalState]
    account: DelegationState
    native_balance_wei: str
    # Transactions signed by the wallet so far (its nonce) at the snapshot block. The next
    # snapshot locates the wallet's new transactions from here without old-state reads.
    nonce: int | None = None


def pair_key(token: str, spender: str) -> str:
    return f"{token}:{spender}"


def approval_state(entry: ApprovalEntry, event: ApprovalEvent, block: int) -> ApprovalState:
    return ApprovalState(
        token=entry.token.address,
        spender=entry.spender.address,
        token_symbol=entry.token.symbol,
        token_decimals=entry.token.decimals,
        allowance=entry.current_allowance.raw,
        allowance_status=entry.current_allowance.status,
        unknown_reason=entry.current_allowance.unknown_reason,
        level=entry.allowance_level,
        balance=entry.owner_balance.raw,
        exposure=entry.exposure_upper_bound.raw,
        spender_code_kind=entry.spender.code_kind,
        spender_label=entry.spender.label,
        latest_event=EventRef(
            value=str(event.value),
            block_number=event.block_number,
            block_hash=event.block_hash,
            transaction_hash=event.transaction_hash,
            transaction_index=event.transaction_index,
            log_index=event.log_index,
        ),
        verified_at_block=block,
    )


def account_state(inspection: AddressInspection) -> DelegationState:
    code = inspection.account_code
    return DelegationState(
        code_kind=code.kind,
        code_hash=code.code_hash,
        target=code.delegation.target if code.delegation else None,
        target_code_kind=code.delegation.target_code_kind if code.delegation else None,
    )


def canonical_json(state: WalletState) -> str:
    return json.dumps(state.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def state_hash(state: WalletState) -> str:
    return "0x" + keccak256(canonical_json(state).encode()).hex()

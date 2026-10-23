"""Deterministic comparison ``previous_state -> current_state -> security_delta``.

A change is located in the interval ``(from_block, to_block]`` between two snapshots. It gets a
transaction-level cause only when an observed Approval event in that interval explains the new
value exactly; otherwise the cause is "state comparison" and no transaction hash is invented.
Output order is fixed (sorted by subject, then kind), so identical inputs give identical deltas.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.core.chains import ChainInfo, explorer_tx_url
from cryptoguard.history.state import ApprovalState, DelegationState, WalletState


class ChangeKind(StrEnum):
    ALLOWANCE_GRANTED = "allowance_granted"
    ALLOWANCE_DISCOVERED_UNVERIFIED = "allowance_discovered_unverified"
    ALLOWANCE_INCREASED = "allowance_increased"
    ALLOWANCE_REDUCED = "allowance_reduced"
    ALLOWANCE_REVOKED = "allowance_revoked"
    ALLOWANCE_BECAME_UNKNOWN = "allowance_became_unknown"
    ALLOWANCE_BECAME_KNOWN = "allowance_became_known"
    DELEGATION_SET = "delegation_set"
    DELEGATION_CHANGED = "delegation_changed"
    DELEGATION_CLEARED = "delegation_cleared"
    ACCOUNT_CODE_CHANGED = "account_code_changed"


class Cause(BaseModel):
    kind: Literal["approval_event", "state_comparison"]
    transaction_hash: str | None = None
    block_number: int | None = None
    log_index: int | None = None
    explorer_url: str | None = None
    note: str


class Change(BaseModel):
    kind: ChangeKind
    subject: str
    token: str | None = None
    spender: str | None = None
    before: str | None
    after: str | None
    from_block_exclusive: int
    to_block: int
    cause: Cause
    explanation: str
    why_it_matters: str


_WHY = {
    ChangeKind.ALLOWANCE_GRANTED: "A new spender can now move this token from the wallet.",
    ChangeKind.ALLOWANCE_DISCOVERED_UNVERIFIED: "An approval was observed but the current "
    "allowance could not be read, so the permission's size is unknown.",
    ChangeKind.ALLOWANCE_INCREASED: "The spender may now move more of this token than before.",
    ChangeKind.ALLOWANCE_REDUCED: "The spender's permission shrank; if no Approval event "
    "explains it, the spender probably used part of it via transferFrom.",
    ChangeKind.ALLOWANCE_REVOKED: "The spender can no longer move this token.",
    ChangeKind.ALLOWANCE_BECAME_UNKNOWN: "The permission can no longer be verified, so a "
    "change may be hidden.",
    ChangeKind.ALLOWANCE_BECAME_KNOWN: "A previously unverifiable permission was verified.",
    ChangeKind.DELEGATION_SET: "The account now executes a delegate contract's code; that code "
    "governs what can happen to the account's assets.",
    ChangeKind.DELEGATION_CHANGED: "A different contract now governs the account's behaviour.",
    ChangeKind.DELEGATION_CLEARED: "The account no longer delegates its execution.",
    ChangeKind.ACCOUNT_CODE_CHANGED: "The account's code changed in a way that is not a plain "
    "EIP-7702 delegation transition.",
}

_DELEGATION_CAUSE = (
    "Observed by comparing account code at the two blocks. The set-code (type 0x04) transaction "
    "was not identified: transaction-level indexing is not implemented."
)


def _allowance_cause(
    current: ApprovalState, from_block: int, to_block: int, chain: ChainInfo, simulated: bool
) -> Cause:
    event = current.latest_event
    in_interval = from_block < event.block_number <= to_block
    if in_interval and current.allowance == event.value:
        return Cause(
            kind="approval_event",
            transaction_hash=event.transaction_hash,
            block_number=event.block_number,
            log_index=event.log_index,
            explorer_url=None if simulated else explorer_tx_url(chain, event.transaction_hash),
            note="The latest Approval event in the interval sets exactly the observed allowance.",
        )
    note = (
        "No Approval event in the interval explains the new value; it was observed by comparing "
        "allowance() at the two blocks (e.g. transferFrom spending, which often emits no event)."
    )
    if in_interval:
        note = (
            f"An Approval event at block {event.block_number} set {event.value}, but the allowance "
            "at the snapshot block differs, so the event alone does not explain the final value."
        )
    return Cause(kind="state_comparison", note=note)


def _approval_change(
    before: ApprovalState | None,
    after: ApprovalState,
    from_block: int,
    to_block: int,
    chain: ChainInfo,
    simulated: bool,
) -> Change | None:
    kind: ChangeKind | None = None
    if before is None:
        if after.active is True:
            kind = ChangeKind.ALLOWANCE_GRANTED
        elif after.active is None:
            kind = ChangeKind.ALLOWANCE_DISCOVERED_UNVERIFIED
    elif before.allowance is not None and after.allowance is None:
        kind = ChangeKind.ALLOWANCE_BECAME_UNKNOWN
    elif before.allowance is None and after.allowance is not None:
        kind = ChangeKind.ALLOWANCE_BECAME_KNOWN
    elif before.allowance is not None and after.allowance is not None:
        old, new = int(before.allowance), int(after.allowance)
        if new > old:
            kind = ChangeKind.ALLOWANCE_GRANTED if old == 0 else ChangeKind.ALLOWANCE_INCREASED
        elif new < old:
            kind = ChangeKind.ALLOWANCE_REVOKED if new == 0 else ChangeKind.ALLOWANCE_REDUCED
    if kind is None:
        return None
    label = f" ({after.spender_label})" if after.spender_label else ""
    symbol = after.token_symbol or "token"
    return Change(
        kind=kind,
        subject=after.key,
        token=after.token,
        spender=after.spender,
        before=before.allowance if before else None,
        after=after.allowance,
        from_block_exclusive=from_block,
        to_block=to_block,
        cause=_allowance_cause(after, from_block, to_block, chain, simulated),
        explanation=(
            f"{kind.value.replace('_', ' ').capitalize()}: {symbol} {after.token} allowance for "
            f"spender {after.spender}{label} went from {before.allowance if before else 'none'} "
            f"to {after.allowance if after.allowance is not None else 'unknown'} (base units, "
            f"level {after.level.value}) between blocks {from_block} and {to_block}."
        ),
        why_it_matters=_WHY[kind],
    )


def _account_change(
    before: DelegationState, after: DelegationState, from_block: int, to_block: int
) -> Change | None:
    if before.code_hash == after.code_hash:
        return None
    delegated = CodeKind.EIP7702_DELEGATION
    if before.code_kind is not delegated and after.code_kind is delegated:
        kind = ChangeKind.DELEGATION_SET
    elif before.code_kind is delegated and after.code_kind is delegated:
        kind = ChangeKind.DELEGATION_CHANGED
    elif before.code_kind is delegated and after.code_kind is CodeKind.NO_CODE:
        kind = ChangeKind.DELEGATION_CLEARED
    else:
        kind = ChangeKind.ACCOUNT_CODE_CHANGED
    before_text = before.target or before.code_kind.value
    after_text = after.target or after.code_kind.value
    return Change(
        kind=kind,
        subject="account",
        before=before_text,
        after=after_text,
        from_block_exclusive=from_block,
        to_block=to_block,
        cause=Cause(kind="state_comparison", note=_DELEGATION_CAUSE),
        explanation=(
            f"{kind.value.replace('_', ' ').capitalize()}: account code went from {before_text} "
            f"to {after_text} between blocks {from_block} and {to_block}."
        ),
        why_it_matters=_WHY[kind],
    )


def compute_delta(
    previous: WalletState,
    current: WalletState,
    *,
    from_block: int,
    to_block: int,
    chain: ChainInfo,
    simulated: bool,
) -> list[Change]:
    changes: list[Change] = []
    account = _account_change(previous.account, current.account, from_block, to_block)
    if account is not None:
        changes.append(account)
    for key in sorted(current.approvals):
        after = current.approvals[key]
        if after.verified_at_block != to_block:
            continue  # carried forward unverified; no claim about a change
        change = _approval_change(
            previous.approvals.get(key), after, from_block, to_block, chain, simulated
        )
        if change is not None:
            changes.append(change)
    return sorted(changes, key=lambda c: (c.subject, c.kind.value))

"""ERC-20 approval discovery and current-state verification.

1. **Discover** (owner, token, spender) relationships from ``Approval`` logs in an explicit,
   bounded block window, scanning newest-first in chunks. If the provider refuses a chunk as too
   large, the chunk is split; if the request budget runs out, coverage is reported as partial.
2. **Verify** current state at one pinned block: ``allowance(owner, spender)``,
   ``balanceOf(owner)``, ``decimals()``, ``symbol()``, and the spender's account code.
   Events show that an approval *happened*; only the ``allowance`` call shows what is active.
3. **Bound** exposure conservatively as ``min(balance, allowance)`` when both are known.

Values that cannot be read are reported as unknown with a reason; nothing is guessed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    SEL_BALANCE_OF,
    SEL_DECIMALS,
    SEL_SYMBOL,
    UINT256_MAX,
    address_topic,
    decode_decimals,
    decode_symbol,
    decode_uint256,
    encode_call,
)
from cryptoguard.blockchain.eip7702 import CodeKind, classify_code
from cryptoguard.blockchain.erc20 import ApprovalEvent, ApprovalLogShape, classify_approval_log
from cryptoguard.blockchain.provider import BlockHeader, DataSource, EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import ChainInfo, explorer_tx_url
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import (
    BlockRangeTooLargeError,
    InvalidScanRequestError,
    LogFilterRestrictedError,
    LogQueryTooLargeError,
    ReorgDetectedError,
    RpcError,
    ScanBudgetExceededError,
)
from cryptoguard.core.known_contracts import lookup_known_contract
from cryptoguard.core.units import format_units

APPROVAL_SCAN_SCHEMA_VERSION = "approval-scan/1"
APPROVAL_SCAN_OBSERVATION_TYPE = "approval_scan"
# No real token supply approaches 2**128 base units; allowances at or above it are set as
# "infinite" by the approving dapp, even when not exactly 2**256 - 1.
EFFECTIVELY_UNLIMITED_THRESHOLD = 2**128
MAX_SCOPED_TOKENS = 25


@dataclass(frozen=True)
class ScanLimits:
    lookback_blocks: int
    max_scan_blocks: int
    chunk_blocks: int
    max_log_requests: int
    max_pairs: int

    @classmethod
    def from_settings(cls, settings: Settings) -> ScanLimits:
        return cls(
            lookback_blocks=settings.approval_default_lookback_blocks,
            max_scan_blocks=settings.approval_max_scan_blocks,
            chunk_blocks=settings.max_log_block_range,
            max_log_requests=settings.approval_max_log_requests,
            max_pairs=settings.approval_max_pairs,
        )


class AllowanceLevel(StrEnum):
    NONE = "none"
    LIMITED = "limited"
    EFFECTIVELY_UNLIMITED = "effectively_unlimited"
    UNLIMITED = "unlimited"
    UNKNOWN = "unknown"


class Reading(BaseModel):
    """An on-chain integer that is either known exactly or explicitly unknown."""

    status: Literal["known", "unknown"]
    raw: str | None = Field(default=None, description="Exact integer in base units, as a string.")
    formatted: str | None = None
    unknown_reason: str | None = None


class TokenView(BaseModel):
    address: str
    symbol: str | None = Field(description="Untrusted, sanitized contract-supplied text.")
    decimals: int | None
    code_kind: CodeKind


class SpenderView(BaseModel):
    address: str
    code_kind: CodeKind
    label: str | None = Field(description="Identification only; not a safety verdict.")
    label_source: str | None


class EventView(BaseModel):
    value: str
    value_formatted: str | None
    block_number: int
    block_hash: str
    transaction_hash: str
    log_index: int
    explorer_url: str | None


class Signal(BaseModel):
    code: str
    evidence_class: Literal["observed_fact", "heuristic_signal"]
    explanation: str


class ApprovalEntry(BaseModel):
    token: TokenView
    spender: SpenderView
    latest_event: EventView
    events_in_range: int
    current_allowance: Reading
    allowance_level: AllowanceLevel
    active: bool | None = Field(description="Allowance > 0 now; null when unknown.")
    owner_balance: Reading
    exposure_upper_bound: Reading = Field(
        description="min(balance, allowance): visible upper bound, not a loss prediction."
    )
    signals: list[Signal]


class ScanCoverage(BaseModel):
    requested_from_block: int
    requested_to_block: int
    scanned_from_block: int
    scanned_to_block: int
    complete_for_requested_range: bool
    log_requests: int
    log_query_splits: int
    description: str


class LogCounts(BaseModel):
    erc20_approvals: int
    erc721_shaped_approvals: int
    removed: int
    malformed: int


class ApprovalScanReport(BaseModel):
    schema_version: str = APPROVAL_SCAN_SCHEMA_VERSION
    data_source: DataSource
    simulated: bool
    provider: str
    owner: str
    chain_id: int
    chain_name: str
    block_number: int = Field(description="Block at which current state was read.")
    block_hash: str
    block_timestamp: datetime
    observed_at: datetime
    coverage: ScanCoverage
    token_scope: list[str] | None = Field(
        description="Token contracts the scan was limited to; null means all tokens."
    )
    log_counts: LogCounts
    pairs_discovered: int
    pairs_truncated: int
    approvals: list[ApprovalEntry]
    exposure_model: str
    limitations: list[str]


@dataclass(frozen=True)
class ApprovalScan:
    report: ApprovalScanReport
    events: list[ApprovalEvent]


@dataclass
class _TokenState:
    code_kind: CodeKind
    balance: Reading
    decimals: int | None
    symbol: str | None


async def _scan_logs(
    provider: EthereumProvider,
    owner: str,
    from_block: int,
    to_block: int,
    limits: ScanLimits,
    tokens: list[str] | None,
) -> tuple[list[dict[str, object]], ScanCoverage]:
    owner_topic = address_topic(owner)
    pending: list[tuple[int, int]] = []
    next_high = to_block
    lowest_scanned = to_block + 1
    requests = splits = 0
    logs: list[dict[str, object]] = []
    exhausted = False

    while True:
        if not pending:
            if next_high < from_block:
                break
            low = max(from_block, next_high - limits.chunk_blocks + 1)
            pending.append((low, next_high))
            next_high = low - 1
        if requests >= limits.max_log_requests:
            exhausted = True
            break
        low, high = pending.pop()
        requests += 1
        try:
            batch = await provider.get_logs(
                from_block=low,
                to_block=high,
                address=tokens,
                topics=[APPROVAL_TOPIC, owner_topic],
            )
        except (LogQueryTooLargeError, BlockRangeTooLargeError):
            if low == high:
                raise
            middle = (low + high) // 2
            pending.append((low, middle))
            pending.append((middle + 1, high))  # popped first: keeps newest-first contiguity
            splits += 1
            continue
        logs.extend(batch)
        lowest_scanned = low

    if lowest_scanned > to_block:
        raise ScanBudgetExceededError(
            "The log request budget was exhausted before any block range was scanned."
        )
    complete = not exhausted and lowest_scanned == from_block
    description = (
        f"Approval events were scanned in blocks {lowest_scanned} to {to_block}"
        + (
            "."
            if complete
            else f"; blocks {from_block} to {lowest_scanned - 1} were NOT scanned "
            "because the request budget ran out."
        )
        + " Approvals granted before the scanned range are not discovered."
        + (
            f" Only these {len(tokens)} token contract(s) were scanned: {', '.join(tokens)}."
            if tokens
            else " All token contracts were included."
        )
    )
    return logs, ScanCoverage(
        requested_from_block=from_block,
        requested_to_block=to_block,
        scanned_from_block=lowest_scanned,
        scanned_to_block=to_block,
        complete_for_requested_range=complete,
        log_requests=requests,
        log_query_splits=splits,
        description=description,
    )


async def _read_int(
    read: Callable[[], Awaitable[bytes]], decode: Callable[[bytes], int]
) -> tuple[int | None, str | None]:
    try:
        data = await read()
    except RpcError as exc:
        return None, "call_reverted" if exc.code == "contract_call_failed" else f"rpc:{exc.code}"
    try:
        return decode(data), None
    except ValueError:
        return None, "nonstandard_return"


def _reading(value: int | None, reason: str | None, decimals: int | None) -> Reading:
    if value is None:
        return Reading(status="unknown", unknown_reason=reason)
    return Reading(
        status="known",
        raw=str(value),
        formatted=format_units(value, decimals) if decimals is not None else None,
    )


async def _read_token(
    provider: EthereumProvider, token: str, owner: str, block: int
) -> _TokenState:
    kind = classify_code(await provider.get_code(token, block)).kind
    if kind is CodeKind.NO_CODE:
        unknown = Reading(status="unknown", unknown_reason="token_has_no_code")
        return _TokenState(kind, unknown, None, None)
    (balance, balance_reason), (decimals, _), symbol_bytes = await asyncio.gather(
        _read_int(
            lambda: provider.call(token, encode_call(SEL_BALANCE_OF, owner), block), decode_uint256
        ),
        _read_int(lambda: provider.call(token, SEL_DECIMALS, block), decode_decimals),
        _read_symbol(provider, token, block),
    )
    return _TokenState(kind, _reading(balance, balance_reason, decimals), decimals, symbol_bytes)


async def _read_symbol(provider: EthereumProvider, token: str, block: int) -> str | None:
    try:
        return decode_symbol(await provider.call(token, SEL_SYMBOL, block)) or None
    except (RpcError, ValueError):
        return None


def _allowance_level(allowance: int | None) -> AllowanceLevel:
    if allowance is None:
        return AllowanceLevel.UNKNOWN
    if allowance == 0:
        return AllowanceLevel.NONE
    if allowance == UINT256_MAX:
        return AllowanceLevel.UNLIMITED
    if allowance >= EFFECTIVELY_UNLIMITED_THRESHOLD:
        return AllowanceLevel.EFFECTIVELY_UNLIMITED
    return AllowanceLevel.LIMITED


def _signals(
    allowance: int | None,
    balance: int | None,
    level: AllowanceLevel,
    latest: ApprovalEvent,
    spender_kind: CodeKind,
    token: _TokenState,
) -> list[Signal]:
    signals: list[Signal] = []
    if level is AllowanceLevel.UNLIMITED:
        signals.append(
            Signal(
                code="unlimited_allowance",
                evidence_class="observed_fact",
                explanation="The current allowance is the maximum uint256 value: the "
                "spender may transfer any amount of this token the owner holds now "
                "or later, until the approval is reduced.",
            )
        )
    elif level is AllowanceLevel.EFFECTIVELY_UNLIMITED:
        signals.append(
            Signal(
                code="effectively_unlimited_allowance",
                evidence_class="observed_fact",
                explanation="The current allowance is at least 2^128 base units, "
                "far beyond any real token supply, so it acts as unlimited.",
            )
        )
    if allowance and balance is not None and allowance > balance:
        signals.append(
            Signal(
                code="allowance_exceeds_balance",
                evidence_class="observed_fact",
                explanation="The allowance exceeds the owner's current balance, so "
                "the entire visible balance is within the spender's permission.",
            )
        )
    if allowance and spender_kind is CodeKind.NO_CODE:
        signals.append(
            Signal(
                code="spender_has_no_code",
                evidence_class="heuristic_signal",
                explanation="The spender has no contract code. Dapps normally "
                "approve contracts; an active approval to a plain account deserves "
                "verification, as it is a pattern seen in approval phishing. It is "
                "not proof of wrongdoing.",
            )
        )
    if allowance and spender_kind is CodeKind.EIP7702_DELEGATION:
        signals.append(
            Signal(
                code="spender_is_delegated_eoa",
                evidence_class="observed_fact",
                explanation="The spender is an EOA with an EIP-7702 delegation; its "
                "behaviour is defined by the delegate contract.",
            )
        )
    if allowance is not None and allowance != latest.value:
        signals.append(
            Signal(
                code="allowance_differs_from_latest_event",
                evidence_class="observed_fact",
                explanation="The current allowance differs from the value in the "
                "latest Approval event in range. Many tokens reduce allowances on "
                "transferFrom without emitting Approval, so spending or changes "
                "outside the scanned range can explain this.",
            )
        )
    if token.code_kind is CodeKind.CONTRACT and token.decimals is None:
        signals.append(
            Signal(
                code="token_metadata_unavailable",
                evidence_class="observed_fact",
                explanation="decimals() could not be read; amounts are shown in base units only.",
            )
        )
    return signals


async def scan_approvals(
    provider: EthereumProvider,
    owner: str,
    *,
    chain: ChainInfo,
    limits: ScanLimits,
    from_block: int | None = None,
    lookback_blocks: int | None = None,
    tokens: list[str] | None = None,
) -> ApprovalScan:
    """Scan ``owner``'s approvals. ``tokens`` limits discovery to those contracts, which also
    makes scans possible on providers that refuse address-less ``eth_getLogs`` queries."""
    owner = to_checksum_address(owner)
    token_scope: list[str] | None = None
    if tokens:
        token_scope = sorted({to_checksum_address(t) for t in tokens})
        if len(token_scope) > MAX_SCOPED_TOKENS:
            raise InvalidScanRequestError(
                f"At most {MAX_SCOPED_TOKENS} token contracts can be scanned at once."
            )
    await provider.verify_chain()
    head = await provider.block_number()
    header: BlockHeader = await provider.get_block(head)
    to_block = header.number

    if from_block is None:
        lookback = lookback_blocks or limits.lookback_blocks
        from_block = max(0, to_block - lookback + 1)
    if from_block < 0 or from_block > to_block:
        raise BlockRangeTooLargeError(f"from_block must be between 0 and {to_block}.")
    span = to_block - from_block + 1
    if span > limits.max_scan_blocks:
        raise BlockRangeTooLargeError(
            f"Requested {span} blocks; the maximum per scan is {limits.max_scan_blocks}."
        )

    try:
        raw_logs, coverage = await _scan_logs(
            provider, owner, from_block, to_block, limits, token_scope
        )
    except LogFilterRestrictedError as exc:
        if token_scope is not None:
            raise
        raise LogFilterRestrictedError(
            exc.message + " Name specific token contracts to scan (API: tokens, CLI: --token), "
            "or configure a provider that serves wallet-wide log queries.",
            details=exc.details,
        ) from None

    counts = dict.fromkeys(ApprovalLogShape, 0)
    latest: dict[tuple[str, str], ApprovalEvent] = {}
    occurrences: dict[tuple[str, str], int] = {}
    seen_logs: set[tuple[str, int]] = set()
    unique_events: list[ApprovalEvent] = []
    for log in raw_logs:
        shape, event = classify_approval_log(log)
        counts[shape] += 1
        if event is None or event.owner != owner:
            continue
        identity = (event.block_hash, event.log_index)
        if identity in seen_logs:  # overlapping/duplicated provider results
            continue
        seen_logs.add(identity)
        unique_events.append(event)
        key = (event.token, event.spender)
        occurrences[key] = occurrences.get(key, 0) + 1
        if key not in latest or event.position > latest[key].position:
            latest[key] = event

    ranked = sorted(latest.items(), key=lambda kv: kv[1].position, reverse=True)
    kept = ranked[: limits.max_pairs]
    block = header.number

    tokens = sorted({token for (token, _), _ in kept})
    spenders = sorted({spender for (_, spender), _ in kept})
    token_states = dict(
        zip(
            tokens,
            await asyncio.gather(*(_read_token(provider, t, owner, block) for t in tokens)),
            strict=True,
        )
    )
    spender_kinds = dict(
        zip(
            spenders,
            [
                classify_code(code).kind
                for code in await asyncio.gather(*(provider.get_code(s, block) for s in spenders))
            ],
            strict=True,
        )
    )

    async def allowance_of(token: str, spender: str) -> tuple[int | None, str | None]:
        if token_states[token].code_kind is CodeKind.NO_CODE:
            return None, "token_has_no_code"
        return await _read_int(
            lambda: provider.call(token, encode_call(SEL_ALLOWANCE, owner, spender), block),
            decode_uint256,
        )

    allowances = await asyncio.gather(*(allowance_of(t, s) for (t, s), _ in kept))

    recheck = await provider.get_block(block)
    if recheck.hash != header.hash:
        raise ReorgDetectedError("The chain reorganized during the approval scan; try again.")

    entries: list[ApprovalEntry] = []
    for ((token, spender), event), (allowance, reason) in zip(kept, allowances, strict=True):
        state = token_states[token]
        balance = int(state.balance.raw) if state.balance.raw is not None else None
        level = _allowance_level(allowance)
        exposure: Reading
        if allowance is not None and balance is not None:
            exposure = _reading(min(allowance, balance), None, state.decimals)
        else:
            exposure = Reading(status="unknown", unknown_reason="allowance_or_balance_unknown")
        known = lookup_known_contract(chain.chain_id, spender)
        simulated = provider.source == "demo_fixture"
        entries.append(
            ApprovalEntry(
                token=TokenView(
                    address=token,
                    symbol=state.symbol,
                    decimals=state.decimals,
                    code_kind=state.code_kind,
                ),
                spender=SpenderView(
                    address=spender,
                    code_kind=spender_kinds[spender],
                    label=known.label if known else None,
                    label_source=known.source if known else None,
                ),
                latest_event=EventView(
                    value=str(event.value),
                    value_formatted=format_units(event.value, state.decimals)
                    if state.decimals is not None
                    else None,
                    block_number=event.block_number,
                    block_hash=event.block_hash,
                    transaction_hash=event.transaction_hash,
                    log_index=event.log_index,
                    explorer_url=None
                    if simulated
                    else explorer_tx_url(chain, event.transaction_hash),
                ),
                events_in_range=occurrences[(token, spender)],
                current_allowance=_reading(allowance, reason, state.decimals),
                allowance_level=level,
                active=None if allowance is None else allowance > 0,
                owner_balance=state.balance,
                exposure_upper_bound=exposure,
                signals=_signals(allowance, balance, level, event, spender_kinds[spender], state),
            )
        )
    entries.sort(key=lambda e: (e.token.address, e.spender.address))

    simulated = provider.source == "demo_fixture"
    limitations = [
        coverage.description,
        "Only ERC-20 allowances are analyzed. ERC-721/ERC-1155 approvals (including "
        "ApprovalForAll) and Permit2 sub-allowances are not covered yet.",
        "Exposure is min(balance, allowance) at the observed block: a visible upper bound, not a "
        "prediction of loss. It assumes standard ERC-20 transferFrom semantics; rebasing, "
        "fee-on-transfer or upgradeable tokens may behave differently.",
        "Token symbols are contract-supplied, untrusted text and can impersonate other tokens.",
    ]
    if len(ranked) > len(kept):
        limitations.append(
            f"{len(ranked) - len(kept)} older token/spender pairs were not verified "
            f"(limit {limits.max_pairs} pairs per scan)."
        )
    if simulated:
        limitations.insert(0, "SIMULATED DATA: fictional demo fixture, not Ethereum state.")

    report = ApprovalScanReport(
        data_source=provider.source,
        simulated=simulated,
        provider=provider.endpoint_display,
        owner=owner,
        chain_id=chain.chain_id,
        chain_name=chain.name,
        block_number=header.number,
        block_hash=header.hash,
        block_timestamp=header.timestamp_utc,
        observed_at=datetime.now(UTC),
        coverage=coverage,
        log_counts=LogCounts(
            erc20_approvals=counts[ApprovalLogShape.ERC20],
            erc721_shaped_approvals=counts[ApprovalLogShape.ERC721_SHAPED],
            removed=counts[ApprovalLogShape.REMOVED],
            malformed=counts[ApprovalLogShape.MALFORMED],
        ),
        token_scope=token_scope,
        pairs_discovered=len(ranked),
        pairs_truncated=len(ranked) - len(kept),
        approvals=entries,
        exposure_model="min(current_balance, current_allowance) at the observed block",
        limitations=limitations,
    )
    unique_events.sort(key=lambda e: e.position)
    return ApprovalScan(report=report, events=unique_events)

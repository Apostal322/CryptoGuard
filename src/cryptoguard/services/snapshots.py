"""Take a wallet security snapshot and fold it into the wallet's timeline.

One snapshot = one block ``B`` (default: ``confirmations`` blocks behind the head):

1. Re-check the previous snapshots' block hashes. Any that were reorganized out are marked
   orphaned, stored events above the surviving base are dropped, and the base moves back.
2. Read account code / delegation and native balance at ``B``.
3. Discover Approval events only in ``(base, B]`` (or a bounded lookback for the first
   snapshot), then re-verify every pair that was not known to be zero plus the new ones.
4. Re-check ``B``'s hash, build the canonical state, diff it against the base, evaluate the
   ruleset, and store snapshot + events + finding transitions atomically.

Coverage is cumulative and explicit: windows that were never scanned are listed as gaps.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from itertools import pairwise

from pydantic import BaseModel

from cryptoguard.blockchain.erc20 import ApprovalEvent
from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import ChainInfo
from cryptoguard.core.errors import InvalidScanRequestError, ReorgDetectedError
from cryptoguard.database.history import FindingEvent, HistoryRepository, NewSnapshot, SnapshotRef
from cryptoguard.history.delta import Change, compute_delta
from cryptoguard.history.state import (
    ApprovalState,
    WalletState,
    account_state,
    approval_state,
    pair_key,
    state_hash,
)
from cryptoguard.risk.rules import evaluate
from cryptoguard.services.approvals import (
    Pair,
    ScanLimits,
    discover_approvals,
    normalize_token_scope,
    rank_pairs,
    verify_approval_pairs,
)
from cryptoguard.services.inspection import inspect_address

REORG_LOOKBACK_SNAPSHOTS = 10


class CoverageRange(BaseModel):
    from_block: int
    to_block: int


class SnapshotCoverage(BaseModel):
    scanned: list[CoverageRange]
    gaps: list[CoverageRange]
    unverified_pairs: int
    description: str


class FindingEventView(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    from_status: str | None
    to_status: str
    reason: str


class SnapshotOutcome(BaseModel):
    snapshot_id: int
    created: bool
    simulated: bool
    owner: str
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: datetime
    head_block_number: int
    lag_blocks: int
    is_baseline: bool
    previous_block: int | None
    state_hash: str
    coverage: SnapshotCoverage
    changes: list[Change]
    finding_events: list[FindingEventView]
    findings_not_reverified: int
    orphaned_snapshots: int
    notes: list[str]


def finding_event_view(event: FindingEvent) -> FindingEventView:
    return FindingEventView(
        finding_id=event.fingerprint,
        rule_id=event.rule_id,
        title=event.title,
        severity=event.severity,
        confidence=event.confidence,
        from_status=event.from_status,
        to_status=event.to_status,
        reason=event.reason,
    )


def _merge(ranges: list[CoverageRange]) -> list[CoverageRange]:
    merged: list[CoverageRange] = []
    for r in sorted(ranges, key=lambda x: x.from_block):
        if merged and r.from_block <= merged[-1].to_block + 1:
            last = merged[-1]
            merged[-1] = CoverageRange(
                from_block=last.from_block, to_block=max(last.to_block, r.to_block)
            )
        else:
            merged.append(r)
    return merged


def _gaps(scanned: list[CoverageRange]) -> list[CoverageRange]:
    return [
        CoverageRange(from_block=a.to_block + 1, to_block=b.from_block - 1)
        for a, b in pairwise(scanned)
    ]


def _coverage(
    base: SnapshotRef | None,
    scanned_from: int,
    to_block: int,
    token_scope: list[str] | None,
    unverified: int,
) -> SnapshotCoverage:
    previous = (
        [CoverageRange.model_validate(r) for r in base.coverage.get("scanned", [])] if base else []
    )
    scanned = _merge([*previous, CoverageRange(from_block=scanned_from, to_block=to_block)])
    gaps = _gaps(scanned)
    scope = f"token contracts {', '.join(token_scope)}" if token_scope else "all token contracts"
    text = (
        f"Approval events scanned for {scope} in "
        + ", ".join(f"{r.from_block}-{r.to_block}" for r in scanned)
        + ". Approvals granted outside these ranges are not discovered."
    )
    if gaps:
        text += " NOT scanned: " + ", ".join(f"{g.from_block}-{g.to_block}" for g in gaps) + "."
    if unverified:
        text += f" {unverified} token/spender pair(s) could not be re-verified (pair limit)."
    return SnapshotCoverage(
        scanned=scanned, gaps=gaps, unverified_pairs=unverified, description=text
    )


async def _find_base(
    provider: EthereumProvider, repo: HistoryRepository, chain_id: int, owner: str, source: str
) -> tuple[SnapshotRef | None, int]:
    recent = await asyncio.to_thread(
        repo.recent_snapshots, chain_id, owner, source, REORG_LOOKBACK_SNAPSHOTS
    )
    orphans: list[int] = []
    base: SnapshotRef | None = None
    for snapshot in recent:
        header = await provider.get_block(snapshot.block_number)
        if header.hash == snapshot.block_hash:
            base = snapshot
            break
        orphans.append(snapshot.id)
    if orphans:
        keep = base.block_number if base else -1
        await asyncio.to_thread(repo.orphan_snapshots, chain_id, owner, orphans, keep)
    return base, len(orphans)


async def take_snapshot(
    provider: EthereumProvider,
    repo: HistoryRepository,
    owner: str,
    *,
    chain: ChainInfo,
    limits: ScanLimits,
    confirmations: int,
    block: int | None = None,
    tokens: list[str] | None = None,
    lookback_blocks: int | None = None,
) -> SnapshotOutcome:
    owner = to_checksum_address(owner)
    source = provider.source
    await provider.verify_chain()
    head = await provider.block_number()
    base, orphaned = await _find_base(provider, repo, chain.chain_id, owner, source)

    token_scope = normalize_token_scope(tokens)
    if base is not None:
        if token_scope is None:
            token_scope = base.token_scope
        elif token_scope != base.token_scope:
            raise InvalidScanRequestError(
                "The token scope differs from this wallet's earlier snapshots. Coverage would "
                "become inconsistent; purge the wallet's history to change the scope."
            )

    target = block if block is not None else head - confirmations
    if target < 0 or target > head:
        raise InvalidScanRequestError(f"Snapshot block must be between 0 and the head ({head}).")
    if base is not None and target < base.block_number:
        raise InvalidScanRequestError(
            f"Snapshots must move forward: the latest snapshot is at block {base.block_number}."
        )
    header = await provider.get_block(target)
    if base is not None and target == base.block_number:
        return await _unchanged(
            repo, base, provider, owner, chain, head, header.timestamp_utc, orphaned
        )

    inspection = await inspect_address(provider, owner, chain=chain, at=header)

    if base is not None:
        requested_from = base.block_number + 1
    else:
        requested_from = max(0, target - (lookback_blocks or limits.lookback_blocks) + 1)
    scan_from = max(requested_from, target - limits.max_scan_blocks + 1)
    discovery = await discover_approvals(
        provider,
        owner,
        from_block=scan_from,
        to_block=target,
        limits=limits,
        token_scope=token_scope,
    )

    carried: dict[Pair, ApprovalState] = {}
    if base is not None:
        carried = {
            (s.token, s.spender): s for s in base.state.approvals.values() if s.active is not False
        }
    latest: dict[Pair, ApprovalEvent] = {pair: s.to_event(owner) for pair, s in carried.items()}
    latest.update(discovery.latest_by_pair())
    kept, dropped = rank_pairs(latest, limits.max_pairs)
    entries = await verify_approval_pairs(
        provider,
        owner,
        {pair: latest[pair] for pair in kept},
        discovery.occurrences(),
        chain=chain,
        block=target,
    )
    if (await provider.get_block(target)).hash != header.hash:
        raise ReorgDetectedError("The chain reorganized during the snapshot; try again.")

    approvals = {
        pair_key(e.token.address, e.spender.address): approval_state(
            e, latest[(e.token.address, e.spender.address)], target
        )
        for e in entries
    }
    stale = [pair for pair in dropped if pair in carried]
    for pair in stale:  # kept as last verified; the rules treat them as unverifiable
        approvals[pair_key(*pair)] = carried[pair]
    state = WalletState(
        approvals=dict(sorted(approvals.items())),
        account=account_state(inspection),
        native_balance_wei=inspection.native_balance.wei,
    )
    simulated = source == "demo_fixture"
    changes = (
        compute_delta(
            base.state,
            state,
            from_block=base.block_number,
            to_block=target,
            chain=chain,
            simulated=simulated,
        )
        if base is not None
        else []
    )
    evaluation = evaluate(state, chain_id=chain.chain_id, wallet=owner, block=target)
    coverage = _coverage(
        base, discovery.coverage.scanned_from_block, target, token_scope, len(dropped)
    )
    recorded = await asyncio.to_thread(
        repo.record_snapshot,
        NewSnapshot(
            chain_id=chain.chain_id,
            address=owner,
            block_number=target,
            block_hash=header.hash,
            block_timestamp=header.timestamp_utc,
            head_block_number=head,
            data_source=source,
            previous_snapshot_id=base.id if base else None,
            token_scope=token_scope,
            coverage=coverage.model_dump(mode="json"),
            state=state,
            changes=changes,
        ),
        discovery.events,
        evaluation,
    )
    notes = _notes(base, simulated, orphaned)
    return SnapshotOutcome(
        snapshot_id=recorded.snapshot_id,
        created=recorded.created,
        simulated=simulated,
        owner=owner,
        chain_id=chain.chain_id,
        block_number=target,
        block_hash=header.hash,
        block_timestamp=header.timestamp_utc,
        head_block_number=head,
        lag_blocks=head - target,
        is_baseline=base is None,
        previous_block=base.block_number if base else None,
        state_hash=state_hash(state),
        coverage=coverage,
        changes=changes,
        finding_events=[finding_event_view(e) for e in recorded.finding_events],
        findings_not_reverified=len(recorded.not_reverified),
        orphaned_snapshots=orphaned,
        notes=notes,
    )


def _notes(base: SnapshotRef | None, simulated: bool, orphaned: int) -> list[str]:
    notes = [
        "Monitoring is by polling: changes are located between two snapshot blocks, not at the "
        "moment they happened.",
    ]
    if base is None:
        notes.insert(
            0,
            "Baseline snapshot: no earlier state to compare, so no changes are "
            "listed; current conditions appear as new findings.",
        )
    if orphaned:
        notes.append(
            f"{orphaned} earlier snapshot(s) were on a reorganized-out chain and were "
            "marked orphaned; this snapshot compares against the last canonical one."
        )
    if simulated:
        notes.insert(0, "SIMULATED DATA: fictional demo fixture, not Ethereum state.")
    return notes


async def _unchanged(
    repo: HistoryRepository,
    base: SnapshotRef,
    provider: EthereumProvider,
    owner: str,
    chain: ChainInfo,
    head: int,
    block_time: datetime,
    orphaned: int,
) -> SnapshotOutcome:
    """The target block already has a canonical snapshot: return it without new reads."""
    simulated = provider.source == "demo_fixture"
    return SnapshotOutcome(
        snapshot_id=base.id,
        created=False,
        simulated=simulated,
        owner=owner,
        chain_id=chain.chain_id,
        block_number=base.block_number,
        block_hash=base.block_hash,
        block_timestamp=block_time,
        head_block_number=head,
        lag_blocks=head - base.block_number,
        is_baseline=False,
        previous_block=None,
        state_hash=state_hash(base.state),
        coverage=SnapshotCoverage.model_validate(base.coverage),
        changes=[],
        finding_events=[],
        findings_not_reverified=0,
        orphaned_snapshots=orphaned,
        notes=[
            f"A snapshot at block {base.block_number} already exists; nothing was re-read. "
            f"Generated {datetime.now(UTC).isoformat()}."
        ],
    )

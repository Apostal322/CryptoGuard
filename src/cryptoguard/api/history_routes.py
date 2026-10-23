"""Snapshot, timeline and finding routes."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.api.state import error_response, get_state
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import ChainInfo, explorer_block_url
from cryptoguard.core.errors import InvalidScanRequestError
from cryptoguard.core.hexutil import parse_hash32
from cryptoguard.database.history import TimelineRow
from cryptoguard.database.models import FindingRecord, FindingTransitionRecord
from cryptoguard.history.delta import Change
from cryptoguard.risk.lifecycle import OPEN_STATUSES, FindingStatus, InvalidTransitionError
from cryptoguard.risk.rules import RULES, RULESET_ID, RULESET_VERSION, Severity
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.providers import require_provider
from cryptoguard.services.snapshots import (
    FindingEventView,
    SnapshotCoverage,
    SnapshotOutcome,
    finding_event_view,
    take_snapshot,
)

router = APIRouter(prefix="/api/v1")


class SnapshotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block: int | None = Field(
        default=None, ge=0, description="Snapshot block; default is head minus confirmations."
    )
    tokens: list[str] | None = Field(
        default=None, max_length=25, description="Token scope (fixed after the first snapshot)."
    )
    lookback_blocks: int | None = Field(
        default=None, ge=1, description="Discovery window for the first (baseline) snapshot."
    )


class TimelineEntry(BaseModel):
    snapshot_id: int
    block_number: int
    block_hash: str
    block_timestamp: datetime
    created_at: datetime
    previous_block: int | None
    is_baseline: bool
    orphaned: bool
    simulated: bool
    state_hash: str
    ruleset_version: str
    changes: list[Change]
    finding_events: list[FindingEventView]
    coverage: SnapshotCoverage
    explorer_block_url: str | None


class TimelinePage(BaseModel):
    items: list[TimelineEntry]
    total: int
    limit: int
    offset: int


class FindingView(BaseModel):
    finding_id: str
    rule_id: str
    ruleset_version: str
    category: str
    status: str
    severity: str
    confidence: str
    subject: str
    title: str
    explanation: str
    evidence: list[dict[str, object]]
    simulated: bool
    first_seen_block: int
    last_seen_block: int
    resolved_block: int | None
    reopen_count: int


class TransitionView(BaseModel):
    from_status: str | None
    to_status: str
    reason: str
    block_number: int | None
    snapshot_id: int | None
    created_at: datetime


class FindingDetail(BaseModel):
    finding: FindingView
    transitions: list[TransitionView]


class FindingList(BaseModel):
    items: list[FindingView]
    total: int


class RuleView(BaseModel):
    rule_id: str
    category: str
    description: str


class RulesetView(BaseModel):
    ruleset_id: str
    version: str
    severities: list[str]
    rules: list[RuleView]


def _finding_view(f: FindingRecord) -> FindingView:
    return FindingView(
        finding_id=f.fingerprint,
        rule_id=f.rule_id,
        ruleset_version=f.ruleset_version,
        category=f.category,
        status=f.status,
        severity=f.severity,
        confidence=f.confidence,
        subject=f.subject,
        title=f.title,
        explanation=f.explanation,
        evidence=f.evidence,
        simulated=f.data_source == "demo_fixture",
        first_seen_block=f.first_seen_block,
        last_seen_block=f.last_seen_block,
        resolved_block=f.resolved_block,
        reopen_count=f.reopen_count,
    )


def _detail(f: FindingRecord, transitions: list[FindingTransitionRecord]) -> FindingDetail:
    return FindingDetail(
        finding=_finding_view(f),
        transitions=[
            TransitionView(
                from_status=t.from_status,
                to_status=t.to_status,
                reason=t.reason,
                block_number=t.block_number,
                snapshot_id=t.snapshot_id,
                created_at=t.created_at,
            )
            for t in transitions
        ],
    )


def _timeline_entry(row: TimelineRow, chain: ChainInfo) -> TimelineEntry:
    s = row.snapshot
    simulated = s.data_source == "demo_fixture"
    return TimelineEntry(
        snapshot_id=s.id,
        block_number=s.block_number,
        block_hash=s.block_hash,
        block_timestamp=s.block_timestamp,
        created_at=s.created_at,
        previous_block=row.previous_block,
        is_baseline=s.is_baseline,
        orphaned=s.orphaned,
        simulated=simulated,
        state_hash=s.state_hash,
        ruleset_version=s.ruleset_version,
        changes=[Change.model_validate(c) for c in s.changes],
        finding_events=[finding_event_view(e) for e in row.finding_events],
        coverage=SnapshotCoverage.model_validate(s.coverage),
        explorer_block_url=None if simulated else explorer_block_url(chain, s.block_number),
    )


def _finding_id(value: str) -> str:
    try:
        return parse_hash32(value)
    except ValueError:
        raise InvalidScanRequestError("A finding id is a 0x-prefixed 32-byte hex value.") from None


@router.post("/wallets/{address}/snapshots", response_model=SnapshotOutcome)
async def create_snapshot(request: Request, address: str, body: SnapshotRequest) -> SnapshotOutcome:
    """Take a security snapshot and add it to the wallet's timeline."""
    state = get_state(request)
    return await take_snapshot(
        require_provider(state.provider),
        state.repository,
        to_checksum_address(address),
        chain=state.chain,
        limits=ScanLimits.from_settings(state.settings),
        confirmations=state.settings.snapshot_confirmations,
        block=body.block,
        tokens=body.tokens,
        lookback_blocks=body.lookback_blocks,
    )


@router.get("/wallets/{address}/timeline", response_model=TimelinePage)
async def wallet_timeline(
    request: Request,
    address: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    include_orphaned: bool = False,
) -> TimelinePage:
    state = get_state(request)
    rows, total = await asyncio.to_thread(
        state.repository.timeline,
        state.chain.chain_id,
        to_checksum_address(address),
        limit=limit,
        offset=offset,
        include_orphaned=include_orphaned,
    )
    return TimelinePage(
        items=[_timeline_entry(row, state.chain) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/wallets/{address}/findings", response_model=FindingList)
async def wallet_findings(
    request: Request,
    address: str,
    status: Literal["open", "all", "new", "active", "acknowledged", "resolved", "superseded"] = (
        "open"
    ),
) -> FindingList:
    state = get_state(request)
    statuses: list[str] | None
    if status == "open":
        statuses = [s.value for s in OPEN_STATUSES]
    elif status == "all":
        statuses = None
    else:
        statuses = [FindingStatus(status).value]
    findings = await asyncio.to_thread(
        state.repository.list_findings, state.chain.chain_id, to_checksum_address(address), statuses
    )
    return FindingList(items=[_finding_view(f) for f in findings], total=len(findings))


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def finding_detail(request: Request, finding_id: str) -> FindingDetail | JSONResponse:
    found = await asyncio.to_thread(
        get_state(request).repository.get_finding, _finding_id(finding_id)
    )
    if found is None:
        return error_response(404, "finding_not_found", "No finding with this id.")
    return _detail(*found)


@router.post("/findings/{finding_id}/acknowledge", response_model=FindingDetail)
async def acknowledge_finding(request: Request, finding_id: str) -> FindingDetail | JSONResponse:
    repo = get_state(request).repository
    fingerprint = _finding_id(finding_id)
    try:
        finding = await asyncio.to_thread(repo.acknowledge_finding, fingerprint)
    except InvalidTransitionError as exc:
        return error_response(409, "invalid_transition", str(exc))
    if finding is None:
        return error_response(404, "finding_not_found", "No finding with this id.")
    found = await asyncio.to_thread(repo.get_finding, fingerprint)
    assert found is not None
    return _detail(*found)


@router.get("/rules", response_model=RulesetView)
async def ruleset() -> RulesetView:
    return RulesetView(
        ruleset_id=RULESET_ID,
        version=RULESET_VERSION,
        severities=[s.value for s in Severity],
        rules=[
            RuleView(rule_id=r.rule_id, category=r.category, description=r.description)
            for r in RULES
        ],
    )

"""Persistence for wallet snapshots, findings and the finding audit trail.

``record_snapshot`` stores a snapshot, its newly observed Approval events and every finding
transition in a single transaction, so the timeline never shows half-applied state.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from cryptoguard.blockchain.erc20 import ApprovalEvent
from cryptoguard.database.models import (
    ApprovalEventRecord,
    FindingRecord,
    FindingTransitionRecord,
    WalletSnapshotRecord,
)
from cryptoguard.database.repository import ObservationRepository, insert_approval_events
from cryptoguard.history.delta import Change
from cryptoguard.history.state import SNAPSHOT_SCHEMA_VERSION, WalletState, state_hash
from cryptoguard.risk.lifecycle import (
    FindingStatus,
    KnownFinding,
    acknowledge,
    reconcile,
)
from cryptoguard.risk.rules import RULESET_VERSION, RuleEvaluation


@dataclass(frozen=True)
class SnapshotRef:
    id: int
    block_number: int
    block_hash: str
    state: WalletState
    token_scope: list[str] | None
    coverage: dict[str, Any]


@dataclass(frozen=True)
class NewSnapshot:
    chain_id: int
    address: str
    block_number: int
    block_hash: str
    block_timestamp: datetime
    head_block_number: int
    data_source: str
    previous_snapshot_id: int | None
    token_scope: list[str] | None
    coverage: dict[str, Any]
    state: WalletState
    changes: list[Change]


@dataclass(frozen=True)
class FindingEvent:
    fingerprint: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    from_status: str | None
    to_status: str
    reason: str


@dataclass(frozen=True)
class RecordedSnapshot:
    snapshot_id: int
    created: bool
    new_events: int
    finding_events: list[FindingEvent]
    not_reverified: list[str]


@dataclass(frozen=True)
class TimelineRow:
    snapshot: WalletSnapshotRecord
    previous_block: int | None
    finding_events: list[FindingEvent]


def _ref(row: WalletSnapshotRecord) -> SnapshotRef:
    return SnapshotRef(
        id=row.id,
        block_number=row.block_number,
        block_hash=row.block_hash,
        state=WalletState.model_validate(row.state),
        token_scope=row.token_scope,
        coverage=row.coverage,
    )


class HistoryRepository(ObservationRepository):
    def recent_snapshots(
        self, chain_id: int, address: str, data_source: str, limit: int = 10
    ) -> list[SnapshotRef]:
        """Most recent non-orphaned snapshots, newest first."""
        with self._sessions() as session:
            rows = session.scalars(
                select(WalletSnapshotRecord)
                .where(
                    (WalletSnapshotRecord.chain_id == chain_id)
                    & (WalletSnapshotRecord.address == address)
                    & (WalletSnapshotRecord.data_source == data_source)
                    & WalletSnapshotRecord.orphaned.is_(False)
                )
                .order_by(WalletSnapshotRecord.block_number.desc())
                .limit(limit)
            ).all()
        return [_ref(row) for row in rows]

    def orphan_snapshots(
        self, chain_id: int, address: str, snapshot_ids: Sequence[int], keep_up_to_block: int
    ) -> int:
        """Mark reorged-out snapshots and drop stored events above the surviving base block,
        so they are re-ingested from the canonical chain. Returns events deleted."""
        with self._sessions() as session, session.begin():
            for row in session.scalars(
                select(WalletSnapshotRecord).where(WalletSnapshotRecord.id.in_(snapshot_ids))
            ):
                row.orphaned = True
            result = session.execute(
                delete(ApprovalEventRecord).where(
                    (ApprovalEventRecord.chain_id == chain_id)
                    & (ApprovalEventRecord.owner == address)
                    & (ApprovalEventRecord.block_number > keep_up_to_block)
                )
            )
        return int(getattr(result, "rowcount", 0) or 0)

    def record_snapshot(
        self, new: NewSnapshot, events: Sequence[ApprovalEvent], evaluation: RuleEvaluation
    ) -> RecordedSnapshot:
        now = datetime.now(UTC)
        with self._sessions() as session, session.begin():
            existing = session.scalar(
                select(WalletSnapshotRecord).where(
                    (WalletSnapshotRecord.chain_id == new.chain_id)
                    & (WalletSnapshotRecord.address == new.address)
                    & (WalletSnapshotRecord.block_hash == new.block_hash)
                    & (WalletSnapshotRecord.data_source == new.data_source)
                )
            )
            if existing is not None:
                return RecordedSnapshot(existing.id, False, 0, [], [])

            new_events = insert_approval_events(session, new.chain_id, new.data_source, events)
            row = WalletSnapshotRecord(
                chain_id=new.chain_id,
                address=new.address,
                block_number=new.block_number,
                block_hash=new.block_hash,
                block_timestamp=new.block_timestamp,
                head_block_number=new.head_block_number,
                created_at=now,
                data_source=new.data_source,
                schema_version=SNAPSHOT_SCHEMA_VERSION,
                ruleset_version=RULESET_VERSION,
                previous_snapshot_id=new.previous_snapshot_id,
                is_baseline=new.previous_snapshot_id is None,
                orphaned=False,
                token_scope=new.token_scope,
                coverage=new.coverage,
                state=new.state.model_dump(mode="json"),
                state_hash=state_hash(new.state),
                changes=[c.model_dump(mode="json") for c in new.changes],
            )
            session.add(row)
            session.flush()
            finding_events, not_reverified = self._apply_lifecycle(session, row, evaluation, now)
        return RecordedSnapshot(row.id, True, new_events, finding_events, not_reverified)

    @staticmethod
    def _apply_lifecycle(
        session: Session, row: WalletSnapshotRecord, evaluation: RuleEvaluation, now: datetime
    ) -> tuple[list[FindingEvent], list[str]]:
        findings = session.scalars(
            select(FindingRecord).where(
                (FindingRecord.chain_id == row.chain_id)
                & (FindingRecord.address == row.address)
                & (FindingRecord.data_source == row.data_source)
            )
        ).all()
        by_fp = {f.fingerprint: f for f in findings}
        known = {
            f.fingerprint: KnownFinding(
                f.fingerprint, FindingStatus(f.status), f.ruleset_version, f.subject
            )
            for f in findings
        }
        result = reconcile(known, evaluation)
        events: list[FindingEvent] = []

        def record(f: FindingRecord, from_status: str | None, to_status: str, reason: str) -> None:
            session.add(
                FindingTransitionRecord(
                    finding_id=f.id,
                    snapshot_id=row.id,
                    from_status=from_status,
                    to_status=to_status,
                    reason=reason,
                    block_number=row.block_number,
                    created_at=now,
                )
            )
            events.append(
                FindingEvent(
                    f.fingerprint,
                    f.rule_id,
                    f.title,
                    f.severity,
                    f.confidence,
                    from_status,
                    to_status,
                    reason,
                )
            )

        for candidate in result.observed:
            f = by_fp.get(candidate.fingerprint)
            if f is None:
                f = FindingRecord(
                    chain_id=row.chain_id,
                    address=row.address,
                    fingerprint=candidate.fingerprint,
                    rule_id=candidate.rule_id,
                    status=FindingStatus.NEW.value,
                    data_source=row.data_source,
                    first_seen_snapshot_id=row.id,
                    first_seen_block=row.block_number,
                    reopen_count=0,
                )
                session.add(f)
                by_fp[candidate.fingerprint] = f
            elif f.status not in (FindingStatus.RESOLVED, FindingStatus.SUPERSEDED) and (
                f.severity != candidate.severity.value
            ):
                record(
                    f,
                    f.status,
                    f.status,
                    f"Severity changed from {f.severity} to {candidate.severity.value}.",
                )
            f.ruleset_version = candidate.ruleset_version
            f.category = candidate.category
            f.severity = candidate.severity.value
            f.confidence = candidate.confidence.value
            f.subject = candidate.subject
            f.title = candidate.title
            f.explanation = candidate.explanation
            f.evidence = [e.model_dump(mode="json") for e in candidate.evidence]
            f.last_seen_snapshot_id = row.id
            f.last_seen_block = row.block_number
            f.updated_at = now
        session.flush()

        for transition in result.transitions:
            f = by_fp[transition.fingerprint]
            if transition.from_status in (FindingStatus.RESOLVED, FindingStatus.SUPERSEDED):
                f.reopen_count += 1
                f.resolved_block = None
            if transition.to_status in (FindingStatus.RESOLVED, FindingStatus.SUPERSEDED):
                f.resolved_block = row.block_number
            f.status = transition.to_status.value
            f.updated_at = now
            record(
                f,
                transition.from_status.value if transition.from_status else None,
                transition.to_status.value,
                transition.reason,
            )
        return events, result.not_reverified

    def timeline(
        self,
        chain_id: int,
        address: str,
        *,
        limit: int,
        offset: int,
        include_orphaned: bool = False,
    ) -> tuple[list[TimelineRow], int]:
        condition = (WalletSnapshotRecord.chain_id == chain_id) & (
            WalletSnapshotRecord.address == address
        )
        if not include_orphaned:
            condition = condition & WalletSnapshotRecord.orphaned.is_(False)
        with self._sessions() as session:
            total = session.scalar(
                select(func.count()).select_from(WalletSnapshotRecord).where(condition)
            )
            snapshots = session.scalars(
                select(WalletSnapshotRecord)
                .where(condition)
                .order_by(WalletSnapshotRecord.block_number.desc(), WalletSnapshotRecord.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
            ids = [s.id for s in snapshots]
            previous_ids = {s.previous_snapshot_id for s in snapshots if s.previous_snapshot_id}
            previous_blocks = {
                snapshot_id: number
                for snapshot_id, number in session.execute(
                    select(WalletSnapshotRecord.id, WalletSnapshotRecord.block_number).where(
                        WalletSnapshotRecord.id.in_(previous_ids)
                    )
                )
            }
            pairs = session.execute(
                select(FindingTransitionRecord, FindingRecord)
                .join(FindingRecord, FindingRecord.id == FindingTransitionRecord.finding_id)
                .where(FindingTransitionRecord.snapshot_id.in_(ids))
                .order_by(FindingTransitionRecord.id)
            ).all()
        grouped: dict[int, list[FindingEvent]] = {i: [] for i in ids}
        for transition, finding in pairs:
            assert transition.snapshot_id is not None
            grouped[transition.snapshot_id].append(
                FindingEvent(
                    finding.fingerprint,
                    finding.rule_id,
                    finding.title,
                    finding.severity,
                    finding.confidence,
                    transition.from_status,
                    transition.to_status,
                    transition.reason,
                )
            )
        rows = [
            TimelineRow(
                s,
                previous_blocks.get(s.previous_snapshot_id) if s.previous_snapshot_id else None,
                grouped[s.id],
            )
            for s in snapshots
        ]
        return rows, int(total or 0)

    def list_findings(
        self, chain_id: int, address: str, statuses: Sequence[str] | None = None
    ) -> list[FindingRecord]:
        condition = (FindingRecord.chain_id == chain_id) & (FindingRecord.address == address)
        if statuses:
            condition = condition & FindingRecord.status.in_(list(statuses))
        with self._sessions() as session:
            return list(
                session.scalars(
                    select(FindingRecord)
                    .where(condition)
                    .order_by(FindingRecord.first_seen_block.desc(), FindingRecord.fingerprint)
                ).all()
            )

    def get_finding(
        self, fingerprint: str
    ) -> tuple[FindingRecord, list[FindingTransitionRecord]] | None:
        with self._sessions() as session:
            finding = session.scalar(
                select(FindingRecord).where(FindingRecord.fingerprint == fingerprint)
            )
            if finding is None:
                return None
            transitions = session.scalars(
                select(FindingTransitionRecord)
                .where(FindingTransitionRecord.finding_id == finding.id)
                .order_by(FindingTransitionRecord.id)
            ).all()
        return finding, list(transitions)

    def acknowledge_finding(self, fingerprint: str) -> FindingRecord | None:
        """Mark a new/active finding acknowledged. Raises InvalidTransitionError otherwise."""
        now = datetime.now(UTC)
        with self._sessions() as session, session.begin():
            finding = session.scalar(
                select(FindingRecord).where(FindingRecord.fingerprint == fingerprint)
            )
            if finding is None:
                return None
            previous = finding.status
            finding.status = acknowledge(FindingStatus(previous)).value
            finding.updated_at = now
            session.add(
                FindingTransitionRecord(
                    finding_id=finding.id,
                    snapshot_id=None,
                    from_status=previous,
                    to_status=finding.status,
                    reason="Acknowledged by the user.",
                    block_number=None,
                    created_at=now,
                )
            )
        return finding

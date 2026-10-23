"""Engine setup and the observation repository."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, delete, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cryptoguard.blockchain.erc20 import ApprovalEvent
from cryptoguard.database.models import AddressObservation, ApprovalEventRecord, Base
from cryptoguard.services.approvals import APPROVAL_SCAN_OBSERVATION_TYPE, ApprovalScanReport
from cryptoguard.services.inspection import OBSERVATION_TYPE, AddressInspection


def create_db_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)
    if url.database in (None, "", ":memory:"):
        # One shared connection so the in-memory database survives across threads.
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Path(url.database).parent.mkdir(parents=True, exist_ok=True)
    return create_engine(url, connect_args={"check_same_thread": False})


def init_schema(engine: Engine) -> None:
    """Create tables. Versioned Alembic migrations replace this before schemas evolve."""
    Base.metadata.create_all(engine)


class ObservationRepository:
    def __init__(self, engine: Engine) -> None:
        self._sessions = sessionmaker(engine, expire_on_commit=False)
        self._engine = engine

    def ping(self) -> bool:
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    def _save_observation(self, row: AddressObservation) -> bool:
        with self._sessions() as session:
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return False
        return True

    def save_inspection(self, inspection: AddressInspection) -> bool:
        """Store an inspection. Returns ``False`` if the identical observation already exists."""
        return self._save_observation(
            AddressObservation(
                chain_id=inspection.chain_id,
                address=inspection.address,
                block_number=inspection.block.number,
                block_hash=inspection.block.hash,
                block_timestamp=inspection.block.timestamp,
                observation_type=OBSERVATION_TYPE,
                schema_version=inspection.schema_version,
                data_source=inspection.data_source,
                observed_at=inspection.observed_at,
                payload=inspection.model_dump(mode="json"),
            )
        )

    def save_approval_scan(
        self, report: ApprovalScanReport, events: Sequence[ApprovalEvent]
    ) -> tuple[bool, int]:
        """Store a scan report and its events. Returns (report stored, new events inserted)."""
        stored = self._save_observation(
            AddressObservation(
                chain_id=report.chain_id,
                address=report.owner,
                block_number=report.block_number,
                block_hash=report.block_hash,
                block_timestamp=report.block_timestamp,
                observation_type=APPROVAL_SCAN_OBSERVATION_TYPE,
                schema_version=report.schema_version,
                data_source=report.data_source,
                observed_at=report.observed_at,
                payload=report.model_dump(mode="json"),
            )
        )
        return stored, self._insert_events(report.chain_id, report.data_source, events)

    def _insert_events(
        self, chain_id: int, data_source: str, events: Sequence[ApprovalEvent]
    ) -> int:
        if not events:
            return 0
        hashes = {e.block_hash for e in events}
        now = datetime.now(UTC)
        with self._sessions() as session, session.begin():
            rows = session.execute(
                select(ApprovalEventRecord.block_hash, ApprovalEventRecord.log_index).where(
                    (ApprovalEventRecord.chain_id == chain_id)
                    & ApprovalEventRecord.block_hash.in_(hashes)
                )
            )
            existing = {(block_hash, log_index) for block_hash, log_index in rows}
            new = [e for e in events if (e.block_hash, e.log_index) not in existing]
            session.add_all(
                ApprovalEventRecord(
                    chain_id=chain_id,
                    token=e.token,
                    owner=e.owner,
                    spender=e.spender,
                    value=str(e.value),
                    block_number=e.block_number,
                    block_hash=e.block_hash,
                    transaction_hash=e.transaction_hash,
                    transaction_index=e.transaction_index,
                    log_index=e.log_index,
                    data_source=data_source,
                    ingested_at=now,
                )
                for e in new
            )
        return len(new)

    def list_for_address(
        self,
        chain_id: int,
        address: str,
        *,
        limit: int,
        offset: int,
        observation_type: str | None = None,
    ) -> tuple[list[AddressObservation], int]:
        condition = (AddressObservation.chain_id == chain_id) & (
            AddressObservation.address == address
        )
        if observation_type is not None:
            condition = condition & (AddressObservation.observation_type == observation_type)
        with self._sessions() as session:
            total = session.scalar(
                select(func.count()).select_from(AddressObservation).where(condition)
            )
            rows = session.scalars(
                select(AddressObservation)
                .where(condition)
                .order_by(AddressObservation.block_number.desc(), AddressObservation.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
        return list(rows), int(total or 0)

    def latest_payload(
        self, chain_id: int, address: str, observation_type: str
    ) -> dict[str, Any] | None:
        rows, _ = self.list_for_address(
            chain_id, address, limit=1, offset=0, observation_type=observation_type
        )
        return rows[0].payload if rows else None

    def count_approval_events(self, chain_id: int, owner: str) -> int:
        with self._sessions() as session:
            total = session.scalar(
                select(func.count())
                .select_from(ApprovalEventRecord)
                .where(
                    (ApprovalEventRecord.chain_id == chain_id)
                    & (ApprovalEventRecord.owner == owner)
                )
            )
        return int(total or 0)

    def purge(self, address: str | None = None) -> int:
        """Delete locally stored observations and events (all, or for one address)."""
        observations = delete(AddressObservation)
        events = delete(ApprovalEventRecord)
        if address is not None:
            observations = observations.where(AddressObservation.address == address)
            events = events.where(ApprovalEventRecord.owner == address)
        with self._sessions() as session, session.begin():
            removed = session.execute(observations)
            removed_events = session.execute(events)
        return sum(int(getattr(r, "rowcount", 0) or 0) for r in (removed, removed_events))


def open_repository(database_url: str) -> ObservationRepository:
    engine = create_db_engine(database_url)
    init_schema(engine)
    return ObservationRepository(engine)

"""Engine setup and the observation repository."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import Connection, Engine, create_engine, delete, event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from cryptoguard.blockchain.erc20 import ApprovalEvent, TransferEvent
from cryptoguard.database.models import (
    AddressObservation,
    ApprovalEventRecord,
    CampaignExpansionTaskRecord,
    CampaignMembershipRecord,
    CampaignRunRecord,
    FindingRecord,
    FindingTransitionRecord,
    TokenTransferRecord,
    WalletSnapshotRecord,
    WalletTransactionRecord,
)
from cryptoguard.services.wallet_txs import WalletTransaction

if TYPE_CHECKING:
    from cryptoguard.database.history import HistoryRepository
from cryptoguard.services.approvals import APPROVAL_SCAN_OBSERVATION_TYPE, ApprovalScanReport
from cryptoguard.services.inspection import OBSERVATION_TYPE, AddressInspection


def create_db_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)
    if url.database in (None, "", ":memory:"):
        # One shared connection so the in-memory database survives across threads.
        engine = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    else:
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False})
    _transactional_sqlite(engine)
    return engine


def _transactional_sqlite(engine: Engine) -> None:
    """Let SQLAlchemy, not the sqlite3 driver, start transactions.

    The driver opens a transaction only before INSERT/UPDATE/DELETE, so DDL (``ALTER TABLE``
    in a migration) autocommits even inside ``engine.begin()``: an interrupted migration
    left half its changes behind. SQLAlchemy's documented recipe: disable the driver's
    transaction handling and emit ``BEGIN`` when SQLAlchemy begins one.
    """

    @event.listens_for(engine, "connect")
    def _no_driver_transactions(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _begin(conn: Connection) -> None:
        conn.exec_driver_sql("BEGIN")


def init_schema(engine: Engine) -> None:
    """Create missing tables, apply pending migrations, then verify the live schema."""
    from cryptoguard.database.migrations import migrate, verify

    migrate(engine)
    verify(engine)


def insert_approval_events(
    session: Session, chain_id: int, data_source: str, events: Sequence[ApprovalEvent]
) -> int:
    """Insert events not yet stored (identity: chain, block hash, log index). Returns count."""
    if not events:
        return 0
    hashes = {e.block_hash for e in events}
    rows = session.execute(
        select(ApprovalEventRecord.block_hash, ApprovalEventRecord.log_index).where(
            (ApprovalEventRecord.chain_id == chain_id) & ApprovalEventRecord.block_hash.in_(hashes)
        )
    )
    existing = {(block_hash, log_index) for block_hash, log_index in rows}
    new = [e for e in events if (e.block_hash, e.log_index) not in existing]
    now = datetime.now(UTC)
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


def insert_wallet_transactions(
    session: Session,
    chain_id: int,
    wallet: str,
    data_source: str,
    transactions: Sequence[WalletTransaction],
) -> int:
    """Insert wallet-signed transactions not yet stored. Returns the number inserted."""
    if not transactions:
        return 0
    rows = session.execute(
        select(WalletTransactionRecord.transaction_hash, WalletTransactionRecord.block_hash).where(
            (WalletTransactionRecord.chain_id == chain_id)
            & (WalletTransactionRecord.wallet == wallet)
            & WalletTransactionRecord.transaction_hash.in_(
                {t.transaction_hash for t in transactions}
            )
        )
    )
    existing = {(tx_hash, block_hash) for tx_hash, block_hash in rows}
    new = [t for t in transactions if (t.transaction_hash, t.block_hash) not in existing]
    now = datetime.now(UTC)
    session.add_all(
        WalletTransactionRecord(
            chain_id=chain_id,
            wallet=wallet,
            transaction_hash=t.transaction_hash,
            block_number=t.block_number,
            block_hash=t.block_hash,
            transaction_index=t.transaction_index,
            nonce=t.nonce,
            to=t.to,
            value=str(t.value),
            succeeded=t.succeeded,
            data_source=data_source,
            ingested_at=now,
        )
        for t in new
    )
    return len(new)


def insert_transfers(
    session: Session,
    chain_id: int,
    wallet: str,
    data_source: str,
    transfers: Sequence[TransferEvent],
) -> int:
    """Insert transfers not yet stored for ``wallet``. Returns the number inserted."""
    if not transfers:
        return 0
    hashes = {t.block_hash for t in transfers}
    rows = session.execute(
        select(TokenTransferRecord.block_hash, TokenTransferRecord.log_index).where(
            (TokenTransferRecord.chain_id == chain_id)
            & (TokenTransferRecord.wallet == wallet)
            & TokenTransferRecord.block_hash.in_(hashes)
        )
    )
    existing = {(block_hash, log_index) for block_hash, log_index in rows}
    new = [t for t in transfers if (t.block_hash, t.log_index) not in existing]
    now = datetime.now(UTC)
    session.add_all(
        TokenTransferRecord(
            chain_id=chain_id,
            wallet=wallet,
            token=t.token,
            sender=t.sender,
            recipient=t.recipient,
            value=str(t.value),
            block_number=t.block_number,
            block_hash=t.block_hash,
            transaction_hash=t.transaction_hash,
            transaction_index=t.transaction_index,
            log_index=t.log_index,
            tx_sender=t.tx_sender,
            data_source=data_source,
            ingested_at=now,
        )
        for t in new
    )
    return len(new)


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
        with self._sessions() as session, session.begin():
            return insert_approval_events(session, chain_id, data_source, events)

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
        """Delete all locally stored data (or one address's): observations, events, snapshots,
        findings and their transitions. Returns the number of rows removed."""
        finding_ids = select(FindingRecord.id)
        transitions = delete(FindingTransitionRecord)
        findings = delete(FindingRecord)
        snapshots = delete(WalletSnapshotRecord)
        observations = delete(AddressObservation)
        events = delete(ApprovalEventRecord)
        transfers = delete(TokenTransferRecord)
        wallet_txs = delete(WalletTransactionRecord)
        # Campaign runs are derived from many wallets: purging one wallet removes every run
        # that mentions it, so no derived copy of its data outlives the purge.
        run_ids = select(CampaignMembershipRecord.run_id).distinct()
        tasks = delete(CampaignExpansionTaskRecord)
        if address is not None:
            run_ids = run_ids.where(CampaignMembershipRecord.address == address)
            tasks = tasks.where(CampaignExpansionTaskRecord.entity == address)
            transfers = transfers.where(TokenTransferRecord.wallet == address)
            wallet_txs = wallet_txs.where(WalletTransactionRecord.wallet == address)
            finding_ids = finding_ids.where(FindingRecord.address == address)
            transitions = transitions.where(FindingTransitionRecord.finding_id.in_(finding_ids))
            findings = findings.where(FindingRecord.address == address)
            snapshots = snapshots.where(WalletSnapshotRecord.address == address)
            observations = observations.where(AddressObservation.address == address)
            events = events.where(ApprovalEventRecord.owner == address)
        removed = 0
        with self._sessions() as session, session.begin():
            # Children first, so foreign keys hold on databases that enforce them.
            members = delete(CampaignMembershipRecord)
            runs = delete(CampaignRunRecord)
            if address is not None:
                run_list = [int(r) for r in session.scalars(run_ids).all()]
                members = members.where(CampaignMembershipRecord.run_id.in_(run_list))
                runs = runs.where(CampaignRunRecord.id.in_(run_list))
            for statement in (
                members,
                runs,
                tasks,
                transitions,
                findings,
                snapshots,
                observations,
                events,
                transfers,
                wallet_txs,
            ):
                removed += int(getattr(session.execute(statement), "rowcount", 0) or 0)
        return removed


def open_repository(database_url: str) -> HistoryRepository:
    from cryptoguard.database.history import HistoryRepository

    engine = create_db_engine(database_url)
    init_schema(engine)
    return HistoryRepository(engine)

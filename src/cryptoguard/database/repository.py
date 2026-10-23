"""Engine setup and the observation repository."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, delete, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cryptoguard.database.models import AddressObservation, Base
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

    def save_inspection(self, inspection: AddressInspection) -> bool:
        """Store an inspection. Returns ``False`` if the identical observation already exists."""
        row = AddressObservation(
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
        with self._sessions() as session:
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return False
        return True

    def list_for_address(
        self, chain_id: int, address: str, *, limit: int, offset: int
    ) -> tuple[list[AddressObservation], int]:
        condition = (AddressObservation.chain_id == chain_id) & (
            AddressObservation.address == address
        )
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

    def purge(self, address: str | None = None) -> int:
        """Delete locally stored observations (all, or for one address)."""
        statement = delete(AddressObservation)
        if address is not None:
            statement = statement.where(AddressObservation.address == address)
        with self._sessions() as session, session.begin():
            result = session.execute(statement)
        return int(getattr(result, "rowcount", 0) or 0)


def open_repository(database_url: str) -> ObservationRepository:
    engine = create_db_engine(database_url)
    init_schema(engine)
    return ObservationRepository(engine)

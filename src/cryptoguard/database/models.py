"""ORM models.

Timestamps are stored as naive UTC (SQLite has no time zones) and returned as aware UTC.
Block time (``block_timestamp``) and CryptoGuard's own observation time (``observed_at``) are
kept as separate columns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Index, String, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not accepted; use UTC-aware values")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class AddressObservation(Base):
    """One observation of an address's state at a specific block.

    The identity (chain, address, block hash, type, source) makes writes idempotent: repeating
    an inspection at the same block does not create a duplicate row. Keying on the block hash
    rather than the number keeps observations from different forks distinct.
    """

    __tablename__ = "address_observations"
    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "address",
            "block_hash",
            "observation_type",
            "data_source",
            name="uq_address_observation_identity",
        ),
        Index("ix_address_observation_wallet_block", "chain_id", "address", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    address: Mapped[str] = mapped_column(String(42))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    block_timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    observation_type: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(64))
    data_source: Mapped[str] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime())
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

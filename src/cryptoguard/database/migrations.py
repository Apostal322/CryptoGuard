"""Versioned schema migrations, small enough to read in full.

``create_all`` creates missing tables but never changes an existing one. Each migration
below changes existing tables, is idempotent (it inspects before altering), and has a
``down`` step. ``migrate`` records what it applied in ``schema_versions``; ``verify``
then compares every mapped column with the live database and refuses to start on a
mismatch instead of failing later with an obscure SQL error.

Version 1 is the schema of every database created before versioning existed (0.1.0
development builds up to ``7fe824a``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Connection, Engine, delete, insert, inspect, select, text

from cryptoguard.core.errors import CryptoGuardError
from cryptoguard.database.models import Base, SchemaVersionRecord


class SchemaMismatchError(CryptoGuardError):
    code = "schema_mismatch"
    http_status = 500


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    up: Callable[[Connection], None]
    down: Callable[[Connection], None]


def _has_column(conn: Connection, table: str, column: str) -> bool:
    return column in {c["name"] for c in inspect(conn).get_columns(table)}


def _add_wallet_tx_status(conn: Connection) -> None:
    if not _has_column(conn, "wallet_transactions", "succeeded"):
        conn.execute(text("ALTER TABLE wallet_transactions ADD COLUMN succeeded BOOLEAN"))


def _drop_wallet_tx_status(conn: Connection) -> None:
    if _has_column(conn, "wallet_transactions", "succeeded"):
        conn.execute(text("ALTER TABLE wallet_transactions DROP COLUMN succeeded"))


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        2,
        "wallet_transactions.succeeded: receipt status of ETH-carrying transactions",
        _add_wallet_tx_status,
        _drop_wallet_tx_status,
    ),
)
CURRENT_VERSION = max(m.version for m in MIGRATIONS)


def current_version(conn: Connection) -> int:
    if not inspect(conn).has_table("schema_versions"):
        return 1
    applied = conn.execute(select(SchemaVersionRecord.version)).scalars().all()
    return max(applied, default=1)


def migrate(engine: Engine) -> list[int]:
    """Create missing tables, then apply pending migrations in order (one transaction).
    Returns the versions applied."""
    applied: list[int] = []
    with engine.begin() as conn:
        version = current_version(conn)
        Base.metadata.create_all(conn)
        for m in MIGRATIONS:
            if m.version <= version:
                continue
            m.up(conn)
            conn.execute(
                insert(SchemaVersionRecord).values(
                    version=m.version, description=m.description, applied_at=datetime.now(UTC)
                )
            )
            applied.append(m.version)
    return applied


def downgrade(engine: Engine, target: int) -> list[int]:
    """Undo migrations above ``target`` (newest first). For tests and recovery only."""
    undone: list[int] = []
    with engine.begin() as conn:
        version = current_version(conn)
        for m in sorted(MIGRATIONS, key=lambda m: -m.version):
            if target < m.version <= version:
                m.down(conn)
                conn.execute(
                    delete(SchemaVersionRecord).where(SchemaVersionRecord.version == m.version)
                )
                undone.append(m.version)
    return undone


def verify(engine: Engine) -> None:
    """Every mapped table and column must exist in the database."""
    insp = inspect(engine)
    problems: list[str] = []
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            problems.append(f"missing table {table.name}")
            continue
        live = {c["name"] for c in insp.get_columns(table.name)}
        problems += [
            f"missing column {table.name}.{c.name}" for c in table.columns if c.name not in live
        ]
    if problems:
        raise SchemaMismatchError(
            "The database schema does not match this version of CryptoGuard ("
            + "; ".join(problems)
            + "). Back it up and run with a matching version, or purge it."
        )

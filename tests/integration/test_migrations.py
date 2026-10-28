"""Schema upgrade path: a database created by 7fe824a (schema v1) opens and upgrades."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import inspect

from cryptoguard.database.history import HistoryRepository
from cryptoguard.database.migrations import (
    CURRENT_VERSION,
    SchemaMismatchError,
    current_version,
    downgrade,
    migrate,
)
from cryptoguard.database.repository import (
    create_db_engine,
    init_schema,
    insert_wallet_transactions,
)
from cryptoguard.services.wallet_txs import WalletTransaction

V1_DDL = Path(__file__).parent.parent / "fixtures" / "schema_v1.sql"
WALLET = "0x" + "AB" * 20


def v1_database(path: Path) -> str:
    con = sqlite3.connect(path)
    con.executescript(V1_DDL.read_text(encoding="utf-8"))
    con.execute(
        "INSERT INTO wallet_transactions (chain_id, wallet, transaction_hash, block_number, "
        'block_hash, transaction_index, nonce, "to", value, data_source, ingested_at) VALUES '
        "(1, ?, ?, 10, ?, 0, 0, ?, '5', 'rpc', '2026-10-01 00:00:00')",
        (WALLET, "0x" + "11" * 32, "0x" + "22" * 32, "0x" + "CD" * 20),
    )
    con.commit()
    con.close()
    return f"sqlite:///{path.as_posix()}"


def test_v1_database_upgrades_in_place_and_keeps_its_data(tmp_path: Path) -> None:
    engine = create_db_engine(v1_database(tmp_path / "v1.db"))
    with engine.connect() as conn:
        assert current_version(conn) == 1
    init_schema(engine)
    with engine.connect() as conn:
        assert current_version(conn) == CURRENT_VERSION
    columns = {c["name"] for c in inspect(engine).get_columns("wallet_transactions")}
    assert "succeeded" in columns
    assert inspect(engine).has_table("operation_leases")
    repo = HistoryRepository(engine)
    [old] = repo.load_wallet_transactions(1, WALLET, "rpc", 10)
    assert (old.value, old.succeeded) == (5, None)  # pre-migration rows: status unknown
    with repo._sessions() as session, session.begin():
        insert_wallet_transactions(
            session,
            1,
            WALLET,
            "rpc",
            [WalletTransaction("0x" + "33" * 32, 11, "0x" + "44" * 32, 0, 1, None, 7, False)],
        )
    assert [t.succeeded for t in repo.load_wallet_transactions(1, WALLET, "rpc", 10)] == [
        None,
        False,
    ]


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    engine = create_db_engine(v1_database(tmp_path / "v1.db"))
    assert migrate(engine) == [2]
    assert migrate(engine) == []
    init_schema(engine)  # and verification passes on the result


def test_downgrade_and_reupgrade(tmp_path: Path) -> None:
    engine = create_db_engine(v1_database(tmp_path / "v1.db"))
    init_schema(engine)
    assert downgrade(engine, 1) == [2]
    assert "succeeded" not in {
        c["name"] for c in inspect(engine).get_columns("wallet_transactions")
    }
    init_schema(engine)
    assert "succeeded" in {c["name"] for c in inspect(engine).get_columns("wallet_transactions")}


def test_fresh_database_is_created_at_the_current_version(tmp_path: Path) -> None:
    engine = create_db_engine(f"sqlite:///{(tmp_path / 'new.db').as_posix()}")
    init_schema(engine)
    with engine.connect() as conn:
        assert current_version(conn) == CURRENT_VERSION


def test_mismatched_schema_refuses_to_start(tmp_path: Path) -> None:
    path = tmp_path / "broken.db"
    engine = create_db_engine(f"sqlite:///{path.as_posix()}")
    init_schema(engine)
    engine.dispose()
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE token_transfers DROP COLUMN tx_sender")
    con.commit()
    con.close()
    with pytest.raises(SchemaMismatchError, match=r"token_transfers\.tx_sender"):
        init_schema(create_db_engine(f"sqlite:///{path.as_posix()}"))


def test_interrupted_migration_leaves_the_database_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import text

    from cryptoguard.database import migrations

    def half_done(conn) -> None:  # type: ignore[no-untyped-def]
        conn.execute(text("ALTER TABLE wallet_transactions ADD COLUMN succeeded BOOLEAN"))
        raise RuntimeError("power cut")  # fails after its first change

    broken = migrations.Migration(2, "interrupted", half_done, migrations._drop_wallet_tx_status)
    monkeypatch.setattr(migrations, "MIGRATIONS", (broken,))
    engine = create_db_engine(v1_database(tmp_path / "v1.db"))
    with pytest.raises(RuntimeError, match="power cut"):
        migrations.migrate(engine)
    with engine.connect() as conn:
        assert current_version(conn) == 1  # nothing recorded
    assert "succeeded" not in {
        c["name"] for c in inspect(engine).get_columns("wallet_transactions")
    }
    with engine.connect() as conn:  # the old row survived (raw SQL: the model expects v2)
        assert conn.execute(text("SELECT count(*) FROM wallet_transactions")).scalar() == 1
    monkeypatch.undo()
    init_schema(engine)  # a later normal start completes the upgrade
    with engine.connect() as conn:
        assert current_version(conn) == CURRENT_VERSION

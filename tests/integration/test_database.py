from __future__ import annotations

from pathlib import Path

from cryptoguard.core.chains import get_chain
from cryptoguard.database.repository import open_repository
from cryptoguard.services.demo import DEMO_ACCOUNTS, DemoProvider
from cryptoguard.services.inspection import inspect_address


async def test_observations_survive_restart_and_can_be_purged(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'nested' / 'cg.db').as_posix()}"
    demo = DemoProvider(1)
    inspection = await inspect_address(demo, DEMO_ACCOUNTS[0].address, chain=get_chain(1))

    first = open_repository(url)
    assert first.save_inspection(inspection) is True
    assert first.save_inspection(inspection) is False  # unique identity → idempotent

    reopened = open_repository(url)  # simulates an application restart
    rows, total = reopened.list_for_address(1, inspection.address, limit=10, offset=0)
    assert total == 1
    row = rows[0]
    assert row.block_hash == inspection.block.hash
    assert row.block_timestamp == inspection.block.timestamp  # round-trips as aware UTC
    assert row.observed_at.tzinfo is not None
    assert row.data_source == "demo_fixture"

    assert reopened.purge(inspection.address) == 1
    assert reopened.list_for_address(1, inspection.address, limit=10, offset=0)[1] == 0

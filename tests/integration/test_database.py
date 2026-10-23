from __future__ import annotations

from pathlib import Path

from cryptoguard.core.chains import get_chain
from cryptoguard.database.repository import open_repository
from cryptoguard.services.approvals import ScanLimits, scan_approvals
from cryptoguard.services.demo import DEMO_ACCOUNTS, DemoProvider
from cryptoguard.services.inspection import inspect_address
from cryptoguard.services.snapshots import take_snapshot


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


async def test_approval_events_are_idempotent_and_purgeable(tmp_path: Path) -> None:
    repo = open_repository(f"sqlite:///{(tmp_path / 'cg.db').as_posix()}")
    wallet = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
    scan = await scan_approvals(
        DemoProvider(1),
        wallet,
        chain=get_chain(1),
        limits=ScanLimits(10_000, 100_000, 1000, 100, 50),
    )
    assert len(scan.events) == 4

    assert repo.save_approval_scan(scan.report, scan.events) == (True, 4)
    assert repo.save_approval_scan(scan.report, scan.events) == (False, 0)
    assert repo.count_approval_events(1, wallet) == 4
    payload = repo.latest_payload(1, wallet, "approval_scan")
    assert payload is not None
    assert payload["owner"] == wallet

    assert repo.purge(wallet) == 5  # 1 report + 4 events
    assert repo.count_approval_events(1, wallet) == 0


async def test_purge_removes_snapshots_findings_and_transitions(tmp_path: Path) -> None:
    repo = open_repository(f"sqlite:///{(tmp_path / 'cg.db').as_posix()}")
    wallet = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
    outcome = await take_snapshot(
        DemoProvider(1),
        repo,
        wallet,
        chain=get_chain(1),
        limits=ScanLimits(10_000, 100_000, 1000, 100, 50),
        confirmations=0,
    )
    assert outcome.finding_events
    assert repo.list_findings(1, wallet)
    removed = repo.purge(wallet)
    assert removed >= 1 + len(outcome.finding_events) * 2  # snapshot, findings, transitions
    assert repo.list_findings(1, wallet) == []
    assert repo.timeline(1, wallet, limit=10, offset=0)[1] == 0

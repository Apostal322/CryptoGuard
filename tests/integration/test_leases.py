"""Database leases: single-flight across real OS processes, crash recovery and fencing."""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import get_chain
from cryptoguard.database.history import HistoryRepository
from cryptoguard.database.leases import LeaseLostError, LeaseStore
from cryptoguard.database.repository import create_db_engine, init_schema
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.snapshots import take_snapshot
from tests.fakenode import FakeNode

KEY = "campaign-run:1:rpc"


def _repo(url: str) -> HistoryRepository:
    engine = create_db_engine(url)
    init_schema(engine)
    return HistoryRepository(engine)


def _contend(url: str, start: float, results: mp.Queue) -> None:  # runs in a child process
    repo = _repo(url)
    while time.time() < start:  # line every process up on the same instant
        time.sleep(0.001)
    lease = LeaseStore(repo).acquire(KEY, 30)
    results.put(os.getpid() if lease is not None else None)


def _crash_holding_lease(url: str) -> None:  # child: take the lease, then die without release
    LeaseStore(_repo(url)).acquire(KEY, 1)
    os._exit(1)


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    url = f"sqlite:///{(tmp_path / 'leases.db').as_posix()}"
    _repo(url)  # create the schema once, before any child starts
    return url


def test_only_one_process_wins_a_simultaneous_acquire(db_url: str) -> None:
    ctx = mp.get_context("spawn")
    results: mp.Queue = ctx.Queue()
    start = time.time() + 3.0
    procs = [ctx.Process(target=_contend, args=(db_url, start, results)) for _ in range(6)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0
    winners = [r for r in (results.get(timeout=5) for _ in procs) if r is not None]
    assert len(winners) == 1


def test_lease_of_a_crashed_process_is_recovered_after_expiry(db_url: str) -> None:
    ctx = mp.get_context("spawn")
    p = ctx.Process(target=_crash_holding_lease, args=(db_url,))
    p.start()
    p.join(timeout=60)
    assert p.exitcode == 1
    store = LeaseStore(_repo(db_url))
    assert store.acquire(KEY, 30) is None  # still held by the dead owner
    time.sleep(1.2)
    recovered = store.acquire(KEY, 30)
    assert recovered is not None
    assert recovered.generation == 2


def test_stale_worker_is_fenced_out_and_cannot_release_the_new_lease(db_url: str) -> None:
    repo = _repo(db_url)
    store = LeaseStore(repo)
    stale = store.acquire(KEY, 0.5)
    assert stale is not None
    time.sleep(0.7)
    fresh = store.acquire(KEY, 30)
    assert fresh is not None
    assert fresh.generation == stale.generation + 1
    with repo._sessions() as session, session.begin(), pytest.raises(LeaseLostError):
        LeaseStore.check(session, stale)
    assert store.release(stale) is False  # the stale owner cannot free the new lease
    assert store.holder(KEY) == fresh
    with repo._sessions() as session, session.begin():
        LeaseStore.check(session, fresh)  # the current owner passes


async def test_overrunning_snapshot_saves_nothing_and_frees_the_wallet(
    node: FakeNode, provider: RpcEthereumProvider, db_url: str
) -> None:
    repo = _repo(db_url)
    node.head = 1_000
    wallet = "0x" + "a1" * 20
    node.set_account(wallet)
    limits = ScanLimits(1_000, 5_000, 1_000, 100, 50)
    with pytest.raises(LeaseLostError):
        await take_snapshot(
            provider,
            repo,
            wallet,
            chain=get_chain(1),
            limits=limits,
            confirmations=0,
            block=950,
            lease_seconds=0.000001,  # expires before the write
        )
    assert repo.recent_snapshots(1, to_checksum_address(wallet), "rpc", 1) == []
    assert LeaseStore(repo).holder(f"snapshot:1:rpc:{to_checksum_address(wallet)}") is None
    ok = await take_snapshot(
        provider, repo, wallet, chain=get_chain(1), limits=limits, confirmations=0, block=950
    )
    assert ok.created
    assert len(repo.recent_snapshots(1, to_checksum_address(wallet), "rpc", 5)) == 1


def test_failing_campaign_run_releases_its_lease(
    monkeypatch: pytest.MonkeyPatch, db_url: str
) -> None:
    from cryptoguard.core.config import Settings
    from cryptoguard.services import campaigns

    repo = _repo(db_url)

    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("analysis failed")

    monkeypatch.setattr(campaigns, "_run_analysis", boom)
    settings = Settings(_env_file=None, campaign_analysis="shadow")  # type: ignore[call-arg]
    with pytest.raises(RuntimeError):
        campaigns.run_analysis(repo, chain_id=1, data_source="rpc", settings=settings)
    assert LeaseStore(repo).holder(KEY) is None  # no permanent lock after a failure

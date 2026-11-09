"""Database leases: single-flight across real OS processes, crash recovery and fencing."""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from datetime import UTC, datetime, timedelta
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
    try:
        repo = _repo(url)
        while time.time() < start:  # line every process up on the same instant
            time.sleep(0.001)
        lease = LeaseStore(repo).acquire(KEY, 30)
        results.put(("won" if lease is not None else "lost", os.getpid()))
    except Exception as exc:  # reported to the parent: a failure must say what happened
        results.put(("error", f"{type(exc).__name__}: {exc}"))


CRASH_TTL = 3_600.0  # expiry is probed with explicit clock values, so no real wait depends on it
CRASHED_HOLDING = 17  # the child took the lease and died without releasing it
CHILD_GOT_NONE = 3  # the child could not take the lease (a test-setup failure)
# An exception in the child exits with code 1: distinct from both, so a child failure is never
# mistaken for the crash under test.


def _crash_holding_lease(url: str) -> None:  # child: take the lease, then die without release
    lease = LeaseStore(_repo(url)).acquire(KEY, CRASH_TTL)
    os._exit(CRASHED_HOLDING if lease is not None else CHILD_GOT_NONE)


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
    outcomes = [results.get(timeout=5) for _ in procs]
    winners = [o for o in outcomes if o[0] == "won"]
    assert len(winners) <= 1, outcomes  # safety: never two owners, whatever else happens
    errors = [o for o in outcomes if o[0] == "error"]
    assert not errors, errors  # liveness: every contender got an answer
    assert len(winners) == 1, outcomes
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]


def test_a_locked_database_is_reported_as_busy_not_as_free_or_held(tmp_path: Path) -> None:
    """When other writers keep the database locked past the busy timeout, acquire raises the
    retryable LeaseBusyError instead of returning None ("held") or crashing."""
    import sqlite3

    from sqlalchemy import create_engine

    from cryptoguard.database.leases import LeaseBusyError
    from cryptoguard.database.repository import _transactional_sqlite

    path = tmp_path / "busy.db"
    _repo(f"sqlite:///{path.as_posix()}")  # schema
    engine = create_engine(
        f"sqlite:///{path.as_posix()}", connect_args={"timeout": 0.2, "check_same_thread": False}
    )
    _transactional_sqlite(engine)
    store = LeaseStore(HistoryRepository(engine))
    blocker = sqlite3.connect(path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")  # another writer holds the write lock
    try:
        with pytest.raises(LeaseBusyError) as err:
            store.acquire(KEY, 30)
        assert err.value.retryable
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert store.acquire(KEY, 30) is not None  # free again once the writer is gone


def test_lease_of_a_crashed_process_is_recovered_after_expiry(db_url: str) -> None:
    ctx = mp.get_context("spawn")
    p = ctx.Process(target=_crash_holding_lease, args=(db_url,))
    p.start()
    p.join(timeout=180)  # spawn start-up alone took up to 11 s under CPU contention
    if p.is_alive():
        p.kill()
        pytest.fail("the child did not finish within 180 s")
    assert p.exitcode == CRASHED_HOLDING, f"child exit code {p.exitcode} (1: it raised)"
    store = LeaseStore(_repo(db_url))
    held = store.holder(KEY)
    assert held is not None  # the dead owner never released it
    # Expiry is judged with explicit clock values, so these assertions always run and cannot
    # race the scheduler (the earlier version skipped "still held" when the check came late).
    tick = timedelta(microseconds=1)
    assert store.acquire(KEY, 30, now=datetime.now(UTC)) is None  # held, by real time too
    assert store.acquire(KEY, 30, now=held.expires_at - tick) is None  # held until expiry
    assert store.acquire(KEY, 30, now=held.expires_at) is None  # not yet free at the instant
    assert store.holder(KEY) == held  # failed attempts changed nothing
    recovered = store.acquire(KEY, 30, now=held.expires_at + tick)
    assert recovered is not None
    assert recovered.generation == 2
    assert recovered.owner != held.owner


def test_expiry_boundary_never_has_two_owners(db_url: str) -> None:
    """At the expiry instant the old owner is already fenced out and nobody can take over yet;
    one microsecond later the takeover succeeds. No instant has two valid owners."""
    repo = _repo(db_url)
    store = LeaseStore(repo)
    tick = timedelta(microseconds=1)
    first = store.acquire(KEY, 10, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert first is not None
    exp = first.expires_at
    with repo._sessions() as session, session.begin():
        LeaseStore.check(session, first, now=exp - tick)  # still valid just before
    for at in (exp, exp + tick):
        with repo._sessions() as session, session.begin(), pytest.raises(LeaseLostError):
            LeaseStore.check(session, first, now=at)
    assert store.acquire(KEY, 10, now=exp) is None
    second = store.acquire(KEY, 10, now=exp + tick)
    assert second is not None
    assert second.generation == 2


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

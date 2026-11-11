"""Collector and request budget: the cap must hold under retries, crashes and concurrency.

Mock transports only (no RPC). Every test counts real HTTP attempts and compares them with
the ledger: reservations may exceed attempts (a crash after reserving), never the reverse.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import httpx
import pytest

pytest.importorskip("pandas")

import pandas as pd

from cryptoguard.ml import collect as collect_mod
from cryptoguard.ml.collect import (
    BudgetExhaustedError,
    LedgerCorruptError,
    RequestLedger,
    collect,
    load_collected,
)
from tests.ml_synthetic import FakeRpc, make_records


async def _no_sleep(_: float) -> None:
    return None


class Counting(httpx.AsyncBaseTransport):
    """Wraps a transport; counts attempts and can fail or crash on chosen attempts."""

    def __init__(self, inner: httpx.AsyncBaseTransport, *, crash_after: int | None = None):
        self.inner = inner
        self.attempts = 0
        self.crash_after = crash_after

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        if self.crash_after is not None and self.attempts > self.crash_after:
            raise KeyboardInterrupt  # the process dies mid-collection
        return await self.inner.handle_async_request(request)


def _run(
    sample: pd.DataFrame,
    out: Path,
    ledger: RequestLedger,
    transport: httpx.AsyncBaseTransport,
    concurrency: int = 1,
) -> dict[str, int]:
    return asyncio.run(
        collect(
            sample,
            out,
            ledger=ledger,
            transport=transport,
            concurrency=concurrency,
            sleep=_no_sleep,
        )
    )


def test_cap_holds_and_resume_does_not_refetch(tmp_path: Path) -> None:
    labels, records = make_records(n=40)
    sample, out = pd.DataFrame(labels), tmp_path / "chain.jsonl"
    ledger = RequestLedger(tmp_path / "budget.json", cap=60)
    first = Counting(FakeRpc(records).transport())
    stats = _run(sample, out, ledger, first)
    assert first.attempts <= 60
    assert ledger.used() == first.attempts  # every attempt reserved, nothing else
    assert stats["skipped_budget"] > 0
    done = len(load_collected(out))
    second = Counting(FakeRpc(records).transport())
    _run(sample, out, RequestLedger(tmp_path / "budget.json", cap=10_000), second)
    assert len(load_collected(out)) == 40
    assert second.attempts == (40 - done) * collect_mod.REQUESTS_PER_TX


def test_retries_are_reserved_before_they_are_sent(tmp_path: Path) -> None:
    labels, records = make_records(n=3)
    ledger = RequestLedger(tmp_path / "budget.json", cap=1_000)
    transport = Counting(FakeRpc(records, fail={"eth_getCode"}).transport())
    _run(pd.DataFrame(labels), tmp_path / "c.jsonl", ledger, transport)
    # Each transaction: 3 good calls + eth_getCode tried 1 + 4 retries, all reserved.
    assert transport.attempts == 3 * (3 + 5)
    assert ledger.used() == transport.attempts
    rows = [json.loads(line) for line in (tmp_path / "c.jsonl").read_text().splitlines()]
    assert {r["status"] for r in rows} == {"error"}
    assert load_collected(tmp_path / "c.jsonl") == {}  # failures are retried next time


def test_crash_mid_run_never_undercounts(tmp_path: Path) -> None:
    labels, records = make_records(n=20)
    ledger = RequestLedger(tmp_path / "budget.json", cap=1_000)
    transport = Counting(FakeRpc(records).transport(), crash_after=13)
    with pytest.raises(KeyboardInterrupt):
        _run(pd.DataFrame(labels), tmp_path / "c.jsonl", ledger, transport)
    # The 14th attempt was reserved, then the process died while sending it.
    assert ledger.used() >= transport.attempts
    assert ledger.used() == 14


def test_concurrent_collectors_cannot_exceed_a_shared_cap(tmp_path: Path) -> None:
    labels, records = make_records(n=30)
    ledger_path = tmp_path / "budget.json"
    t1, t2 = (Counting(FakeRpc(records).transport()) for _ in range(2))

    async def both() -> None:
        await asyncio.gather(
            collect(
                pd.DataFrame(labels[:15]),
                tmp_path / "a.jsonl",
                ledger=RequestLedger(ledger_path, cap=50),
                transport=t1,
                concurrency=3,
                sleep=_no_sleep,
            ),
            collect(
                pd.DataFrame(labels[15:]),
                tmp_path / "b.jsonl",
                ledger=RequestLedger(ledger_path, cap=50),
                transport=t2,
                concurrency=3,
                sleep=_no_sleep,
            ),
        )

    asyncio.run(both())
    assert t1.attempts + t2.attempts <= 50
    assert RequestLedger(ledger_path, cap=50).used() == t1.attempts + t2.attempts


def test_ledger_reservations_from_many_threads_are_never_lost(tmp_path: Path) -> None:
    ledger_path = tmp_path / "budget.json"
    granted: list[int] = []
    errors: list[BaseException] = []

    def worker() -> None:
        ledger = RequestLedger(ledger_path, cap=150, lock_timeout=300)  # timeouts are fail-safe
        for _ in range(40):
            try:
                ledger.reserve(1)
                granted.append(1)
            except BudgetExhaustedError:
                return
            except BaseException as exc:  # any other failure fails the test
                errors.append(exc)
                return

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(granted) == 150  # 200 asked, exactly the cap granted
    assert RequestLedger(ledger_path, cap=150).used() == 150


def test_corrupt_ledger_stops_collection(tmp_path: Path) -> None:
    labels, records = make_records(n=2)
    (tmp_path / "budget.json").write_text("{not json")
    transport = Counting(FakeRpc(records).transport())
    with pytest.raises(LedgerCorruptError):
        _run(
            pd.DataFrame(labels),
            tmp_path / "c.jsonl",
            RequestLedger(tmp_path / "budget.json", cap=100),
            transport,
        )
    assert transport.attempts == 0  # nothing sent without a valid budget


def test_phase11_ledger_usage_still_counts(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text(json.dumps({"requests": 11_953, "notes": ["interrupted run"]}))
    ledger = RequestLedger(path, cap=12_000)
    assert ledger.reserve(47) == 12_000
    with pytest.raises(BudgetExhaustedError):
        ledger.reserve(1)
    assert json.loads(path.read_text())["notes"] == ["interrupted run"]


def test_cut_off_checkpoint_line_is_repaired_and_refetched(tmp_path: Path) -> None:
    labels, records = make_records(n=4)
    out = tmp_path / "c.jsonl"
    ledger = RequestLedger(tmp_path / "budget.json", cap=1_000)
    _run(pd.DataFrame(labels[:2]), out, ledger, FakeRpc(records).transport())
    with out.open("a", encoding="utf-8") as fh:
        fh.write('{"tx_hash": "0x' + "0" * 20)  # the process died while writing
    assert len(load_collected(out)) == 2  # the cut-off tail is ignored when reading
    stats = _run(pd.DataFrame(labels), out, ledger, FakeRpc(records).transport())
    assert stats["repaired_tail"] == 1
    assert len(load_collected(out)) == 4
    for line in out.read_text().splitlines():
        json.loads(line)  # no corrupt line left behind


def test_corrupt_line_in_the_middle_is_an_error(tmp_path: Path) -> None:
    out = tmp_path / "c.jsonl"
    out.write_text(
        '{"tx_hash": "0xa", "status": "ok"}\n{broken\n{"tx_hash": "0xb", "status": "ok"}\n'
    )
    with pytest.raises(ValueError, match="corrupt checkpoint line 2"):
        load_collected(out)


def test_missing_receipt_is_incomplete_not_a_failed_transaction(tmp_path: Path) -> None:
    labels, records = make_records(n=3)
    gone = labels[0]["tx_hash"]
    out = tmp_path / "c.jsonl"
    stats = _run(
        pd.DataFrame(labels),
        out,
        RequestLedger(tmp_path / "b.json", cap=1_000),
        FakeRpc(records, no_receipt={gone}).transport(),
    )
    assert stats["incomplete"] == 1
    assert gone not in load_collected(out)  # not a finished record: retried next run


def test_duplicate_records_keep_the_latest_success(tmp_path: Path) -> None:
    out = tmp_path / "c.jsonl"
    out.write_text(
        '{"tx_hash": "0xa", "status": "error", "error": "rpc_unavailable"}\n'
        '{"tx_hash": "0xa", "status": "ok", "tx": {"n": 1}}\n'
        '{"tx_hash": "0xa", "status": "ok", "tx": {"n": 2}}\n'
    )
    assert load_collected(out)["0xa"]["tx"] == {"n": 2}


# --- Phase 11.2: process-level failure modes ------------------------------------------

_WORKER = """
import sys
from pathlib import Path
from cryptoguard.ml.collect import BudgetExhaustedError, RequestLedger
ledger = RequestLedger(Path(sys.argv[1]), cap=int(sys.argv[2]))
granted = 0
for _ in range(int(sys.argv[3])):
    try:
        ledger.reserve(1)
        granted += 1
    except BudgetExhaustedError:
        break
print(granted)
"""

_DIES_HOLDING_LOCK = """
import os, sys
from pathlib import Path
from cryptoguard.ml.collect import RequestLedger
ledger = RequestLedger(Path(sys.argv[1]), cap=10)
ledger._acquire()  # take the lock, then die without releasing it
os._exit(0)
"""


def _python(code: str, *args: str) -> str:
    import subprocess
    import sys

    done = subprocess.run(  # noqa: S603 - fixed test code
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_two_processes_cannot_exceed_a_shared_cap(tmp_path: Path) -> None:
    import subprocess
    import sys

    path = tmp_path / "budget.json"
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed test code
            [sys.executable, "-c", _WORKER, str(path), "120", "100"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    granted = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert p.returncode == 0, err
        granted.append(int(out))
    assert sum(granted) == 120  # 200 asked across two processes, exactly the cap granted
    assert RequestLedger(path, cap=120).used() == 120


def test_a_process_that_dies_holding_the_lock_does_not_block_or_corrupt(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    RequestLedger(path, cap=10).reserve(3)
    _python(_DIES_HOLDING_LOCK, str(path))
    ledger = RequestLedger(path, cap=10, lock_timeout=5)
    assert ledger.reserve(1) == 4  # the OS released the dead holder's lock at once


def test_lock_held_by_a_live_holder_times_out_instead_of_being_broken(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    holder = RequestLedger(path, cap=10)
    fd = holder._acquire()
    try:
        with pytest.raises(TimeoutError):
            RequestLedger(path, cap=10, lock_timeout=0.2).reserve(1)
    finally:
        holder._release(fd)
    assert RequestLedger(path, cap=10).used() == 0


def test_zero_budget_sends_nothing(tmp_path: Path) -> None:
    labels, records = make_records(n=3)
    transport = Counting(FakeRpc(records).transport())
    stats = _run(
        pd.DataFrame(labels),
        tmp_path / "c.jsonl",
        RequestLedger(tmp_path / "b.json", cap=0),
        transport,
    )
    assert transport.attempts == 0
    assert stats["skipped_budget"] == 3


class Flaky(httpx.AsyncBaseTransport):
    """Answers 429 or times out on chosen attempts, else a valid eth_chainId reply."""

    def __init__(self, plan: list[str]):
        self.plan = plan
        self.attempts = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        kind = self.plan[self.attempts] if self.attempts < len(self.plan) else "ok"
        self.attempts += 1
        if kind == "429":
            return httpx.Response(429, json={"error": "rate limited"})
        if kind == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        body = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": "0x1"})


def _client(transport: httpx.AsyncBaseTransport, ledger: RequestLedger):  # type: ignore[no-untyped-def]
    from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
    from cryptoguard.ml.collect import BudgetedTransport

    return JsonRpcClient(
        "https://rpc.invalid",
        retry=RetryPolicy(max_retries=4, base_delay=0, max_delay=0),
        transport=BudgetedTransport(transport, ledger),
        sleep=_no_sleep,
    )


def test_rate_limits_and_timeouts_are_counted_as_attempts(tmp_path: Path) -> None:
    ledger = RequestLedger(tmp_path / "b.json", cap=100)
    inner = Flaky(["429", "timeout", "429"])

    async def go() -> object:
        client = _client(inner, ledger)
        try:
            return await client.call("eth_chainId", [])
        finally:
            await client.aclose()

    assert asyncio.run(go()) == "0x1"
    assert inner.attempts == 4
    assert ledger.used() == 4  # three failed attempts and the success, all reserved first


def test_retries_stop_at_the_cap_mid_call(tmp_path: Path) -> None:
    ledger = RequestLedger(tmp_path / "b.json", cap=2)
    inner = Flaky(["429"] * 10)

    async def go() -> None:
        client = _client(inner, ledger)
        try:
            await client.call("eth_chainId", [])
        finally:
            await client.aclose()

    with pytest.raises(BudgetExhaustedError):
        asyncio.run(go())
    assert inner.attempts == 2
    assert ledger.used() == 2


def test_five_async_workers_on_one_client_stay_under_the_cap(tmp_path: Path) -> None:
    ledger = RequestLedger(tmp_path / "b.json", cap=37)
    inner = Flaky([])

    async def go() -> int:
        client = _client(inner, ledger)

        async def worker() -> int:
            done = 0
            for _ in range(20):
                try:
                    await client.call("eth_chainId", [])
                except BudgetExhaustedError:
                    break
                done += 1
            return done

        try:
            return sum(await asyncio.gather(*(worker() for _ in range(5))))
        finally:
            await client.aclose()

    assert asyncio.run(go()) == 37
    assert inner.attempts == 37
    assert ledger.used() == 37


def test_truncated_ledger_file_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text("")  # e.g. a filesystem that lost an unsynced write
    with pytest.raises(LedgerCorruptError):
        RequestLedger(path, cap=10).reserve(1)
    assert path.read_text() == ""  # never silently reset to zero

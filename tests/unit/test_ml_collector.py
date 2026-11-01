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
        ledger = RequestLedger(ledger_path, cap=150)
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

"""Budgeted, resumable collection of point-in-time chain data for labelled transactions.

For each sampled transaction the collector reads, from one RPC endpoint:

1. the transaction (``eth_getTransactionByHash``),
2. its receipt (``eth_getTransactionReceipt``: status, gas used, logs),
3. the sender's nonce at the block *before* the transaction's block
   (``eth_getTransactionCount``), and
4. the target's code at that same earlier block (``eth_getCode``; skipped for contract
   creations).

Nothing after the transaction's own block is read, so features describe what was knowable
when the transaction executed (post-inclusion: the receipt is part of the input). Labels are
never sent anywhere: the sample order is fixed by a seed before collection starts.

Budget: every HTTP attempt (retries included) reserves one unit in a durable ledger *before*
it is sent (``RequestLedger``, ``BudgetedTransport``). The run stops when the ledger is full
and resumes from its JSONL checkpoint, skipping transactions already collected.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.core.errors import RpcError

if TYPE_CHECKING:
    import pandas as pd

REQUESTS_PER_TX = 4
SAMPLE_SEED = 20261029


@dataclass(frozen=True)
class SamplePlan:
    phishing: int = 1_350  # all address-poisoning rows, the rest stratified by subtype
    benign: int = 1_350  # stratified by subtype
    seed: int = SAMPLE_SEED


DEFAULT_PLAN = SamplePlan()


def draw_sample(labels: pd.DataFrame, plan: SamplePlan = DEFAULT_PLAN) -> pd.DataFrame:
    """Deterministic stratified sample, returned in collection order (shuffled, so a
    partial collection stays stratified)."""
    import pandas as pd

    rng = random.Random(plan.seed)  # noqa: S311 - reproducible sampling, not cryptography
    chosen: list[pd.DataFrame] = []

    def stratified(frame: pd.DataFrame, n: int) -> pd.DataFrame:
        counts = frame["subtype"].value_counts().sort_index()
        quotas = (counts / counts.sum() * n).round().astype(int).clip(upper=counts)
        parts = []
        for subtype, quota in quotas.items():
            rows = frame[frame["subtype"] == subtype].sort_values("tx_hash")
            idx = sorted(rng.sample(range(len(rows)), int(quota)))
            parts.append(rows.iloc[idx])
        return pd.concat(parts)

    poisoning = labels[labels["family"] == "address_poisoning"]
    chosen.append(poisoning)
    other = labels[(labels["label"] == 1) & (labels["family"] != "address_poisoning")]
    chosen.append(stratified(other, max(plan.phishing - len(poisoning), 0)))
    chosen.append(stratified(labels[labels["label"] == 0], plan.benign))
    sample = pd.concat(chosen).sort_values("tx_hash").reset_index(drop=True)
    order = list(range(len(sample)))
    rng.shuffle(order)
    sample = sample.iloc[order].reset_index(drop=True)
    sample.insert(0, "order", range(len(sample)))
    return sample


def _done(path: Path) -> set[str]:
    if not path.exists():
        return set()
    done = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row["status"] in ("ok", "not_found"):
                done.add(row["tx_hash"])
    return done


async def collect_one(client: JsonRpcClient, tx_hash: str) -> dict[str, Any]:
    tx = await client.call("eth_getTransactionByHash", [tx_hash])
    if tx is None or tx.get("blockNumber") is None:
        return {"tx_hash": tx_hash, "status": "not_found"}
    receipt = await client.call("eth_getTransactionReceipt", [tx_hash])
    if receipt is None:
        # Mined but no receipt served: never stand in "no logs, failed" for missing data.
        return {"tx_hash": tx_hash, "status": "incomplete"}
    before = hex(int(tx["blockNumber"], 16) - 1)
    nonce = await client.call("eth_getTransactionCount", [tx["from"], before])
    code = "0x"
    if tx.get("to"):
        code = await client.call("eth_getCode", [tx["to"], before])
    logs = receipt.get("logs") or []
    return {
        "tx_hash": tx_hash,
        "status": "ok",
        "tx": {
            k: tx.get(k)
            for k in (
                "blockNumber",
                "from",
                "to",
                "value",
                "gas",
                "gasPrice",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "nonce",
                "type",
                "input",
            )
        },
        "receipt": {
            "status": receipt.get("status"),
            "gasUsed": receipt.get("gasUsed"),
            "contractAddress": receipt.get("contractAddress"),
            "logs": [
                {"address": log["address"], "topics": log["topics"], "data": log["data"]}
                for log in logs
            ],
        },
        "from_nonce_before": nonce,
        "to_code_before": {"size": (len(code) - 2) // 2, "prefix": code[:8]},
    }


class BudgetExhaustedError(RuntimeError):
    """The request ledger has no room for another attempt."""


class LedgerCorruptError(RuntimeError):
    """The request ledger cannot be read; collection refuses to guess (fail closed)."""


def _try_os_lock(fd: int) -> bool:
    """Non-blocking exclusive lock on byte 0 of ``fd``; the OS drops it when the process dies."""
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _os_unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


class RequestLedger:
    """Durable, cross-process request budget: one unit is *reserved before* every HTTP
    attempt (retries included), under an exclusive OS file lock, with an fsynced atomic write.

    Guarantee: the recorded count is never below the number of attempts budgeted clients
    have sent. A crash after reserving over-counts by the attempts it never sent (safe); it
    cannot under-count. Collectors in any number of threads or processes on the same ledger
    cannot together exceed the cap. The lock is an OS lock (``msvcrt``/``flock``), released
    by the OS if its holder dies, so no stale-lock breaking (and its race) is needed. What the
    provider bills is not reconstructed: an attempt cut off in flight may or may not have
    reached it, and the ledger counts it either way. Each reservation is fsynced before the
    request is sent (about 50 ms on a desktop disk), which caps one ledger at roughly 20
    reservations per second: far above free-endpoint rate limits, and the price of surviving
    power loss. A lock timeout raises before anything is sent. The file keeps the Phase 11 format
    (``{"requests": n, "notes": [...]}``) so earlier usage still counts.
    """

    def __init__(self, path: Path, cap: int, *, lock_timeout: float = 30.0) -> None:
        self.path = path
        self.cap = cap
        self.lock_timeout = lock_timeout
        self._lock = path.with_name(path.name + ".lock")

    _local_locks: ClassVar[dict[str, threading.Lock]] = {}
    _local_guard: ClassVar[threading.Lock] = threading.Lock()

    def _local(self) -> threading.Lock:
        key = os.path.abspath(self._lock)
        with self._local_guard:
            return self._local_locks.setdefault(key, threading.Lock())

    def _acquire(self) -> int:
        """Threads of one process queue on a blocking in-process lock (no polling, so none
        starves under load); the OS lock then excludes other processes."""
        deadline = time.monotonic() + self.lock_timeout
        local = self._local()
        if not local.acquire(timeout=self.lock_timeout):
            raise TimeoutError(f"request ledger lock {self._lock} is held")
        try:
            fd = os.open(self._lock, os.O_CREAT | os.O_RDWR)
            while not _try_os_lock(fd):
                if time.monotonic() > deadline:
                    os.close(fd)
                    raise TimeoutError(f"request ledger lock {self._lock} is held")
                time.sleep(0.005)
        except BaseException:
            local.release()
            raise
        return fd

    def _release(self, fd: int) -> None:
        try:
            _os_unlock(fd)
        finally:
            os.close(fd)
            self._local().release()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"requests": 0}
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            int(state["requests"])
        except (ValueError, KeyError, TypeError):
            raise LedgerCorruptError(f"{self.path} is unreadable; fix it by hand") from None
        return dict(state)

    def _write(self, state: dict[str, Any]) -> None:
        tmp = self.path.with_name(self.path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(state, indent=1))
            fh.flush()
            os.fsync(fh.fileno())  # the count is on disk before it can be relied on
        for attempt in range(50):
            try:
                os.replace(tmp, self.path)  # atomic on Windows and POSIX
                return
            except PermissionError:  # Windows: a scanner may hold the target for a moment
                if attempt == 49:
                    raise
                time.sleep(0.01)

    def used(self) -> int:
        fd = self._acquire()  # never read while another process replaces the file
        try:
            return int(self._read()["requests"])
        finally:
            self._release(fd)

    def reserve(self, n: int = 1) -> int:
        """Reserve ``n`` attempts or raise; returns the total reserved afterwards."""
        fd = self._acquire()
        try:
            state = self._read()
            total = int(state["requests"]) + n
            if total > self.cap:
                raise BudgetExhaustedError(f"{state['requests']} of {self.cap} requests used")
            state["requests"] = total
            self._write(state)
            return total
        finally:
            self._release(fd)

    def note(self, text: str, requests: int = 0) -> int:
        """Record a manual charge (e.g. requests made outside the collector)."""
        fd = self._acquire()
        try:
            state = self._read()
            state["requests"] = int(state["requests"]) + requests
            state.setdefault("notes", []).append(text)
            self._write(state)
            return int(state["requests"])
        finally:
            self._release(fd)


class BudgetedTransport(httpx.AsyncBaseTransport):
    """Reserves one ledger unit before handing each HTTP attempt to the real transport."""

    def __init__(self, inner: httpx.AsyncBaseTransport, ledger: RequestLedger) -> None:
        self.inner = inner
        self.ledger = ledger

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.ledger.reserve(1)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def _repair_tail(out: Path) -> bool:
    """Drop a final checkpoint line cut off by a crash (its transaction is fetched again)."""
    if not out.exists():
        return False
    data = out.read_bytes()
    if not data or data.endswith(b"\n"):
        return False
    cut = data.rfind(b"\n") + 1
    with out.open("r+b") as fh:
        fh.truncate(cut)
    return True


async def collect(
    sample: pd.DataFrame,
    out: Path,
    *,
    ledger: RequestLedger,
    rpc_url: str = "https://rpc.invalid",
    transport: httpx.AsyncBaseTransport | None = None,
    concurrency: int = 3,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, int]:
    """Collect chain data for the sample in order until done or the ledger is full. Every
    HTTP attempt is reserved in ``ledger`` first, so the cap holds under retries, crashes
    and concurrent collectors."""
    out.parent.mkdir(parents=True, exist_ok=True)
    repaired = _repair_tail(out)
    done = _done(out)
    todo = [h for h in sample["tx_hash"] if h not in done]
    rpc = JsonRpcClient(
        rpc_url,
        timeout=20,
        retry=RetryPolicy(max_retries=4),
        max_concurrency=concurrency,
        transport=BudgetedTransport(transport or httpx.AsyncHTTPTransport(), ledger),
        sleep=sleep,
    )
    stats = {
        "already": len(done),
        "ok": 0,
        "not_found": 0,
        "incomplete": 0,
        "error": 0,
        "skipped_budget": 0,
        "repaired_tail": int(repaired),
    }
    lock = asyncio.Lock()
    queue: asyncio.Queue[str] = asyncio.Queue()
    for h in todo:
        queue.put_nowait(h)
    exhausted = False

    async def worker() -> None:
        nonlocal exhausted
        while not queue.empty() and not exhausted:
            tx_hash = queue.get_nowait()
            try:
                row = await collect_one(rpc, tx_hash)
            except BudgetExhaustedError:
                exhausted = True
                stats["skipped_budget"] += 1
                return
            except RpcError as exc:
                row = {"tx_hash": tx_hash, "status": "error", "error": exc.code}
            async with lock:
                stats[row["status"]] += 1
                with out.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")

    try:
        await asyncio.gather(*(worker() for _ in range(concurrency)))
    finally:
        stats["skipped_budget"] += queue.qsize()
        stats["requests"] = rpc.metrics.requests
        stats["retries"] = rpc.metrics.retries
        await rpc.aclose()
    return stats


def budget_path(out: Path) -> Path:
    return out.with_name(out.name + ".budget.json")


def requests_used(out: Path) -> int:
    """Cumulative RPC attempts reserved by every run that wrote ``out`` (the cap is a total)."""
    return RequestLedger(budget_path(out), cap=0).used()


def load_collected(path: Path) -> dict[str, dict[str, Any]]:
    """Latest successful record per transaction. A cut-off final line (crash during a
    write) is ignored; a corrupt line anywhere else raises."""
    rows: dict[str, dict[str, Any]] = {}
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for i, line in enumerate(lines):
        try:
            row = json.loads(line)
        except ValueError:
            if i == len(lines) - 1:
                break
            raise ValueError(f"{path}: corrupt checkpoint line {i + 1}") from None
        if row["status"] in ("ok", "not_found"):
            rows[row["tx_hash"]] = row
    return rows

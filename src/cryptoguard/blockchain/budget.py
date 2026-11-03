"""Durable request budgets for live RPC work.

Every HTTP attempt, retries included, reserves one unit in a ledger file *before* it is sent
(``RequestLedger``, ``BudgetedTransport``). The cap therefore holds under retries, crashes and
concurrent processes. Used by the ML collector and by the replay recorders.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

import httpx


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


def run_ledger(path: Path, cap: int, *, per_run: int | None = None) -> RequestLedger:
    """The ledger for one run: never past ``cap`` in total (one approval), and never more than
    ``per_run`` attempts beyond what the ledger already holds."""
    if cap < 1 or (per_run is not None and per_run < 1):
        raise ValueError("request caps must be positive")
    if per_run is None:
        return RequestLedger(path, cap)
    used = RequestLedger(path, cap).used()
    return RequestLedger(path, min(cap, used + per_run))


def budgeted_transport(
    ledger: RequestLedger, inner: httpx.AsyncBaseTransport | None = None
) -> BudgetedTransport:
    return BudgetedTransport(inner or httpx.AsyncHTTPTransport(), ledger)

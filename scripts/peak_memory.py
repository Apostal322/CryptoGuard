"""Run a cryptoguard CLI command and report wall time and peak memory of this process.

Usage: python scripts/peak_memory.py replay run --analytics
Peak memory: PeakWorkingSetSize on Windows (GetProcessMemoryInfo), ru_maxrss elsewhere.
"""

from __future__ import annotations

import ctypes
import sys
import time


def peak_mib() -> float:
    if sys.platform == "win32":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        query = kernel32.K32GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        query.restype = wintypes.BOOL
        if not query(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        return counters.PeakWorkingSetSize / 2**20
    import resource

    kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return kib / 1024 if sys.platform != "darwin" else kib / 2**20


def main() -> int:
    from contextlib import redirect_stdout
    from io import StringIO

    from cryptoguard.cli import main as cli

    sys.argv = ["cryptoguard", *sys.argv[1:]]
    start = time.perf_counter()
    with redirect_stdout(StringIO()):
        code = cli()
    elapsed = time.perf_counter() - start
    print(f"{' '.join(sys.argv[1:])}: {elapsed:.1f} s, peak {peak_mib():.0f} MiB, exit {code}")
    return int(code or 0)


if __name__ == "__main__":
    raise SystemExit(main())

"""Verified, resumable download of one pinned large research file (no default caller).

Nothing here runs from a build, test or default command: ``cryptoguard ml fetch-file``
downloads only the file named on its command line, and only after the user approved it.

Guarantees:
- The data lands in ``<name>.part`` and is renamed only after size, published MD5,
  SHA-256 and (for ``.gz``) a full gzip CRC check pass.
- A resume sends ``Range: bytes=<offset>-`` and appends only to a ``206`` whose
  ``Content-Range`` starts exactly at that offset with the pinned total. A ``200`` means
  the server ignored the range, so the partial file is restarted from byte 0 rather than
  appended to.
- The download stops before free disk would fall below ``reserve_bytes``.
- A completed file that fails verification is renamed ``<name>.corrupt``, never deleted
  and never resumed.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

CHUNK = 1 << 20
DEFAULT_RESERVE = 10 << 30  # keep 10 GiB free on the target disk
GUARD_EVERY_BYTES = 256 << 20  # re-check free space every 256 MiB written
_CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")


@dataclass(frozen=True)
class PinnedFile:
    name: str
    url: str
    size: int
    md5: str  # as published by the repository
    source: str  # DOI or stable identifier
    license: str
    sha256: str | None = None  # pinned after the first verified download


TSUCHIYA_RECORD = "10.1184/R1/29212703.v1"
TSUCHIYA_LICENSE = "CC BY-NC-ND 4.0"
TSUCHIYA_FILES: dict[str, PinnedFile] = {
    f.name: f
    for f in (
        PinnedFile(
            "address_poisoning_ethereum.sql.gz",
            "https://ndownloader.figshare.com/files/55052912",
            2_316_354_530,
            "5001c79f81741eabf54d2917a7954330",
            TSUCHIYA_RECORD,
            TSUCHIYA_LICENSE,
            "270211acb28684dd6eeae549c7b4cec1c8276bee2d302cad0fa79a233b227cea",
        ),
        PinnedFile(
            "README.txt",
            "https://ndownloader.figshare.com/files/55053422",
            9_981,
            "e8cd076a9ba1474133262d43dafa56dc",
            TSUCHIYA_RECORD,
            TSUCHIYA_LICENSE,
            "f5805a108d7b3cbe9a70df721a7f997f6020e303909863bce86d329c4aeed142",
        ),
        PinnedFile(
            "guidance.ipynb",
            "https://ndownloader.figshare.com/files/55053158",
            22_830,
            "10cdc28bb347ebc7eb3e80d9a3891a8e",
            TSUCHIYA_RECORD,
            TSUCHIYA_LICENSE,
            "12d173523d0dcf42f2789fe37aaed7b5c6732b2ec003ad737ed08b6efdb66f85",
        ),
        PinnedFile(
            "payoff_transfers_ethereum.csv",
            "https://ndownloader.figshare.com/files/55053137",
            482_397,
            "a42bda4339981d31a7e31b66c2d92297",
            TSUCHIYA_RECORD,
            TSUCHIYA_LICENSE,
            "7851f9f9edcf04189137894e16dd228a544d13f4a0799548ece79c69762f2f78",
        ),
    )
}


class DownloadError(RuntimeError):
    """The transfer could not be completed safely; the partial file is kept for resume."""


class DiskReserveError(DownloadError):
    """Continuing would push free disk space below the configured reserve."""


class IntegrityError(DownloadError):
    """The completed file does not match its pinned size, checksum or gzip structure."""


def digests(path: Path) -> tuple[str, str]:
    md5, sha = hashlib.md5(usedforsecurity=False), hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(CHUNK):
            md5.update(block)
            sha.update(block)
    return md5.hexdigest(), sha.hexdigest()


def gzip_check(path: Path) -> int:
    """Decompress to nowhere, verifying every member's CRC and length; returns the
    decompressed size. Raises ``IntegrityError`` on truncation or corruption."""
    total = 0
    try:
        with gzip.open(path, "rb") as fh:
            while block := fh.read(CHUNK):
                total += len(block)
    except (OSError, EOFError) as exc:
        raise IntegrityError(f"{path}: gzip check failed: {exc}") from exc
    return total


def _free(path: Path) -> int:
    return shutil.disk_usage(path).free


def verify_local(pinned: PinnedFile, path: Path, *, gzip_crc: bool = True) -> dict[str, Any]:
    """Size and checksums of an already-present file (raises ``IntegrityError``)."""
    return _verify(pinned, path, gzip_crc=gzip_crc)


def _verify(pinned: PinnedFile, path: Path, *, gzip_crc: bool = True) -> dict[str, Any]:
    size = path.stat().st_size
    if size != pinned.size:
        raise IntegrityError(f"{path}: {size} bytes, pinned {pinned.size}")
    md5, sha = digests(path)
    if md5 != pinned.md5:
        raise IntegrityError(f"{path}: md5 {md5} != published {pinned.md5}")
    if pinned.sha256 is not None and sha != pinned.sha256:
        raise IntegrityError(f"{path}: sha256 {sha} != pinned {pinned.sha256}")
    record: dict[str, Any] = {"name": pinned.name, "size": size, "md5": md5, "sha256": sha}
    if gzip_crc and pinned.name.endswith(".gz"):
        record["decompressed_size"] = gzip_check(path)
    return record


def download(
    pinned: PinnedFile,
    dest_dir: Path,
    *,
    client: httpx.Client | None = None,
    reserve_bytes: int = DEFAULT_RESERVE,
    retries: int = 5,
    backoff_s: float = 2.0,
    progress: Callable[[int, int], None] | None = None,
    free_bytes: Callable[[Path], int] = _free,
) -> dict[str, Any]:
    """Download ``pinned`` into ``dest_dir``; returns its verification record."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    final = dest_dir / pinned.name
    part = dest_dir / (pinned.name + ".part")
    if final.exists():
        return {**_verify(pinned, final), "status": "cached"}

    def guard() -> None:
        if free_bytes(dest_dir) < reserve_bytes:
            raise DiskReserveError(f"free disk fell below the {reserve_bytes}-byte reserve")

    own = client is None
    http = client or httpx.Client(timeout=httpx.Timeout(60, read=120), follow_redirects=True)
    try:
        failures = 0
        while True:
            offset = part.stat().st_size if part.exists() else 0
            if offset > pinned.size:
                part.write_bytes(b"")  # our own partial file overshot: restart it
                offset = 0
            if offset == pinned.size:
                break
            if free_bytes(dest_dir) - (pinned.size - offset) < reserve_bytes:
                raise DiskReserveError(
                    f"need {pinned.size - offset} more bytes and a {reserve_bytes}-byte reserve"
                )
            try:
                _transfer(http, pinned, part, offset, progress, guard)
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                failures += 1
                if failures > retries:
                    raise DownloadError(f"{pinned.url}: gave up after {retries} retries") from exc
                time.sleep(backoff_s * failures)
    finally:
        if own:
            http.close()
    try:
        record = _verify(pinned, part)
    except IntegrityError:
        os.replace(part, dest_dir / (pinned.name + ".corrupt"))
        raise
    os.replace(part, final)
    return {
        **record,
        "status": "downloaded",
        "url": pinned.url,
        "source": pinned.source,
        "license": pinned.license,
        "downloaded_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def _transfer(
    http: httpx.Client,
    pinned: PinnedFile,
    part: Path,
    offset: int,
    progress: Callable[[int, int], None] | None,
    guard: Callable[[], None],
) -> None:
    headers = {"Range": f"bytes={offset}-"} if offset else {}
    with http.stream("GET", pinned.url, headers=headers) as resp:
        resp.raise_for_status()
        mode = "ab"
        if offset and resp.status_code == 206:
            m = _CONTENT_RANGE.match(resp.headers.get("content-range", ""))
            if not m or int(m[1]) != offset or int(m[3]) != pinned.size:
                raise DownloadError(
                    f"unexpected Content-Range {resp.headers.get('content-range')!r} "
                    f"for offset {offset}"
                )
        elif resp.status_code == 200:
            if offset:
                offset, mode = 0, "wb"  # range ignored: never append a full body
            length = resp.headers.get("content-length")
            if length is not None and int(length) != pinned.size:
                raise DownloadError(f"Content-Length {length}, pinned {pinned.size}")
        else:
            raise DownloadError(f"unexpected HTTP {resp.status_code}")
        written = offset
        next_guard = written
        with part.open(mode) as fh:
            for block in resp.iter_bytes(CHUNK):
                if written + len(block) > pinned.size:
                    raise DownloadError("server sent more bytes than the pinned size")
                if written >= next_guard:
                    guard()
                    next_guard = written + GUARD_EVERY_BYTES
                fh.write(block)
                written += len(block)
                if progress is not None:
                    progress(written, pinned.size)
            fh.flush()
            os.fsync(fh.fileno())

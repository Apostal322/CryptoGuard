"""Pinned large-file download: range validation, verification and disk safety.

All transfers are mocked (no network). Each test states the invariant it guards.
"""

from __future__ import annotations

import gzip
import hashlib
import random
from pathlib import Path

import httpx
import pytest

from cryptoguard.ml.fetch import (
    DiskReserveError,
    DownloadError,
    IntegrityError,
    PinnedFile,
    download,
    gzip_check,
)

BODY = gzip.compress(random.Random(0).randbytes(50_000))  # incompressible: about 50 KB


def pinned(body: bytes = BODY, name: str = "x.sql.gz") -> PinnedFile:
    md5 = hashlib.md5(body, usedforsecurity=False).hexdigest()
    return PinnedFile(name, "https://example.test/f", len(body), md5, "doi:test", "test")


def server(body: bytes, *, honour_range: bool = True, log: list[str] | None = None) -> httpx.Client:
    def handle(request: httpx.Request) -> httpx.Response:
        rng = request.headers.get("range")
        if log is not None:
            log.append(rng or "")
        if rng and honour_range:
            start = int(rng.removeprefix("bytes=").rstrip("-"))
            return httpx.Response(
                206,
                content=body[start:],
                headers={"content-range": f"bytes {start}-{len(body) - 1}/{len(body)}"},
            )
        return httpx.Response(200, content=body, headers={"content-length": str(len(body))})

    return httpx.Client(transport=httpx.MockTransport(handle))


def plenty(_: Path) -> int:
    return 1 << 40


def test_fresh_download_is_verified_then_renamed(tmp_path: Path) -> None:
    """The file appears under its final name only after size, MD5, SHA-256 and gzip pass."""
    rec = download(pinned(), tmp_path, client=server(BODY), free_bytes=plenty, reserve_bytes=0)
    assert rec["status"] == "downloaded"
    assert rec["sha256"] == hashlib.sha256(BODY).hexdigest()
    assert rec["decompressed_size"] == len(gzip.decompress(BODY))
    assert (tmp_path / "x.sql.gz").read_bytes() == BODY
    assert not (tmp_path / "x.sql.gz.part").exists()


def test_resume_appends_only_a_matching_206(tmp_path: Path) -> None:
    """A partial file resumes from its exact length when the server honours the range."""
    (tmp_path / "x.sql.gz.part").write_bytes(BODY[:1000])
    log: list[str] = []
    download(pinned(), tmp_path, client=server(BODY, log=log), free_bytes=plenty, reserve_bytes=0)
    assert log == ["bytes=1000-"]
    assert (tmp_path / "x.sql.gz").read_bytes() == BODY


def test_ignored_range_restarts_instead_of_appending(tmp_path: Path) -> None:
    """A 200 to a ranged request carries the whole file: appending it would corrupt the
    download, so it is written from byte 0."""
    (tmp_path / "x.sql.gz.part").write_bytes(BODY[:1000])
    download(
        pinned(),
        tmp_path,
        client=server(BODY, honour_range=False),
        free_bytes=plenty,
        reserve_bytes=0,
    )
    assert (tmp_path / "x.sql.gz").read_bytes() == BODY


def test_misaligned_content_range_is_refused(tmp_path: Path) -> None:
    (tmp_path / "x.sql.gz.part").write_bytes(BODY[:1000])

    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            206,
            content=BODY[500:],
            headers={"content-range": f"bytes 500-{len(BODY) - 1}/{len(BODY)}"},
        )

    with pytest.raises(DownloadError, match="Content-Range"):
        download(
            pinned(),
            tmp_path,
            client=httpx.Client(transport=httpx.MockTransport(handle)),
            free_bytes=plenty,
            reserve_bytes=0,
        )
    assert (tmp_path / "x.sql.gz.part").read_bytes() == BODY[:1000]  # kept for a later resume


def test_checksum_mismatch_quarantines_the_file(tmp_path: Path) -> None:
    """A complete file with the wrong content is renamed .corrupt, never kept as final."""
    bad = PinnedFile("x.sql.gz", "https://example.test/f", len(BODY), "0" * 32, "doi:test", "test")
    with pytest.raises(IntegrityError, match="md5"):
        download(bad, tmp_path, client=server(BODY), free_bytes=plenty, reserve_bytes=0)
    assert (tmp_path / "x.sql.gz.corrupt").exists()
    assert not (tmp_path / "x.sql.gz").exists()


def test_truncated_gzip_fails_integrity(tmp_path: Path) -> None:
    """Right size and checksum can still describe a broken archive: the gzip CRC decides."""
    broken = BODY[: len(BODY) // 2]
    path = tmp_path / "b.gz"
    path.write_bytes(broken)
    with pytest.raises(IntegrityError, match="gzip"):
        gzip_check(path)


def test_disk_reserve_is_checked_before_and_during_transfer(tmp_path: Path) -> None:
    """Nothing is written when the reserve cannot be kept, and a shrinking disk stops it."""
    with pytest.raises(DiskReserveError):
        download(
            pinned(), tmp_path, client=server(BODY), free_bytes=lambda _: len(BODY), reserve_bytes=1
        )
    assert not (tmp_path / "x.sql.gz.part").exists()
    calls = iter([1 << 40, 0])
    with pytest.raises(DiskReserveError, match="fell below"):
        download(
            pinned(),
            tmp_path,
            client=server(BODY),
            free_bytes=lambda _: next(calls),
            reserve_bytes=1,
        )


def test_transient_errors_retry_with_a_bound(tmp_path: Path) -> None:
    attempts = []

    def handle(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("boom", request=request)

    with pytest.raises(DownloadError, match="retries"):
        download(
            pinned(),
            tmp_path,
            client=httpx.Client(transport=httpx.MockTransport(handle)),
            free_bytes=plenty,
            reserve_bytes=0,
            retries=2,
            backoff_s=0,
        )
    assert len(attempts) == 3


def test_existing_final_file_is_reverified_not_redownloaded(tmp_path: Path) -> None:
    (tmp_path / "x.sql.gz").write_bytes(BODY)
    log: list[str] = []
    rec = download(
        pinned(), tmp_path, client=server(BODY, log=log), free_bytes=plenty, reserve_bytes=0
    )
    assert rec["status"] == "cached"
    assert log == []

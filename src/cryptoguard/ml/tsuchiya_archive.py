"""Safe streaming reader for Tsuchiya et al.'s ``address_poisoning_ethereum.sql.gz``.

The archive is a PostgreSQL 16 plain-format dump: a preamble (``SET``, ``CREATE DATABASE``,
the psql meta-command ``\\connect``, one ``CREATE TABLE``), one ``COPY ... FROM stdin;``
block of tab-separated rows terminated by ``\\.``, and nothing else of substance. It is
**data, never instructions**: nothing here executes, evaluates or forwards any of its text
to a database. The reader recognises a small whitelist of statement prefixes, checks the
table definition and the COPY column list against the documented schema, parses each row
with type checks, and refuses anything else (another table, ``INSERT`` statements, unknown
statements, truncated input) with a specific error rather than producing partial data.

Memory: the gzip stream is read line by line with a bounded line length (no
decompression to disk, no full materialisation). Exact distinct counts of millions of
addresses spill to bucketed temporary files (``SpillDistinct``) instead of growing an
in-memory set. Only rows touching a small target manifest are stored, in SQLite.

Resumption: gzip offers no record-level seek, so an interrupted scan restarts from byte 0
(deterministic replay). The output database is built under a temporary name and renamed
only when the whole pass completes, so a rerun can never mix partial and complete results.

Column notes (dump header, checked against the README): the COPY column order differs from
the README's (``zero_value_transfer`` precedes ``tiny_transfer``), so columns are always
mapped by name. ``value``/``value_usd`` are PostgreSQL ``real`` (float4, about 7
significant digits) with ``NaN`` for missing: amounts are approximate. There is no log
index, so two identical transfers in one transaction cannot be told apart.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import time
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptoguard.detectors.poisoning import PoisoningConfig, affix_match, is_lookalike
from cryptoguard.ml.candidates import similar, transfer_methods

PARSER_VERSION = "tsuchiya-archive/1"
SCHEMA_VERSION = 1
TABLE = "address_poisoning_ethereum"
COLUMNS: dict[str, str] = {
    "block_number": "integer",
    "tx_hash": "character(66)",
    "addr": "character(42)",
    "topics_from_addr": "character(42)",
    "topics_to_addr": "character(42)",
    "is_sender_victim": "boolean",
    "value": "real",
    "value_usd": "real",
    "intended_transfer": "boolean",
    "zero_value_transfer": "boolean",
    "tiny_transfer": "boolean",
    "counterfeit_token_transfer": "boolean",
    "payoff_transfer": "boolean",
    "payoff_transfer_unconfirmed": "boolean",
    "is_not_categorized": "boolean",
    "intended_addr": "character(42)",
    "num_first_matched_digits": "integer",
    "num_last_matched_digits": "integer",
}
MAX_LINE = 4096  # a valid row is about 400 bytes
NULL = "\\N"

# Category flags (bitmask), in the README's vocabulary.
INTENDED, ZERO, TINY, COUNTERFEIT, PAYOFF, PAYOFF_UNCONFIRMED, UNCATEGORIZED = (
    1 << i for i in range(7)
)
FLAG_COLUMNS = {
    "intended_transfer": INTENDED,
    "zero_value_transfer": ZERO,
    "tiny_transfer": TINY,
    "counterfeit_token_transfer": COUNTERFEIT,
    "payoff_transfer": PAYOFF,
    "payoff_transfer_unconfirmed": PAYOFF_UNCONFIRMED,
    "is_not_categorized": UNCATEGORIZED,
}
FLAG_NAMES = {v: k for k, v in FLAG_COLUMNS.items()}
_FLAG_BITS = tuple(FLAG_COLUMNS.values())  # same order as the flag columns in COLUMNS
_BOOLS: dict[str, bool | None] = {"t": True, "f": False, NULL: None}
POISONING = ZERO | TINY | COUNTERFEIT  # the notebook's definition of a poisoning transfer

_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_COPY = re.compile(rb"^COPY public\.(\w+) \(([^)]*)\) FROM stdin;\n$")
_COLUMN_DEF = re.compile(rb"^    (\w+) ([a-z ]+(?:\(\d+\))?),?\n$")
_PREAMBLE_OK = (
    b"--",
    b"SET ",
    b"SELECT pg_catalog.set_config(",
    b"CREATE DATABASE ",
    b"\\connect ",
)
_POSTAMBLE_OK = (
    b"--",
    b"SET ",
    b"SELECT pg_catalog.",
    b"CREATE INDEX ",
    b"CREATE UNIQUE INDEX ",
    b"ALTER TABLE ",
)
_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\"}


class ArchiveError(ValueError):
    """The archive cannot be read safely; nothing partial is produced."""


class InvalidArchiveError(ArchiveError):
    """Not a gzip stream, or the gzip stream is corrupt."""


class TruncatedArchiveError(ArchiveError):
    """The stream ended inside the data block or inside a gzip member."""


class UnsupportedDumpError(ArchiveError):
    """A statement, table or dump format outside the narrow supported subset."""


class SchemaMismatchError(ArchiveError):
    """The table definition or COPY column list differs from the documented schema."""


class TooManyMalformedError(ArchiveError):
    """More rows failed validation than the configured tolerance."""


def copy_unescape(text: str) -> str:
    """Decode PostgreSQL COPY text escapes (``\\t``, ``\\\\``, octal ``\\NNN``, ``\\xHH``)."""
    if "\\" not in text:
        return text
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\" or i + 1 == len(text):
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
        elif nxt == "x" and i + 2 < len(text) and text[i + 2] in "0123456789abcdefABCDEF":
            j = i + 2
            while j < min(i + 4, len(text)) and text[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(chr(int(text[i + 2 : j], 16)))
            i = j
        elif nxt in "01234567":
            j = i + 1
            while j < min(i + 4, len(text)) and text[j] in "01234567":
                j += 1
            out.append(chr(int(text[i + 1 : j], 8)))
            i = j
        else:
            out.append(nxt)  # PostgreSQL: any other backslashed character stands for itself
            i += 2
    return "".join(out)


@dataclass(frozen=True, slots=True)
class ArchiveTransfer:
    """One validated source row. ``line`` (1-based line in the decompressed dump) is the
    stable source identifier; addresses and hashes are lowercase."""

    line: int
    block: int
    tx: str
    token: str
    sender: str
    receiver: str
    sender_is_victim: bool | None
    value: float | None  # base units, float4-approximate; None for NaN/NULL
    value_usd: float | None
    flags: int
    intended: str | None
    first_digits: int | None
    last_digits: int | None

    @property
    def is_poisoning(self) -> bool:
        return bool(self.flags & POISONING)

    @property
    def victim(self) -> str | None:
        if self.sender_is_victim is None:
            return None
        return self.sender if self.sender_is_victim else self.receiver

    @property
    def counterparty(self) -> str | None:
        """The non-victim side: the lookalike for poisoning and payoff rows."""
        if self.sender_is_victim is None:
            return None
        return self.receiver if self.sender_is_victim else self.sender


@dataclass
class ReaderStats:
    lines: int = 0
    data_rows: int = 0
    valid_rows: int = 0
    decompressed_bytes: int = 0
    preamble: Counter[str] = field(default_factory=Counter)
    postamble: Counter[str] = field(default_factory=Counter)
    malformed: Counter[str] = field(default_factory=Counter)
    malformed_lines: dict[str, list[int]] = field(default_factory=dict)

    def reject(self, reason: str, line: int) -> None:
        self.malformed[reason] += 1
        examples = self.malformed_lines.setdefault(reason, [])
        if len(examples) < 5:
            examples.append(line)

    def as_dict(self) -> dict[str, Any]:
        return {
            "lines": self.lines,
            "data_rows": self.data_rows,
            "valid_rows": self.valid_rows,
            "malformed_rows": sum(self.malformed.values()),
            "decompressed_bytes": self.decompressed_bytes,
            "preamble_statements": dict(sorted(self.preamble.items())),
            "postamble_statements": dict(sorted(self.postamble.items())),
            "malformed": dict(sorted(self.malformed.items())),
            "malformed_example_lines": dict(sorted(self.malformed_lines.items())),
        }


def _keyword(line: bytes) -> str:
    head = line.strip().split(b" ", 2)
    word = b" ".join(head[:2]) if head[0] in (b"CREATE", b"ALTER") else head[0]
    return word.decode("ascii", "replace")[:40] or "(blank)"


def _bool(text: str) -> bool | None:
    if text == "t":
        return True
    if text == "f":
        return False
    if text == NULL:
        return None
    raise ValueError("boolean")


def _real(text: str) -> float | None:
    if text in ("NaN", NULL):
        return None
    try:
        value = float(text)
    except ValueError:
        raise ValueError("real") from None
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non_finite_real")
    return value


def _int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise ValueError("integer") from None


def _opt_int(text: str) -> int | None:
    return None if text == NULL else _int(text)


def _addr(text: str) -> str:
    if not _ADDR.fullmatch(text):
        raise ValueError("address")
    return text.lower()


class ArchiveReader:
    """Iterate validated rows of the dump. Raises an ``ArchiveError`` subclass for
    anything outside the supported subset; per-row validation failures are counted in
    ``stats`` (and fail the read when ``max_malformed_fraction`` is exceeded)."""

    def __init__(self, path: Path, *, max_malformed_fraction: float = 0.001) -> None:
        self.path = path
        self.max_malformed_fraction = max_malformed_fraction
        self.stats = ReaderStats()
        self.columns: list[str] = []

    def __iter__(self) -> Iterator[ArchiveTransfer]:
        try:
            with gzip.open(self.path, "rb") as fh:
                yield from self._read(fh)
        except EOFError as exc:
            raise TruncatedArchiveError(f"{self.path}: gzip stream ended early") from exc
        except (gzip.BadGzipFile, zlib.error) as exc:
            raise InvalidArchiveError(f"{self.path}: {exc}") from exc
        rows = self.stats.data_rows
        bad = rows - self.stats.valid_rows
        if rows and bad / rows > self.max_malformed_fraction:
            raise TooManyMalformedError(
                f"{bad} of {rows} rows malformed: {dict(self.stats.malformed)}"
            )

    def _readline(self, fh: io.BufferedIOBase) -> bytes:
        line = fh.readline(MAX_LINE + 1)
        self.stats.decompressed_bytes += len(line)
        if line:
            self.stats.lines += 1
        return line

    def _skip_rest(self, fh: io.BufferedIOBase) -> None:
        while True:
            chunk = fh.readline(MAX_LINE + 1)
            self.stats.decompressed_bytes += len(chunk)
            if not chunk or chunk.endswith(b"\n"):
                return

    def _read(self, fh: io.BufferedIOBase) -> Iterator[ArchiveTransfer]:
        self._preamble(fh)  # validates the table definition and the COPY column set
        index = {name: i for i, name in enumerate(self.columns)}
        perm = tuple(index[name] for name in COLUMNS)  # dump order -> documented order
        while True:
            raw = self._readline(fh)
            n = self.stats.lines
            if not raw:
                raise TruncatedArchiveError(f"line {n}: end of input inside the COPY block")
            if not raw.endswith(b"\n"):
                if len(raw) > MAX_LINE:
                    self.stats.data_rows += 1
                    self.stats.reject("oversize_line", n)
                    self._skip_rest(fh)
                    continue
                raise TruncatedArchiveError(f"line {n}: last line has no terminator")
            if raw == b"\\.\n":
                break
            self.stats.data_rows += 1
            row = self._row(raw, n, perm)
            if row is not None:
                self.stats.valid_rows += 1
                yield row
        self._postamble(fh)

    def _preamble(self, fh: io.BufferedIOBase) -> dict[str, str]:
        table: dict[str, str] | None = None
        while True:
            raw = self._readline(fh)
            n = self.stats.lines
            if not raw:
                raise TruncatedArchiveError(f"line {n}: no COPY block found")
            if len(raw) > MAX_LINE:
                raise UnsupportedDumpError(f"line {n}: statement longer than {MAX_LINE} bytes")
            if raw.strip() == b"":
                continue
            if raw.startswith(f"CREATE TABLE public.{TABLE} (".encode()):
                if table is not None:
                    raise UnsupportedDumpError(f"line {n}: table {TABLE} defined twice")
                table = self._table(fh)
                self.stats.preamble["CREATE TABLE"] += 1
                continue
            if raw.startswith(b"COPY "):
                m = _COPY.match(raw)
                if not m or m[1].decode() != TABLE:
                    raise UnsupportedDumpError(f"line {n}: COPY for an unsupported table")
                if table is None:
                    raise SchemaMismatchError(f"line {n}: COPY before the table definition")
                self.columns = [c.strip().decode() for c in m[2].split(b",")]
                if sorted(self.columns) != sorted(COLUMNS):
                    raise SchemaMismatchError(f"line {n}: COPY columns {self.columns}")
                self.stats.preamble["COPY"] += 1
                return table
            if raw.startswith(b"INSERT "):
                raise UnsupportedDumpError(f"line {n}: INSERT-format dumps are not supported")
            if not raw.startswith(_PREAMBLE_OK):
                raise UnsupportedDumpError(f"line {n}: unexpected statement {_keyword(raw)!r}")
            self.stats.preamble[_keyword(raw)] += 1

    def _table(self, fh: io.BufferedIOBase) -> dict[str, str]:
        found: dict[str, str] = {}
        while True:
            raw = self._readline(fh)
            n = self.stats.lines
            if not raw:
                raise TruncatedArchiveError(f"line {n}: end of input inside CREATE TABLE")
            if raw == b");\n":
                break
            m = _COLUMN_DEF.match(raw)
            if not m:
                raise SchemaMismatchError(f"line {n}: unexpected table definition line")
            found[m[1].decode()] = m[2].decode()
        if found != COLUMNS:
            raise SchemaMismatchError(f"table definition {found} differs from {COLUMNS}")
        return found

    def _postamble(self, fh: io.BufferedIOBase) -> None:
        while raw := self._readline(fh):
            n = self.stats.lines
            if len(raw) > MAX_LINE:
                raise UnsupportedDumpError(f"line {n}: statement longer than {MAX_LINE} bytes")
            if raw.strip() == b"":
                continue
            if raw.startswith(b"COPY "):
                raise UnsupportedDumpError(f"line {n}: a second COPY block is not supported")
            if not raw.startswith(_POSTAMBLE_OK) and not raw.startswith(b"    "):
                raise UnsupportedDumpError(f"line {n}: unexpected statement {_keyword(raw)!r}")
            self.stats.postamble[_keyword(raw)] += 1

    def _row(self, raw: bytes, n: int, perm: tuple[int, ...]) -> ArchiveTransfer | None:
        try:
            text = raw[:-1].decode("utf-8")
        except UnicodeDecodeError:
            self.stats.reject("encoding", n)
            return None
        parts = text.split("\t")
        if len(parts) != len(COLUMNS):
            self.stats.reject("field_count", n)
            return None
        if "\\" in text:
            parts = [copy_unescape(p) if "\\" in p and p != NULL else p for p in parts]
        (block, tx, token, sender, receiver, siv, value, usd, *flag_values, intended,
         first, last) = [parts[i] for i in perm]  # fmt: skip
        try:
            if not _HASH.fullmatch(tx):
                raise ValueError("tx_hash")
            flags = 0
            for v, bit in zip(flag_values, _FLAG_BITS, strict=True):
                if _BOOLS[v]:
                    flags |= bit
            return ArchiveTransfer(
                line=n,
                block=_int(block),
                tx=tx.lower(),
                token=_addr(token),
                sender=_addr(sender),
                receiver=_addr(receiver),
                sender_is_victim=_BOOLS[siv],
                value=_real(value),
                value_usd=_real(usd),
                flags=flags,
                intended=None if intended == NULL else _addr(intended),
                first_digits=_opt_int(first),
                last_digits=_opt_int(last),
            )
        except KeyError:
            self.stats.reject("invalid_boolean", n)
        except ValueError as exc:  # every helper raises with a short tag
            self.stats.reject(f"invalid_{exc.args[0]}", n)
        return None


class SpillDistinct:
    """Exact distinct count of fixed-width byte strings with bounded memory.

    Values are deduplicated in memory up to ``mem_items``, then appended to one of
    ``BUCKETS`` files chosen by a middle byte (addresses share prefixes and suffixes with
    their targets, so the ends are not uniform). ``count`` deduplicates each bucket on its
    own. Bucket files stay open between flushes: opening files is slow on some Windows
    setups (about 28 ms per open was measured here)."""

    BUCKETS = 64

    def __init__(self, directory: Path, name: str, width: int, mem_items: int = 500_000) -> None:
        self.directory = directory / name
        self.directory.mkdir(parents=True, exist_ok=True)
        for stale in self.directory.glob("b*.bin"):
            stale.unlink()  # our own spill files from an interrupted run
        self.width = width
        self.mem_items = mem_items
        self.added = 0
        self.bytes_written = 0
        self._pending: set[bytes] = set()
        self._files: dict[int, io.BufferedWriter] = {}

    def add(self, value: bytes) -> None:
        if len(value) != self.width:
            raise ValueError(f"expected {self.width} bytes, got {len(value)}")
        self.added += 1
        self._pending.add(value)
        if len(self._pending) >= self.mem_items:
            self.flush()

    def flush(self) -> None:
        if not self._pending:
            return
        buckets: dict[int, list[bytes]] = {}
        mid, n = self.width // 2, self.BUCKETS
        for v in self._pending:
            buckets.setdefault(v[mid] % n, []).append(v)
        for b, values in buckets.items():
            fh = self._files.get(b)
            if fh is None:
                fh = self._files[b] = (self.directory / f"b{b:03d}.bin").open("ab")
            data = b"".join(values)
            fh.write(data)
            self.bytes_written += len(data)
        self._pending = set()

    def _close_files(self) -> None:
        for fh in self._files.values():
            fh.close()
        self._files = {}

    def count(self) -> int:
        self.flush()
        self._close_files()
        total = 0
        w = self.width
        for path in sorted(self.directory.glob("b*.bin")):
            data = path.read_bytes()
            total += len({data[i : i + w] for i in range(0, len(data), w)})
        return total

    def close(self) -> None:
        self._pending = set()
        self._close_files()
        for path in self.directory.glob("b*.bin"):
            path.unlink()
        self.directory.rmdir()


@dataclass(frozen=True)
class TargetManifest:
    addresses: frozenset[str]
    txs: frozenset[str]
    sha256: str


def build_targets(groups: dict[str, Iterable[str]]) -> dict[str, Any]:
    """Deterministic manifest: sorted lowercase addresses and tx hashes from named groups
    (for example ``ph_victims``, ``payoff_lookalikes``), with a hash over the content."""
    body: dict[str, list[str]] = {
        name: sorted({v.lower() for v in values}) for name, values in sorted(groups.items())
    }
    for name, values in body.items():
        pattern = _HASH if name.endswith("_txs") else _ADDR
        bad = [v for v in values if not pattern.fullmatch(v)]
        if bad:
            raise ValueError(f"target group {name}: {len(bad)} malformed values")
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {"version": 1, "groups": body, "sha256": digest}


def load_targets(path: Path) -> TargetManifest:
    """Load and verify a manifest; a modified or truncated file is refused."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        body = data["groups"]
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ArchiveError(f"{path}: unreadable target manifest: {exc}") from exc
    if digest != data.get("sha256"):
        raise ArchiveError(f"{path}: target manifest hash mismatch (modified or corrupt)")
    addresses = frozenset(v for k, vs in body.items() if not k.endswith("_txs") for v in vs)
    txs = frozenset(v for k, vs in body.items() if k.endswith("_txs") for v in vs)
    return TargetManifest(addresses, txs, digest)


def peak_rss_bytes() -> int | None:
    """Peak resident set size of this process, from the OS (None if unavailable)."""
    if sys.platform == "win32":
        import ctypes
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

        c = Counters()
        c.cb = ctypes.sizeof(c)
        psapi = ctypes.WinDLL("psapi")
        kernel = ctypes.WinDLL("kernel32")
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Counters),
            wintypes.DWORD,
        ]
        ok = psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(c), c.cb)
        return int(c.PeakWorkingSetSize) if ok else None
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


_SUBTYPES = ((ZERO, "zero_value"), (TINY, "tiny"), (COUNTERFEIT, "counterfeit_token"))
_SIDE = {True: "victim_sends", False: "victim_receives", None: "unknown"}
_DB_FIELDS = (
    "line", "block", "tx", "token", "sender", "receiver", "sender_is_victim", "value",
    "value_usd", "flags", "intended", "first_digits", "last_digits",
)  # fmt: skip


def _to_db(t: ArchiveTransfer) -> tuple[Any, ...]:
    return tuple(getattr(t, f) for f in _DB_FIELDS)


def _from_db(r: tuple[Any, ...]) -> ArchiveTransfer:
    values = dict(zip(_DB_FIELDS, r, strict=True))
    if values["sender_is_victim"] is not None:
        values["sender_is_victim"] = bool(values["sender_is_victim"])
    return ArchiveTransfer(**values)


def rule_coverage(t: ArchiveTransfer, config: PoisoningConfig) -> tuple[str, ...]:
    """CryptoGuard's single-transfer candidate rules applied to a source poisoning row,
    seen from the victim. ``lookalike_in`` assumes the intended address was a counterparty
    the victim chose earlier (the source's own selection presumes that). The planting
    signer is not in the archive, so ``spoofed_out`` cannot be evaluated."""
    lookalike, victim = t.counterparty, t.victim
    if lookalike is None or victim is None:
        return ("direction_unknown",)
    matched = t.intended is not None and similar(lookalike, t.intended) is not None
    methods = transfer_methods(
        incoming=t.receiver == victim,
        outgoing=t.sender == victim,
        value=int(t.value) if t.value is not None else -1,
        token=t.token,
        wallet_signed=None,
        matched=matched,
    )
    out = list(methods)
    if t.intended and is_lookalike(lookalike, t.intended, config):
        out.append("detector_predicate")
    return tuple(out)


def scan(
    archive: Path,
    targets: TargetManifest,
    out_db: Path,
    *,
    work_dir: Path,
    source_sha256: str | None = None,
    progress: Callable[[ReaderStats], None] | None = None,
    progress_every: int = 1_000_000,
    batch: int = 20_000,
    mem_items: int = 500_000,
    max_malformed_fraction: float = 0.001,
    max_stored_rows: int = 5_000_000,
) -> dict[str, Any]:
    """One pass over the archive: reproduce the publisher's aggregate counts, measure
    candidate-rule coverage per subtype, and store the rows touching ``targets``.

    The database is written to ``<out_db>.tmp`` and renamed on success; the returned
    summary is also stored in its ``meta`` table."""
    t0 = time.perf_counter()
    tmp = out_db.with_name(out_db.name + ".tmp")
    out_db.parent.mkdir(parents=True, exist_ok=True)
    # Our own incomplete output from an interrupted (possibly killed) run. The rollback
    # journal must go too: SQLite would replay a stale "hot" journal into the new file.
    for leftover in (tmp, *(tmp.with_name(tmp.name + s) for s in ("-journal", "-wal", "-shm"))):
        leftover.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    db.executescript(_DDL_TABLES)
    db.executemany(
        "INSERT INTO meta(key, value) VALUES (?, ?)",
        [("schema_version", str(SCHEMA_VERSION)), ("parser_version", PARSER_VERSION)],
    )
    reader = ArchiveReader(archive, max_malformed_fraction=max_malformed_fraction)
    config = PoisoningConfig()
    counters = {
        "poisoning_txs": SpillDistinct(work_dir, "poisoning_txs", 32, mem_items),
        "victims": SpillDistinct(work_dir, "victims", 20, mem_items),
        "lookalikes": SpillDistinct(work_dir, "lookalikes", 20, mem_items),
        "transfer_keys": SpillDistinct(work_dir, "transfer_keys", 16, mem_items),
    }
    flags = Counter[int]()
    digits = Counter[tuple[int | None, int | None]]()
    declared_mismatch = 0
    coverage = Counter[tuple[str, str]]()
    any_rule = Counter[str]()
    by_subtype = Counter[str]()
    direction = Counter[tuple[str, str]]()
    tokens_genuine = Counter[str]()
    counterfeit_contracts: set[str] = set()
    nan_value = nan_usd = 0
    blocks = [sys.maxsize, -1]
    poisoning_blocks = [sys.maxsize, -1]
    pending: list[tuple[Any, ...]] = []
    stored = 0
    addresses, txs = targets.addresses, targets.txs
    try:
        for t in reader:
            flags[t.flags] += 1
            blocks[0] = min(blocks[0], t.block)
            blocks[1] = max(blocks[1], t.block)
            nan_value += t.value is None
            nan_usd += t.value_usd is None
            key = f"{t.tx}|{t.token}|{t.sender}|{t.receiver}|{t.value!r}".encode()
            counters["transfer_keys"].add(hashlib.blake2b(key, digest_size=16).digest())
            if t.flags & POISONING:
                poisoning_blocks[0] = min(poisoning_blocks[0], t.block)
                poisoning_blocks[1] = max(poisoning_blocks[1], t.block)
                counters["poisoning_txs"].add(bytes.fromhex(t.tx[2:]))
                if t.victim is not None and t.counterparty is not None:
                    counters["victims"].add(bytes.fromhex(t.victim[2:]))
                    counters["lookalikes"].add(bytes.fromhex(t.counterparty[2:]))
                digits[(t.first_digits, t.last_digits)] += 1
                if (
                    t.intended
                    and t.counterparty
                    and (t.first_digits, t.last_digits) != (affix_match(t.counterparty, t.intended))
                ):
                    declared_mismatch += 1
                methods = rule_coverage(t, config)
                side = _SIDE[t.sender_is_victim]
                for bit, name in _SUBTYPES:
                    if t.flags & bit:
                        by_subtype[name] += 1
                        direction[(name, side)] += 1
                        for m in methods:
                            coverage[(name, m)] += 1
                        if set(methods) - {"detector_predicate", "direction_unknown"}:
                            any_rule[name] += 1
                if t.flags & COUNTERFEIT:
                    counterfeit_contracts.add(t.token)
                elif t.flags & (ZERO | TINY):
                    tokens_genuine[t.token] += 1
            if t.sender in addresses or t.receiver in addresses or t.tx in txs:
                pending.append(_to_db(t))
                if len(pending) >= batch:
                    stored += _insert(db, pending)
                    pending = []
                    if stored > max_stored_rows:
                        raise ArchiveError(
                            f"target subset exceeded {max_stored_rows} rows: the manifest "
                            "is too broad for a bounded subset"
                        )
            if progress is not None and reader.stats.data_rows % progress_every == 0:
                progress(reader.stats)
        stored += _insert(db, pending)
        db.executescript(_DDL_INDEXES)
        distinct = {name: c.count() for name, c in counters.items()}
        # Spill files only grow until cleanup, so the total written after the final flush
        # in ``count`` is the peak temporary disk use.
        peak_spill = sum(c.bytes_written for c in counters.values())
        added = {name: c.added for name, c in counters.items()}
    except BaseException:
        db.close()
        tmp.unlink(missing_ok=True)
        raise
    finally:
        for c in counters.values():
            if c.directory.exists():
                c.close()
    category_counts = {
        name: sum(c for f, c in flags.items() if f & bit) for bit, name in FLAG_NAMES.items()
    }
    summary: dict[str, Any] = {
        "parser_version": PARSER_VERSION,
        "schema_version": SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "target_manifest_sha256": targets.sha256,
        "reader": reader.stats.as_dict(),
        "columns_in_dump_order": reader.columns,
        "block_range": blocks if blocks[1] >= 0 else None,
        "poisoning_block_range": poisoning_blocks if poisoning_blocks[1] >= 0 else None,
        "categories": category_counts,
        "category_combinations": {
            "+".join(n for b, n in FLAG_NAMES.items() if f & b) or "(none)": c
            for f, c in sorted(flags.items())
        },
        "poisoning_transfers": sum(c for f, c in flags.items() if f & POISONING),
        "poisoning_by_subtype": dict(by_subtype),
        "poisoning_direction": {f"{a}/{b}": c for (a, b), c in sorted(direction.items())},
        "distinct": {
            "poisoning_txs": distinct["poisoning_txs"],
            "victims": distinct["victims"],
            "lookalikes": distinct["lookalikes"],
            "counterfeit_token_contracts": len(counterfeit_contracts),
            "transfer_keys": distinct["transfer_keys"],
        },
        "repeated_transfer_keys": added["transfer_keys"] - distinct["transfer_keys"],
        "nan_value": nan_value,
        "nan_value_usd": nan_usd,
        "poisoning_digit_pairs": {f"{a}+{b}": c for (a, b), c in sorted(digits.items(), key=str)},
        "declared_digits_disagree": declared_mismatch,
        "rule_coverage": {f"{s}/{m}": c for (s, m), c in sorted(coverage.items())},
        "any_candidate_rule": dict(any_rule),
        "genuine_token_top": dict(tokens_genuine.most_common(10)),
        "genuine_tokens_distinct": len(tokens_genuine),
        "stored_target_rows": stored,
        "runtime_seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "peak_spill_bytes": peak_spill,
    }
    db.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?)",
        ("summary", json.dumps(summary, sort_keys=True)),
    )
    db.execute("INSERT INTO meta(key, value) VALUES ('complete', '1')")
    db.commit()
    db.close()
    summary["output_bytes"] = tmp.stat().st_size
    os.replace(tmp, out_db)
    return summary


_DDL_TABLES = """
PRAGMA journal_mode = DELETE;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE transfers (
    line INTEGER PRIMARY KEY,
    block INTEGER NOT NULL,
    tx TEXT NOT NULL,
    token TEXT NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    sender_is_victim INTEGER,
    value REAL,
    value_usd REAL,
    flags INTEGER NOT NULL,
    intended TEXT,
    first_digits INTEGER,
    last_digits INTEGER
);
"""
# Built once after the load: maintaining three random-key indexes during the insert
# rewrites most index pages on every batch commit (gigabytes of journal for a
# million-row subset on a contended disk). The finished schema is the same.
_DDL_INDEXES = """
CREATE INDEX transfers_sender ON transfers(sender);
CREATE INDEX transfers_receiver ON transfers(receiver);
CREATE INDEX transfers_tx ON transfers(tx);
"""
_DDL = _DDL_TABLES + _DDL_INDEXES


def _insert(db: sqlite3.Connection, rows: list[tuple[Any, ...]]) -> int:
    if not rows:
        return 0
    with db:
        db.executemany("INSERT INTO transfers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def load_subset(db_path: Path) -> tuple[list[ArchiveTransfer], dict[str, Any]]:
    """Rows stored by ``scan`` and its summary; refuses an incomplete or foreign file."""
    db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        meta = dict(db.execute("SELECT key, value FROM meta").fetchall())
        if meta.get("complete") != "1" or meta.get("parser_version") != PARSER_VERSION:
            raise ArchiveError(f"{db_path}: incomplete scan or parser version mismatch")
        rows = [_from_db(r) for r in db.execute("SELECT * FROM transfers ORDER BY line")]
    finally:
        db.close()
    return rows, json.loads(meta["summary"])

"""Streaming reader for the Tsuchiya et al. PostgreSQL dump: safety, schema checks,
row validation, bounded memory, the target subset and deterministic replay.

Synthetic gzip dumps only (no network, no third-party data). Each test states the invariant
it guards.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from cryptoguard.ml import tsuchiya_archive as ta

VICTIM = "0x" + "11" * 20
FRIEND = "0xd296222fb44f5ec8d9600a8c91ed70ed5657d7d5"
LOOKALIKE = "0xd296261b103d698c272887274f38d7ea8097d7d5"  # 5+5 with FRIEND
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE = "0x" + "fa" * 20
ORDER = list(ta.COLUMNS)
DUMP_ORDER = ORDER  # the real dump's order (zero_value before tiny), as in COLUMNS


def h(n: int) -> str:
    return "0x" + f"{n:064x}"


def row(**over: str) -> dict[str, str]:
    base = {
        "block_number": "16000000", "tx_hash": h(1), "addr": USDT, "topics_from_addr": LOOKALIKE,
        "topics_to_addr": VICTIM, "is_sender_victim": "f", "value": "0", "value_usd": "0",
        "intended_transfer": "f", "zero_value_transfer": "t", "tiny_transfer": "f",
        "counterfeit_token_transfer": "f", "payoff_transfer": "f",
        "payoff_transfer_unconfirmed": "f", "is_not_categorized": "f", "intended_addr": FRIEND,
        "num_first_matched_digits": "5", "num_last_matched_digits": "5",
    }  # fmt: skip
    return {**base, **over}


PREAMBLE = [
    "--",
    "-- PostgreSQL database dump",
    "--",
    "",
    "SET statement_timeout = 0;",
    "SELECT pg_catalog.set_config('search_path', '', false);",
    "CREATE DATABASE addrpoisoning WITH TEMPLATE = template0 ENCODING = 'UTF8';",
    "\\connect addrpoisoning",
    "",
]


def table(columns: dict[str, str] = ta.COLUMNS) -> list[str]:
    items = list(columns.items())
    body = [f"    {n} {t}," for n, t in items[:-1]] + [f"    {items[-1][0]} {items[-1][1]}"]
    return [f"CREATE TABLE public.{ta.TABLE} (", *body, ");", ""]


def dump(
    path: Path,
    rows: list[dict[str, str]],
    *,
    order: list[str] = DUMP_ORDER,
    preamble: list[str] | None = None,
    postamble: list[str] | None = None,
    terminate: bool = True,
    raw_lines: list[str] | None = None,
) -> Path:
    lines = [*(PREAMBLE if preamble is None else preamble), *table()]
    lines.append(f"COPY public.{ta.TABLE} ({', '.join(order)}) FROM stdin;")
    lines += ["\t".join(r[c] for c in order) for r in rows]
    lines += raw_lines or []
    if terminate:
        lines.append("\\.")
        lines += postamble if postamble is not None else ["", "--", "-- done", "--"]
    path.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))
    return path


def read(path: Path, **kw: float) -> tuple[list[ta.ArchiveTransfer], ta.ArchiveReader]:
    reader = ta.ArchiveReader(path, **kw)
    return list(reader), reader


# --- format and safety ------------------------------------------------------------------


def test_valid_dump_parses_by_column_name_with_provenance(tmp_path: Path) -> None:
    """Columns are mapped by the COPY header's names; each row keeps its dump line number."""
    shuffled = ORDER[::-1]
    rows, reader = read(
        dump(
            tmp_path / "d.gz",
            [row(), row(tx_hash=h(2), tiny_transfer="t", zero_value_transfer="f", value="5000")],
            order=shuffled,
        )
    )
    assert [r.flags for r in rows] == [ta.ZERO, ta.TINY]
    assert rows[0].victim == VICTIM and rows[0].counterparty == LOOKALIKE  # noqa: PT018
    assert rows[0].line == len(PREAMBLE) + len(table()) + 2
    assert reader.stats.preamble["CREATE DATABASE"] == 1
    assert reader.stats.preamble["\\connect"] == 1


def test_nothing_is_executed_or_imported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reader never opens a database connection or evaluates dump text: hostile
    statements in the preamble are refused, not run."""

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("the reader must not touch a database")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    rows, _ = read(dump(tmp_path / "d.gz", [row()]))
    assert len(rows) == 1
    hostile = [*PREAMBLE, "DROP TABLE users;"]
    with pytest.raises(ta.UnsupportedDumpError, match="DROP"):
        read(dump(tmp_path / "h.gz", [row()], preamble=hostile))


@pytest.mark.parametrize(
    ("extra", "error", "match"),
    [
        (
            ["INSERT INTO public.address_poisoning_ethereum VALUES (1);"],
            ta.UnsupportedDumpError,
            "INSERT",
        ),
        (
            ["CREATE FUNCTION evil() RETURNS void AS $$ $$ LANGUAGE sql;"],
            ta.UnsupportedDumpError,
            "CREATE FUNCTION",
        ),
        (["COPY public.other (a) FROM stdin;"], ta.UnsupportedDumpError, "unsupported table"),
    ],
)
def test_unsupported_statements_fail_explicitly(
    tmp_path: Path, extra: list[str], error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match):
        read(dump(tmp_path / "d.gz", [row()], preamble=[*PREAMBLE, *extra]))


def test_second_copy_block_is_refused(tmp_path: Path) -> None:
    post = ["", f"COPY public.{ta.TABLE} ({', '.join(ORDER)}) FROM stdin;", "\\."]
    with pytest.raises(ta.UnsupportedDumpError, match="second COPY"):
        read(dump(tmp_path / "d.gz", [row()], postamble=post))


def test_schema_changes_are_refused(tmp_path: Path) -> None:
    """A changed type in CREATE TABLE or a missing COPY column is a schema change."""
    path = dump(tmp_path / "d.gz", [row()])
    text = (
        gzip.decompress(path.read_bytes()).decode().replace("    value real,", "    value numeric,")
    )
    path.write_bytes(gzip.compress(text.encode()))
    with pytest.raises(ta.SchemaMismatchError):
        read(path)
    with pytest.raises(ta.SchemaMismatchError, match="COPY columns"):
        read(dump(tmp_path / "e.gz", [row()], order=ORDER[:-1]))


def test_invalid_and_truncated_gzip(tmp_path: Path) -> None:
    """Not-gzip input and a cut-off gzip stream fail with distinct, explicit errors."""
    bad = tmp_path / "bad.gz"
    bad.write_bytes(b"not a gzip stream at all")
    with pytest.raises(ta.InvalidArchiveError):
        read(bad)
    good = dump(tmp_path / "d.gz", [row(tx_hash=h(i)) for i in range(2000)]).read_bytes()
    cut = tmp_path / "cut.gz"
    cut.write_bytes(good[: len(good) // 2])
    with pytest.raises(ta.TruncatedArchiveError):
        read(cut)


def test_missing_terminator_is_truncation_not_success(tmp_path: Path) -> None:
    """A dump whose COPY block never ends (valid gzip, cut text) is not a complete read."""
    with pytest.raises(ta.TruncatedArchiveError, match="inside the COPY block"):
        read(dump(tmp_path / "d.gz", [row()], terminate=False))


# --- row validation ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"tx_hash": "0x12"}, "invalid_tx_hash"),
        ({"topics_to_addr": "0xnothex"}, "invalid_address"),
        ({"is_sender_victim": "yes"}, "invalid_boolean"),
        ({"block_number": "16.5"}, "invalid_integer"),
        ({"value": "Infinity"}, "invalid_non_finite_real"),
        ({"value": "lots"}, "invalid_real"),
    ],
)
def test_malformed_rows_are_counted_with_reasons(
    tmp_path: Path, over: dict[str, str], reason: str
) -> None:
    rows, reader = read(
        dump(tmp_path / "d.gz", [row(), row(**{"tx_hash": h(2), **over})]),
        max_malformed_fraction=1.0,
    )
    assert len(rows) == 1
    assert list(reader.stats.malformed) == [reason]
    assert reader.stats.malformed_lines[reason] == [rows[0].line + 1]


def test_field_count_encoding_and_oversize_lines(tmp_path: Path) -> None:
    good = "\t".join(row()[c] for c in DUMP_ORDER)
    path = tmp_path / "d.gz"
    lines = [*PREAMBLE, *table(), f"COPY public.{ta.TABLE} ({', '.join(DUMP_ORDER)}) FROM stdin;"]
    body = (
        "\n".join(lines).encode()
        + b"\n"
        + good.encode()
        + b"\n"
        + b"a\tb\n"
        + good.encode()[:-3]
        + b"\xff\xfe\n"
        + b"x" * (ta.MAX_LINE + 50)
        + b"\n"
        + b"\\.\n"
    )
    path.write_bytes(gzip.compress(body))
    rows, reader = read(path, max_malformed_fraction=1.0)
    assert len(rows) == 1
    assert reader.stats.malformed == {"field_count": 1, "encoding": 1, "oversize_line": 1}


def test_too_many_malformed_rows_fail_the_read(tmp_path: Path) -> None:
    rows = [row(tx_hash=h(i)) for i in range(10)] + [row(tx_hash="bad")]
    with pytest.raises(ta.TooManyMalformedError):
        read(dump(tmp_path / "d.gz", rows), max_malformed_fraction=0.05)


def test_nan_and_null_markers_are_missing_not_zero(tmp_path: Path) -> None:
    rows, _ = read(
        dump(
            tmp_path / "d.gz",
            [
                row(
                    value="NaN",
                    value_usd="\\N",
                    intended_addr="\\N",
                    is_sender_victim="\\N",
                    num_first_matched_digits="\\N",
                )
            ],
        )
    )
    r = rows[0]
    assert (r.value, r.value_usd, r.intended, r.sender_is_victim, r.first_digits) == (
        None,
        None,
        None,
        None,
        None,
    )
    assert r.victim is None


def test_copy_escapes_and_unicode() -> None:
    assert ta.copy_unescape("a\\tb\\\\c\\nd") == "a\tb\\c\nd"
    assert ta.copy_unescape("\\101\\x42é") == "ABé"
    assert ta.copy_unescape("plain") == "plain"


def test_escaped_separator_does_not_split_a_field(tmp_path: Path) -> None:
    """A backslash-escaped tab inside a field stays one field (and then fails validation as
    an address), instead of shifting every later column."""
    rows, reader = read(
        dump(tmp_path / "d.gz", [row(), row(tx_hash=h(2), topics_to_addr="0xab\\tcd")]),
        max_malformed_fraction=1.0,
    )
    assert len(rows) == 1
    assert reader.stats.malformed == {"invalid_address": 1}


# --- distinct counting, targets, scan ---------------------------------------------------


def test_spill_distinct_is_exact_with_tiny_memory(tmp_path: Path) -> None:
    """Exact counts survive many flushes and duplicates across flushes."""
    c = ta.SpillDistinct(tmp_path, "x", 4, mem_items=7)
    for i in range(1000):
        c.add((i % 300).to_bytes(4, "big"))
    assert c.count() == 300
    assert c.added == 1000
    c.close()
    assert not (tmp_path / "x").exists()


def test_target_manifest_round_trip_and_corruption(tmp_path: Path) -> None:
    m = ta.build_targets({"ph_victims": [VICTIM.upper().replace("0X", "0x")], "payoff_txs": [h(5)]})
    path = tmp_path / "m.json"
    path.write_text(json.dumps(m), encoding="utf-8")
    t = ta.load_targets(path)
    assert t.addresses == {VICTIM}
    assert t.txs == {h(5)}
    m["groups"]["ph_victims"].append(LOOKALIKE)
    path.write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(ta.ArchiveError, match="hash mismatch"):
        ta.load_targets(path)
    path.write_text('{"groups":', encoding="utf-8")
    with pytest.raises(ta.ArchiveError, match="unreadable"):
        ta.load_targets(path)
    with pytest.raises(ValueError, match="malformed"):
        ta.build_targets({"ph_victims": ["0x12"]})


def _targets(tmp_path: Path, **groups: list[str]) -> ta.TargetManifest:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(ta.build_targets(groups)), encoding="utf-8")
    return ta.load_targets(path)


def _rows() -> list[dict[str, str]]:
    other = "0x" + "22" * 20
    return [
        row(),  # zero-value planting to VICTIM
        row(
            tx_hash=h(2),
            tiny_transfer="t",
            zero_value_transfer="f",
            value="5000",
            value_usd="0.005",
        ),
        row(
            tx_hash=h(3),
            addr=FAKE,
            counterfeit_token_transfer="t",
            zero_value_transfer="f",
            value="1e+06",
            value_usd="NaN",
        ),
        row(
            tx_hash=h(4),
            topics_from_addr=VICTIM,
            topics_to_addr=LOOKALIKE,
            is_sender_victim="t",
            payoff_transfer="t",
            zero_value_transfer="f",
            value="5e+09",
            value_usd="5000",
        ),
        row(
            tx_hash=h(5),
            topics_to_addr=other,
            intended_addr="0x" + "33" * 20,
            zero_value_transfer="t",
        ),  # declares 5+5, really 0+0
        row(tx_hash=h(1)),  # same key as the first row: indistinguishable without a log index
    ]


def test_scan_reproduces_counts_and_stores_only_targets(tmp_path: Path) -> None:
    archive = dump(tmp_path / "d.gz", _rows())
    out = tmp_path / "subset.sqlite"
    s = ta.scan(
        archive, _targets(tmp_path, ph_victims=[VICTIM]), out, work_dir=tmp_path / "w", mem_items=2
    )
    assert s["poisoning_transfers"] == 5
    assert s["categories"]["payoff_transfer"] == 1
    assert s["distinct"]["poisoning_txs"] == 4
    assert s["distinct"]["victims"] == 2
    assert s["distinct"]["counterfeit_token_contracts"] == 1
    assert s["repeated_transfer_keys"] == 1
    assert s["nan_value_usd"] == 1
    assert s["stored_target_rows"] == 5  # every row touching VICTIM, not the other victim
    # every counted value reached a spill file, including the final flush
    assert s["peak_spill_bytes"] >= 32 * 4 + 20 * 4 + 16 * 5
    rows, summary = ta.load_subset(out)
    assert [r.tx for r in rows] == [h(1), h(2), h(3), h(4), h(1)]
    assert summary["target_manifest_sha256"] == s["target_manifest_sha256"]
    assert not (tmp_path / "w" / "victims").exists()  # spill files cleaned up
    # The lookup indexes are built after the load, but they must exist in the result.
    con = sqlite3.connect(out)
    indexes = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    con.close()
    assert {"transfers_sender", "transfers_receiver", "transfers_tx"} <= indexes


def test_rule_coverage_is_measured_per_subtype(tmp_path: Path) -> None:
    """Zero-value rows trigger zero_value_in; 5,000-unit USDT dust triggers dust_in; the
    counterfeit row triggers lookalike_in + untrusted_token_in; a 0+0 lookalike does not,
    and its wrong declared digit counts are counted."""
    s = ta.scan(
        dump(tmp_path / "d.gz", _rows()),
        _targets(tmp_path, ph_victims=[VICTIM]),
        tmp_path / "s.sqlite",
        work_dir=tmp_path / "w",
    )
    cov = s["rule_coverage"]
    assert cov["zero_value/zero_value_in"] == 3
    assert cov["zero_value/lookalike_in"] == 2
    assert cov["tiny/dust_in"] == 1
    assert cov["counterfeit_token/untrusted_token_in"] == 1
    assert s["declared_digits_disagree"] == 1


def test_rerun_is_idempotent_and_interruption_leaves_no_output(tmp_path: Path) -> None:
    """A rerun replaces the output with identical content; an interrupted scan leaves the
    previous complete file untouched and no temporary file behind."""
    archive = dump(tmp_path / "d.gz", _rows())
    targets = _targets(tmp_path, ph_victims=[VICTIM])
    out = tmp_path / "s.sqlite"
    first = ta.scan(archive, targets, out, work_dir=tmp_path / "w")
    before = ta.load_subset(out)[0]
    second = ta.scan(archive, targets, out, work_dir=tmp_path / "w")
    assert ta.load_subset(out)[0] == before
    assert {
        k: v
        for k, v in first.items()
        if k not in ("runtime_seconds", "peak_rss_bytes", "output_bytes")
    } == {
        k: v
        for k, v in second.items()
        if k not in ("runtime_seconds", "peak_rss_bytes", "output_bytes")
    }

    def boom(_: ta.ReaderStats) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        ta.scan(archive, targets, out, work_dir=tmp_path / "w", progress=boom, progress_every=2)
    assert ta.load_subset(out)[0] == before
    assert not (tmp_path / "s.sqlite.tmp").exists()


JOURNAL_HEADER = bytes.fromhex("d9d505f920a163d7")  # SQLite rollback-journal magic


def test_killed_run_leftovers_are_cleared_before_rescan(tmp_path: Path) -> None:
    """A hard kill leaves the temporary database, its rollback journal and spill files.
    A rescan must not let SQLite replay that stale journal into the new database."""
    archive = dump(tmp_path / "d.gz", _rows())
    out = tmp_path / "s.sqlite"
    (tmp_path / "s.sqlite.tmp").write_bytes(b"partial")
    (tmp_path / "s.sqlite.tmp-journal").write_bytes(JOURNAL_HEADER + bytes(504))
    spill = tmp_path / "w" / "victims"
    spill.mkdir(parents=True)
    (spill / "b000.bin").write_bytes(bytes([1]) * 20)
    s = ta.scan(archive, _targets(tmp_path, ph_victims=[VICTIM]), out, work_dir=tmp_path / "w")
    assert s["distinct"]["victims"] == 2  # the stale spill value was not counted
    assert len(ta.load_subset(out)[0]) == 5
    assert not (tmp_path / "s.sqlite.tmp-journal").exists()


def test_incomplete_or_foreign_subset_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "x.sqlite"
    db = sqlite3.connect(path)
    db.executescript(ta._DDL)
    db.commit()
    db.close()
    with pytest.raises(ta.ArchiveError, match="incomplete"):
        ta.load_subset(path)


def test_peak_rss_is_reported() -> None:
    peak = ta.peak_rss_bytes()
    assert peak is None or peak > 1 << 20


def test_synthetic_benchmark_runs_and_is_deterministic(tmp_path: Path) -> None:
    """The scaling benchmark's generator yields a dump the scanner accepts, twice alike."""
    from cryptoguard.ml.bench_archive import run_one

    out = run_one(300, tmp_path)
    assert out["rows"] == 300
    assert out["deterministic"] is True
    assert out["distinct_lookalikes"] > 0

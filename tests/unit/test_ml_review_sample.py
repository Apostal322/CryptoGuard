"""Frozen review sample: allocation, one packet per campaign group, determinism, blinding,
and refusal to re-draw once frozen.

Synthetic packets only. Each test states the invariant it guards.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.review import ReviewPacket

B2022, B2023, B2024 = 16_000_000, 17_000_000, 19_000_000


def addr(n: int) -> str:
    return "0x" + f"{n:040x}"


def pkt(
    n: int,
    *,
    subtype: str = "fake_token",
    block: int = B2023,
    victim: int | None = None,
    lookalike: int | None = None,
    rival: bool = False,
) -> ReviewPacket:
    return ReviewPacket(
        victim_event_id=f"{n:016x}",
        victim=addr(victim if victim is not None else 10_000 + n),
        lookalike=addr(lookalike if lookalike is not None else 20_000 + n),
        imitated=addr(30_000 + n),
        planting_tx="0x" + f"{n:064x}",
        observation_block=block + n,
        subtype=subtype,
        evidence_summary=f"Source-labelled poisoning transfer {n}; the victim paid later.",
        coverage_limitations="no wallet history observed",
        source_labels=(f"tsuchiya-archive:{subtype}", "tsuchiya-payoff:confirmed"),
        competing_lookalikes=(addr(40_000 + n),) if rival else (),
        payment_evidence=(f"0x{n + 7:064x} block {block + n + 50} after_planting",),
    )


def queue() -> list[ReviewPacket]:
    out: list[ReviewPacket] = []
    n = 0
    for subtype, block, rival, count in (
        ("fake_token", B2023, False, 40),
        ("fake_token", B2023, True, 50),
        ("fake_token", B2024, True, 6),
        ("spoofed_transfer_from", B2022, False, 20),
        ("spoofed_transfer_from", B2023, True, 60),
        ("dust", B2023, True, 12),
        ("zero_value", B2023, True, 2),
        ("unknown", B2023, False, 3),
    ):
        for _ in range(count):
            n += 1
            out.append(pkt(n, subtype=subtype, block=block, rival=rival))
    return out


def write_queue(path: Path, packets: list[ReviewPacket]) -> Path:
    path.write_text("".join(p.model_dump_json() + "\n" for p in packets), encoding="utf-8")
    return path


def test_allocation_is_proportional_with_one_per_cell_and_exact_total() -> None:
    sizes = {("a",): 300, ("b",): 100, ("c",): 2, ("d",): 0}
    n = rs.allocate(sizes, 20)
    assert sum(n.values()) == 20
    assert n[("c",)] == 1
    assert n[("d",)] == 0
    assert n[("a",)] > n[("b",)] > n[("c",)]
    assert rs.allocate(sizes, 500) == sizes  # take-all below quota
    assert rs.allocate(sizes, 20) == n  # deterministic


def test_allocation_refuses_more_cells_than_quota() -> None:
    with pytest.raises(rs.ReviewSampleError):
        rs.allocate({("a",): 5, ("b",): 5, ("c",): 5}, 2)


def test_quotas_strata_and_weights() -> None:
    sample = rs.draw(queue(), "q")
    m = sample["manifest"]
    per_subtype = Counter(r["stratum"].split("|")[0] for r in m["selected"])
    assert per_subtype == {"fake_token": 24, "spoofed_transfer_from": 24, "dust": 9,
                           "zero_value": 2}  # fmt: skip
    assert "unknown" not in per_subtype  # unlisted subtypes are not sampled
    table = {row["stratum"]: row for row in m["strata_table"]}
    assert table["fake_token|2024|rival"]["selected"] >= 1
    assert table["spoofed_transfer_from|2022|no_rival"]["groups"] == 20
    for row in table.values():  # weights reproduce each cell's group count
        if row["selected"]:
            got = sum(r["weight"] for r in m["selected"] if r["stratum"] == row["stratum"])
            assert got == pytest.approx(row["groups"])


def test_one_packet_per_victim_and_campaign_group() -> None:
    packets = queue()
    # Five packets against one victim, two sharing a lookalike with another victim.
    packets += [pkt(900 + i, victim=1, rival=True) for i in range(5)]
    packets += [pkt(910, lookalike=20_000 + 900), pkt(911, victim=10_000 + 910)]
    sample = rs.draw(packets, "q")
    root = rs.groups(packets)
    chosen = [r["victim_event_id"] for r in sample["manifest"]["selected"]]
    assert len({root[e] for e in chosen}) == len(chosen)
    chained = {root[f"{n:016x}"] for n in (900, 901, 902, 903, 904, 910, 911)}
    assert len(chained) == 1  # victim -> lookalike -> lookalike links form one group
    by_id = {p.victim_event_id: p for p in packets}
    assert len({by_id[e].victim for e in chosen}) == len(chosen)


def test_reserves_are_disjoint_ordered_and_cover_every_representative() -> None:
    m = rs.draw(queue(), "q")["manifest"]
    chosen = {r["victim_event_id"] for r in m["selected"]}
    reserved = [e for ids in m["reserves"].values() for e in ids]
    assert not chosen & set(reserved)
    assert len(chosen) + len(reserved) == m["groups"]["count"]
    for ids in m["reserves"].values():
        assert ids == sorted(ids, key=lambda e: rs.rank("select", e))


def test_draw_is_deterministic_and_independent_of_input_order() -> None:
    packets = queue()
    a = rs.draw(packets, "q")
    b = rs.draw(list(reversed(packets)), "q")
    assert a == b
    assert (
        a["manifest"]["selection_sha256"]
        != rs.draw(packets, "other")["manifest"]["selection_sha256"]
    )  # the queue hash is part of the frozen selection


def test_reviewer_sheet_is_blinded() -> None:
    packets = queue()
    sample = rs.draw(packets, "q")
    by_id = {p.victim_event_id: p for p in packets}
    allowed = {"schema_version", "item", "victim_event_id", "chain_id", "wallet",
               "address_under_review", "transaction", "block"}  # fmt: skip
    for line in sample["sheet"]:
        assert set(line) == allowed
        p = by_id[line["victim_event_id"]]
        text = json.dumps(line)
        for leaked in (p.imitated, p.subtype, *p.payment_evidence, *p.competing_lookalikes):
            assert leaked
            assert leaked.split()[0] not in text
    items = [line["item"] for line in sample["sheet"]]
    assert items == list(range(1, len(items) + 1))
    ids = [line["victim_event_id"] for line in sample["sheet"]]
    assert ids == sorted(ids, key=lambda e: rs.rank("order", e))  # not grouped by stratum
    key = {k["packet"]["victim_event_id"]: k for k in sample["key"]}
    assert all(key[e]["role"] == "selected" for e in ids)  # the key unblinds every item


def test_freeze_writes_once_then_verifies_and_refuses_a_redraw(tmp_path: Path) -> None:
    q = write_queue(tmp_path / "queue.jsonl", queue())
    out = tmp_path / "sample"
    manifest, written = rs.freeze(q, out)
    assert written
    assert manifest["rpc_requests"] == 0
    files = {p.name: p.read_bytes() for p in out.iterdir()}
    assert set(files) == {rs.MANIFEST, rs.SHEET, rs.KEY}  # no temporary files left
    again, written = rs.freeze(q, out)
    assert not written
    assert again["selection_sha256"] == manifest["selection_sha256"]
    assert {p.name: p.read_bytes() for p in out.iterdir()} == files

    write_queue(q, queue()[:-1])
    with pytest.raises(rs.SampleFrozenError, match="queue changed"):
        rs.freeze(q, out)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == files  # untouched


def test_freeze_is_reproducible_in_a_fresh_directory(tmp_path: Path) -> None:
    q = write_queue(tmp_path / "queue.jsonl", queue())
    a, _ = rs.freeze(q, tmp_path / "a")
    b, _ = rs.freeze(q, tmp_path / "b")
    assert a["selection_sha256"] == b["selection_sha256"]
    assert a["files"] == b["files"]
    for name in (rs.SHEET, rs.KEY):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_malformed_or_repeated_packets_reject_the_whole_queue(tmp_path: Path) -> None:
    packets = queue()
    q = write_queue(tmp_path / "queue.jsonl", [*packets, packets[0]])
    with pytest.raises(rs.ReviewSampleError, match="repeated event"):
        rs.load_queue(q)
    q.write_text(packets[0].model_dump_json() + "\n{not json\n", encoding="utf-8")
    with pytest.raises(rs.ReviewSampleError, match="line 2"):
        rs.load_queue(q)
    q.write_text("", encoding="utf-8")
    with pytest.raises(rs.ReviewSampleError, match="empty"):
        rs.load_queue(q)
    assert not (tmp_path / "sample").exists()


def test_year_bins_follow_block_height() -> None:
    assert rs.year(16_308_189) == 2022
    assert rs.year(16_308_190) == 2023
    assert rs.year(18_908_895) == 2024

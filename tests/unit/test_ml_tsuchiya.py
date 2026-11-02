"""Tsuchiya et al. payoff parser and the offline cross-check with Poison-Hunter rows.

Synthetic data only (no RPC, no third-party files). Each test states the invariant it guards.
"""

from __future__ import annotations

import csv
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml.poison_hunter import PoisonHunterRecord, SchemaMismatchError
from cryptoguard.ml.tsuchiya import EXPECTED_HEADER, cross_check, parse_payoffs, profile

VICTIM = "0x" + "11" * 20
OTHER_VICTIM = "0x" + "22" * 20
FRIEND = "0xd296222fb44f5ec8d9600a8c91ed70ed5657d7d5"
LOOKALIKE = "0xd296261b103d698c272887274f38d7ea8097d7d5"  # 5+5 with FRIEND
OTHER_LOOKALIKE = "0xd29" + "0" * 33 + "d7d5"  # 3+4 with FRIEND
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
WBTC = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"
COMPLETE = "no_direct_payment_observed_with_complete_declared_coverage"


def h(n: int) -> str:
    return "0x" + f"{n:064x}"


def payoff(**over: str) -> dict[str, str]:
    row = {
        "block_number": "16100000", "tx_hash": h(1), "addr": USDT, "topics_from_addr": VICTIM,
        "topics_to_addr": LOOKALIKE, "value": "5000000000.0", "value_usd": "5000.0",
        "is_sender_victim": "True", "num_first_matched_digits": "5",
        "num_last_matched_digits": "5", "intended_addr": FRIEND,
    }  # fmt: skip
    return {**row, **over}


def write_payoffs(
    path: Path, rows: list[dict[str, str]], header: list[str] = EXPECTED_HEADER
) -> Path:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return path


def ph(
    line: int = 2,
    *,
    victim: str = VICTIM,
    lookalike: str = LOOKALIKE,
    block: int | None = 16_090_000,
) -> PoisonHunterRecord:
    return PoisonHunterRecord(
        source_line=line, status="valid", issues=(), lookalike=lookalike, victim=victim,
        imitated=FRIEND, planting_tx=h(99), token_symbol="usdt", subtype="dust",
        log_contract=USDT.lower(), fake_token_deployer=None, tx_signer=lookalike,
        tx_target=USDT.lower(), batch_size=1, block_number=block, block_distance=12,
        imitated_direction="from", source_similarity=10, prefix_match=5, suffix_match=5,
        cryptoguard_lookalike=True, tsuchiya_lookalike=True,
    )  # fmt: skip


def test_parser_lowercases_checks_affixes_and_keeps_provenance(tmp_path: Path) -> None:
    """Addresses are normalised, the declared affix counts are re-derived from the addresses,
    and the file hash is recorded."""
    parsed = parse_payoffs(write_payoffs(tmp_path / "p.csv", [payoff()]))
    (r,) = parsed.records
    assert (r.status, r.source_line) == ("valid", 2)
    assert (r.payer, r.lookalike, r.token) == (VICTIM, LOOKALIKE, USDT.lower())
    assert (r.prefix_match, r.suffix_match) == (5, 5)
    assert len(parsed.source_sha256) == 64


def test_header_or_width_changes_are_refused(tmp_path: Path) -> None:
    """A reordered header or a row of the wrong width is a schema change: refuse to guess."""
    swapped = [EXPECTED_HEADER[1], EXPECTED_HEADER[0], *EXPECTED_HEADER[2:]]
    with pytest.raises(SchemaMismatchError):
        parse_payoffs(write_payoffs(tmp_path / "a.csv", [payoff()], swapped))
    path = write_payoffs(tmp_path / "b.csv", [payoff()])
    path.write_text(path.read_text() + "1,2,3\n", encoding="utf-8")
    with pytest.raises(SchemaMismatchError):
        parse_payoffs(path)


@pytest.mark.parametrize(
    ("over", "issue"),
    [
        ({"num_first_matched_digits": "6"}, "declared affix"),
        ({"is_sender_victim": "False"}, "is_sender_victim"),
        ({"tx_hash": "0x12"}, "tx_hash"),
        ({"topics_to_addr": "0xnothex"}, "topics_to_addr"),
        ({"block_number": "16.1e6"}, "block_number"),
        ({"value_usd": "-1"}, "value_usd"),
    ],
)
def test_inconsistent_rows_are_quarantined_with_reasons(
    tmp_path: Path, over: dict[str, str], issue: str
) -> None:
    """A row that contradicts itself or the layout is kept, marked and explained."""
    (r,) = parse_payoffs(write_payoffs(tmp_path / "p.csv", [payoff(**over)])).records
    assert r.status == "quarantined"
    assert any(issue in i for i in r.issues)


def test_float4_amounts_are_marked_approximate_beyond_2_pow_24(tmp_path: Path) -> None:
    """The source column is a PostgreSQL real: integers above 2**24 base units (about 16.8
    USDT) are rounded, so only small integral amounts count as exact. Human amounts use
    the token's decimals and stay separate from the source's USD valuation."""
    rows = [
        payoff(value="16777216.0"),  # 2**24: still exact
        payoff(tx_hash=h(2), value="16777217.0"),
        payoff(tx_hash=h(3), value="5e+09", value_usd="4999.5"),
        payoff(tx_hash=h(4), value="1.5", addr=WBTC),
        payoff(tx_hash=h(5), value="lots"),
    ]
    recs = parse_payoffs(write_payoffs(tmp_path / "p.csv", rows)).records
    assert [r.amount_precision for r in recs] == [
        "exact",
        "float4_approximate",
        "float4_approximate",
        "float4_approximate",
        "unparseable",
    ]
    assert recs[2].human_amount == Decimal("5000")  # 5e9 base units of a 6-decimal token
    assert recs[2].value_usd == 4999.5  # the source's valuation is kept, not recomputed
    assert recs[3].human_amount is None  # unknown decimals: no human amount is invented
    assert recs[4].status == "quarantined"


def test_payoff_identity_and_provenance(tmp_path: Path) -> None:
    parsed = parse_payoffs(write_payoffs(tmp_path / "p.csv", [payoff(), payoff()]))
    assert parsed.source_file == "p.csv"
    assert parsed.source_version.startswith("KiltHub v1")
    assert parsed.records[0].payoff_id == f"1:{h(1)}:{USDT.lower()}:{VICTIM}:{LOOKALIKE}"
    assert profile(parsed)["duplicate_payoff_ids"] == 1  # a repeated row is not two payoffs


def _check(
    payoffs: list[dict[str, str]],
    rows: list[PoisonHunterRecord],
    outcomes: list[str] | None,
    tmp_path: Path,
    incidents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parsed = parse_payoffs(write_payoffs(tmp_path / "p.csv", payoffs))
    return cross_check(parsed.valid, rows, outcomes, incidents or [])


def test_payoff_to_the_same_lookalike_in_window_contradicts_complete_coverage(
    tmp_path: Path,
) -> None:
    """A complete-coverage pilot row whose victim paid that lookalike inside the window is a
    contradiction and is listed by Poison-Hunter line."""
    x = _check([payoff(block_number="16100000")], [ph(7)], [COMPLETE], tmp_path)
    b = x["by_outcome"][COMPLETE]
    assert b["victim_paid_this_lookalike"] == b["victim_paid_this_lookalike_in_window"] == 1
    assert x["contradicted_complete_rows"] == [7]


@pytest.mark.parametrize("block", ["16090000", "16080000", "16140401"])
def test_payoffs_at_before_or_after_the_window_are_not_in_window(
    tmp_path: Path, block: str
) -> None:
    """The window is (planting, planting + 50,400]: the planting block itself, earlier blocks
    and later blocks do not count as a payment caused within the window."""
    x = _check([payoff(block_number=block)], [ph(7)], [COMPLETE], tmp_path)
    b = x["by_outcome"][COMPLETE]
    assert (b["victim_paid_this_lookalike"], b["victim_paid_this_lookalike_in_window"]) == (1, 0)
    assert x["contradicted_complete_rows"] == []


def test_other_lookalikes_and_other_victims_are_reported_separately(tmp_path: Path) -> None:
    """Paying a different lookalike of the same address, and the row's lookalike being paid
    by someone else, are separate findings: neither is a payment for this event."""
    rows = [
        payoff(
            topics_to_addr=OTHER_LOOKALIKE,
            num_first_matched_digits="3",
            num_last_matched_digits="4",
        ),
        payoff(tx_hash=h(2), topics_from_addr=OTHER_VICTIM, block_number="16000000"),
    ]
    x = _check(rows, [ph(9)], ["not_evaluated"], tmp_path)
    b = x["by_outcome"]["not_evaluated"]
    assert b["victim_paid_this_lookalike"] == 0
    assert b["victim_paid_other_lookalike_of_same_address"] == 1
    assert b["lookalike_paid_by_another_victim"] == 1
    kinds = {(f["paid"], f["blocks_after_planting"]) for f in x["findings"]}
    assert kinds == {
        ("another lookalike of the same address", 10_000),
        ("this lookalike, by another victim", -90_000),
    }


def test_output_has_no_addresses_and_rows_without_outcomes_are_grouped(tmp_path: Path) -> None:
    """Only aggregates and line numbers leave the cross-check (licence and privacy)."""
    incident = {"case": "case-1", "victim": VICTIM, "block": 16_100_000, "tx": h(1), "token": WBTC}
    x = _check([payoff()], [ph(3)], None, tmp_path, [incident])
    assert "no_pilot_record" in x["by_outcome"]
    assert "0x" not in json.dumps(x["by_outcome"]) + json.dumps(x["findings"]) + json.dumps(
        x["incidents"]
    )
    assert x["incidents"] == [
        {
            "case": "case-1",
            "in_period": True,
            "token_in_file": False,
            "harm_tx_listed": True,
            "victim_listed": True,
        }
    ]


def test_period_and_definition_coverage(tmp_path: Path) -> None:
    """Rows outside the payoff block range, or with lookalikes outside 3+4, cannot appear in
    the file by construction and are counted as outside its coverage."""
    rows = [ph(2, block=15_000_000), ph(3), ph(4).model_copy(update={"tsuchiya_lookalike": False})]
    span = [payoff(block_number="16000000"), payoff(tx_hash=h(2), block_number="16200000")]
    x = _check(span, rows, None, tmp_path)
    b = x["by_outcome"]["no_pilot_record"]
    assert (b["rows"], b["in_period"], b["in_definition"]) == (3, 2, 1)


def test_misaligned_outcomes_raise(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outcomes"):
        _check([payoff()], [ph(2), ph(3)], [COMPLETE], tmp_path)


def test_profile_counts_predicates_and_tokens(tmp_path: Path) -> None:
    rows = [payoff(), payoff(tx_hash=h(2), addr=WBTC)]
    p = profile(parse_payoffs(write_payoffs(tmp_path / "p.csv", rows)))
    assert p["tokens"] == {"USDT": 1, "other": 1}
    assert p["detector_predicate_accepts"] == p["candidate_rule_accepts"] == 2
    assert p["source_md5_matches_published"] is False  # synthetic file
    assert p["source_sha256_matches_pinned"] is False

"""Cross-dataset reconciliation: match levels, payoff-attempt linkage, outcome levels and
temporal categories, with the line-74 (competing lookalike) and line-87 (payment before
planting) patterns as regression cases.

Synthetic records only. Each test states the invariant it guards.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptoguard.ml import reconcile as rc
from cryptoguard.ml.poison_hunter import PoisonHunterRecord
from cryptoguard.ml.tsuchiya import PayoffTransfer
from cryptoguard.ml.tsuchiya_archive import (
    COUNTERFEIT,
    PAYOFF,
    PAYOFF_UNCONFIRMED,
    TINY,
    ZERO,
    ArchiveTransfer,
)

VICTIM = "0x" + "11" * 20
OTHER_VICTIM = "0x" + "22" * 20
FRIEND = "0xd296222fb44f5ec8d9600a8c91ed70ed5657d7d5"
LOOKALIKE = "0xd296261b103d698c272887274f38d7ea8097d7d5"  # 5+5 with FRIEND
RIVAL = "0xd29" + "0" * 33 + "d7d5"  # 3+4 with FRIEND
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def h(n: int) -> str:
    return "0x" + f"{n:064x}"


def att(
    block: int,
    *,
    victim: str = VICTIM,
    lookalike: str = LOOKALIKE,
    tx: int = 1,
    flags: int = ZERO,
    intended: str | None = FRIEND,
    line: int = 0,
    victim_sends: bool = False,
) -> ArchiveTransfer:
    sender, receiver = (victim, lookalike) if victim_sends else (lookalike, victim)
    return ArchiveTransfer(
        line=line or block + tx,
        block=block,
        tx=h(tx),
        token=USDT,
        sender=sender,
        receiver=receiver,
        sender_is_victim=victim_sends,
        value=0.0,
        value_usd=0.0,
        flags=flags,
        intended=intended,
        first_digits=5,
        last_digits=5,
    )


def pay_row(
    block: int,
    *,
    victim: str = VICTIM,
    lookalike: str = LOOKALIKE,
    tx: int = 900,
    flags: int = PAYOFF,
) -> ArchiveTransfer:
    return att(block, victim=victim, lookalike=lookalike, tx=tx, flags=flags, victim_sends=True)


def ph(
    line: int = 2,
    *,
    victim: str = VICTIM,
    lookalike: str = LOOKALIKE,
    tx: int = 1,
    block: int | None = 1_000,
    subtype: str = "zero",
    imitated: str = FRIEND,
) -> PoisonHunterRecord:
    return PoisonHunterRecord(
        source_line=line,
        status="valid",
        issues=(),
        lookalike=lookalike,
        victim=victim,
        imitated=imitated,
        planting_tx=h(tx),
        token_symbol="usdt",
        subtype=subtype,
        log_contract=USDT,
        fake_token_deployer=None,
        tx_signer=lookalike,
        tx_target=USDT,
        batch_size=1,
        block_number=block,
        block_distance=1,
        imitated_direction="from",
        source_similarity=10,
        prefix_match=5,
        suffix_match=5,
        cryptoguard_lookalike=True,
        tsuchiya_lookalike=True,
    )


def payoff(
    block: int,
    *,
    victim: str = VICTIM,
    lookalike: str = LOOKALIKE,
    tx: int = 900,
    intended: str = FRIEND,
) -> PayoffTransfer:
    p, s = (5, 5) if lookalike == LOOKALIKE else (3, 4)
    return PayoffTransfer(
        source_line=2,
        status="valid",
        issues=(),
        block_number=block,
        tx_hash=h(tx),
        token=USDT,
        payer=victim,
        lookalike=lookalike,
        intended=intended,
        value_usd=1000.0,
        prefix_match=p,
        suffix_match=s,
    )


@pytest.mark.parametrize(
    ("planting", "payment", "category"),
    [
        (100, 99, "before_planting"),
        (100, 100, "same_block_order_unknown"),
        (100, 101, "after_planting"),
        (None, 5, "temporally_ambiguous"),
        (5, None, "temporally_ambiguous"),
    ],
)
def test_temporal_categories(planting: int | None, payment: int | None, category: str) -> None:
    assert rc.temporal(planting, payment) == category


# --- match levels ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rows", "level"),
    [
        ([att(1_000)], "exact_tx_event"),
        ([att(900, tx=7)], "victim_lookalike_imitated"),
        ([att(900, tx=7, intended="0x" + "33" * 20)], "victim_lookalike"),
        ([att(1_000, victim=OTHER_VICTIM)], "tx_only"),
        ([att(900, victim=OTHER_VICTIM, tx=7)], "shared_lookalike"),
        ([att(900, lookalike=RIVAL, tx=7)], "competing_lookalike"),
        ([att(900, lookalike=RIVAL, tx=7, intended="0x" + "44" * 20)], "victim_only"),
        ([], "none"),
    ],
)
def test_each_match_level_is_distinct(rows: list[ArchiveTransfer], level: str) -> None:
    """The strongest applicable level wins, and weaker evidence keeps its own name."""
    out = rc.ph_matches([ph()], rc.ArchiveIndex(rows), (0, 10**9))
    assert out["levels"][level] == 1
    assert sum(out["levels"].values()) == 1


def test_unmatched_reasons_and_subtype_agreement() -> None:
    rows = [att(1_000, flags=TINY)]
    out = rc.ph_matches(
        [
            ph(2),
            ph(3, tx=5, block=50),
            ph(4, tx=6).model_copy(update={"tsuchiya_lookalike": False, "victim": OTHER_VICTIM}),
        ],
        rc.ArchiveIndex(rows),
        (100, 10**9),
    )
    assert out["subtype_agreement_on_exact"] == {"zero->tiny": 1}  # disagreement is reported
    assert out["not_exact_reasons"] == {"outside_archive_period": 1, "below_3_plus_4_similarity": 1}


def test_repeated_rows_in_one_transaction_count_as_one_attempt() -> None:
    ix = rc.ArchiveIndex([att(1_000, line=1), att(1_000, line=2)])
    assert ix.attempts == 1
    assert ix.repeated_attempt_rows == 1


def test_non_poisoning_rows_are_not_attempts() -> None:
    """Intended transfers and payoffs are not attempts, even between the same pair."""
    ix = rc.ArchiveIndex([att(1_000, flags=1), pay_row(1_500)])
    assert ix.attempts == 0
    assert ix.payoff_rows == {(h(900), VICTIM, LOOKALIKE): PAYOFF}


# --- payoff linkage ----------------------------------------------------------------------


def test_payoff_links_only_to_earlier_attempts_by_the_same_pair() -> None:
    ix = rc.ArchiveIndex([att(1_000), att(1_200, tx=2), att(2_000, tx=3), pay_row(1_500)])
    out = rc.payoff_linkage([payoff(1_500)], ix)
    assert out["linkage"] == {"attempt_before_payoff": 1}
    assert out["blocks_from_last_attempt_to_payoff"]["median"] == 300  # from block 1,200
    assert out["attempts_by_pair_before_payoff"]["median"] == 2  # the 2,000 attempt is later
    assert out["archive_status"] == {"archive_flag_payoff_confirmed": 1}


@pytest.mark.parametrize(
    ("rows", "category"),
    [
        ([att(1_500)], "same_block_only"),
        ([att(1_600)], "attempts_only_after_payoff"),
        ([att(1_000, lookalike=RIVAL)], "no_attempt_between_pair"),
    ],
)
def test_payoffs_without_an_earlier_attempt_are_not_linked(
    rows: list[ArchiveTransfer], category: str
) -> None:
    out = rc.payoff_linkage([payoff(1_500)], rc.ArchiveIndex(rows))
    assert out["linkage"] == {category: 1}
    assert out["linked_distinct"]["payoff_txs"] == 0


def test_unconfirmed_and_missing_archive_payoffs_are_distinguished() -> None:
    ix = rc.ArchiveIndex([pay_row(1_500, flags=PAYOFF_UNCONFIRMED)])
    out = rc.payoff_linkage([payoff(1_500), payoff(1_600, tx=901)], ix)
    assert out["archive_status"] == {
        "archive_flag_payoff_unconfirmed_only": 1,
        "payoff_not_in_archive_subset": 1,
    }


def test_competing_lookalikes_are_counted_and_compared() -> None:
    """Line-74 pattern: several lookalikes of the same intended address reach the victim;
    the comparison is reported against the uniform expectation, not as an effect."""
    rows = [att(1_000), att(1_100, lookalike=RIVAL, tx=2), pay_row(1_500)]
    out = rc.payoff_linkage([payoff(1_500)], rc.ArchiveIndex(rows))
    assert out["payoffs_with_rival_of_same_intended"] == 1
    cmp = out["similarity_recency_comparison"]
    assert (
        cmp["payoffs_compared"],
        cmp["paid_lookalike_most_similar"],
        cmp["paid_lookalike_most_recent"],
    ) == (1, 1, 0)
    assert cmp["expected_if_uniform"] == 0.5


# --- outcome levels ----------------------------------------------------------------------


def test_line_74_loss_to_a_rival_is_a_victim_outcome_not_an_attempt_outcome() -> None:
    out = rc.ph_outcomes([ph(74)], [payoff(12_653, lookalike=RIVAL)])["outcomes"]
    assert out["attempt_outcome_paid_after"] == 0
    assert out["victim_outcome_paid_any_lookalike_after"] == 1


def test_line_87_earlier_payment_is_address_history_not_an_outcome() -> None:
    out = rc.ph_outcomes([ph(87)], [payoff(500, victim=OTHER_VICTIM)])
    o = out["outcomes"]
    assert o["attempt_outcome_paid_after"] == 0
    assert o["address_outcome_paid_by_anyone_before"] == 1
    assert o["address_outcome_paid_by_anyone_after"] == 0
    assert out["payment_pairs_by_temporal_category"] == {"address/before_planting": 1}


def test_attempt_outcome_window_and_same_block() -> None:
    out = rc.ph_outcomes([ph(2)], [payoff(1_000), payoff(60_000, tx=901)])
    o = out["outcomes"]
    assert o["attempt_outcome_paid_after"] == 1
    assert o["attempt_outcome_paid_in_window"] == 0  # 59,000 blocks later
    assert out["payment_pairs_by_temporal_category"]["this_pair/same_block_order_unknown"] == 1


def test_campaign_outcome_uses_group_mates() -> None:
    other_lk = "0x" + "55" * 20
    groups = {LOOKALIKE: "g0001", other_lk: "g0001"}
    out = rc.ph_outcomes([ph(2)], [payoff(2_000, victim=OTHER_VICTIM, lookalike=other_lk)], groups)
    assert out["outcomes"]["campaign_outcome_paid_after"] == 1
    assert out["outcomes"]["attempt_outcome_paid_after"] == 0


def test_zero_match_scenario_has_complete_denominators() -> None:
    out = rc.reconcile(
        [], {"poisoning_block_range": None, "block_range": None}, [ph()], [payoff(5)], []
    )
    assert out["poison_hunter"]["levels"]["none"] == 1
    assert out["payoffs"]["linkage"] == {"no_attempt_between_pair": 1}
    assert out["subset"]["attempts"] == 0


def test_incident_case_study_counts_only_earlier_pair_attempts() -> None:
    inc = {
        "case": "c",
        "victim": VICTIM,
        "recipient": LOOKALIKE,
        "block": 1_500,
        "tx": h(900),
        "token": USDT,
    }
    out = rc.incident_case_studies(
        [inc], rc.ArchiveIndex([att(1_000), att(2_000, tx=2)]), (0, 10**9)
    )
    assert out[0]["pair_attempts_before_harm"] == 1
    assert out[0]["harm_tx_in_archive"] is False


def test_counterfeit_rows_are_attempts() -> None:
    assert rc.ArchiveIndex([att(1, flags=COUNTERFEIT)]).attempts == 1


# --- shadow-mode isolation ----------------------------------------------------------------

RESEARCH = (
    "cryptoguard.ml.fetch",
    "cryptoguard.ml.tsuchiya",
    "cryptoguard.ml.tsuchiya_archive",
    "cryptoguard.ml.reconcile",
    "cryptoguard.ml.cross_dataset",
    "cryptoguard.ml.bench_archive",
)
# The pure lookalike predicates live in detectors.poisoning, whose base module imports type
# definitions from history/services/risk. Persistence and the API are what could create,
# change or serve findings, so those must stay unloaded.
PRODUCTION_STATE = ("cryptoguard.database", "cryptoguard.api")


def test_research_pipeline_cannot_reach_findings_or_persistence() -> None:
    """Running the whole research pipeline (scan, subset, reconciliation) never loads the
    application database or API layers, so it cannot persist, change or serve findings."""
    import subprocess
    import sys

    code = (
        "import sys, json, tempfile, pathlib\n"
        f"mods = {RESEARCH!r}\n"
        "for m in mods: __import__(m)\n"
        "from cryptoguard.ml.bench_archive import run_one\n"
        "from cryptoguard.ml.reconcile import reconcile\n"
        "from cryptoguard.ml.tsuchiya_archive import load_subset\n"
        "from cryptoguard.ml.cross_dataset import incident_refs\n"
        "d = pathlib.Path(tempfile.mkdtemp())\n"
        "run_one(200, d)\n"
        "rows, summary = load_subset(d / 'a.sqlite')\n"
        "reconcile(rows, summary, [], [], incident_refs())\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('cryptoguard.'))))\n"
    )
    out = subprocess.run(  # noqa: S603 - a fixed in-test script
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    loaded = __import__("json").loads(out.stdout.strip().splitlines()[-1])
    leaked = [m for m in loaded if m.startswith(PRODUCTION_STATE)]
    assert leaked == []


# --- review queue -------------------------------------------------------------------------


def test_payoff_linked_attempts_become_review_packets_without_labels_or_scores() -> None:
    """Only attempts before a payoff become packets; each carries the payment and the
    competing lookalikes, and no score or label."""
    rows = [att(1_000), att(1_100, lookalike=RIVAL, tx=2), att(2_000, tx=3)]
    packets = rc.payoff_review_packets([payoff(1_500), payoff(500, tx=901)], rc.ArchiveIndex(rows))
    assert len(packets) == 1
    p = packets[0]
    assert p.planting_tx == h(1)
    assert p.competing_lookalikes == (RIVAL,)
    assert p.payment_evidence[0].startswith(h(900))
    assert "after_planting" in p.payment_evidence[0]
    assert "score" not in p.model_dump()
    assert p.source_labels == ("tsuchiya-archive:zero_value", "tsuchiya-payoff:confirmed")


def test_spoofed_sender_attempts_are_typed_as_transfer_from() -> None:
    rows = [att(1_000, victim_sends=True)]
    (p,) = rc.payoff_review_packets([payoff(1_500)], rc.ArchiveIndex(rows))
    assert p.subtype == "spoofed_transfer_from"


def test_version_1_review_packets_still_load() -> None:
    from cryptoguard.ml.review import ReviewPacket

    v1 = {
        "schema_version": "poisoning-review/1", "victim_event_id": "e", "victim": VICTIM,
        "lookalike": LOOKALIKE, "imitated": FRIEND, "planting_tx": h(1),
        "observation_block": 1, "subtype": "dust", "evidence_summary": "x",
        "coverage_limitations": "y", "source_labels": ["s"],
    }  # fmt: skip
    p = ReviewPacket.model_validate(v1)
    assert (p.competing_lookalikes, p.payment_evidence) == ((), ())


def test_similarity_comparison_counts_ties_in_the_uniform_expectation() -> None:
    """When the paid lookalike ties with a rival on similarity, chance alone picks one of
    the best with probability 2/2, so the tie is not evidence of anything."""
    twin = "0xd2962" + "a" * 29 + "07d7d5"  # also 5+5 with FRIEND
    rows = [att(1_000), att(1_100, lookalike=twin, tx=2)]
    cmp = rc.payoff_linkage([payoff(1_500)], rc.ArchiveIndex(rows))["similarity_recency_comparison"]
    assert cmp["paid_lookalike_most_similar"] == 1
    assert cmp["expected_if_uniform"] == 1.0
    assert cmp["paid_lookalike_most_recent"] == 0
    assert cmp["expected_if_uniform_recent"] == 0.5


def test_transaction_only_matches_say_whether_the_victim_was_listed() -> None:
    rows = [att(1_000, lookalike=RIVAL), att(1_000, victim=OTHER_VICTIM)]
    out = rc.ph_matches([ph()], rc.ArchiveIndex(rows), (0, 10**9))
    assert out["levels"]["tx_only"] == 1
    assert out["tx_only_detail"] == {"victim_listed_with_another_lookalike": 1}


# --- end-to-end report on synthetic inputs ------------------------------------------------


def test_cross_dataset_report_end_to_end_on_synthetic_inputs(tmp_path: Path) -> None:
    """Scan -> subset -> reconciliation -> tables, with no real data: the integrity gate
    fails because synthetic counts differ from the publisher's, and no address leaks."""
    import json
    import re

    from cryptoguard.ml import cross_dataset as cd
    from cryptoguard.ml import tsuchiya_archive as ta
    from cryptoguard.ml.bench_archive import synthetic_dump
    from tests.unit.test_ml_poisoning import ph_row, write_ph
    from tests.unit.test_ml_tsuchiya import payoff as payoff_row
    from tests.unit.test_ml_tsuchiya import write_payoffs

    data, out = tmp_path / "data", tmp_path / "out"
    (data / "poison-hunter").mkdir(parents=True)
    (data / "tsuchiya2025").mkdir(parents=True)
    write_ph(data / "poison-hunter" / "phishing_transfers_sample.csv", [ph_row()])
    write_payoffs(data / "tsuchiya2025" / "payoff_transfers_ethereum.csv", [payoff_row()])
    out.mkdir()
    manifest = out / "targets.json"
    manifest.write_text(json.dumps(ta.build_targets({"x": [VICTIM]})), encoding="utf-8")
    summary = ta.scan(
        synthetic_dump(tmp_path / "d.gz", 500),
        ta.load_targets(manifest),
        out / "archive_subset.sqlite",
        work_dir=out / "spill",
    )
    (out / "archive-scan.json").write_text(json.dumps(summary), encoding="utf-8")

    report = cd.build_report(data, out)
    gates = {g["gate"]: g["status"] for g in report["gates"]}
    assert gates["1 Data integrity"] == "fail"
    assert gates["5 Independent evaluation"] == "fail"
    assert report["rpc_requests"] == 0
    text = cd.render(report)
    assert "Publisher counts reproduced" in text
    assert "**no**" in text
    assert not re.search(r"0x[0-9a-fA-F]{40}", text)
    written = cd.write_report(report, out, tmp_path / "tables.md")
    assert json.loads(written.read_text(encoding="utf-8"))["tables_sha256"]


def test_scan_refuses_a_missing_archive_without_downloading(tmp_path: Path) -> None:
    from cryptoguard.ml.cross_dataset import run_scan

    with pytest.raises(FileNotFoundError, match="never fetched automatically"):
        run_scan(tmp_path, tmp_path / "out")

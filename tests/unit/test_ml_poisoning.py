# ruff: noqa: E501  (tabular test cases are kept on one line each)
"""Phase 11.2: poisoning research data model, parser, pilot records, payment verification,
candidate generation, point-in-time features, review workflow, planner and monitoring.

Synthetic data only (no RPC, no third-party files). Each test states the invariant it guards.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import candidates as cand
from cryptoguard.ml.events import (
    LabelRecord,
    PoisoningEvent,
    campaign_groups,
    deduplicate,
    grouped_temporal_split,
    manifest,
    quality_gates,
    resolve_labels,
)
from cryptoguard.ml.history import events_from_fixture
from cryptoguard.ml.monitoring import missing_share, psi, reference_bins
from cryptoguard.ml.payments import verify_payment
from cryptoguard.ml.pilot import (
    PilotRecordError,
    YieldRecord,
    cost_record,
    read_jsonl,
    reconstruct,
    render_markdown,
    summarize_fixture,
    summarize_fixture_json,
    yield_record,
)
from cryptoguard.ml.planner import CollectionJob, PlanRejected, plan
from cryptoguard.ml.poison_hunter import (
    EXPECTED_HEADER,
    SchemaMismatchError,
    parse_sample,
    profile,
)
from cryptoguard.ml.review import ReviewImportError, export_packets, import_reviews, packet
from cryptoguard.replay.models import RecordedTransaction, RecordedTransfer, ReplayFixture

WALLET = "0x" + "11" * 20
FRIEND = "0xd296222fb44f5ec8d9600a8c91ed70ed5657d7d5"
LOOKALIKE = "0xd296261b103d698c272887274f38d7ea8097d7d5"
STRANGER = "0x" + "3c" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE = "0x" + "fa" * 20
TX = "0x" + "ab" * 32


def h(n: int) -> str:
    return "0x" + f"{n:064x}"


# --- Poison-Hunter parser -------------------------------------------------------------


def ph_row(**over: str) -> list[str]:
    row = {
        0: LOOKALIKE, 1: WALLET, 2: FRIEND, 3: h(1), 4: "usdt", 5: "dust", 6: USDT, 7: "",
        8: LOOKALIKE, 9: USDT, 10: "0.001", 11: "1.0", 12: "", 13: "16000000", 14: "12",
        15: "from", 16: "10",
    }  # fmt: skip
    for k, v in over.items():
        row[int(k[1:])] = v
    return [row[i] for i in range(17)]


def write_ph(path: Path, rows: list[list[str]], header: list[str] = EXPECTED_HEADER) -> Path:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return path


def test_parser_maps_fields_and_keeps_provenance(tmp_path: Path) -> None:
    res = parse_sample(write_ph(tmp_path / "s.csv", [ph_row()]))
    (r,) = res.records
    assert r.status == "valid"
    assert (r.lookalike, r.victim, r.imitated) == (LOOKALIKE, WALLET, FRIEND)
    assert r.source_line == 2  # traceable to the original row
    assert (r.prefix_match, r.suffix_match) == (5, 5)
    assert len(res.source_sha256) == 64


def test_header_or_width_changes_are_refused(tmp_path: Path) -> None:
    with pytest.raises(SchemaMismatchError):
        parse_sample(write_ph(tmp_path / "a.csv", [ph_row()], header=EXPECTED_HEADER[1:]))
    with pytest.raises(SchemaMismatchError):
        parse_sample(write_ph(tmp_path / "b.csv", [ph_row()[:16]]))


def test_bad_rows_are_quarantined_with_reasons_not_dropped(tmp_path: Path) -> None:
    rows = [
        ph_row(c3="0x123"),  # malformed hash
        ph_row(c2="0x" + "99" * 20),  # imitated address not similar at all
        ph_row(c15="to"),  # the unverified direction
        ph_row(c13="", c0="0xZZ"),  # missing block, malformed address
    ]
    res = parse_sample(write_ph(tmp_path / "s.csv", rows))
    assert len(res.records) == 4
    assert all(r.status == "quarantined" and r.issues for r in res.records)
    assert any("below any published lookalike" in i for i in res.records[1].issues)


def test_batch_planting_and_duplicates_are_profiled(tmp_path: Path) -> None:
    other = "0x" + "22" * 20
    batch = dict(c5="zero", c8=STRANGER, c9=FAKE, c11="2.0", c12=STRANGER)
    rows = [ph_row(**batch), ph_row(**batch, c1=other), ph_row(**batch)]
    p = profile(parse_sample(write_ph(tmp_path / "s.csv", rows)))
    assert p["distinct_planting_txs"] == 1
    assert p["planting_txs_with_several_rows"] == 1
    assert p["duplicate_victim_events"] == 1  # the third row repeats the first victim-event


# --- pilot records: the lost-data bug and its migration ---------------------------------


def fixture(
    transfers: list[RecordedTransfer], txs: list[RecordedTransaction], **kw: Any
) -> ReplayFixture:
    base: dict[str, Any] = dict(
        case_id="t", chain_id=1, wallet=WALLET, from_block=100, to_block=10_000,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC), recorded_with="test", rpc_requests=0,
        transfer_scan_complete=True, sender_lookups_skipped=0, method=[], wallet_code_hex={},
        block_timestamps={},
    )  # fmt: skip
    base.update(kw)
    return ReplayFixture(**base, transfers=transfers, wallet_transactions=txs)


def transfer(block: int, sender: str, recipient: str, value: int, *, token: str = USDT,
             tx_sender: str | None = None, idx: int = 0, log: int = 0) -> RecordedTransfer:  # fmt: skip
    return RecordedTransfer(
        token=token, sender=sender, recipient=recipient, value=str(value), block_number=block,
        block_hash=h(block), transaction_hash=h(block * 1000 + idx * 10 + log),
        transaction_index=idx, log_index=log, tx_sender=tx_sender,
    )  # fmt: skip


def eth_tx(block: int, to: str, value: int, *, succeeded: bool | None = True, idx: int = 0) -> RecordedTransaction:  # fmt: skip
    return RecordedTransaction(
        transaction_hash=h(block * 7 + idx), block_number=block, transaction_index=idx, nonce=block,
        to=to, value=str(value), succeeded=succeeded,
    )  # fmt: skip


def test_summary_reads_wallet_transactions_and_counts_payments() -> None:
    fx = fixture(
        [
            transfer(200, WALLET, FRIEND, 5, tx_sender=WALLET),  # a payment
            transfer(210, WALLET, LOOKALIKE, 0, tx_sender=LOOKALIKE),  # spoofed, not a payment
        ],
        [eth_tx(300, FRIEND, 10**18), eth_tx(310, FRIEND, 10**18, succeeded=False)],
    )
    s = summarize_fixture(fx)
    assert (s.wallet_transactions, s.outgoing_payments, s.transfers) == (2, 2, 2)


def test_empty_valid_history_is_a_real_zero() -> None:
    s = summarize_fixture(fixture([], []))
    assert (s.wallet_transactions, s.outgoing_payments, s.scan_complete) == (0, 0, True)


def test_old_field_name_or_missing_field_raises_instead_of_reading_zero() -> None:
    good = json.loads(fixture([], [eth_tx(300, FRIEND, 1)]).model_dump_json())
    renamed = dict(good)
    renamed["transactions"] = renamed.pop("wallet_transactions")  # the pilot's misreading
    with pytest.raises(PilotRecordError):
        summarize_fixture_json(renamed)
    missing = {k: v for k, v in good.items() if k != "wallet_transactions"}
    with pytest.raises(PilotRecordError):
        summarize_fixture_json(missing)
    wrong_type = dict(good, wallet_transactions="none")
    with pytest.raises(PilotRecordError):
        summarize_fixture_json(wrong_type)
    assert summarize_fixture_json(good).wallet_transactions == 1


def test_lost_recordings_migrate_to_unknown_not_zero() -> None:
    legacy = {
        "block": 5, "draw": 7, "has_code": False, "nonce_end": 176, "requests": 228,
        "result": "error", "sends": 6, "wallet_sha": "ee",
        "error": "AttributeError: 'ReplayFixture' object has no attribute 'transactions'",
    }  # fmt: skip
    rec = cost_record(legacy)
    assert rec.result == "recorded_contents_lost"
    assert rec.outgoing_payments is None and rec.wallet_transactions is None  # noqa: PT018
    assert rec.signed_in_window == 6  # recoverable: the nonce difference was logged
    assert rec.record_requests == 224
    assert rec.migrated_from == "pilot-cost/legacy-1"


def test_unknown_schema_versions_and_fields_are_rejected() -> None:
    with pytest.raises(PilotRecordError):
        yield_record({"schema_version": "pilot-yield/9"})
    with pytest.raises(PilotRecordError):
        yield_record({"victim": WALLET, "attacker": LOOKALIKE, "type": "dust", "lo": 1, "hi": 2,
                      "requests": 2, "surprise": 1})  # fmt: skip
    with pytest.raises(PilotRecordError):
        cost_record({"draw": 1})


def _legacy_yield(**kw: Any) -> dict[str, Any]:
    base = {"victim": WALLET, "attacker": LOOKALIKE, "type": "dust", "lo": 101, "hi": 50_500,
            "n0": 3, "requests": 2}  # fmt: skip
    base.update(kw)
    return base


@pytest.mark.parametrize(
    ("kw", "outcome"),
    [
        (dict(sent_in_window=0, resolved=True), "no_direct_payment_observed_with_complete_declared_coverage"),
        (dict(sent_in_window=2, resolved=True, paid_attacker=[]), "no_direct_payment_observed_with_complete_declared_coverage"),
        (dict(sent_in_window=2, resolved=False, paid_attacker=[]), "partial_coverage"),
        (dict(sent_in_window=40, resolved=False), "unresolved"),
        (dict(sent_in_window=3, resolved=False, skipped="phase_cap"), "not_evaluated"),
        (dict(error="RpcTimeoutError", resolved=False), "unresolved"),
        (dict(sent_in_window=1, resolved=True,
              paid_attacker=[{"tx": TX, "kind": "eth", "succeeded": True}]), "confirmed_direct_payment"),
        (dict(sent_in_window=1, resolved=True,
              paid_attacker=[{"tx": TX, "kind": "eth", "succeeded": False}]),
         "no_direct_payment_observed_with_complete_declared_coverage"),
    ],
)  # fmt: skip
def test_outcomes_never_call_an_unobserved_victim_benign(kw: dict[str, Any], outcome: str) -> None:
    assert yield_record(_legacy_yield(**kw)).outcome == outcome


def test_jsonl_cut_off_tail_is_skipped_and_middle_corruption_raises(tmp_path: Path) -> None:
    p = tmp_path / "y.jsonl"
    p.write_text('{"a": 1}\n{"a": 2}\n{"a": 3', encoding="utf-8")
    rows, truncated = read_jsonl(p)
    assert rows == [{"a": 1}, {"a": 2}]
    assert truncated
    p.write_text('{"a": 1}\n{broken\n{"a": 3}\n', encoding="utf-8")
    with pytest.raises(PilotRecordError, match="corrupt line 2"):
        read_jsonl(p)


def _pilot_dir(tmp_path: Path) -> Path:
    d = tmp_path / "pilot"
    d.mkdir()
    ys = [_legacy_yield(sent_in_window=0, resolved=True),
          _legacy_yield(victim="0x" + "22" * 20, sent_in_window=200, resolved=False, requests=2)]  # fmt: skip
    (d / "yield.jsonl").write_text("".join(json.dumps(y) + "\n" for y in ys), encoding="utf-8")
    (d / "cost.jsonl").write_text(
        json.dumps({"draw": 1, "block": 9, "requests": 3, "result": "ineligible",
                    "has_code": False, "nonce_end": 4}) + "\n", encoding="utf-8")  # fmt: skip
    (d / "budget.json").write_text(json.dumps({"requests": 10}), encoding="utf-8")
    (d / "summary.json").write_text(
        json.dumps({"started_used": 2, "ended_used": 10, "seconds": 1.0}), encoding="utf-8"
    )
    (d / "plan.json").write_text("{}", encoding="utf-8")
    return d


def test_reconstruction_is_deterministic_and_bounds_are_conditional(tmp_path: Path) -> None:
    d = _pilot_dir(tmp_path)
    cands = [(2, WALLET, LOOKALIKE), (3, "0x" + "22" * 20, LOOKALIKE)]
    a, b = reconstruct(d, cands), reconstruct(d, cands)
    assert a == b
    assert render_markdown(a) == render_markdown(b)
    assert a["requests"]["run_overhead"] == 1  # 10 - 2 - (2 + 2) - 3
    assert a["yield"]["outcomes"]["unresolved"] == 1
    assert a["yield"]["observed_complete"] == 1
    assert "not a random sample" in a["yield"]["conditional_on"]


def test_reconstruction_refuses_misaligned_candidates(tmp_path: Path) -> None:
    d = _pilot_dir(tmp_path)
    with pytest.raises(PilotRecordError):
        reconstruct(d, [(2, LOOKALIKE, WALLET), (3, WALLET, LOOKALIKE)])
    with pytest.raises(PilotRecordError):
        reconstruct(d, [(2, WALLET, LOOKALIKE)])


def test_new_records_round_trip_through_the_versioned_schema() -> None:
    rec = yield_record(_legacy_yield(sent_in_window=0, resolved=True), source_line=4)
    again = yield_record(json.loads(rec.model_dump_json()))
    assert again == rec
    assert isinstance(again, YieldRecord)


# --- payment verification ---------------------------------------------------------------


def _topic(a: str) -> str:
    return "0x" + "0" * 24 + a[2:]


def tok_transfer(token: str, to: str, amount: int) -> dict[str, Any]:
    data = "0xa9059cbb" + "0" * 24 + to[2:] + f"{amount:064x}"
    return {"hash": TX, "from": WALLET, "to": token, "value": "0x0", "input": data}


def tlog(token: str, frm: str, to: str, amount: int) -> dict[str, Any]:
    from cryptoguard.blockchain.abi import TRANSFER_TOPIC

    return {"address": token, "topics": [TRANSFER_TOPIC, _topic(frm), _topic(to)],
            "data": f"0x{amount:064x}"}  # fmt: skip


OK = {"status": "0x1", "logs": []}


def test_native_transfer_needs_signer_destination_value_and_success() -> None:
    tx = {"hash": TX, "from": WALLET, "to": LOOKALIKE, "value": hex(10**18), "input": "0x"}
    assert verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt=OK).status == (
        "confirmed_direct_payment"
    )
    rev = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt={"status": "0x0"})
    assert rev.status == "reverted"
    assert (
        verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt=None).status
        == "unresolved"
    )
    other = verify_payment(victim=WALLET, candidate=STRANGER, tx=tx, receipt=OK)
    assert other.status == "not_a_payment"
    assert other.ownership_claim is None


def test_trusted_token_transfer_needs_a_matching_log() -> None:
    tx = tok_transfer(USDT, LOOKALIKE, 5_000_000)
    good = {"status": "0x1", "logs": [tlog(USDT, WALLET, LOOKALIKE, 5_000_000)]}
    r = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt=good)
    assert (r.status, r.asset, r.amount) == ("confirmed_direct_payment", "USDT", 5_000_000)
    no_log = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt=OK)
    assert no_log.status == "unresolved"
    wrong_amount = {"status": "0x1", "logs": [tlog(USDT, WALLET, LOOKALIKE, 1)]}
    assert (
        verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx, receipt=wrong_amount).status
        == "unresolved"
    )


def test_fake_tokens_zero_amounts_and_forged_logs_are_not_losses() -> None:
    fake = tok_transfer(FAKE, LOOKALIKE, 9)
    fake_receipt = {"status": "0x1", "logs": [tlog(FAKE, WALLET, LOOKALIKE, 9)]}
    r = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=fake, receipt=fake_receipt)
    assert r.status == "unresolved"
    assert "untrusted_token" in r.evidence
    zero = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tok_transfer(USDT, LOOKALIKE, 0),
                          receipt={"status": "0x1", "logs": [tlog(USDT, WALLET, LOOKALIKE, 0)]})  # fmt: skip
    assert zero.status == "not_a_payment"
    # The attacker's own transferFrom(victim, lookalike, 0): a genuine-token log, not victim-signed.
    spoof = {"hash": TX, "from": LOOKALIKE, "to": USDT, "value": "0x0", "input": "0x23b872dd"}
    s = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=spoof,
                       receipt={"status": "0x1", "logs": [tlog(USDT, WALLET, LOOKALIKE, 0)]})  # fmt: skip
    assert s.status == "unresolved"
    assert "spender_mediated_transfer_from" in s.evidence


def test_router_and_contract_calls_stay_unresolved() -> None:
    tx = {
        "hash": TX,
        "from": WALLET,
        "to": STRANGER,
        "value": "0x0",
        "input": "0x5ae401dc" + "00" * 64,
    }
    r = verify_payment(victim=WALLET, candidate=LOOKALIKE, tx=tx,
                       receipt={"status": "0x1", "logs": [tlog(USDT, WALLET, LOOKALIKE, 7)]})  # fmt: skip
    assert r.status == "unresolved"


# --- events, labels, groups, splits, gates ----------------------------------------------


def event(victim: str = WALLET, lookalike: str = LOOKALIKE, tx: str = TX, block: int = 1_000,
          signer: str | None = None, log: int | None = 0) -> PoisoningEvent:  # fmt: skip
    return PoisoningEvent(
        chain_id=1, victim=victim, lookalike=lookalike, imitated=FRIEND, planting_tx=tx,
        planting_block=block, planting_tx_index=0, planting_log_index=log,
        observation_timestamp=None, subtype="zero_value", tx_signer=signer, log_contract=USDT,
        token_contract=USDT, candidate_method="test",
    )  # fmt: skip


def test_one_batch_transaction_gives_separate_victim_events_and_one_group() -> None:
    a, b = event(victim=WALLET, log=0), event(victim="0x" + "22" * 20, log=1)
    assert a.planting_tx_id == b.planting_tx_id
    assert a.victim_event_id != b.victim_event_id
    kept, dropped = deduplicate([a, b, a])
    assert (len(kept), dropped) == (2, 1)
    groups = campaign_groups([a, b])
    assert groups[a.victim_event_id] == groups[b.victim_event_id]  # one campaign


def test_public_infrastructure_does_not_merge_campaigns() -> None:
    a = event(victim=WALLET, lookalike=LOOKALIKE, tx=h(1), signer=USDT)
    b = event(victim="0x" + "22" * 20, lookalike=STRANGER, tx=h(2), signer=USDT)
    groups = campaign_groups([a, b])
    assert groups[a.victim_event_id] != groups[b.victim_event_id]


def test_grouped_split_keeps_campaigns_whole_and_test_later() -> None:
    evs = [event(victim="0x" + f"{i:040x}", lookalike="0x" + f"{i + 900:040x}", tx=h(i), block=i * 10)
           for i in range(1, 21)]  # fmt: skip
    evs.append(event(victim="0x" + f"{20:040x}", lookalike="0x" + f"{999:040x}", tx=h(99), block=5))
    groups = campaign_groups(evs)
    split = grouped_temporal_split(evs, groups, test_fraction=0.3)
    for g in set(groups.values()):
        assert len({split[e] for e, gg in groups.items() if gg == g}) == 1
    train_max = max(e.planting_block for e in evs if split[e.victim_event_id] == "train"
                    and groups[e.victim_event_id] != groups[evs[-1].victim_event_id])  # fmt: skip
    test_min = min(e.planting_block for e in evs if split[e.victim_event_id] == "test"
                   and groups[e.victim_event_id] != groups[evs[-1].victim_event_id])  # fmt: skip
    assert train_max < test_min
    # The early event shares a victim with the latest group: it follows its group to test.
    assert split[evs[-1].victim_event_id] == split[evs[19].victim_event_id]


def test_labels_keep_weak_verified_and_conflicts_apart() -> None:
    labs = [
        LabelRecord(victim_event_id="a", tier="weak_attempt", source="ph", available_at=None),
        LabelRecord(victim_event_id="b", tier="weak_attempt", source="ph", available_at=None),
        LabelRecord(victim_event_id="b", tier="verified_attempt", source="review:x", available_at=None),
        LabelRecord(victim_event_id="c", tier="verified_attempt", source="review:x", available_at=None),
        LabelRecord(victim_event_id="c", tier="verified_legitimate", source="review:y", available_at=None),
    ]  # fmt: skip
    assert resolve_labels(labs) == {
        "a": "weak_attempt",
        "b": "verified_attempt",
        "c": "conflicting",
    }


def test_gates_block_training_on_weak_positives_without_verified_negatives() -> None:
    evs = [event(victim="0x" + f"{i:040x}", tx=h(i)) for i in range(40)]
    labels = {e.victim_event_id: "weak_attempt" for e in evs}
    gates = {g.gate: g for g in quality_gates(evs, labels, license_ok=False)}  # type: ignore[arg-type]
    assert not gates["B_label_validity"].passed
    assert not gates["license"].passed
    assert gates["A_data_validity"].passed


def test_manifest_hash_is_order_independent() -> None:
    a, b = event(tx=h(1)), event(tx=h(2))
    assert manifest([a, b], [])["sha256"] == manifest([b, a], [])["sha256"]
    assert manifest([a], [])["sha256"] != manifest([a, b], [])["sha256"]


# --- candidates and point-in-time features ----------------------------------------------


def _history() -> list[RecordedTransfer]:
    return [
        transfer(500, WALLET, FRIEND, 100, tx_sender=WALLET, idx=1),  # the wallet pays FRIEND
        transfer(900, LOOKALIKE, WALLET, 0, idx=2),  # zero-value planting from a lookalike
        transfer(950, WALLET, LOOKALIKE, 0, tx_sender=LOOKALIKE, idx=3),  # spoofed transferFrom
    ]


def test_generator_finds_each_planting_shape_independently_of_the_detector() -> None:
    fx = fixture([*_history(), transfer(960, STRANGER, WALLET, 5_000, idx=1),
                  transfer(970, LOOKALIKE, WALLET, 3, token=FAKE, idx=1)], [])  # fmt: skip
    cs = cand.generate(fx)
    methods = {c.event.planting_block: set(c.methods) for c in cs}
    assert methods[900] == {"zero_value_in", "lookalike_in"}
    assert methods[950] == {"spoofed_out"}
    assert methods[960] == {"dust_in"}
    assert methods[970] == {"lookalike_in", "untrusted_token_in"}
    assert 500 not in methods  # an ordinary payment is not a candidate
    assert cs[0].event.imitated == FRIEND


def test_lookalike_is_relative_to_counterparties_chosen_before_the_event() -> None:
    # The planting comes before the wallet ever pays FRIEND: no imitated counterparty yet.
    fx = fixture([transfer(400, LOOKALIKE, WALLET, 5_000_000, idx=1),
                  transfer(500, WALLET, FRIEND, 100, tx_sender=WALLET, idx=1)], [])  # fmt: skip
    assert cand.generate(fx) == []


def _features_at(fx: ReplayFixture, block: int) -> cand.EventFeatures:
    events, coverage = events_from_fixture(fx)
    c = next(c for c in cand.generate(fx) if c.event.planting_block == block)
    return cand.event_features(c, events, coverage)


def test_future_events_and_losses_do_not_change_past_features() -> None:
    base = fixture(_history(), [])
    later = fixture([*_history(), transfer(5_000, WALLET, LOOKALIKE, 10**9, tx_sender=WALLET)],
                    [eth_tx(6_000, LOOKALIKE, 10**18)])  # fmt: skip
    assert _features_at(base, 900) == _features_at(later, 900)


def test_input_order_does_not_change_features() -> None:
    fx = fixture(_history(), [])
    shuffled = fixture(list(reversed(_history())), [])
    assert _features_at(fx, 950) == _features_at(shuffled, 950)


def test_later_transactions_in_the_same_block_are_invisible() -> None:
    same_block_later = transfer(900, WALLET, FRIEND, 100, tx_sender=WALLET, idx=9)
    a = _features_at(fixture(_history(), []), 900)
    b = _features_at(fixture([*_history(), same_block_later], []), 900)
    assert a == b


def test_unknown_history_is_not_safe_history() -> None:
    partial = fixture(_history(), [], transfer_scan_complete=False)
    f = _features_at(partial, 900)
    assert f.history.history_status == "partial"
    assert f.history.prior_payments_to_recipient is None
    assert f.plausible_impersonated is None
    assert f.as_model_row()["prior_payments_to_recipient"] == -1.0


def test_known_empty_history_gives_zeros() -> None:
    fx = fixture([transfer(500, WALLET, FRIEND, 1, tx_sender=WALLET, idx=1),
                  transfer(900, LOOKALIKE, WALLET, 0, idx=2)], [])  # fmt: skip
    f = _features_at(fx, 900)
    assert f.history.prior_payments_to_recipient == 0
    assert f.plausible_impersonated == 1
    assert f.blocks_since_imitated_chosen == 400


def test_cross_wallet_index_sees_only_earlier_blocks() -> None:
    idx = cand.PriorIndex()
    idx.add(event(victim="0x" + "22" * 20, block=800))
    idx.add(event(victim="0x" + "33" * 20, block=900))  # same block as the query: invisible
    idx.add(event(victim="0x" + "44" * 20, block=2_000))  # future
    assert idx.distinct_victims_before("lookalike", LOOKALIKE, 900) == 1
    assert idx.distinct_victims_before("signer", None, 900) is None


# --- review workflow --------------------------------------------------------------------


def test_review_export_has_no_score_and_imports_preserve_disagreement(tmp_path: Path) -> None:
    e = event()
    out = tmp_path / "packets.jsonl"
    export_packets([packet(e, ["poison-hunter:weak_attempt"], "zero-value transfer")], out)
    line = json.loads(out.read_text().splitlines()[0])
    assert not any("score" in k for k in line)
    decisions = tmp_path / "d.jsonl"
    rows = [
        {"victim_event_id": e.victim_event_id, "decision": "confirmed_poisoning_attempt",
         "rationale": "r", "reviewer": "a", "reviewed_at": "2026-11-02T00:00:00Z"},
        {"victim_event_id": e.victim_event_id, "decision": "confirmed_legitimate_interaction",
         "rationale": "r", "reviewer": "b", "reviewed_at": "2026-11-02T01:00:00Z"},
    ]  # fmt: skip
    decisions.write_text("".join(json.dumps(r) + "\n" for r in rows))
    prior = [LabelRecord(victim_event_id=e.victim_event_id, tier="weak_attempt", source="ph",
                         available_at=None)]  # fmt: skip
    history = import_reviews(decisions, {e.victim_event_id}, prior)
    assert len(history) == 3  # nothing overwritten
    assert resolve_labels(history)[e.victim_event_id] == "conflicting"


def test_review_import_is_all_or_nothing(tmp_path: Path) -> None:
    bad = tmp_path / "d.jsonl"
    bad.write_text(json.dumps({"victim_event_id": "x", "decision": "benign", "rationale": "",
                               "reviewer": "a", "reviewed_at": "t"}) + "\n")  # fmt: skip
    with pytest.raises(ReviewImportError):
        import_reviews(bad, {"x"}, [])


# --- planner ----------------------------------------------------------------------------


def test_planner_estimates_conservatively_and_rejects_over_cap() -> None:
    small = plan(CollectionJob(wallets=2, window_blocks=7_200, request_cap=10_000))
    assert small["executes"] is False
    assert small["estimate"]["log_requests_per_wallet"] == 144
    with pytest.raises(PlanRejected):
        plan(CollectionJob(wallets=120, window_blocks=50_400, request_cap=200_000))
    assert plan(CollectionJob(wallets=2, window_blocks=7_200, request_cap=10_000)) == small


# --- monitoring -------------------------------------------------------------------------


def test_psi_edge_cases() -> None:
    ref = reference_bins([float(i % 10) for i in range(200)])
    assert psi(ref, []) is None  # empty batch: no PSI, not 0
    assert psi(ref, [None, float("nan")]) is None  # only missing values
    assert missing_share([1.0, None, float("nan"), 2.0]) == 0.5
    assert missing_share([]) is None
    constant = reference_bins([3.0] * 100)
    assert psi(constant, [3.0] * 10) == pytest.approx(0.0, abs=1e-9)
    sparse = reference_bins([0.0] * 95 + [1.0, 2.0, 5.0, 9.0, 40.0])
    stable = psi(sparse, [0.0] * 95 + [1.0, 2.0, 5.0, 9.0, 40.0])
    assert stable is not None
    assert stable < 0.01
    shifted = psi(sparse, [40.0] * 20)
    assert shifted is not None
    assert shifted > 1.0  # zero-frequency bins handled by the floor, no division by zero


def test_phase11_reference_bins_keep_their_original_semantics() -> None:
    # A Phase 11 card stores shares counted with bisect_right and has no "closed" key.
    old = {"edges": [0.0], "expected": [0.0, 1.0]}
    assert psi(old, [0.0] * 50) == pytest.approx(0.0, abs=1e-9)  # no false drift on old cards


def test_option_b_estimate_under_pilot_assumptions() -> None:
    p = plan(CollectionJob(wallets=120, window_blocks=50_400, request_cap=240_000))
    assert p["estimate"]["total_requests_conservative"] == 237_360

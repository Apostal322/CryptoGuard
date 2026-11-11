"""ML features: point in time, deterministic, no identifiers (pure Python, no ml extra)."""

from __future__ import annotations

import copy
import math

from cryptoguard.ml.features import (
    APPROVAL,
    APPROVAL_FOR_ALL,
    FEATURES,
    TRANSFER,
    UNLIMITED,
    _vanity_zeros,
    affix_match,
    extract,
    parties,
)

SENDER = "0x" + "11" * 20
TARGET = "0x0000553f880ffa3728b290e04e819053a3590000"
VICTIM = "0x" + "22" * 20
LOOK_A = "0xabcd" + "1" * 32 + "ef12"
LOOK_B = "0xabcd" + "9" * 32 + "ef12"


def topic(a: str) -> str:
    return "0x" + "0" * 24 + a[2:]


def record(**tx: object) -> dict:  # type: ignore[type-arg]
    base = {
        "tx_hash": "0x" + "ab" * 32,
        "status": "ok",
        "tx": {
            "blockNumber": hex(17_000_000),
            "from": SENDER,
            "to": TARGET,
            "value": "0x0",
            "gas": hex(100_000),
            "gasPrice": hex(20 * 10**9),
            "maxFeePerGas": None,
            "maxPriorityFeePerGas": None,
            "nonce": "0x5",
            "type": "0x0",
            "input": "0x23b872dd" + "00" * 96,
            **tx,
        },
        "receipt": {
            "status": "0x1",
            "gasUsed": hex(50_000),
            "contractAddress": None,
            "logs": [
                {
                    "address": TARGET,
                    "topics": [TRANSFER, topic(VICTIM), topic(LOOK_A)],
                    "data": "0x" + "00" * 32,
                },
                {
                    "address": TARGET,
                    "topics": [APPROVAL, topic(VICTIM), topic(LOOK_B)],
                    "data": "0x" + f"{UNLIMITED:064x}",
                },
                {
                    "address": TARGET,
                    "topics": [APPROVAL_FOR_ALL, topic(VICTIM), topic(SENDER)],
                    "data": "0x" + "00" * 31 + "01",
                },
            ],
        },
        "from_nonce_before": "0x63",
        "to_code_before": {"size": 2_000, "prefix": "0x608060"},
    }
    return base


def test_feature_vector_has_the_declared_order_and_finite_values() -> None:
    f = extract(record())
    assert tuple(f) == FEATURES
    assert all(math.isfinite(v) for v in f.values())


def test_transaction_shape_is_encoded() -> None:
    f = extract(record())
    assert f["fn_transfer_from"] == 1.0
    assert f["fn_other"] == 0.0
    assert f["is_zero_value"] == 1.0
    assert f["n_transfers"] == 1
    assert f["n_zero_value_transfers"] == 1
    assert f["n_transfers_not_from_sender"] == 1
    assert f["n_approvals"] == 1
    assert f["n_unlimited_approvals"] == 1
    assert f["n_approval_for_all_granted"] == 1
    assert f["to_is_contract"] == 1.0
    assert f["to_is_delegated_eoa"] == 0.0
    assert f["to_vanity_zero_nibbles"] == 8  # 0x0000553f…0000
    assert f["sender_prior_txs_log"] == math.log1p(99)
    assert f["max_party_affix_match"] == 8  # the two lookalikes share abcd…ef12
    assert f["gas_used_ratio"] == 0.5


def test_block_number_is_never_a_feature() -> None:
    """Point in time and no era leakage: moving a transaction in time changes nothing."""
    early, late = record(), record(blockNumber=hex(19_000_000))
    assert extract(early) == extract(late)


def test_extract_does_not_mutate_its_input() -> None:
    rec = record()
    before = copy.deepcopy(rec)
    extract(rec)
    assert rec == before


def test_contract_creation_and_delegated_target() -> None:
    created = extract({**record(to=None), "to_code_before": {"size": 0, "prefix": "0x"}})
    assert created["is_contract_creation"] == 1.0
    assert created["to_is_contract"] == 0.0
    delegated = extract({**record(), "to_code_before": {"size": 23, "prefix": "0xef0100"}})
    assert delegated["to_is_delegated_eoa"] == 1.0
    assert delegated["to_is_contract"] == 0.0


def test_reverted_transaction_without_receipt_logs() -> None:
    rec = record()
    rec["receipt"] = {"status": "0x0", "gasUsed": hex(100_000), "logs": []}
    f = extract(rec)
    assert f["status_success"] == 0.0
    assert f["n_logs"] == 0
    assert f["n_transfers"] == 0


def test_helpers() -> None:
    assert affix_match(LOOK_A, LOOK_B) == 8
    assert affix_match(LOOK_A, LOOK_A) == 0  # identical is not a lookalike
    assert _vanity_zeros(None) == 0
    assert _vanity_zeros("0x" + "0" * 39 + "1") == 39


def test_parties_cover_sender_target_spenders_and_recipients() -> None:
    got = parties(record())
    assert {SENDER, TARGET.lower(), LOOK_A, LOOK_B} <= got
    assert VICTIM not in got  # a transfer's source is the victim, not infrastructure
    assert "0x" + "0" * 40 not in parties(record(to=None))

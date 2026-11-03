"""Phase 12.3 incident benchmark: manifest validation, provenance and overlap audit, tier
assignment, and an end-to-end operational replay on a synthetic incident (software
correctness only, never evidence)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cryptoguard.ml import incident_benchmark as ib
from cryptoguard.replay.models import ReplayCase
from tests.integration.test_replay import HARM, fixture, manifest
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, WALLET, addr, transfer

FAKE2 = addr("a1b2c" + "8" * 30 + "4e5f6")  # a second lookalike of REAL


def cand(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case_id": "c1",
        "source": {"publisher": "p", "url": "https://example.org", "date": "2026-08-09"},
        "chain_id": 1,
        "mechanism": "zero_value_transfer",
        "identifiers": {
            "victim": "0x" + "a" * 40,
            "lookalike": "0x" + "b" * 40,
            "harm_tx": "0x" + "c" * 64,
        },
        "identifier_status": "verbatim",
        "fixture_case_id": None,
        "synthetic": False,
    }
    base.update(over)
    return base


def manifest_of(*cands: dict[str, Any]) -> ib.CandidateManifest:
    return ib.CandidateManifest.model_validate(
        {
            "schema_version": "incident-candidates/1",
            "protocol": "p",
            "discovery": {},
            "candidates": list(cands),
        }
    )


def no_refs(_d: Path) -> dict[str, frozenset[str] | None]:
    return {
        "frozen_cohorts:addresses": frozenset({"0x" + "f" * 40}),
        "phase12_1:candidate_lookalikes": None,
    }


# --- manifest -------------------------------------------------------------------------------


def test_committed_manifest_is_valid_and_has_no_synthetic_case() -> None:
    m = ib.load_manifest()
    assert m.candidates
    assert not any(c.synthetic for c in m.candidates)


def test_an_oracle_candidate_list_is_rejected(tmp_path: Path) -> None:
    bad = cand() | {"candidate_list": ["0x" + "b" * 40]}
    with pytest.raises(ValidationError):
        manifest_of(bad)
    p = tmp_path / "m.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "incident-candidates/1",
                "protocol": "p",
                "discovery": {},
                "candidates": [cand(), cand()],
            }
        )
    )
    with pytest.raises(ValueError, match="duplicate"):
        ib.load_manifest(p)


# --- verify ---------------------------------------------------------------------------------


def test_tiers_follow_identifiers_chain_date_and_synthetic_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ib, "reference_sets", no_refs)
    rows = {
        r["case_id"]: r
        for r in ib.verify(
            manifest_of(
                cand(case_id="late"),
                cand(
                    case_id="in_range", source={"publisher": "p", "url": "u", "date": "2023-05-01"}
                ),
                cand(case_id="partial", identifiers={"victim": None, "harm_tx": "0x" + "c" * 64}),
                cand(
                    case_id="truncated",
                    identifiers={
                        "victim": "0x65f3...773c",
                        "lookalike": "0x" + "b" * 40,
                        "harm_tx": "0x" + "c" * 64,
                    },
                ),
                cand(case_id="base", chain_id=8453),
                cand(case_id="synth", synthetic=True),
            ),
            Path("unused"),
            cases=[],
        )
    }
    assert rows["late"]["tier"] == "not_evaluable"
    assert "RPC" in rows["late"]["status"]
    assert rows["in_range"]["tier"] == "A_prime_candidate"
    assert rows["partial"]["tier"] == rows["truncated"]["tier"] == "not_evaluable"
    assert rows["base"]["tier"] == "excluded"
    assert rows["synth"]["level"] == "IV"
    assert rows["synth"]["verified"] is False  # synthetic can never be verified real
    # A set that could not be read is unknown, never evidence of independence.
    assert rows["late"]["overlap"]["lookalike"] == ["unknown:phase12_1:candidate_lookalikes"]
    assert rows["late"]["overlap_found"] == []


def test_frozen_cohort_overlap_excludes_a_case(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "reference_sets", no_refs)
    [row] = ib.verify(
        manifest_of(
            cand(
                identifiers={
                    "victim": "0x" + "f" * 40,
                    "lookalike": "0x" + "b" * 40,
                    "harm_tx": "0x" + "c" * 64,
                }
            )
        ),
        Path("unused"),
        cases=[],
    )
    assert row["tier"] == "excluded"
    assert row["overlap_found"] == ["frozen_cohorts:addresses"]


def test_fixture_identifiers_are_cross_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "reference_sets", no_refs)
    case = ReplayCase(manifest=manifest(), fixture=fixture([]), fixture_sha256=None)
    ok = cand(
        fixture_case_id="synthetic",
        identifiers={"victim": WALLET.lower(), "lookalike": FAKE.lower(), "harm_tx": None},
    )
    bad = cand(
        case_id="c2",
        fixture_case_id="synthetic",
        identifiers={"victim": "0x" + "1" * 40, "lookalike": None, "harm_tx": None},
    )
    rows = ib.verify(manifest_of(ok, bad), Path("unused"), cases=[case])
    assert rows[0]["verified"] is True
    assert rows[0]["level"] == "III"
    assert rows[0]["tier"] == "A"
    assert rows[1]["verified"] is False
    assert "MISMATCH" in rows[1]["status"]


# --- run --------------------------------------------------------------------------------------


def incident(extra: list[Any] | None = None) -> ReplayCase:
    """Legitimate payments to REAL, an older lookalike FAKE2 (block 105), a newer one FAKE
    (block 120), and the theft to FAKE at HARM."""
    ts = [
        transfer(WALLET, REAL, 5, 100, signer=WALLET),
        transfer(WALLET, FAKE2, 0, 105, signer=ATTACKER_SIGNER),
        transfer(WALLET, FAKE, 0, 120, signer=ATTACKER_SIGNER),
        transfer(WALLET, FAKE, 1000, HARM, signer=WALLET),
        *(extra or []),
    ]
    return ReplayCase(manifest=manifest(), fixture=fixture(ts), fixture_sha256=None)


def test_end_to_end_replay_finds_warns_and_ranks_without_the_outcome() -> None:
    r = ib.run_case(incident())
    assert r["candidates"]["target_recovered"] is True
    full = r["visibilities"]["erc20_plus_wallet_transactions"]
    assert full["outcome"] == "early_warning"
    assert full["lead_time_blocks"] == HARM - 120
    p = r["ranking"]["primary"]
    assert p["target_warned"] is True
    assert p["k"] == 2
    assert p["OP1_expected_rank"] == 1.0  # the most recent planting
    assert p["OP0_expected_rank"] == 1.5  # same tier and similarity: tied
    assert p["warning_set_preserved"] is True
    assert p["target_first_planting_signal_lead_blocks"] == HARM - 120
    assert r["leakage_checks_passed"] is True
    # Observed 300 blocks late, the window holds nothing yet; a day late, it is unobservable.
    assert r["ranking"]["delayed_1_day"]["note"] == "cutoff before the window"
    assert r["ranking"]["duplicate_records"]["OP1_expected_rank"] == 1.0
    md = ib.report([], {"cases": [r]})
    assert "| synthetic | True | True | True | 10 | 2 | 1.5 | 1.0 | 1.5 |" in md


def test_future_records_cannot_change_the_ranking_at_the_cutoff() -> None:
    later = transfer(WALLET, FAKE2, 0, HARM + 5, signer=ATTACKER_SIGNER)
    a = ib.run_case(incident())["ranking"]["primary"]
    b = ib.run_case(incident([later]))["ranking"]["primary"]
    assert a == b


def test_expected_rank_and_trim() -> None:
    assert ib.expected_rank({"a": 3, "b": 3, "c": 1}, "a") == 1.5
    assert ib.expected_rank({"a": 1, "b": 3, "c": 3}, "a") == 3.0
    f = incident().fixture
    assert f is not None
    assert max(t.block_number for t in ib.trim(f, 110).transfers) == 105

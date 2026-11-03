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


def test_run_never_computes_excluded_or_frozen_cases() -> None:
    case = incident()
    admitted = [{"case_id": "synthetic", "tier": "A", "status": "ok"}]
    none: tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())
    assert len(ib.run(admitted, none, cases=[case])["cases"]) == 1
    excluded = [
        {
            "case_id": "synthetic",
            "tier": "excluded",
            "status": "excluded: frozen review cohort overlap",
        }
    ]
    r = ib.run(excluded, none, cases=[case])
    assert r["cases"] == []
    assert r["not_computed"][0]["reason"].startswith("excluded")
    # Even when admitted, a window holding a frozen address (here a competing lookalike) is
    # never computed.
    frozen = (frozenset({FAKE2.lower()}), frozenset())
    r = ib.run(admitted, frozen, cases=[case])
    assert r["cases"] == []
    assert r["not_computed"][0]["reason"] == "recorded window holds a frozen review item"


def test_phase_12_2_replays_skip_windows_with_frozen_items() -> None:
    from cryptoguard.ml import recency_validation as rv
    from cryptoguard.replay.models import load_cases

    cases = [c for c in load_cases() if c.fixture is not None]
    victims = frozenset(c.manifest.victim.lower() for c in cases)
    out = rv.incidents((victims, frozenset()))
    assert all(e.get("excluded") == "holds a frozen review item" for e in out)
    f = cases[0].fixture
    assert f is not None
    assert rv.touches_frozen(f, (frozenset(), frozenset({f.transfers[0].transaction_hash.lower()})))
    assert not rv.touches_frozen(f, (frozenset(), frozenset()))


# --- new (Level I) cases ----------------------------------------------------------------------


def new_cand(**over: Any) -> ib.Candidate:
    """The synthetic incident's identifiers, as a public source would report them."""
    theft = transfer(WALLET, FAKE, 1000, HARM, signer=WALLET)
    plant = transfer(WALLET, FAKE, 0, 120, signer=ATTACKER_SIGNER)
    ids = {
        "victim": WALLET.lower(),
        "lookalike": FAKE.lower(),
        "intended": REAL.lower(),
        "planting_tx": plant.transaction_hash,
        "harm_tx": theft.transaction_hash,
    }
    return ib.Candidate.model_validate(cand(case_id="synthetic", identifiers=ids) | over)


def located(c: ib.Candidate, **over: Any) -> list[dict[str, Any]]:
    harm = {
        "transaction_hash": c.identifiers["harm_tx"],
        "found": True,
        "block_number": HARM,
        "from": WALLET,
        "to": "0x" + "e" * 40,
        "succeeded": True,
        "transfers": [
            {"token": "0x" + "e" * 40, "from": WALLET, "to": FAKE, "value_base_units": "1000"}
        ],
    }
    return [harm | over]


def test_prepare_fixes_the_window_by_rule_and_refuses_unconfirmed_identifiers() -> None:
    c = new_cand()
    m = ib.prepare(c, located(c), title="t", first_report="2026-11-03")
    assert (m.evaluation.from_block, m.evaluation.to_block) == (HARM - ib.WINDOW_BLOCKS, HARM)
    assert m.harm.recipient == FAKE
    assert m.victim == WALLET
    assert m.harm.value_base_units == "1000"
    for bad in (
        {"found": False},
        {"succeeded": False},
        {"from": REAL},  # not signed by the victim
        {
            "transfers": [
                {"token": "0x" + "e" * 40, "from": WALLET, "to": FAKE2, "value_base_units": "1"}
            ]
        },
    ):
        with pytest.raises(ValueError, match=r"not located|not confirmed"):
            ib.prepare(c, located(c, **bad), title="t", first_report="2026-11-03")
    with pytest.raises(ValueError, match="complete identifiers"):
        ib.prepare(new_cand(chain_id=None), located(c), title="t", first_report="2026-11-03")


def test_a_new_case_is_level_i_only_when_the_chain_confirms_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ib, "reference_sets", no_refs)
    c = new_cand()
    prepared = ib.prepare(c, located(c), title="t", first_report="2026-11-03")
    case = ReplayCase(manifest=prepared, fixture=incident().fixture, fixture_sha256=None)
    rows = ib.verify(manifest_of(c.model_dump()), Path("unused"), cases=[], new_cases=[case])
    assert rows[0]["level"] == "I"
    assert rows[0]["tier"] == "A"
    assert rows[0]["onchain"]["planting"] == "confirmed in the window"
    wrong = new_cand(identifiers={**c.identifiers, "lookalike": FAKE2.lower()})
    rows = ib.verify(manifest_of(wrong.model_dump()), Path("unused"), cases=[], new_cases=[case])
    assert rows[0]["verified"] is False
    assert rows[0]["tier"] == "B"
    assert "NOT confirmed" in rows[0]["status"]
    unrecorded = ReplayCase(manifest=prepared, fixture=None, fixture_sha256=None)
    rows = ib.verify(manifest_of(c.model_dump()), Path("unused"), cases=[], new_cases=[unrecorded])
    assert rows[0]["status"] == "pre-registered; window not recorded"
    with pytest.raises(ValueError, match="both case sets"):
        ib.verify(manifest_of(c.model_dump()), Path("unused"), cases=[case], new_cases=[case])


def test_levels_are_summarised_separately() -> None:
    admitted = [{"case_id": "synthetic", "tier": "A", "level": "I", "status": "ok"}]
    none: tuple[frozenset[str], frozenset[str]] = (frozenset(), frozenset())
    r = ib.run(admitted, none, cases=[incident()])
    assert r["cases"][0]["level"] == "I"
    assert r["summary_level_I"]["tier_A_cases"] == 1
    assert r["summary_level_I"]["OP1_vs_OP0"] == {"better": 1, "equal": 0, "worse": 0}
    assert r["summary_level_III"]["tier_A_cases"] == 0


PILOT = "usdt-counterfeit-39890-2026-08-09"


def test_stage_1_pilot_case_is_frozen_and_reproduces_exactly() -> None:
    """The first Level I case is a frozen benchmark input: its recorded data and its result
    may not change silently (a detector or ranker change that moves it must be disclosed)."""
    import hashlib

    [case] = [c for c in ib.load_new_cases() if c.manifest.case_id == PILOT]
    assert case.fixture_sha256 == (
        "62b3744c496cca63bdef6e34e8881718f9f9a125cb14c6c8af7656255f0573b8"
    )
    assert hashlib.sha256(case.manifest.model_dump_json().encode()).hexdigest() == (
        "ef903fbbcd94837188a6624310eef8f6eda9abcee7d5fc4baa43362d45095e39"
    )
    row = ib.run_case(case, level="I")
    primary = row["ranking"]["primary"]
    full = row["visibilities"]["erc20_plus_wallet_transactions"]
    assert row["candidates"]["target_recovered"]
    assert row["leakage_checks_passed"]
    assert (full["outcome"], full["lead_time_blocks"], full["lead_time_seconds"]) == (
        "early_warning",
        48,
        576,
    )
    assert (primary["k"], primary["OP0_expected_rank"], primary["OP1_expected_rank"]) == (
        6,
        4.0,
        2.0,
    )


def _stage2(**over: Any) -> ib.Candidate:
    return ib.Candidate.model_validate(
        cand(
            case_id="webacy-6.88m-usdt-2025-09",
            identifiers={"victim": "0x" + "e" * 40, "lookalike": None},
            identifier_status="partial",
        )
        | over
    )


def _found(c: ib.Candidate, **over: Any) -> dict[str, Any]:
    v, look = "0x" + "e" * 40, "0x4186a058" + "0" * 32
    harm = "0x" + "1" * 64
    base: dict[str, Any] = {
        "query": ib.resolution_query(c),
        "scan_complete": True,
        "transfers": [{"transaction_hash": harm, "to": look}],
        "located": [
            {
                "transaction_hash": harm,
                "found": True,
                "succeeded": True,
                "from": v,
                "transfers": [{"from": v, "to": look, "token": ib.USDT, "value_base_units": "5"}],
            }
        ],
    }
    return base | over


def test_resolve_follows_only_the_frozen_rule() -> None:
    c = _stage2()
    done = ib.resolve(c, _found(c))
    assert done.identifiers["harm_tx"] == "0x" + "1" * 64
    assert done.identifiers["lookalike"] == "0x4186a058" + "0" * 32
    assert done.identifier_status.startswith("resolved on chain (amendment-12.3-A1)")
    other_dates = _found(c) | {"query": ib.resolution_query(c) | {"until": 0}}
    with pytest.raises(ValueError, match="differs from the pre-registered rule"):
        ib.resolve(c, other_dates)
    with pytest.raises(ValueError, match="scan is incomplete"):
        ib.resolve(c, _found(c, scan_complete=False))
    signed_by_attacker = _found(c)
    signed_by_attacker["located"][0]["from"] = "0x" + "a" * 40
    with pytest.raises(ValueError, match="identifiers not confirmed on chain"):
        ib.resolve(c, signed_by_attacker)
    with pytest.raises(ValueError, match="no pre-registered resolution rule"):
        ib.resolution_query(_stage2(case_id="unknown-case"))


def _ranked(better: bool | None, signers: list[str]) -> dict[str, Any]:
    r1 = {True: 1.0, False: 3.0, None: 2.0}[better]
    return {
        "ranking": {
            "primary": {
                "target_warned": True,
                "k": 3,
                "OP0_expected_rank": 2.0,
                "OP1_expected_rank": r1,
            }
        },
        "cluster_signers": signers,
        "lead_possibly_censored": False,
    }


def test_amended_gate_h_is_descriptive_below_six_clusters_and_votes_by_cluster() -> None:
    assert ib.amended_gate_h([_ranked(True, ["0xs"])])["status"] == "DESCRIPTIVE"
    # ten cases, all better, but sharing one signer: one cluster, one vote
    same = ib.amended_gate_h([_ranked(True, ["0xs"]) for _ in range(10)])
    assert (same["clusters"], same["cluster_votes"]["better"], same["status"]) == (
        1,
        1,
        "DESCRIPTIVE",
    )
    distinct = ib.amended_gate_h([_ranked(True, [f"0x{i}"]) for i in range(10)])
    assert distinct["status"] == "PASS"
    assert distinct["sign_test_p_one_sided"] == pytest.approx(1 / 1024)
    unknown = ib.amended_gate_h([_ranked(True, []) for _ in range(10)])
    assert (unknown["clusters"], unknown["linkage_unknown_cases"]) == (10, 10)
    mixed = [_ranked(True, [f"0x{i}"]) for i in range(7)] + [
        _ranked(False, [f"0xw{i}"]) for i in range(3)
    ]
    assert ib.amended_gate_h(mixed)["status"] == "NOT PASSED"  # p = 0.172
    assert ib.sign_test_p(9, 1) == pytest.approx(11 / 1024)


def test_manifests_merge_and_reject_duplicate_case_ids(tmp_path: Path) -> None:
    def write(name: str, ids: list[str]) -> Path:
        p = tmp_path / name
        body = {
            "schema_version": "incident-candidates/1",
            "protocol": "p",
            "discovery": {},
            "candidates": [cand(case_id=i) for i in ids],
        }
        p.write_text(json.dumps(body), encoding="utf-8")
        return p

    a, b = write("a.json", ["x"]), write("b.json", ["y"])
    merged = ib.load_manifests([a, b, tmp_path / "missing.json"])
    assert [c.case_id for c in merged.candidates] == ["x", "y"]
    with pytest.raises(ValueError, match="more than one manifest"):
        ib.load_manifests([a, write("c.json", ["x"])])


def test_stage_2a_case_is_frozen_and_reproduces_exactly() -> None:
    """The first resolved Level I case: frozen like the pilot, including its miss (the theft
    recipient never appears in the recorded stream before the harm)."""
    import hashlib

    [case] = [c for c in ib.load_new_cases() if c.manifest.case_id == "scamsniffer-763k-2025-02-20"]
    assert case.fixture_sha256 == (
        "67e44177ad7785bd5779bb3db205f3175ee8aca404f6d29e0dc1e6f3d95674f1"
    )
    assert hashlib.sha256(case.manifest.model_dump_json().encode()).hexdigest() == (
        "770b1200f3d4dd3231232533beb1cfc2900f68d2a00ef899cfd2c732644192f1"
    )
    row = ib.run_case(case, level="I")
    assert row["leakage_checks_passed"]
    assert not row["candidates"]["target_recovered"]
    assert row["visibilities"]["erc20_plus_wallet_transactions"]["outcome"] == (
        "post_incident_only"
    )
    assert (row["ranking"]["primary"]["k"], row["ranking"]["primary"]["target_warned"]) == (
        2,
        False,
    )

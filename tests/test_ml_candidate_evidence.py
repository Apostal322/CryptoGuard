"""Protocol 12.6: evidence-preserving candidate groups, signer provenance (rule R-SIG), the
bounded summary and spam resilience. Synthetic only; every expectation is written from the
scenario's definition."""

from __future__ import annotations

import json

import pytest

from cryptoguard.detectors.poisoning import PoisoningConfig
from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_evidence as ce
from cryptoguard.ml import reliability_study as rs
from cryptoguard.replay.engine import Visibility, detector_outputs

W, REF, USDT, FAKE, END = rs.WALLET, rs.REF, rs.USDT, rs.FAKE, rs.END
ATTACKER = "0x" + "a1" * 20
STRONG = rs.lookalike(0, prefix=5, suffix=5)
WEAK = rs.lookalike(1)


def by_look(res: ce.EvidenceResult) -> dict[str, ce.CandidateGroup]:
    return {g.lookalike: g for g in res.groups}


def test_lookalike_helper_shares_exactly_the_requested_affix() -> None:
    from cryptoguard.detectors.poisoning import affix_match

    assert affix_match(STRONG, REF) == (5, 5)
    assert affix_match(WEAK, REF) == (3, 3)


# --- provenance ----------------------------------------------------------------------------


def test_event_sender_is_never_taken_as_the_signer() -> None:
    fx = rs.wallet_fixture(transfers=[(W, STRONG, 0, 2_000, ATTACKER, USDT, 0)])
    [r] = by_look(ce.build(fx, cutoff=END))[STRONG].evidence
    assert (r.event_sender, r.signer, r.signer_status) == (W, ATTACKER, "foreign_known")
    assert r.mechanisms == ("spoofed_out",)
    assert r.level == "directly_verified"


def test_rsig_recovers_an_unknown_signer_both_ways() -> None:
    fx = rs.wallet_fixture(transfers=[(W, STRONG, 0, 2_000, None, USDT, 0)])
    res = ce.build(fx, cutoff=END)
    [r] = by_look(res)[STRONG].evidence
    assert (r.signer_status, r.signer) == ("foreign_identity_unknown", None)  # never guessed
    assert r.mechanisms == ("spoofed_out",)
    assert "signer_identity" in r.missing
    # the reference payment had a looked-up signer; masking it, R-SIG finds it in the set
    masked = ce.build(fx, cutoff=END, observations=ce.mask(cd.observations(fx), "signer"))
    assert masked.signers_recovered == 2  # the reference (wallet) and the spoof (absence)
    assert by_look(masked)[STRONG].evidence[0].signer_status == "foreign_identity_unknown"


def test_no_absence_inference_for_a_wallet_with_code_or_an_incomplete_signed_set() -> None:
    for kw in ({"code": "0x6080"}, {"refs_complete": False}):
        fx = rs.wallet_fixture(transfers=[(W, STRONG, 0, 2_000, None, USDT, 0)], **kw)  # type: ignore[arg-type]
        g = by_look(ce.build(fx, cutoff=END)).get(STRONG)
        if g is not None:  # a lookalike of a verified reference: kept, never called a spoof
            [r] = g.evidence
            assert (r.signer_status, r.mechanisms) == ("unknown", ("unverified_out_lookalike",))
            assert r.level == "partially_supported"


def test_native_sender_is_the_lookalike_and_receipts_set_the_level() -> None:
    ok = by_look(ce.build(rs.wallet_fixture(native=[(STRONG, 1, 2_000, True)]), cutoff=END))
    unread = by_look(ce.build(rs.wallet_fixture(native=[(STRONG, 1, 2_000, None)]), cutoff=END))
    reverted = by_look(ce.build(rs.wallet_fixture(native=[(STRONG, 1, 2_000, False)]), cutoff=END))
    assert ok[STRONG].evidence[0].signer_status == "lookalike_itself"
    assert (ok[STRONG].level, unread[STRONG].level) == ("directly_verified", "supported")
    assert unread[STRONG].missing == ("receipt",)
    assert STRONG not in reverted  # a reverted transfer is not evidence


def test_unknown_token_identity_never_becomes_untrusted() -> None:
    fx = rs.wallet_fixture(transfers=[(STRONG, W, 10**18, 2_000, None, FAKE, 0)])
    obs = ce.mask(cd.observations(fx), "token")
    [r] = by_look(ce.build(fx, cutoff=END, observations=obs))[STRONG].evidence
    assert "untrusted_token_in" not in r.mechanisms
    assert "token_identity" in r.missing
    [known] = by_look(ce.build(fx, cutoff=END))[STRONG].evidence
    assert known.mechanisms == ("lookalike_in", "untrusted_token_in")


# --- identity and grouping -----------------------------------------------------------------


def test_one_group_per_lookalike_keeps_every_record_in_order() -> None:
    fx = rs.wallet_fixture(
        native=[(STRONG, 1, 2_100, True), (STRONG, 1, 2_000, True)],
        transfers=[(STRONG, W, 0, 2_050, None, USDT, 0), (W, STRONG, 0, 2_200, ATTACKER, USDT, 0)],
    )
    g = by_look(ce.build(fx, cutoff=END))[STRONG]
    assert [r.block for r in g.evidence] == [2_000, 2_050, 2_100, 2_200]
    assert g.mechanisms == ("lookalike_in", "spoofed_out", "zero_value_in")
    assert g.kinds == ("erc20", "native")
    assert g.identity == f"1:{W}:{STRONG}"
    assert g.references == ((REF, 5, 5),)


def test_duplicate_ingestion_does_not_inflate_records() -> None:
    fx = rs.wallet_fixture(native=[(STRONG, 1, 2_000, True)])
    dup = fx.model_copy(update={"native_inbound": fx.native_inbound * 2})
    assert ce.build(dup, cutoff=END).evidence_records == 1
    assert ce.build(dup, cutoff=END).raw_events == ce.build(fx, cutoff=END).raw_events + 1


def test_identity_separates_victims_and_chains() -> None:
    fx = rs.wallet_fixture(native=[(STRONG, 1, 2_000, True)])
    other = fx.model_copy(update={"chain_id": 10})
    a = ce.build(fx, cutoff=END).groups[0].identity
    b = ce.build(other, cutoff=END).groups[0].identity
    assert a != b
    assert a.split(":")[2] == b.split(":")[2] == STRONG


def test_future_events_do_not_change_groups_at_an_earlier_cutoff() -> None:
    base = rs.wallet_fixture(native=[(STRONG, 1, 2_000, True)])
    later = rs.wallet_fixture(
        native=[(STRONG, 1, 2_000, True), (WEAK, 1, 5_000, True), (STRONG, 1, 6_000, True)],
        transfers=[(W, STRONG, 10**6, 7_000, W, USDT, 0)],
    )
    cut = (3_000, 0)
    a, b = ce.build(base, cutoff=cut), ce.build(later, cutoff=cut)
    assert [(g.identity, g.evidence) for g in a.groups] == [
        (g.identity, g.evidence) for g in b.groups
    ]


# --- summary and spam ----------------------------------------------------------------------


def test_summary_discloses_truncation_and_keeps_everything() -> None:
    fx = rs.wallet_fixture(native=[(rs.lookalike(i + 1), 1, 2_000 + i, True) for i in range(25)])
    res = ce.build(fx, cutoff=END)
    s = ce.summarize(res, 10)
    assert (s["total_groups"], s["shown"], s["truncated"]) == (25, 10, True)
    assert (s["hidden_count"], s["next_offset"]) == (15, 10)
    assert "not assessed as safe" in s["note"]
    assert len(res.groups) == 25  # the display budget deletes nothing
    assert ce.summarize(ce.build(fx, cutoff=END), 10) == s  # deterministic


@pytest.mark.parametrize("name", sorted(rs.scenarios()))
def test_adversarial_scenarios(name: str) -> None:
    fx, strong = rs.scenarios()[name]
    res = ce.build(fx, cutoff=END)
    expected_groups = {
        "1_zero_value_strangers": 0,  # anyone can send 0 ETH: never a candidate alone
        "2_distinct_lookalikes": 1_000,
        "3_repeated_dust_one_lookalike": 1,
        "4_many_lookalikes_one_reference_with_one_strong": 1_001,
        "5_multiple_references": 50,
        "6_fake_token_spam": 1_000,
        "7_same_block_repeats": 100,
        "8_unknown_signer_with_complete_signed_set": 1,
        "9_missing_receipt": 1,
        "10_partial_history": 1,
        "11_one_strong_among_weak": 2_001,  # 1,000 dust strangers + 1,000 lookalikes + strong
        "12_public_token_reuse": 200,
    }[name]
    assert len(res.groups) == expected_groups
    if strong is not None:
        assert res.groups[0].lookalike == strong  # never buried under weaker events
    if name == "3_repeated_dust_one_lookalike":
        assert res.evidence_records == 500
    if name == "10_partial_history":
        assert res.abstain is not None
        assert res.groups[0].level == "partially_supported"


def test_spam_stability_prefers_costly_affixes_over_recency() -> None:
    fx = rs.wallet_fixture(
        transfers=[(W, STRONG, 0, 2_000, ATTACKER, USDT, 0)],
        native=[(rs.lookalike(0, prefix=4, suffix=4), 1, 2_100, True)],
    )
    out = rs.spam_stability(fx, END, n=300, k=10)
    assert out["real_candidates"] == 2
    assert out["evidence_aware"]["real_in_top_k"] == 2
    assert out["recency_only"]["real_in_top_k"] == 0  # cheap recent spam buries them
    assert out["similarity_only"]["real_in_top_k"] == 2


# --- isolation and determinism -------------------------------------------------------------


def test_production_detector_is_untouched() -> None:
    fx, _ = rs.scenarios()["11_one_strong_among_weak"]
    full = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS
    before = detector_outputs(fx, 9_000, full, PoisoningConfig())
    ce.summarize(ce.build(fx, cutoff=END))
    assert detector_outputs(fx, 9_000, full, PoisoningConfig()) == before


def test_result_serializes_deterministically() -> None:
    fx, _ = rs.scenarios()["4_many_lookalikes_one_reference_with_one_strong"]
    a, b = ce.to_json(ce.build(fx, cutoff=END)), ce.to_json(ce.build(fx, cutoff=END))
    assert a == b
    assert json.loads(a)["version"] == ce.EVIDENCE_VERSION


def test_masking_never_produces_unsafe_claims() -> None:
    fx = rs.wallet_fixture(
        transfers=[
            (W, STRONG, 0, 2_000, ATTACKER, USDT, 0),
            (WEAK, W, 10**18, 2_100, None, FAKE, 0),
        ],
        native=[(rs.lookalike(0, prefix=4, suffix=4), 1, 2_200, True)],
    )
    out = rs.masking(fx, END)
    for cond in ("S1_signer", "S2_event_sender", "S3_receipt", "S4_token", "S5_partial_history"):
        assert out[cond]["evidence_unsafe_inferences"] == 0, cond
        assert out[cond]["added"] == 0, cond
        assert out[cond]["level_raised"] == 0, cond
    assert out["S4_token"]["c1_unsafe_inferences"] == 1  # C1 calls an unknown token untrusted
    assert out["S1_signer"]["lost"] == 0  # R-SIG recovers the spoof
    assert out["S3_receipt"]["level_lowered"] == 1  # verified native drops to supported

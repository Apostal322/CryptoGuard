"""Phase 12.6.1: when absence from the signed set proves "not signed by the wallet", what it
never proves (authorization), bounded summaries with page access, and the separation of
evidence support from suspicion. Synthetic only; every expectation follows from the
scenario's definition."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_evidence as ce
from cryptoguard.ml import reliability_study as rs

W, REF, USDT, FAKE, END = rs.WALLET, rs.REF, rs.USDT, rs.FAKE, rs.END
STRONG = rs.STRONG


# --- the signer guard matrix ----------------------------------------------------------------

ALLOWED_SPOOF = (True, "foreign_identity_unknown", ["spoofed_out"])
BLOCKED = (False, "unknown", ["unverified_out_lookalike"])
EXPECTED = {
    "complete_history_zero_value": ALLOWED_SPOOF,
    "complete_history_value_moved_trusted_token": (
        True,
        "foreign_identity_unknown",
        ["foreign_initiated_out"],
    ),
    "complete_history_value_moved_untrusted_token": (
        True,
        "foreign_identity_unknown",
        ["foreign_initiated_out", "untrusted_token_out"],
    ),
    "signer_lookups_capped_at_500": ALLOWED_SPOOF,  # the cap limits lookups, not the set
    "signed_set_truncated": BLOCKED,
    "signed_set_partial_recording": BLOCKED,
    "signed_set_count_mismatch": BLOCKED,
    "missing_page_or_7702_authorization_nonce_gap": BLOCKED,
    "legacy_fixture_without_documented_bisection": BLOCKED,
    "code_deployed_inside_window_before_cutoff": BLOCKED,
    "code_only_after_cutoff_not_used": ALLOWED_SPOOF,
    "code_unknown_at_window_start": BLOCKED,
    "eip7702_delegation_at_window_start": BLOCKED,
    "smart_wallet": BLOCKED,
    "contract_interaction_wallet_signed": (True, "wallet", None),
    "same_block_spoof_before_own_tx": ALLOWED_SPOOF,
    "same_block_own_tx_included": (True, "wallet", None),
    "wallet_signed_with_unknown_receipt": (True, "wallet", None),
    "looked_up_signer_contradicts_signed_set": (
        True,
        "conflicting",
        ["unverified_out_lookalike"],
    ),
}


@pytest.fixture(scope="module")
def matrix() -> dict[str, dict]:
    return rs.signer_matrix()


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_signer_guard_matrix(matrix: dict[str, dict], case: str) -> None:
    row = matrix[case]
    allowed, status, mechanisms = EXPECTED[case]
    assert row["absence_inference"] is allowed, row
    assert bool(row["blocked_by"]) is not allowed
    assert row["signer_status"] == status
    if mechanisms is None:
        assert row["evidence"] is False  # the wallet's own action is never evidence
    else:
        assert row["mechanisms"] == mechanisms
    if not allowed:  # never a negative signer claim from an incomplete source
        assert row["signer_status"] not in ("foreign_identity_unknown", "foreign_known")
        assert row["level"] == "partially_supported"


def test_matrix_covers_every_case(matrix: dict[str, dict]) -> None:
    assert set(matrix) == set(EXPECTED) | {"same_block_own_tx_after_cutoff_excluded"}
    assert matrix["same_block_own_tx_after_cutoff_excluded"]["observed_before_cutoff"] is False


def test_absence_never_proves_authorization() -> None:
    pulled = rs.wallet_fixture(transfers=[(W, STRONG, 10**6, 2_000, None, USDT, 0)])
    [r] = ce.build(pulled, cutoff=END).groups[0].evidence
    assert "spoofed_out" not in r.mechanisms  # an allowance or a permit can authorize a pull
    assert (r.authorization, "authorization" in r.missing) == ("unknown", True)
    spoof = rs.wallet_fixture(transfers=[(W, STRONG, 0, 2_000, None, USDT, 0)])
    [s] = ce.build(spoof, cutoff=END).groups[0].evidence
    assert (s.mechanisms, s.authorization) == (("spoofed_out",), "not_required")


def test_a_known_foreign_signer_does_not_prove_authorization_either() -> None:
    fx = rs.wallet_fixture(transfers=[(W, STRONG, 10**6, 2_000, rs.ATTACKER, USDT, 0)])
    [r] = ce.build(fx, cutoff=END).groups[0].evidence
    assert (r.signer_status, r.signer) == ("foreign_known", rs.ATTACKER)
    assert r.mechanisms == ("foreign_initiated_out",)
    assert r.authorization == "unknown"


def test_conflicting_signer_never_becomes_a_reference() -> None:
    """A looked-up wallet signer whose transaction is absent from a complete signed set is a
    conflict: the counterparty is not treated as a recipient the wallet chose."""
    other = "0x1234500000000000000000000000000000067890"  # unrelated to REF
    late = rs.lookalike(1, prefix=4, suffix=4, ref=other)
    claimed = rs.wallet_fixture(
        transfers=[(W, other, 5, 2_000, W, USDT, 0)], native=[(late, 1, 3_000, True)]
    )
    res = ce.build(claimed, cutoff=END)
    assert res.absence_inference
    # had ``other`` become a reference, its lookalike would be a candidate
    assert late not in {g.lookalike for g in res.groups}
    # control: the same payment, present in the signed set, does make it a reference
    pay = claimed.transfers[-1]
    from cryptoguard.replay.models import RecordedTransaction

    signed = claimed.model_copy(
        update={
            "wallet_transactions": [
                *claimed.wallet_transactions,
                RecordedTransaction(
                    transaction_hash=pay.transaction_hash,
                    block_number=2_000,
                    transaction_index=0,
                    nonce=1,
                    to=USDT,
                    value="0",
                ),
            ]
        }
    )
    assert late in {g.lookalike for g in ce.build(signed, cutoff=END).groups}


def test_duplicate_nonce_blocks_the_absence_inference() -> None:
    fx = rs.wallet_fixture(
        transfers=[(W, STRONG, 0, 2_000, None, USDT, 0)], wallet_txs=[(REF, 10**15, 1_200)]
    )
    txs = [t.model_copy(update={"nonce": 0}) for t in fx.wallet_transactions]
    blocked = ce.absence_guard(fx.model_copy(update={"wallet_transactions": txs}), END[0])
    assert any("nonce" in b for b in blocked)


def test_guard_uses_no_information_after_the_cutoff() -> None:
    early = rs.wallet_fixture(transfers=[(W, STRONG, 0, 2_000, None, USDT, 0)])
    with_future_code = early.model_copy(
        update={"wallet_code_hex": {"1000": "0x", "5000": "0xef0100" + "ab" * 20}}
    )
    cut = (3_000, 0)
    assert ce.absence_guard(with_future_code, cut[0]) == ()
    a, b = ce.build(early, cutoff=cut), ce.build(with_future_code, cutoff=cut)
    assert ce.digest(a) == ce.digest(b)
    assert ce.absence_guard(with_future_code, 6_000)  # once the cutoff passes it, it counts


def test_real_recorder_method_documents_the_bisection() -> None:
    from cryptoguard.replay.record import METHOD

    assert any("nonce bisection" in m for m in METHOD)


# --- bounded summary and page access --------------------------------------------------------


def _many(n: int) -> ce.EvidenceResult:
    fx = rs.wallet_fixture(
        native=[(rs.lookalike(i + 1), 1, 2_000 + i % 5_000, True) for i in range(n)]
    )
    return ce.build(fx, cutoff=END)


def test_summary_size_does_not_grow_with_the_number_of_candidates() -> None:
    small, big = ce.summarize(_many(20), 10), ce.summarize(_many(3_000), 10)
    assert big["hidden_count"] == 2_990
    assert big["truncated"]
    assert abs(len(json.dumps(big)) - len(json.dumps(small))) < 64  # digits only
    assert "hidden_identities" not in big


def test_pages_cover_every_group_exactly_once_in_order() -> None:
    res = _many(57)
    s = ce.summarize(res, 10)
    seen, offset = [i["identity"] for i in s["top"]], s["next_offset"]
    while offset is not None:
        pg = ce.page(res, offset=offset, limit=10, expect_digest=s["result_digest"])
        seen += [i["identity"] for i in pg["items"]]
        offset = pg["next_offset"]
    assert seen == [g.identity for g in res.groups]
    assert [i["rank"] for i in ce.page(res, offset=50, limit=10)["items"]] == list(range(51, 58))


def test_stale_page_and_unbounded_requests_are_refused() -> None:
    res = _many(12)
    with pytest.raises(ce.StaleResultError):
        ce.page(res, offset=10, expect_digest=ce.digest(_many(13)))
    for bad in (0, ce.MAX_PAGE + 1):
        with pytest.raises(ValueError, match="k must be between"):
            ce.summarize(res, bad)
        with pytest.raises(ValueError, match="limit must be between"):
            ce.page(res, limit=bad)
    with pytest.raises(ValueError, match="offset must be"):
        ce.page(res, offset=-1)


def test_group_records_pages_every_record() -> None:
    weak = rs.lookalike(1)
    fx = rs.wallet_fixture(native=[(weak, 1, 2_000 + i, True) for i in range(250)])
    res = ce.build(fx, cutoff=END)
    ident = res.groups[0].identity
    got, offset = [], 0
    while offset is not None:
        pg = ce.group_records(res, ident, offset=offset, limit=100)
        got += [r["identity"] for r in pg["items"]]
        offset = pg["next_offset"]
    assert got == [r.identity for r in res.groups[0].evidence]
    assert len(got) == 250
    with pytest.raises(KeyError):
        ce.group_records(res, "1:nobody:nothing")


def test_summary_items_are_bounded_and_carry_no_probability() -> None:
    res = _many(15)
    s = ce.summarize(res, 10)

    def floats(x: object) -> int:
        if isinstance(x, float):
            return 1
        if isinstance(x, dict):
            return sum(floats(v) for v in x.values())
        if isinstance(x, list):
            return sum(floats(v) for v in x)
        return 0

    assert floats(s) == 0
    assert all(i["legitimacy"] == "not_assessed" for i in s["top"])
    assert all(len(i["references"]) <= ce.MAX_REFERENCES_SHOWN for i in s["top"])
    assert "not a risk score" in s["order_note"]


# --- support is not suspicion ---------------------------------------------------------------


def test_presentation_order_never_reads_the_support_level() -> None:
    res = _many(30)
    for g in res.groups:
        for level in ce.LEVELS:
            assert ce.presentation_key(replace(g, level=level)) == ce.presentation_key(g)
            assert ce.presentation_key(replace(g, missing=("receipt",))) == ce.presentation_key(g)


def test_a_verified_receipt_does_not_move_a_candidate_up() -> None:
    a, b = rs.lookalike(1), rs.lookalike(2)  # same affix
    fx = rs.wallet_fixture(native=[(a, 1, 2_000, True), (b, 1, 3_000, None)])
    res = ce.build(fx, cutoff=END)
    assert [g.lookalike for g in res.groups] == [b, a]  # newer first; support not consulted
    assert [g.level for g in res.groups] == ["supported", "directly_verified"]
    # the pre-registered (H5-failed) evidence order would have put the verified one first
    assert sorted(res.groups, key=ce.evidence_order_key)[0].lookalike == a


def test_missing_evidence_never_changes_the_order() -> None:
    fx = rs.wallet_fixture(
        transfers=[
            (W, STRONG, 0, 2_000, rs.ATTACKER, USDT, 0),
            (rs.lookalike(1), W, 10**18, 2_100, None, FAKE, 0),
        ],
        native=[(rs.lookalike(0, prefix=4, suffix=4), 1, 2_200, True)],
    )
    out = rs.separation(fx, END)
    for what in ("receipt", "token", "signer"):
        assert out[what]["relative_order_unchanged"], what
        assert out[what]["kept"] == 3, what


def test_h5_reproduction_is_preserved() -> None:
    """The pre-registered order still loses to similarity under cheap verified dust; the
    presentation order is reported beside it, never in its place."""
    fx = rs.wallet_fixture(
        transfers=[(W, STRONG, 0, 2_000, rs.ATTACKER, USDT, 0)],
        native=[
            (rs.lookalike(0, prefix=4, suffix=4), 1, 2_100, None),  # unread receipt: supported
        ],
    )
    out = rs.spam_stability(fx, END, n=300, k=10)
    assert out["evidence_aware"]["real_in_top_k"] == 1  # verified spam buries the unread one
    assert out["presentation"]["real_in_top_k"] == 2
    assert out["similarity_only"]["real_in_top_k"] == 2
    assert out["recency_only"]["real_in_top_k"] == 0


# --- adversarial floods (2,000 events here; 10,000 in the study) ----------------------------


@pytest.fixture(scope="module")
def floods() -> dict[str, dict]:
    return rs.adversarial(n=2_000)


@pytest.mark.parametrize("name", sorted(rs.adversarial_fixtures(n=10)))
def test_high_relevance_candidate_stays_reachable(floods: dict[str, dict], name: str) -> None:
    row = floods[name]
    assert row["deterministic"]
    assert row["strong_reachable_by_page"] is True  # never deleted, always reachable
    if name == "identical_similarity_ties":
        # 2,000 newer lookalikes with the same affix: recency decides, disclosed, reachable
        assert row["strong_rank"] == 2_001
    else:
        assert row["strong_rank"] == 1, row
        assert row["strong_in_top_k"]


def test_flood_record_counts(floods: dict[str, dict]) -> None:
    assert floods["repeated_dust_one_lookalike"]["groups"] == 2
    assert floods["repeated_dust_one_lookalike"]["evidence_records"] == 2_001  # none merged
    assert floods["multiple_candidate_mechanisms"]["strong_mechanisms"] == [
        "lookalike_in",
        "spoofed_out",
        "zero_value_in",
    ]
    assert floods["missing_signer_information"]["strong_level"] == "directly_verified"
    assert floods["partial_historical_coverage"]["strong_level"] == "partially_supported"
    assert floods["partial_historical_coverage"]["abstain"]
    assert floods["fake_token_flood"]["groups"] == 2_001


def test_masking_still_makes_no_unsafe_claims_with_value_moving_spoofs() -> None:
    fx = rs.wallet_fixture(
        transfers=[
            (W, STRONG, 0, 2_000, rs.ATTACKER, USDT, 0),
            (W, rs.lookalike(1), 10**6, 2_050, None, FAKE, 0),
        ],
    )
    out = rs.masking(fx, END)
    for cond in ("S1_signer", "S3_receipt", "S4_token", "S5_partial_history"):
        assert out[cond]["evidence_unsafe_inferences"] == 0, cond
        assert out[cond]["added"] == 0, cond
        assert out[cond]["level_raised"] == 0, cond
    obs = cd.observations(fx)
    assert any(o.value and o.direction == "out" for o in obs)


def test_identical_repeated_transfers_stay_distinct_records() -> None:
    """The synthetic builder gives each event its own transaction: two identical dust sends
    in one block are two records, not one (a 12.6.1 study-harness fix)."""
    weak = rs.lookalike(1)
    fx = rs.wallet_fixture(native=[(weak, 1, 2_000, True), (weak, 1, 2_000, True)])
    assert ce.build(fx, cutoff=END).evidence_records == 2

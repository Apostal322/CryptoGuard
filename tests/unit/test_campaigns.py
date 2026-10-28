"""Attempt extraction, relationship evidence and conservative clustering, incl. negative cases."""

from __future__ import annotations

import pytest

from cryptoguard.analytics.observations import BlockRange, ObservationSet
from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.campaigns.attempts import PoisoningAttempt, attempt_id, extract_attempts
from cryptoguard.campaigns.cluster import (
    Deployer,
    articulation_points,
    cluster_attempts,
    cluster_id,
    lineage,
)
from cryptoguard.campaigns.relations import (
    COMMON_CONTRACTS,
    RelationConfig,
    shared_entities,
    temporal_pairs,
)
from cryptoguard.core.address import to_checksum_address


def addr(n: int) -> str:
    return to_checksum_address(f"0x{n:040x}")


USDT = to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
FAKE_TOKEN = addr(0xF4CE)
_n = iter(range(1, 10**6))


def att(
    victim: str,
    lookalike: str,
    *,
    signer: str | None = None,
    block: int = 100,
    tx: str | None = None,
    contract: str = FAKE_TOKEN,
    log_index: int | None = None,
) -> PoisoningAttempt:
    i = next(_n)
    tx = tx or f"0x{i:064x}"
    li = i if log_index is None else log_index
    return PoisoningAttempt(
        block_number=block,
        transaction_index=0,
        log_index=li,
        attempt_id=attempt_id(1, tx, li, victim, lookalike),
        chain_id=1,
        victim=victim,
        lookalike=lookalike,
        imitated=None,
        imitated_confirmed=False,
        event_type="spoofed_outgoing_transfer" if signer else "unsolicited_incoming_transfer",
        transaction_hash=tx,
        block_hash="0x" + "00" * 32,
        contract=contract,
        log_from=victim if signer else lookalike,
        log_to=lookalike if signer else victim,
        value=1,
        signer=signer,
        rule_id="CG-POI-001",
        source="wallet_scan",
    )


V1, V2, V3, V4 = (addr(0xA000 + i) for i in range(4))
S1, S2 = addr(0x5100), addr(0x5200)


def analyse(attempts, **kw):  # type: ignore[no-untyped-def]
    return cluster_attempts(attempts, chain_id=1, cutoff_block=10**9, **kw)


# --- extraction ---------------------------------------------------------------------------


def _tr(
    sender: str,
    recipient: str,
    block: int,
    value: int,
    signer: str | None,
    log: int,
    token: str = FAKE_TOKEN,
    tx: str | None = None,
) -> TransferEvent:
    return TransferEvent(
        token=token,
        sender=sender,
        recipient=recipient,
        value=value,
        block_number=block,
        block_hash="0x" + "11" * 32,
        transaction_hash=tx or f"0x{log:064x}",
        transaction_index=0,
        log_index=log,
        tx_sender=signer,
    )


WALLET = to_checksum_address("0x" + "ab" * 20)
REAL = to_checksum_address("0xd9a1b0b1e1ae382dbdc898ea68012ffcb2853a91")
LOOK = to_checksum_address("0xd9a1c3788d81257612e2581a6ea0ada244853a91")


def _obs(events: list[TransferEvent], cutoff: int = 10_000) -> ObservationSet:
    return ObservationSet.build(
        chain_id=1,
        wallet=WALLET,
        cutoff_block=cutoff,
        transfers=events,
        native_sends=[],
        transfer_ranges=[BlockRange(0, cutoff)],
        wallet_tx_ranges=[BlockRange(0, cutoff)],
    )


def test_extraction_keeps_signer_apart_from_log_fields_and_skips_own_actions() -> None:
    events = [
        _tr(WALLET, REAL, 10, 5, WALLET, 1),  # the victim's real payment (reference)
        _tr(WALLET, LOOK, 12, 0, S1, 2),  # planted: zero-value "from" the victim, signed by S1
        _tr(WALLET, LOOK, 20, 0, WALLET, 3),  # the victim itself sent 0: not a planting event
    ]
    [a] = extract_attempts(_obs(events), wallet_is_plain_eoa=True)
    assert (a.signer, a.log_from, a.log_to, a.lookalike, a.imitated) == (
        S1,
        WALLET,
        LOOK,
        LOOK,
        REAL,
    )
    assert a.event_type == "zero_value_transfer"
    assert a.asset_movement == "unverified"
    assert a.attempt_id == attempt_id(1, a.transaction_hash, 2, WALLET, LOOK)


def test_extraction_is_point_in_time_and_deduplicated() -> None:
    events = [_tr(WALLET, REAL, 10, 5, WALLET, 1), _tr(WALLET, LOOK, 12, 0, S1, 2)]
    early = extract_attempts(_obs(events + events, cutoff=11), wallet_is_plain_eoa=True)
    assert early == []  # the planting event is after the cutoff
    assert len(extract_attempts(_obs(events + events), wallet_is_plain_eoa=True)) == 1


def test_qualification_can_depend_on_later_data_so_extraction_must_be_rerun() -> None:
    # Regression: the planting event (block 12) only qualifies once the victim pays the
    # imitated address (block 20). Filtering attempts found at a later cutoff by block
    # would wrongly report it at cutoff 15.
    events = [_tr(WALLET, LOOK, 12, 0, S1, 2), _tr(WALLET, REAL, 20, 5, WALLET, 1)]
    late = extract_attempts(_obs(events, cutoff=25), wallet_is_plain_eoa=True)
    assert [a.block_number for a in late] == [12]
    assert extract_attempts(_obs(events, cutoff=15), wallet_is_plain_eoa=True) == []


def test_smart_account_foreign_signer_is_not_a_spoof() -> None:
    events = [_tr(WALLET, REAL, 10, 5, WALLET, 1), _tr(WALLET, LOOK, 12, 7, S1, 2)]
    assert extract_attempts(_obs(events), wallet_is_plain_eoa=False) == []


# --- relationships -------------------------------------------------------------------------


def test_strengths_by_entity_kind() -> None:
    tx = "0x" + "77" * 32
    attempts = [
        att(V1, addr(1), signer=S1, tx=tx, log_index=1),
        att(V2, addr(2), signer=S1, tx=tx, log_index=2),
    ]
    by_kind = {e.entity.kind: e.strength for e in shared_entities(attempts, chain_id=1)}
    assert by_kind == {
        "transaction": "directly_observed",
        "signer": "strongly_supported",
        "contract": "tentative",
    }


def test_common_token_contract_is_insufficient() -> None:
    attempts = [att(V1, addr(1), contract=USDT), att(V2, addr(2), contract=USDT)]
    [e] = shared_entities(attempts, chain_id=1)
    assert e.entity.kind == "contract"
    assert e.strength == "insufficient"
    assert USDT in COMMON_CONTRACTS[1]


# --- clustering ----------------------------------------------------------------------------


def test_shared_signer_groups_attempts_across_wallets() -> None:
    a = [att(V1, addr(1), signer=S1), att(V2, addr(2), signer=S1), att(V3, addr(3), signer=S2)]
    result = analyse(a)
    [c] = result.clusters
    assert c.victims == tuple(sorted((V1, V2)))
    assert c.structure == "shared_entity"
    assert c.confidence == "strongly_supported"
    assert result.unclustered == (a[2].attempt_id,)


def test_negative_different_attackers_same_victim_stay_apart() -> None:
    result = analyse([att(V1, addr(1), signer=S1), att(V1, addr(2), signer=S2)])
    assert result.clusters == ()


def test_negative_same_popular_token_does_not_merge() -> None:
    a = [att(V1, addr(1), signer=S1, contract=USDT), att(V2, addr(2), signer=S2, contract=USDT)]
    assert analyse(a).clusters == ()


def test_negative_same_block_and_similar_vanity_do_not_merge() -> None:
    a = [att(V1, addr(0xAB01), signer=S1, block=500), att(V2, addr(0xAB02), signer=S2, block=500)]
    assert analyse(a).clusters == ()
    assert len(temporal_pairs(a, window_blocks=10)) == 1  # reported as a weak feature only


def test_negative_narrow_contract_is_context_not_a_merge() -> None:
    a = [att(V1, addr(1), signer=S1), att(V2, addr(2), signer=S2)]  # same FAKE_TOKEN
    result = analyse(a)
    assert result.clusters == ()
    merged = analyse(
        a,
        config=RelationConfig(
            merge_kinds=frozenset({"transaction", "lookalike", "signer", "contract"}),
            merge_strengths=frozenset({"directly_observed", "strongly_supported", "tentative"}),
        ),
    )
    assert len(merged.clusters) == 1  # only when the ablation explicitly allows it


def test_negative_unsolicited_tokens_cannot_pull_in_an_innocent_wallet() -> None:
    # An attacker sends an innocent wallet tokens from its lookalike: the innocent wallet is a
    # victim, and victims never link attempts.
    innocent = addr(0x1AA0)
    a = [att(V1, addr(1), signer=S1), att(innocent, addr(9)), att(innocent, addr(1))]
    [c] = analyse(a).clusters
    assert innocent in c.victims  # the shared lookalike addr(1) links the innocent's *attempt*
    other = [x for x in analyse(a).unclustered]
    assert a[1].attempt_id in other  # its other attempt is not dragged in


def test_hub_signer_is_reported_and_never_merges() -> None:
    a = [att(addr(0xB000 + i), addr(0xC000 + i), signer=S1) for i in range(30)]
    result = analyse(a, config=RelationConfig(max_lookalikes_per_entity=25))
    assert result.clusters == ()
    assert [h.entity.key for h in result.hub_entities] == [S1]


def test_chained_cluster_is_tentative_and_names_the_bridge() -> None:
    # A-B share signer S1; B-C share lookalike L. A and C share nothing.
    lookalike = addr(0xD00D)
    a = att(V1, addr(1), signer=S1)
    b = att(V2, lookalike, signer=S1)
    c = att(V3, lookalike, signer=S2)
    [cl] = analyse([a, b, c]).clusters
    assert cl.structure == "chained"
    assert cl.confidence == "tentative"
    assert b.attempt_id in cl.articulation_attempts
    assert "tentative" in cl.explanation


def test_signer_shared_by_every_member_is_not_transitive() -> None:
    # Regression (real data): a signer planted one lookalike 7 times on wallet 1 and also
    # targeted two other wallets. Every member shares the signer, so nothing is transitive,
    # although the signer is technically the point holding the group together.
    lookalike = addr(0xD00E)
    a = [att(V1, lookalike, signer=S1) for _ in range(3)] + [
        att(V2, addr(2), signer=S1),
        att(V3, addr(3), signer=S1),
    ]
    [cl] = analyse(a).clusters
    assert cl.structure == "shared_entity"
    assert cl.confidence == "strongly_supported"


def test_multiply_connected_cluster_is_not_tentative() -> None:
    l1, l2 = addr(0xE001), addr(0xE002)
    a = [
        att(V1, l1, signer=S1),
        att(V2, l1, signer=S2),
        att(V3, l2, signer=S1),
        att(V4, l2, signer=S2),
    ]
    [cl] = analyse(a).clusters
    assert cl.structure == "multiply_connected"
    assert cl.confidence == "strongly_supported"


def test_future_attempts_cannot_change_an_earlier_cutoff() -> None:
    early = [att(V1, addr(1), signer=S1, block=100), att(V2, addr(2), signer=S1, block=200)]
    future = [att(V3, addr(3), signer=S1, block=900), att(V4, addr(2), signer=S2, block=950)]
    before = cluster_attempts(early, chain_id=1, cutoff_block=500)
    with_future = cluster_attempts(early + future, chain_id=1, cutoff_block=500)
    assert before.clusters == with_future.clusters
    assert before.input_sha256 == with_future.input_sha256
    late = cluster_attempts(early + future, chain_id=1, cutoff_block=1_000)
    assert late.clusters[0].cluster_id != before.clusters[0].cluster_id


def test_deployer_known_only_after_cutoff_is_ignored() -> None:
    a = [
        att(V1, addr(1), signer=S1, contract=addr(0x71)),
        att(V2, addr(2), signer=S2, contract=addr(0x72)),
    ]
    deployers = {
        addr(0x71): Deployer(addr(0xDE), 50, "0x" + "01" * 32),
        addr(0x72): Deployer(addr(0xDE), 9_999, "0x" + "02" * 32),
    }
    early = cluster_attempts(a, chain_id=1, cutoff_block=500, deployers=deployers)
    assert not any(e.entity.kind == "deployer" for c in early.clusters for e in c.context_evidence)
    assert not any(e.entity.kind == "deployer" for e in shared_entities(a, chain_id=1))


def test_deterministic_output_and_ids() -> None:
    a = [att(V1, addr(1), signer=S1), att(V2, addr(2), signer=S1)]
    r1, r2 = analyse(a), analyse(list(reversed(a)))
    assert r1.clusters == r2.clusters
    assert r1.input_sha256 == r2.input_sha256
    assert r1.clusters[0].cluster_id == cluster_id([x.attempt_id for x in a])


def test_lineage_reports_growth_split_and_merge() -> None:
    a = [att(V1, addr(1), signer=S1), att(V2, addr(2), signer=S1)]
    b = [att(V3, addr(3), signer=S2), att(V4, addr(4), signer=S2)]
    first = analyse(a + b).clusters
    grown = analyse([*a, *b, att(addr(0xF1), addr(5), signer=S1)]).clusters
    kinds = {k for k, _ in lineage(first, grown).values()}
    assert kinds == {"grown", "unchanged"}
    bridge = att(addr(0xF2), addr(1), signer=S2)  # lookalike of group a, signer of group b
    merged = analyse([*a, *b, bridge]).clusters
    assert [k for k, _ in lineage(first, merged).values()] == ["merged"]
    assert {k for k, _ in lineage(merged, first).values()} == {"split"}


@pytest.mark.parametrize(
    ("adj", "expected"),
    [
        ({"a": ["b"], "b": ["a", "c"], "c": ["b"]}, {"b"}),
        ({"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}, set()),
        ({"a": ["b"], "b": ["a"], "x": []}, set()),
    ],
)
def test_articulation_points(adj: dict[str, list[str]], expected: set[str]) -> None:
    assert articulation_points(adj) == expected

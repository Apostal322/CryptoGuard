"""Bounded expansion around planting infrastructure, against the fake node."""

from __future__ import annotations

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.campaigns.attempts import PoisoningAttempt, attempt_id
from cryptoguard.campaigns.cluster import cluster_attempts
from cryptoguard.campaigns.expansion import (
    ExpansionBudget,
    expand,
    outcome_from_dict,
    outcome_to_dict,
    plan_tasks,
)
from cryptoguard.core.address import to_checksum_address
from tests.fakenode import FakeNode


def cs(hex40: str) -> str:
    return to_checksum_address("0x" + hex40)


def pair(tag: str) -> tuple[str, str]:
    """A real payee and its vanity lookalike (same first 4 and last 4 hex characters)."""
    real = cs("abcd" + tag * 32 + "ef12")
    fake = cs("abcd" + "9" * 32 + "ef12") if tag != "9" else cs("abcd" + "8" * 32 + "ef12")
    return real, fake


SIGNER = cs("5" * 40)
FAKE_TOKEN = cs("f" * 39 + "1")
V1, V2, V3 = cs("a1" * 20), cs("a2" * 20), cs("a3" * 20)
R1, L1 = cs("abcd" + "1" * 32 + "ef12"), cs("abcd" + "9" * 32 + "ef12")
R2, L2 = cs("bcde" + "2" * 32 + "fa21"), cs("bcde" + "8" * 32 + "fa21")


def known_attempt(node: FakeNode, tx: str, block: int) -> PoisoningAttempt:
    log = next(entry for entry in node.logs if entry["transactionHash"] == tx)
    li = int(log["logIndex"], 16)
    return PoisoningAttempt(
        block_number=block,
        transaction_index=0,
        log_index=li,
        attempt_id=attempt_id(1, tx, li, V1, L1),
        chain_id=1,
        victim=V1,
        lookalike=L1,
        imitated=R1,
        imitated_confirmed=True,
        event_type="zero_value_transfer",
        transaction_hash=tx,
        block_hash=log["blockHash"],
        contract=FAKE_TOKEN,
        log_from=V1,
        log_to=L1,
        value=0,
        signer=SIGNER,
        rule_id="CG-POI-001",
        source="wallet_scan",
    )


def scenario(node: FakeNode) -> PoisoningAttempt:
    node.head = 2_000
    node.add_token(FAKE_TOKEN)
    # Both victims paid their real counterparties shortly before the planting.
    node.add_transfer_log(FAKE_TOKEN, V1, R1, 5, block=1_000, signer=V1, log_index=1)
    node.add_transfer_log(FAKE_TOKEN, V2, R2, 7, block=1_001, signer=V2, log_index=1)
    # One batch transaction by SIGNER plants lookalikes on both, plus a third wallet that
    # never paid anything resembling its "lookalike" (must stay unverified).
    tx = node.plant(SIGNER, FAKE_TOKEN, [(V1, L1, 0), (V2, L2, 0), (V3, L1, 0)], block=1_010)
    return known_attempt(node, tx, 1_010)


async def test_signer_expansion_finds_a_new_victim_in_the_same_planting_transaction(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    result = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    found = {(c.victim, c.lookalike): c for c in result.candidates}
    assert found[(V2, L2)].status == "verified"
    assert found[(V2, L2)].imitated == R2
    assert found[(V2, L2)].signer == SIGNER
    assert found[(V3, L1)].status == "no_matching_payment"  # never counted as an attempt
    attempts = result.attempts()
    assert {(a.victim, a.lookalike) for a in attempts} >= {(V2, L2)}
    assert all(a.source == "expansion" and a.asset_movement == "unverified" for a in attempts)

    analysis = cluster_attempts([known, *attempts], chain_id=1, cutoff_block=1_500)
    [cl] = analysis.clusters
    assert set(cl.victims) == {V1, V2}
    kinds = {e.entity.kind: e.strength for e in cl.merging_evidence}
    assert kinds["transaction"] == "directly_observed"
    assert result.requests > 0
    assert result.coverage()["not_attempted"]


async def test_nothing_after_the_cutoff_is_read(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    node.add_transfer_log(FAKE_TOKEN, V3, R1, 9, block=1_600, signer=V3, log_index=2)
    node.plant(SIGNER, FAKE_TOKEN, [(V3, L1, 0)], block=1_601)  # after the cutoff
    result = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    assert all(c.block_number <= 1_500 for c in result.candidates)
    for method, params in node.requests:
        if method == "eth_getLogs":
            assert int(params[0]["toBlock"], 16) <= 1_500
        if method in ("eth_getTransactionCount", "eth_getCode") and params[1] != "latest":
            assert int(params[1], 16) <= 1_500


async def test_budget_stops_cleanly_and_reports_what_was_skipped(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    result = await expand(
        provider, [known], chain_id=1, cutoff_block=1_500, budget=ExpansionBudget(max_requests=8)
    )
    assert result.stopped == "request budget"
    statuses = [o.status for o in result.outcomes]
    assert "partial" in statuses or "skipped" in statuses
    assert result.requests <= 8 + 2  # a started call may finish; never far beyond
    assert any(f["reason"] for f in result.coverage()["failures"])  # type: ignore[index, union-attr]


async def test_missing_history_is_a_failure_not_an_empty_result(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    node.state_history = 10  # nonces only for the last 10 blocks
    result = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    signer_task = next(o for o in result.outcomes if o.task.kind == "signer_transactions")
    assert signer_task.status == "failed"
    assert "historical state" in (signer_task.reason or "")


async def test_deployer_found_for_top_level_creation(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    deployer = cs("de" * 20)
    node.deploy(deployer, FAKE_TOKEN, block=900)
    result = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    [d] = result.deployers().values()
    assert (d.address, d.creation_block) == (deployer, 900)


async def test_resume_reuses_completed_tasks_without_requests(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    first = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    saved = {o.task.task_id: outcome_from_dict(outcome_to_dict(o)) for o in first.outcomes}
    again = await expand(provider, [known], chain_id=1, cutoff_block=1_500, completed=saved)
    assert again.requests == 0
    assert again.candidates == first.candidates


async def test_tasks_seeded_after_a_cutoff_are_not_usable_before_it(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    known = scenario(node)
    result = await expand(provider, [known], chain_id=1, cutoff_block=1_500)
    attempts, _ = result.usable_at(1_009)  # before the known attempt that seeded the tasks
    assert attempts == []
    later, _ = result.usable_at(1_500)
    assert later
    # The seed attempt dates from block 1,010 but (say) was only recognised at 1,600:
    # nothing the task found may be used before then.
    unknown = dict.fromkeys((SIGNER, L1, FAKE_TOKEN), 1_600)
    assert result.usable_at(1_500, known_since=unknown) == ([], {})


def test_victims_are_never_expanded() -> None:
    a = PoisoningAttempt(
        block_number=10,
        transaction_index=0,
        log_index=0,
        attempt_id="0x1",
        chain_id=1,
        victim=V1,
        lookalike=L1,
        imitated=R1,
        imitated_confirmed=True,
        event_type="zero_value_transfer",
        transaction_hash="0x" + "11" * 32,
        block_hash="0x" + "22" * 32,
        contract=FAKE_TOKEN,
        log_from=V1,
        log_to=L1,
        value=0,
        signer=SIGNER,
        rule_id="CG-POI-001",
        source="wallet_scan",
    )
    keys = {t.key for t in plan_tasks([a], chain_id=1, cutoff_block=100, budget=ExpansionBudget())}
    assert V1 not in keys
    assert keys == {SIGNER, L1, FAKE_TOKEN}

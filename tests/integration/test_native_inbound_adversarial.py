"""Adversarial checks of the balance-bisection native-inbound locator (protocol 12.4 final
validation). Expected outputs are written from each scenario's definition. Mock node only:
it charges no gas, so the wallet's own transactions move exactly their value."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.services.native_inbound import locate_native_inbound
from tests.fakenode import FakeNode

W = "0x" + "c" * 40
REF = "0xabcde" + "1" * 30 + "54321"
A, B, C = ("0x" + c * 40 for c in "123")
START, END = 1_000, 1_400


def node() -> FakeNode:
    n = FakeNode(head=2_000)
    n.balance_history = True
    n.set_account(W, balance=10**21)
    return n


async def _no_sleep(_: float) -> None:
    return None


async def locate(n: FakeNode, tmp: Path, own: list[int], **kw: Any) -> Any:
    """Plain mock transport (no ledger): these tests check results, not budgets."""
    del tmp
    client = JsonRpcClient(
        "https://rpc.example.invalid",
        retry=RetryPolicy(max_retries=0, base_delay=0.0, max_delay=0.0),
        transport=n.transport(),
        sleep=_no_sleep,
        rng=random.Random(0),
    )
    provider = RpcEthereumProvider(
        client, expected_chain_id=1, endpoint_display="test", max_log_block_range=1000
    )
    try:
        return await locate_native_inbound(
            provider,
            W,
            from_block=START,
            to_block=END,
            own_tx_blocks=own,
            wallet_is_plain_eoa=True,
            **kw,
        )
    finally:
        await provider.aclose()


def seen(found: Any) -> set[tuple[int, str, int, bool | None]]:
    return {(t.block_number, t.sender.lower(), t.value, t.succeeded) for t in found.inbound}


async def test_several_inbound_transfers_in_one_block(tmp_path: Path) -> None:
    n = node()
    n.send_native(A, W, 5, block=1_150, tx_index=1)
    n.send_native(B, W, 7, block=1_150, tx_index=2)
    f = await locate(n, tmp_path, [], read_receipts=True)
    assert seen(f) == {(1_150, A, 5, True), (1_150, B, 7, True)}
    assert (f.unattributed, f.status) == ([], "complete")


async def test_inbound_then_an_equal_spend_is_still_found(tmp_path: Path) -> None:
    n = node()
    n.send_native(A, W, 1_000, block=1_150)
    n.send_native(W, REF, 1_000, block=1_200)  # window endpoints now have equal balances
    f = await locate(n, tmp_path, [1_200], read_receipts=True)
    assert seen(f) == {(1_150, A, 1_000, True)}
    assert f.status == "complete"


async def test_internal_credit_beside_an_external_inbound_is_kept_apart(tmp_path: Path) -> None:
    n = node()
    n.send_native(A, W, 1_000, block=1_150)
    n.credits.append((1_150, W, 300))
    f = await locate(n, tmp_path, [], read_receipts=True)
    assert seen(f) == {(1_150, A, 1_000, True)}
    assert [(u.block_number, u.value) for u in f.unattributed] == [(1_150, 300)]


async def test_reverted_and_successful_inbound_in_one_block(tmp_path: Path) -> None:
    n = node()
    bad = n.send_native(A, W, 10**17, block=1_150, tx_index=1)
    n.reverted.add(bad)
    n.send_native(B, W, 500, block=1_150, tx_index=2)
    f = await locate(n, tmp_path, [])  # sums differ, so receipts are read even without the flag
    assert seen(f) == {(1_150, A, 10**17, False), (1_150, B, 500, True)}
    assert f.unattributed == []


async def test_a_reverted_transfer_masked_by_an_equal_credit(tmp_path: Path) -> None:
    """The one case an inferred status gets wrong; observation/2 reads receipts."""
    n = node()
    bad = n.send_native(A, W, 777, block=1_150)
    n.reverted.add(bad)
    n.credits.append((1_150, W, 777))
    observed = await locate(n, tmp_path / "r", [], read_receipts=True)
    assert seen(observed) == {(1_150, A, 777, False)}
    assert [(u.block_number, u.value) for u in observed.unattributed] == [(1_150, 777)]
    inferred = await locate(n, tmp_path / "i", [], read_receipts=False)
    assert seen(inferred) == {(1_150, A, 777, True)}  # documented limitation of inference
    assert inferred.unattributed == []


async def test_a_missed_own_transaction_is_flagged_not_hidden(tmp_path: Path) -> None:
    n = node()
    n.send_native(W, REF, 5_000, block=1_200)  # the caller fails to pass block 1,200
    n.send_native(A, W, 1_000, block=1_300)
    f = await locate(n, tmp_path, [])
    assert f.status == "partial"
    assert f.note is not None
    assert "fell" in f.note


async def test_too_many_increase_blocks_truncate(tmp_path: Path) -> None:
    n = node()
    for i, b in enumerate((1_100, 1_200, 1_300)):
        n.send_native(A, W, 10 + i, block=b)
    f = await locate(n, tmp_path, [], max_change_blocks=2)
    assert f.status == "truncated"
    assert len(f.change_blocks) == 2


async def test_own_transactions_at_the_window_edges(tmp_path: Path) -> None:
    n = node()
    n.send_native(W, REF, 1, block=START)
    n.send_native(A, W, 900, block=1_200)
    n.send_native(W, REF, 1, block=END)
    f = await locate(n, tmp_path, [START, END], read_receipts=True)
    assert seen(f) == {(1_200, A, 900, True)}
    assert f.status == "complete"


async def test_a_self_transaction_is_not_inbound(tmp_path: Path) -> None:
    n = node()
    n.send_native(W, W, 10, block=1_150)
    f = await locate(n, tmp_path, [1_150])
    assert f.inbound == []


async def test_inbound_outside_the_window_is_not_reported(tmp_path: Path) -> None:
    n = node()
    n.send_native(A, W, 5, block=START - 1)
    n.send_native(A, W, 6, block=END + 1)
    f = await locate(n, tmp_path, [])
    assert (f.inbound, f.change_blocks) == ([], [])


async def test_a_quiet_window_costs_only_the_run_endpoints(tmp_path: Path) -> None:
    n = node()
    n.send_native(W, REF, 1, block=1_100)
    f = await locate(n, tmp_path, [1_100])
    # runs 1,000..1,099 and 1,101..1,400: balances at 999, 1,099, 1,100 and 1,400
    assert (f.balance_reads, f.block_reads, f.receipt_reads) == (4, 1, 0)


async def test_randomized_scenarios_match_an_independent_oracle(tmp_path: Path) -> None:
    rng = random.Random(20261108)
    for k in range(25):
        n = node()
        own = sorted(rng.sample(range(START, END + 1), rng.randint(0, 4)))
        for b in own:
            n.send_native(W, REF, rng.randint(1, 10**6), block=b, tx_index=0)
        expect_found: set[tuple[int, str, int, bool | None]] = set()
        credits: dict[int, int] = {}
        for i in range(rng.randint(0, 6)):
            b = rng.randint(START - 20, END + 20)
            sender = rng.choice([A, B, C])
            value = rng.choice([0, rng.randint(1, 10**9)])
            tx = n.send_native(sender, W, value, block=b, tx_index=10 + i)
            failed = value > 0 and rng.random() < 0.25
            if failed:
                n.reverted.add(tx)
            if START <= b <= END and value > 0:
                expect_found.add((b, sender, value, not failed))
        for _ in range(rng.randint(0, 3)):
            b = rng.randint(START, END)
            v = rng.randint(1, 10**6)
            n.credits.append((b, W, v))
            if b not in own:
                credits[b] = credits.get(b, 0) + v
        f = await locate(n, tmp_path / str(k), own, read_receipts=True)
        nonzero = {s for s in seen(f) if s[2] > 0}
        # every nonzero external inbound in the window, success observed, is found; a
        # reverted one sitting in a block with no balance increase is (correctly) not seen
        assert {s for s in expect_found if s[3]} <= nonzero, k
        assert nonzero <= expect_found, k
        assert {(u.block_number, u.value) for u in f.unattributed} == set(credits.items()), k
        assert f.status == "complete", k

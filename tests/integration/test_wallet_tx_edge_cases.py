"""Adversarial cases for the wallet-transaction locator and how detection uses its output."""

from __future__ import annotations

import pytest

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.errors import RpcInvalidResponseError
from cryptoguard.detectors.poisoning import NativeSend, detect_poisoning
from cryptoguard.services.wallet_txs import locate_wallet_transactions
from tests.fakenode import FakeNode, rpc_error
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET


async def test_reverted_payment_is_located_but_marked_as_moving_no_eth(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    ok = node.send_native(WALLET, REAL, 10**16, block=500)
    bad = node.send_native(WALLET, REAL, 10**18, block=600)
    zero = node.send_native(WALLET, REAL, 0, block=700)  # contract call without value
    node.reverted.add(bad)
    found = await locate_wallet_transactions(provider, WALLET, from_block=1, to_block=1_000)
    status = {t.transaction_hash: t.succeeded for t in found.transactions}
    assert status == {ok: True, bad: False, zero: None}  # zero-value: nothing to verify
    assert found.complete


async def test_unreadable_or_reorganized_receipt_is_unknown_not_failed(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    node.send_native(WALLET, REAL, 10**16, block=500)
    node.script(  # not retryable: the status must stay unknown, not become "failed"
        "eth_getTransactionReceipt", rpc_error(-32601, "the method does not exist/is not available")
    )
    [first] = (
        await locate_wallet_transactions(provider, WALLET, from_block=1, to_block=1_000)
    ).transactions
    assert first.succeeded is None
    tx = node.sent_txs[0]["hash"]
    node.script(
        "eth_getTransactionReceipt",
        lambda payload: __import__("httpx").Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {
                    "transactionHash": tx,
                    "blockHash": "0x" + "ee" * 32,
                    "status": "0x1",
                    "logs": [],
                },
            },
        ),
    )
    [again] = (
        await locate_wallet_transactions(provider, WALLET, from_block=1, to_block=1_000)
    ).transactions
    assert again.succeeded is None  # receipt from another block: not trusted


async def test_many_transactions_in_one_block_and_after_a_long_gap(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000_000
    hashes = [node.send_native(WALLET, REAL, 1, block=10) for _ in range(5)]
    hashes += [node.send_native(WALLET, REAL, 1, block=b) for b in (11, 12, 13)]
    hashes.append(node.send_native(WALLET, REAL, 1, block=999_999))
    found = await locate_wallet_transactions(provider, WALLET, from_block=1, to_block=1_000_000)
    assert [t.transaction_hash for t in found.transactions] == hashes
    assert [t.nonce for t in found.transactions] == list(range(9))
    assert len({t.transaction_hash for t in found.transactions}) == 9  # no duplicates


async def test_provider_missing_the_transaction_is_an_error_not_a_gap(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    node.send_native(WALLET, REAL, 1, block=500)
    node.sent_txs[0]["from"] = "0x" + "99" * 20  # the block no longer lists the wallet's tx
    node.sent_txs.append({**node.sent_txs[0], "from": WALLET.lower(), "nonce": "0x5"})
    with pytest.raises(RpcInvalidResponseError):
        await locate_wallet_transactions(provider, WALLET, from_block=1, to_block=1_000)


def _transfer(block: int, value: int, signer: str):  # type: ignore[no-untyped-def]
    from cryptoguard.blockchain.erc20 import TransferEvent

    return TransferEvent(
        token=TOKEN,
        sender=WALLET,
        recipient=FAKE,
        value=value,
        block_number=block,
        block_hash="0x" + "11" * 32,
        transaction_hash=f"0x{block:064x}",
        transaction_index=0,
        log_index=1,
        tx_sender=signer,
    )


def _native(to: str, block: int, succeeded: bool | None) -> NativeSend:
    return NativeSend(to, 10**18, block, f"0x{block + 7:064x}", 0, succeeded)


@pytest.mark.parametrize(
    ("loss_status", "expected_rule"),
    [(True, "CG-POI-003"), (None, "CG-POI-003"), (False, "CG-POI-001")],
)
def test_reverted_send_to_lookalike_is_not_loss_evidence(
    loss_status: bool | None, expected_rule: str
) -> None:
    planted = _transfer(110, 50_000, ATTACKER_SIGNER)  # spoofed transfer to the lookalike
    natives = [_native(REAL, 100, True), _native(FAKE, 200, loss_status)]
    [case] = detect_poisoning(
        WALLET, [planted], chain_id=1, wallet_is_plain_eoa=True, native_sends=natives
    )
    assert case.rule_id == expected_rule


def test_reverted_payment_still_identifies_the_imitated_recipient() -> None:
    planted = _transfer(110, 50_000, ATTACKER_SIGNER)
    [case] = detect_poisoning(
        WALLET,
        [planted],
        chain_id=1,
        wallet_is_plain_eoa=True,
        native_sends=[_native(REAL, 100, False)],  # the real payment reverted, intent is clear
    )
    assert (case.reference, case.rule_id) == (REAL, "CG-POI-001")

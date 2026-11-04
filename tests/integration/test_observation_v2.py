"""``observation/2`` recording on a mock node (protocol 12.4): native ETH received by
balance bisection, ERC-721-shaped transfers kept, per-category coverage, and an end-to-end
replay comparing the original recorder with the extended one. Mock transports only."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from cryptoguard.blockchain.abi import TRANSFER_TOPIC, address_topic
from cryptoguard.blockchain.budget import RequestLedger, budgeted_transport
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.detectors.poisoning import PoisoningConfig
from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.replay.engine import Visibility, detector_outputs
from cryptoguard.replay.models import ReplayFixture
from cryptoguard.replay.record import record_window
from cryptoguard.services.native_inbound import locate_native_inbound
from tests.fakenode import FakeNode, block_hash

WALLET = "0x" + "c" * 40
REF = "0xabcde" + "1" * 30 + "54321"
DUST = "0xabcde" + "9" * 30 + "54321"  # native-dust lookalike of REF
FAKE_LOOK = "0xabcd" + "8" * 32 + "4321"  # fake-token lookalike of REF
NFT_LOOK = "0xabc" + "7" * 33 + "4321"  # ERC-721 lookalike of REF
STRANGER = "0x" + "5" * 40
ATTACKER = "0x" + "a1" * 20
TOKEN = "0x" + "e" * 40
NFT = "0x" + "d" * 40
START, END = 1_000, 1_400


async def _no_sleep(_: float) -> None:
    return None


def _provider(node: FakeNode, tmp: Path) -> tuple[RpcEthereumProvider, RequestLedger]:
    ledger = RequestLedger(tmp / "ledger.json", cap=5_000)
    client = JsonRpcClient(
        "https://rpc.example.invalid",
        retry=RetryPolicy(max_retries=0, base_delay=0.0, max_delay=0.0),
        transport=budgeted_transport(ledger, node.transport()),
        sleep=_no_sleep,
        rng=random.Random(0),
    )
    provider = RpcEthereumProvider(
        client, expected_chain_id=1, endpoint_display="test", max_log_block_range=1000
    )
    return provider, ledger


def _nft_log(node: FakeNode, sender: str, recipient: str, token_id: int, block: int) -> None:
    tx = "0x" + f"{block:064x}"
    node.logs.append(
        {
            "address": NFT,
            "topics": [
                TRANSFER_TOPIC,
                address_topic(sender),
                address_topic(recipient),
                "0x" + f"{token_id:064x}",
            ],
            "data": "0x",
            "blockNumber": hex(block),
            "blockHash": block_hash(block),
            "transactionHash": tx,
            "transactionIndex": "0x2",
            "logIndex": "0x0",
            "removed": False,
        }
    )
    node.tx_senders[tx] = ATTACKER


def _incident() -> FakeNode:
    """A victim pays REF, then is poisoned three ways; the theft is not in the window."""
    node = FakeNode(head=2_000)
    node.balance_history = True
    node.set_account(WALLET, balance=10**20)
    node.add_token(TOKEN)
    node.send_native(WALLET, REF, 10**18, block=1_100)  # reference use (wallet-signed)
    node.send_native(DUST, WALLET, 1_000, block=1_150, tx_index=3)  # native dust planting
    node.add_transfer_log(TOKEN, FAKE_LOOK, WALLET, 7, block=1_160, signer=ATTACKER)
    _nft_log(node, NFT_LOOK, WALLET, 42, block=1_170)
    node.credits.append((1_180, WALLET.lower(), 5_000))  # internal credit: no sender
    reverted = node.send_native(STRANGER, WALLET, 10**17, block=1_190)
    node.reverted.add(reverted)  # moved nothing
    node.send_native(STRANGER, WALLET, 0, block=1_100, tx_index=4)  # 0 ETH beside own tx
    node.send_native(STRANGER, WALLET, 0, block=1_250)  # 0 ETH alone: invisible to balances
    return node


async def _record(node: FakeNode, tmp: Path, observation: int) -> tuple[ReplayFixture, int]:
    tmp.mkdir(parents=True, exist_ok=True)
    provider, ledger = _provider(node, tmp)
    try:
        fx = await record_window(
            provider,
            case_id="synthetic-e2e",
            chain_id=1,
            wallet=WALLET,
            start=START,
            end=END,
            chunk_blocks=100,
            observation=observation,
        )
    finally:
        await provider.aclose()
    return fx, ledger.used()


async def test_balance_bisection_finds_native_inbound_and_states_its_limits(
    tmp_path: Path,
) -> None:
    node = _incident()
    provider, ledger = _provider(node, tmp_path)
    try:
        found = await locate_native_inbound(
            provider,
            WALLET,
            from_block=START,
            to_block=END,
            own_tx_blocks=[1_100],
            wallet_is_plain_eoa=True,
        )
    finally:
        await provider.aclose()
    by_block = {(n.block_number, n.sender.lower(), n.value, n.succeeded) for n in found.inbound}
    assert by_block == {
        (1_150, DUST, 1_000, True),  # found by bisection, sender from the block
        (1_100, STRANGER, 0, None),  # 0 ETH, seen only because the own-tx block was read
    }
    assert [(u.block_number, u.value) for u in found.unattributed] == [(1_180, 5_000)]
    assert found.change_blocks == [1_150, 1_180]  # the reverted 0.1 ETH changed nothing
    assert (found.status, found.unattributed_status) == ("complete", "partial")
    reads = found.balance_reads + found.block_reads + found.receipt_reads
    assert reads + 1 == ledger.used()  # plus the provider's one chain-id check


async def test_balance_bisection_does_not_apply_to_wallets_with_code(tmp_path: Path) -> None:
    provider, ledger = _provider(_incident(), tmp_path)
    try:
        found = await locate_native_inbound(
            provider,
            WALLET,
            from_block=START,
            to_block=END,
            own_tx_blocks=[],
            wallet_is_plain_eoa=False,
        )
    finally:
        await provider.aclose()
    assert (found.status, found.inbound, ledger.used()) == ("unsupported", [], 0)


async def test_end_to_end_original_versus_extended_observation(tmp_path: Path) -> None:
    node = _incident()
    v1, used1 = await _record(node, tmp_path / "a", 1)
    v2, used2 = await _record(node, tmp_path / "b", 2)

    # observation/1 is exactly what every existing fixture holds
    assert v1.observation is None and v1.native_inbound is None
    assert b'"native_inbound"' not in v1.canonical_bytes()
    assert used2 > used1  # the extension costs requests, all through the ledger
    # observation/2 states what it saw and what it could not
    cov = v2.observation
    assert cov is not None
    assert cov.status("native_inbound_external") == "complete"
    assert cov.status("native_inbound_zero_value") == "partial"
    assert cov.status("native_inbound_unattributed") == "partial"  # own tx in the window
    assert cov.status("internal_value_transfers") == "unsupported"
    assert cov.status("erc721_transfer_logs") == "complete"
    assert [(n.token_id, n.sender.lower()) for n in v2.nft_transfers or []] == [("42", NFT_LOOK)]
    assert v2.discarded_log_counts == {"erc721_shaped": 1, "removed": 0, "malformed": 0}
    # same inputs to the production detector: its findings do not change
    cfg = PoisoningConfig()
    full = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS
    assert detector_outputs(v1, END, full, cfg) == detector_outputs(v2, END, full, cfg)

    cut = (END + 1, 0)
    c0 = cd.discover(v2, cutoff=cut, variant="C0")
    c1_old = cd.discover(v1, cutoff=cut, variant="C1")
    c1 = cd.discover(v2, cutoff=cut, variant="C1")
    expected_c0 = {FAKE_LOOK}  # oracle: only the ERC-20 planting is visible to C0
    assert c0.lookalikes == c1_old.lookalikes == expected_c0
    # C1 applies C0's rules unchanged: zero_value_in fires on the 0 ETH stranger seen in the
    # own-transaction block, which is not a lookalike (candidate volume, not evidence)
    assert c1.lookalikes == {FAKE_LOOK, DUST, NFT_LOOK, STRANGER}
    assert cd.compare(c0, c1)["added"] == sorted([DUST, NFT_LOOK, STRANGER])
    by = {c.lookalike: c for c in c1.candidates}
    assert (by[STRANGER].methods, by[STRANGER].imitated) == (("zero_value_in",), None)
    assert (by[DUST].methods, by[DUST].imitated) == (("lookalike_in",), REF)
    assert c1.unattributed_inbound_blocks == [1_180]
    # serialization is reproducible: same bytes give the same fixture and hash
    again = ReplayFixture.model_validate_json(v2.canonical_bytes())
    assert again.sha256() == v2.sha256()


async def test_a_dust_planting_after_the_cutoff_is_not_seen(tmp_path: Path) -> None:
    v2, _ = await _record(_incident(), tmp_path, 2)
    assert DUST not in cd.discover(v2, cutoff=(1_150, 3), variant="C1").lookalikes
    assert DUST in cd.discover(v2, cutoff=(1_150, 4), variant="C1").lookalikes


def _unused(*_: Any) -> None:  # keep imports explicit for readers
    return None

from __future__ import annotations

import pytest

from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX, CodeKind
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.chains import get_chain
from cryptoguard.core.errors import (
    BlockRangeTooLargeError,
    ChainMismatchError,
    HistoricalStateUnavailableError,
    InvalidAddressError,
    NotInDemoFixturesError,
    ReorgDetectedError,
    RpcInvalidResponseError,
)
from cryptoguard.services.demo import DEMO_ACCOUNTS, DemoProvider
from cryptoguard.services.inspection import inspect_address
from tests.fakenode import FakeNode, result, rpc_error

MAINNET = get_chain(1)
WALLET = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
DELEGATE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
CONTRACT = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"


async def test_chain_mismatch_blocks_all_state_reads(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.chain_id = 11155111
    with pytest.raises(ChainMismatchError) as excinfo:
        await provider.get_balance(WALLET, "latest")
    assert excinfo.value.details == {"expected": 1, "actual": 11155111}
    assert "eth_getBalance" not in node.calls


async def test_chain_verification_is_cached(node: FakeNode, provider: RpcEthereumProvider) -> None:
    await provider.block_number()
    await provider.block_number()
    assert node.calls.count("eth_chainId") == 1


async def test_get_logs_requires_bounded_range(provider: RpcEthereumProvider) -> None:
    assert await provider.get_logs(from_block=1, to_block=1000) == []
    with pytest.raises(BlockRangeTooLargeError):
        await provider.get_logs(from_block=1, to_block=1001)
    with pytest.raises(BlockRangeTooLargeError):
        await provider.get_logs(from_block=10, to_block=9)


async def test_invalid_rpc_values_raise_instead_of_being_guessed(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.script("eth_getBalance", result("not-hex"))
    with pytest.raises(RpcInvalidResponseError):
        await provider.get_balance(WALLET, "latest")
    node.script("eth_getCode", result("0xabc"))
    with pytest.raises(RpcInvalidResponseError):
        await provider.get_code(WALLET, "latest")
    node.script("eth_getBlockByNumber", result({"number": "0x1", "hash": "0x12"}))
    with pytest.raises(RpcInvalidResponseError):
        await provider.get_block(1)


async def test_inspect_plain_eoa(node: FakeNode, provider: RpcEthereumProvider) -> None:
    node.set_account(WALLET, balance=1_250_000_000_000_000_000)
    inspection = await inspect_address(provider, WALLET.lower(), chain=MAINNET)
    assert inspection.address == WALLET
    assert inspection.data_source == "rpc"
    assert inspection.simulated is False
    assert inspection.chain_verified is True
    assert inspection.block.number == node.head
    assert inspection.block.finality == "not_finalized"
    assert inspection.block.finalized_block_number == node.head - 64
    assert inspection.native_balance.wei == "1250000000000000000"
    assert inspection.native_balance.formatted == "1.25"
    assert inspection.account_code.kind is CodeKind.NO_CODE
    assert inspection.account_code.delegation is None
    assert inspection.explorer is not None
    assert inspection.explorer.address == f"https://etherscan.io/address/{WALLET}"
    assert any("No transaction history" in item for item in inspection.limitations)


async def test_inspect_reads_are_pinned_to_one_block(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.set_account(WALLET, balance=1)
    await inspect_address(provider, WALLET, chain=MAINNET)
    state_reads = [
        params[1] for method, params in node.requests if method in ("eth_getBalance", "eth_getCode")
    ]
    assert state_reads
    assert set(state_reads) == {hex(node.head)}


async def test_inspect_delegated_eoa(node: FakeNode, provider: RpcEthereumProvider) -> None:
    node.set_account(WALLET, balance=5, code=DELEGATION_PREFIX + bytes.fromhex(DELEGATE[2:]))
    node.set_account(DELEGATE, code=bytes.fromhex("6080604052"))
    inspection = await inspect_address(provider, WALLET, chain=MAINNET)
    code = inspection.account_code
    assert code.kind is CodeKind.EIP7702_DELEGATION
    assert code.code_size == 23
    assert code.delegation is not None
    assert code.delegation.target == DELEGATE
    assert code.delegation.target_code_kind is CodeKind.CONTRACT
    assert code.delegation.target_code_size == 5
    assert "not malicious by itself" in code.explanation


async def test_inspect_delegation_to_codeless_and_chained_targets(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.set_account(WALLET, code=DELEGATION_PREFIX + bytes.fromhex(DELEGATE[2:]))
    inspection = await inspect_address(provider, WALLET, chain=MAINNET)
    assert inspection.account_code.delegation is not None
    assert inspection.account_code.delegation.target_code_kind is CodeKind.NO_CODE
    assert any("no code" in n for n in inspection.account_code.delegation.notes)

    node.set_account(DELEGATE, code=DELEGATION_PREFIX + bytes.fromhex(CONTRACT[2:]))
    inspection = await inspect_address(provider, WALLET, chain=MAINNET)
    assert inspection.account_code.delegation is not None
    assert inspection.account_code.delegation.target_code_kind is CodeKind.EIP7702_DELEGATION
    assert any("chains" in n for n in inspection.account_code.delegation.notes)


async def test_inspect_contract(node: FakeNode, provider: RpcEthereumProvider) -> None:
    node.set_account(CONTRACT, code=bytes.fromhex("6080604052") * 10)
    inspection = await inspect_address(provider, CONTRACT, chain=MAINNET)
    assert inspection.account_code.kind is CodeKind.CONTRACT
    assert inspection.account_code.code_size == 50


async def test_reorg_during_inspection_is_retried(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.set_account(WALLET, balance=7)
    block_reads = {"n": 0}

    def on_call(method: str) -> None:
        if method == "eth_getBlockByNumber":
            block_reads["n"] += 1
            if block_reads["n"] == 2:  # the post-read recheck of the first attempt
                node.fork = "reorged"

    node.on_call = on_call
    inspection = await inspect_address(provider, WALLET, chain=MAINNET)
    assert inspection.block.hash.startswith("0x")
    assert node.calls.count("eth_getBalance") == 2  # first attempt discarded


async def test_persistent_reorg_raises(node: FakeNode, provider: RpcEthereumProvider) -> None:
    counter = {"n": 0}

    def on_call(method: str) -> None:
        if method == "eth_getBlockByNumber":
            counter["n"] += 1
            node.fork = f"fork-{counter['n']}"

    node.on_call = on_call
    with pytest.raises(ReorgDetectedError):
        await inspect_address(provider, WALLET, chain=MAINNET)


async def test_finality_unknown_when_tag_unsupported(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.finalized = None
    inspection = await inspect_address(provider, WALLET, chain=MAINNET)
    assert inspection.block.finality == "unknown"
    assert inspection.block.finalized_block_number is None


async def test_missing_state_is_an_error_not_a_zero(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.script("eth_getBalance", rpc_error(-32000, "missing trie node 0xabc"))
    with pytest.raises(HistoricalStateUnavailableError):
        await inspect_address(provider, WALLET, chain=MAINNET)


async def test_invalid_address_rejected_before_any_rpc(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    with pytest.raises(InvalidAddressError):
        await inspect_address(provider, "0x123", chain=MAINNET)
    assert node.calls == []


async def test_demo_provider_is_labelled_and_bounded() -> None:
    demo = DemoProvider(1)
    delegated = next(a for a in DEMO_ACCOUNTS if a.label == "delegated-wallet")
    inspection = await inspect_address(demo, delegated.address, chain=MAINNET)
    assert inspection.simulated is True
    assert inspection.data_source == "demo_fixture"
    assert inspection.limitations[0].startswith("SIMULATED DATA")
    assert inspection.explorer is None
    assert inspection.account_code.kind is CodeKind.EIP7702_DELEGATION
    with pytest.raises(NotInDemoFixturesError):
        await inspect_address(demo, WALLET, chain=MAINNET)


async def test_demo_inspection_is_deterministic() -> None:
    demo = DemoProvider(1)
    address = DEMO_ACCOUNTS[0].address
    first = await inspect_address(demo, address, chain=MAINNET)
    second = await inspect_address(demo, address, chain=MAINNET)
    assert first.model_dump(exclude={"observed_at"}) == second.model_dump(exclude={"observed_at"})

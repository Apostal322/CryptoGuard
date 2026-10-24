"""Native-ETH visibility in the live pipeline: wallet-signed transactions via nonce bisection."""

from __future__ import annotations

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.chains import get_chain
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.graph import wallet_graph
from cryptoguard.services.poisoning import scan_poisoning
from cryptoguard.services.snapshots import DEFAULT_DETECTION, take_snapshot
from cryptoguard.services.wallet_txs import locate_wallet_transactions
from tests.fakenode import FakeNode
from tests.integration.test_snapshots import repository
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET

MAINNET = get_chain(1)
LIMITS = ScanLimits(1_000, 5_000, 1_000, 100, 50)


def pays(node: FakeNode, blocks: list[int]) -> list[str]:
    return [node.send_native(WALLET, REAL, 10**16, block=b) for b in blocks]


async def test_locates_every_signed_transaction(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    hashes = pays(node, [100, 100, 450, 999])
    found = await locate_wallet_transactions(provider, WALLET, from_block=50, to_block=1_000)
    assert found.complete
    assert found.signed_in_window == 4
    assert found.nonce_at_end == 4
    assert [t.transaction_hash for t in found.transactions] == hashes
    assert [t.block_number for t in found.transactions] == [100, 100, 450, 999]
    assert all(t.to == REAL and t.value == 10**16 for t in found.transactions)


async def test_window_excludes_earlier_transactions(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    pays(node, [10, 500])
    found = await locate_wallet_transactions(provider, WALLET, from_block=100, to_block=1_000)
    assert [t.block_number for t in found.transactions] == [500]
    assert found.signed_in_window == 1


async def test_cap_keeps_newest_and_reports_the_rest(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    pays(node, [100, 200, 300, 400])
    found = await locate_wallet_transactions(
        provider, WALLET, from_block=50, to_block=1_000, max_transactions=2
    )
    assert [t.block_number for t in found.transactions] == [300, 400]
    assert found.unlocated == 2
    assert not found.complete
    assert found.note is not None


async def test_non_archive_provider_degrades_honestly(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    node.state_history = 128  # like a full node: only recent state
    pays(node, [100, 990])
    blind = await locate_wallet_transactions(provider, WALLET, from_block=50, to_block=1_000)
    assert blind.signed_in_window is None  # the start nonce is too old to read
    assert blind.transactions == []
    assert "historical state" in (blind.note or "")

    # With the start nonce known (stored by the previous snapshot), recent ones are found and
    # the older one is reported as unlocated rather than guessed.
    partial = await locate_wallet_transactions(
        provider, WALLET, from_block=50, to_block=1_000, start_nonce=0
    )
    assert [t.block_number for t in partial.transactions] == [990]
    assert partial.unlocated == 1


async def test_snapshot_flags_lookalike_of_a_native_eth_payee(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    # The WBTC pattern: pay the real address in ETH, then a spoofed token transfer to a lookalike.
    node.add_token(TOKEN)
    node.head = 1_000
    repo = repository()

    async def snap(block: int):  # type: ignore[no-untyped-def]
        return await take_snapshot(
            provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0, block=block
        )

    node.send_native(WALLET, REAL, 5 * 10**16, block=900)
    base = await snap(950)
    assert base.coverage.wallet_txs_scanned[0].to_block == 950
    assert base.finding_events == []

    node.head = 1_100
    node.add_transfer_log(TOKEN, WALLET, FAKE, 50_000, block=1_010, signer=ATTACKER_SIGNER)
    second = await snap(1_050)
    [event] = second.finding_events
    assert (event.rule_id, event.to_status, event.severity) == (
        "CG-POI-001",
        "new",
        "elevated_risk",
    )

    node.head = 1_200
    node.send_native(WALLET, FAKE, 10**18, block=1_150)  # the victim pays the lookalike in ETH
    third = await snap(1_150)
    assert ("CG-POI-003", "critical_evidence") in {
        (e.rule_id, e.severity) for e in third.finding_events
    }
    assert "native-ETH" in third.coverage.description

    graph = wallet_graph(
        repo,
        WALLET,
        chain_id=1,
        data_source="rpc",
        options=DEFAULT_DETECTION,
        max_nodes=60,
        include_inactive=False,
    )
    paid = next(e for e in graph.edges if e.type == "TRANSFERRED_TO" and e.target == REAL)
    assert paid.evidence[0].description.startswith("Native ETH payment")


async def test_stored_nonce_lets_non_archive_snapshots_see_native_sends(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.add_token(TOKEN)
    node.head = 1_000
    node.state_history = 128
    repo = repository()

    async def snap(block: int):  # type: ignore[no-untyped-def]
        return await take_snapshot(
            provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0, block=block
        )

    base = await snap(1_000)  # baseline window start is too old: wallet txs unknown there
    assert base.coverage.wallet_txs_scanned == []
    assert "historical state" in base.coverage.description

    node.head = 1_100
    node.send_native(WALLET, REAL, 10**16, block=1_040)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=1_060, signer=ATTACKER_SIGNER)
    second = await snap(1_100)  # starts from the nonce stored at block 1_000
    assert [(r.from_block, r.to_block) for r in second.coverage.wallet_txs_scanned] == [
        (1_001, 1_100)
    ]
    assert [e.rule_id for e in second.finding_events] == ["CG-POI-001"]


async def test_one_off_scan_uses_native_sends(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.add_token(TOKEN)
    node.head = 1_000
    node.send_native(WALLET, REAL, 10**16, block=900)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=920, signer=ATTACKER_SIGNER)
    report = await scan_poisoning(
        provider,
        WALLET,
        chain=MAINNET,
        limits=LIMITS,
        options=DEFAULT_DETECTION,
        lookback_blocks=500,
    )
    assert report.wallet_transactions_located == 1
    assert report.wallet_transactions_unlocated == 0
    [case] = report.cases
    assert (case.suspect, case.reference, case.rule_id) == (FAKE, REAL, "CG-POI-001")

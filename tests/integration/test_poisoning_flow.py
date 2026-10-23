"""Poisoning detection end to end: RPC discovery, signer lookups, snapshots, API."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.chains import get_chain
from cryptoguard.services.approvals import ScanLimits
from cryptoguard.services.poisoning import scan_poisoning
from cryptoguard.services.snapshots import DEFAULT_DETECTION, take_snapshot
from cryptoguard.services.transfers import discover_transfers
from tests.fakenode import FakeNode
from tests.integration.test_api import rpc_client_for
from tests.integration.test_snapshots import repository
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET

MAINNET = get_chain(1)
LIMITS = ScanLimits(1_000, 5_000, 1_000, 100, 50)


@pytest.fixture
def poisoned(node: FakeNode) -> FakeNode:
    node.add_token(TOKEN)
    head = node.head
    node.add_transfer_log(TOKEN, WALLET, REAL, 100, block=head - 50, signer=WALLET)
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=head - 40, signer=ATTACKER_SIGNER)
    node.add_transfer_log(TOKEN, FAKE, WALLET, 1, block=head - 39, signer=FAKE)
    return node


async def test_transfer_discovery_looks_up_outgoing_signers(
    poisoned: FakeNode, provider: RpcEthereumProvider
) -> None:
    found = await discover_transfers(
        provider,
        WALLET,
        from_block=poisoned.head - 100,
        to_block=poisoned.head,
        limits=LIMITS,
        token_scope=None,
        max_sender_lookups=10,
    )
    assert len(found.transfers) == 3
    assert found.complete
    signers = {(t.sender, t.recipient): t.tx_sender for t in found.transfers}
    assert signers[(WALLET, REAL)] == WALLET
    assert signers[(WALLET, FAKE)] == ATTACKER_SIGNER
    assert signers[(FAKE, WALLET)] is None  # incoming: not looked up
    assert poisoned.calls.count("eth_getTransactionByHash") == 2


async def test_sender_lookup_budget_is_respected(
    poisoned: FakeNode, provider: RpcEthereumProvider
) -> None:
    found = await discover_transfers(
        provider,
        WALLET,
        from_block=poisoned.head - 100,
        to_block=poisoned.head,
        limits=LIMITS,
        token_scope=None,
        max_sender_lookups=1,
    )
    assert (found.sender_lookups, found.sender_lookups_skipped) == (1, 1)


async def test_one_off_scan(poisoned: FakeNode, provider: RpcEthereumProvider) -> None:
    report = await scan_poisoning(
        provider,
        WALLET,
        chain=MAINNET,
        limits=LIMITS,
        options=DEFAULT_DETECTION,
        lookback_blocks=200,
    )
    assert report.wallet_is_plain_eoa
    assert report.transfers_analyzed == 3
    [case] = report.cases
    assert (case.suspect, case.rule_id) == (FAKE, "CG-POI-001")
    assert {"zero_value_transfer", "unsolicited_incoming_transfer"} <= {
        s.code for s in case.signals
    }


async def test_poisoning_between_snapshots_joins_the_timeline(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.add_token(TOKEN)
    node.add_transfer_log(TOKEN, WALLET, REAL, 100, block=node.head - 10, signer=WALLET)
    repo = repository()

    async def snap():  # type: ignore[no-untyped-def]
        return await take_snapshot(
            provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0
        )

    base = await snap()
    assert base.finding_events == []
    assert base.coverage.transfers_scanned[0].to_block == node.head

    node.head += 20
    node.add_transfer_log(TOKEN, WALLET, FAKE, 0, block=node.head - 5, signer=ATTACKER_SIGNER)
    second = await snap()
    [event] = second.finding_events
    assert (event.rule_id, event.to_status, event.severity) == (
        "CG-POI-001",
        "new",
        "elevated_risk",
    )

    # The poisoning transfer is in the stored history, so the finding persists even though
    # the next snapshot only scans newer blocks.
    node.head += 20
    third = await snap()
    assert [(e.rule_id, e.to_status) for e in third.finding_events] == [("CG-POI-001", "active")]
    [finding] = repo.list_findings(1, WALLET)
    assert FAKE in finding.subject
    assert any(e["transaction_hash"] for e in finding.evidence)


@pytest.fixture
def client(poisoned: FakeNode) -> Iterator[TestClient]:
    with rpc_client_for(poisoned) as test_client:
        yield test_client


def test_poisoning_api(client: TestClient) -> None:
    response = client.post(
        f"/api/v1/wallets/{WALLET}/poisoning/scan", json={"lookback_blocks": 200}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    [case] = body["cases"]
    assert case["suspect"] == FAKE
    assert case["reference"] == REAL
    assert case["severity"] == "elevated_risk"
    assert body["simulated"] is False
    bad = client.post(f"/api/v1/wallets/{WALLET}/poisoning/scan", json={"private_key": "x"})
    assert bad.status_code == 422

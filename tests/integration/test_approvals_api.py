from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from cryptoguard.blockchain.abi import UINT256_MAX
from cryptoguard.services.demo import DEMO_ACCOUNTS
from tests.fakenode import FakeNode
from tests.integration.test_api import (
    LOCAL,
    WALLET,
    make_settings,
    memory_repository,
    rpc_client_for,
)

TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
SPENDER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"


@pytest.fixture
def node() -> FakeNode:
    fake = FakeNode()
    token = fake.add_token(TOKEN)
    token.balances[WALLET] = 10**18
    token.allowances[(WALLET, SPENDER)] = UINT256_MAX
    fake.set_account(SPENDER, code=b"\x60\x80")
    fake.add_approval_log(TOKEN, WALLET, SPENDER, UINT256_MAX, block=fake.head - 10)
    return fake


@pytest.fixture
def client(node: FakeNode) -> Iterator[TestClient]:
    with rpc_client_for(node) as test_client:
        yield test_client


def test_scan_then_read_back(client: TestClient, node: FakeNode) -> None:
    assert client.get(f"/api/v1/wallets/{WALLET}/approvals").status_code == 404

    response = client.post(f"/api/v1/wallets/{WALLET.lower()}/approvals/scan", json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["persistence"] == {"report": "stored", "new_events": 1}
    report = body["report"]
    assert report["owner"] == WALLET
    assert report["data_source"] == "rpc"
    [item] = report["approvals"]
    assert item["allowance_level"] == "unlimited"
    assert item["current_allowance"]["raw"] == str(UINT256_MAX)  # exact, as a string
    assert item["exposure_upper_bound"]["raw"] == str(10**18)
    assert item["spender"]["label"] == "Uniswap V2: Router 02"

    again = client.post(f"/api/v1/wallets/{WALLET}/approvals/scan", json={}).json()
    assert again["persistence"] == {"report": "already_stored", "new_events": 0}

    stored = client.get(f"/api/v1/wallets/{WALLET}/approvals").json()
    assert stored["block_number"] == node.head
    assert stored["approvals"][0]["allowance_level"] == "unlimited"

    observations = client.get(f"/api/v1/wallets/{WALLET}/observations").json()
    assert observations["items"][0]["observation_type"] == "approval_scan"


def test_scan_window_parameters(client: TestClient, node: FakeNode) -> None:
    ok = client.post(f"/api/v1/wallets/{WALLET}/approvals/scan", json={"lookback_blocks": 5})
    assert ok.json()["report"]["approvals"] == []  # the approval is 10 blocks back
    assert ok.json()["report"]["coverage"]["scanned_from_block"] == node.head - 4

    too_big = client.post(
        f"/api/v1/wallets/{WALLET}/approvals/scan", json={"lookback_blocks": 10_000_000}
    )
    assert too_big.status_code == 422
    assert too_big.json()["error"]["code"] == "block_range_too_large"

    negative = client.post(f"/api/v1/wallets/{WALLET}/approvals/scan", json={"from_block": -1})
    assert negative.status_code == 422
    unknown = client.post(f"/api/v1/wallets/{WALLET}/approvals/scan", json={"to_block": 1})
    assert unknown.status_code == 422


def test_invalid_address(client: TestClient) -> None:
    response = client.post("/api/v1/wallets/0xnope/approvals/scan", json={})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_address"


def test_scan_requires_rpc_in_real_mode() -> None:
    app = create_app(make_settings(), repository=memory_repository())
    with TestClient(app, base_url=LOCAL) as c:
        response = c.post(f"/api/v1/wallets/{WALLET}/approvals/scan", json={})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rpc_not_configured"


def test_demo_scan() -> None:
    wallet = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
    app = create_app(make_settings(mode="demo"), repository=memory_repository())
    with TestClient(app, base_url=LOCAL) as c:
        report = c.post(f"/api/v1/wallets/{wallet}/approvals/scan", json={}).json()["report"]
    assert report["simulated"] is True
    assert report["data_source"] == "demo_fixture"
    assert len(report["approvals"]) == 3

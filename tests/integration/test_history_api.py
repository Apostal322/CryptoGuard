from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from cryptoguard.blockchain.abi import UINT256_MAX
from cryptoguard.services.demo import DEMO_ACCOUNTS
from tests.fakenode import FakeNode
from tests.integration.test_api import WALLET, make_settings, memory_repository, rpc_client_for

TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
SPENDER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"


@pytest.fixture
def node() -> FakeNode:
    fake = FakeNode()
    token = fake.add_token(TOKEN)
    token.balances[WALLET] = 10**18
    token.allowances[(WALLET, SPENDER)] = UINT256_MAX
    fake.set_account(SPENDER, code=b"\x60\x80")
    fake.add_approval_log(TOKEN, WALLET, SPENDER, UINT256_MAX, block=fake.head - 100)
    return fake


@pytest.fixture
def client(node: FakeNode) -> Iterator[TestClient]:
    with rpc_client_for(node, snapshot_confirmations=0) as test_client:
        yield test_client


def test_snapshot_timeline_findings_and_acknowledge(client: TestClient, node: FakeNode) -> None:
    base = client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={})
    assert base.status_code == 200, base.text
    body = base.json()
    assert body["is_baseline"] is True
    assert body["block_number"] == node.head
    [event] = body["finding_events"]
    finding_id = event["finding_id"]

    node.head += 10
    node.add_approval_log(TOKEN, WALLET, SPENDER, 0, block=node.head - 1)
    node.tokens[TOKEN.lower()].allowances[(WALLET, SPENDER)] = 0
    second = client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={}).json()
    [change] = second["changes"]
    assert change["kind"] == "allowance_revoked"
    assert change["cause"]["explorer_url"].startswith("https://etherscan.io/tx/0x")

    timeline = client.get(f"/api/v1/wallets/{WALLET}/timeline").json()
    assert timeline["total"] == 2
    newest = timeline["items"][0]
    assert newest["previous_block"] == node.head - 10
    assert newest["changes"][0]["kind"] == "allowance_revoked"
    assert newest["finding_events"][0]["to_status"] == "resolved"
    assert newest["explorer_block_url"] == f"https://etherscan.io/block/{node.head}"

    open_findings = client.get(f"/api/v1/wallets/{WALLET}/findings").json()
    assert open_findings["total"] == 0
    everything = client.get(f"/api/v1/wallets/{WALLET}/findings?status=all").json()
    assert [f["status"] for f in everything["items"]] == ["resolved"]

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    assert [t["to_status"] for t in detail["transitions"]] == ["new", "resolved"]
    conflict = client.post(f"/api/v1/findings/{finding_id}/acknowledge", json={})
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "invalid_transition"


def test_acknowledge_open_finding(client: TestClient) -> None:
    body = client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={}).json()
    finding_id = body["finding_events"][0]["finding_id"]
    ack = client.post(f"/api/v1/findings/{finding_id}/acknowledge", json={})
    assert ack.status_code == 200
    assert ack.json()["finding"]["status"] == "acknowledged"
    assert ack.json()["transitions"][-1]["reason"] == "Acknowledged by the user."


def test_finding_id_validation(client: TestClient) -> None:
    assert client.get("/api/v1/findings/not-an-id").status_code == 422
    missing = client.get("/api/v1/findings/0x" + "00" * 32)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "finding_not_found"


def test_snapshot_request_validation(client: TestClient, node: FakeNode) -> None:
    assert client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={"block": -1}).status_code == 422
    future = client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={"block": node.head + 5})
    assert future.status_code == 422
    assert future.json()["error"]["code"] == "invalid_scan_request"
    extra = client.post(f"/api/v1/wallets/{WALLET}/snapshots", json={"rpc_url": "x"})
    assert extra.status_code == 422


def test_rules_catalog(client: TestClient) -> None:
    rules = client.get("/api/v1/rules").json()
    assert rules["ruleset_id"] == "cg-rules"
    assert {r["rule_id"] for r in rules["rules"]} >= {"CG-APR-001", "CG-DEL-001"}
    assert "critical_evidence" in rules["severities"]


def test_demo_snapshot_is_labelled() -> None:
    wallet = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
    app = create_app(make_settings(mode="demo"), repository=memory_repository())
    with TestClient(app) as c:
        body = c.post(f"/api/v1/wallets/{wallet}/snapshots", json={}).json()
        assert body["simulated"] is True
        assert body["notes"][0].startswith("SIMULATED DATA")
        timeline = c.get(f"/api/v1/wallets/{wallet}/timeline").json()
        assert timeline["items"][0]["simulated"] is True
        assert timeline["items"][0]["explorer_block_url"] is None
        findings = c.get(f"/api/v1/wallets/{wallet}/findings").json()
        assert findings["total"] >= 1
        assert all(f["simulated"] for f in findings["items"])

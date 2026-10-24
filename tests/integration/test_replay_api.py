from __future__ import annotations

from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from tests.integration.test_api import make_settings, memory_repository

CASE = "wbtc-1155-poisoning-2024-05-03"


def client() -> TestClient:
    return TestClient(create_app(make_settings(), repository=memory_repository()))


def test_cases_and_offline_run() -> None:
    # Works without any RPC configured: replay uses only the packaged fixture.
    with client() as c:
        cases = c.get("/api/v1/replay/cases").json()["items"]
        case = next(item for item in cases if item["manifest"]["case_id"] == CASE)
        assert case["recorded"] is True
        assert case["manifest"]["public_sources"]

        result = c.post("/api/v1/replay/runs", json={"case_id": CASE})
        assert result.status_code == 200, result.text
        body = result.json()
    outcomes = {r["visibility"]: r for r in body["results"]}
    assert outcomes["erc20_only"]["outcome"] == "not_detected"
    early = outcomes["erc20_plus_wallet_transactions"]
    assert early["outcome"] == "early_warning"
    assert early["first_warning"]["block_number"] == 19_788_642
    assert early["lead_time_blocks"] == 367
    assert all(check["passed"] for check in body["leakage_checks"])
    assert body["rpc_requests_during_replay"] == 0
    assert body["fixture_sha256"] == case["fixture_sha256"]


def test_unknown_case_and_validation() -> None:
    with client() as c:
        missing = c.post("/api/v1/replay/runs", json={"case_id": "nope"})
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "unknown_replay_case"
        assert c.post("/api/v1/replay/runs", json={"case_id": "x" * 200}).status_code == 422
        assert c.post("/api/v1/replay/runs", json={"case_id": CASE, "x": 1}).status_code == 422

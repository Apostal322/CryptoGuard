from __future__ import annotations

import random
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from cryptoguard.blockchain.eip7702 import DELEGATION_PREFIX
from cryptoguard.blockchain.provider import EthereumProvider, build_rpc_provider
from cryptoguard.core.config import Settings
from cryptoguard.database.repository import ObservationRepository, create_db_engine, init_schema
from cryptoguard.services.demo import DEMO_ACCOUNTS
from tests.conftest import SleepRecorder
from tests.fakenode import FakeNode, rpc_error

WALLET = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
DELEGATE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
RPC_URL = "https://rpc.example.invalid/v2/SECRETKEY123"


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"database_url": "sqlite://", "rate_limit_per_minute": 1000}
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def memory_repository() -> ObservationRepository:
    engine = create_db_engine("sqlite://")
    init_schema(engine)
    return ObservationRepository(engine)


@pytest.fixture
def node() -> FakeNode:
    fake = FakeNode()
    fake.set_account(
        WALLET, balance=3 * 10**18, code=DELEGATION_PREFIX + bytes.fromhex(DELEGATE[2:])
    )
    fake.set_account(DELEGATE, code=bytes.fromhex("6080604052"))
    return fake


def rpc_client_for(node: FakeNode, **overrides: object) -> TestClient:
    settings = make_settings(rpc_url=RPC_URL, **overrides)

    def factory(s: Settings) -> EthereumProvider:
        return build_rpc_provider(
            s, transport=node.transport(), sleep=SleepRecorder(), rng=random.Random(0)
        )

    app = create_app(settings, provider_factory=factory, repository=memory_repository())
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(node: FakeNode) -> Iterator[TestClient]:
    with rpc_client_for(node) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_status_reports_verified_chain_and_redacted_provider(
    client: TestClient, node: FakeNode
) -> None:
    body = client.get("/api/v1/status").json()
    assert body["mode"] == "real"
    assert body["simulated"] is False
    assert body["chain_verified"] is True
    assert body["head_block"] == node.head
    assert body["provider"] == "https://rpc.example.invalid/…"
    assert body["rpc_metrics"]["requests"] >= 2
    assert "SECRETKEY123" not in client.get("/api/v1/status").text


def test_status_reports_chain_mismatch(node: FakeNode) -> None:
    node.chain_id = 11155111
    with rpc_client_for(node) as c:
        body = c.get("/api/v1/status").json()
    assert body["chain_verified"] is False
    assert body["provider_error"]["code"] == "chain_mismatch"
    assert body["head_block"] is None


def test_analyze_address_end_to_end_and_persistence(client: TestClient, node: FakeNode) -> None:
    response = client.post("/api/v1/analyze/address", json={"address": WALLET.lower()})
    assert response.status_code == 200, response.text
    body = response.json()
    inspection = body["inspection"]
    assert body["persistence"] == "stored"
    assert inspection["address"] == WALLET
    assert inspection["data_source"] == "rpc"
    assert inspection["chain_id"] == 1
    assert inspection["block"]["number"] == node.head
    assert inspection["native_balance"]["wei"] == str(3 * 10**18)
    assert inspection["native_balance"]["formatted"] == "3"
    assert inspection["account_code"]["kind"] == "eip7702_delegation"
    assert inspection["account_code"]["delegation"]["target"] == DELEGATE

    again = client.post("/api/v1/analyze/address", json={"address": WALLET})
    assert again.json()["persistence"] == "already_stored"  # idempotent per block

    page = client.get(f"/api/v1/wallets/{WALLET}/observations?limit=5").json()
    assert page["total"] == 1
    assert page["items"][0]["block_number"] == node.head
    assert page["items"][0]["payload"]["address"] == WALLET


def test_new_block_creates_new_observation(client: TestClient, node: FakeNode) -> None:
    client.post("/api/v1/analyze/address", json={"address": WALLET})
    node.head += 1
    client.post("/api/v1/analyze/address", json={"address": WALLET})
    page = client.get(f"/api/v1/wallets/{WALLET}/observations").json()
    assert page["total"] == 2
    assert [item["block_number"] for item in page["items"]] == [node.head, node.head - 1]


@pytest.mark.parametrize(
    "payload",
    [
        {"address": "0x123"},
        {"address": "not an address"},
        {"address": "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},  # bad checksum
        {"address": "<script>alert(1)</script>"},
    ],
)
def test_invalid_addresses_return_422_without_echo(
    client: TestClient, payload: dict[str, str]
) -> None:
    response = client.post("/api/v1/analyze/address", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_address"
    assert "<script>" not in response.text


def test_schema_violations_do_not_echo_input(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze/address", json={"address": "0x" + "a" * 70, "extra": "<b>x</b>"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert "<b>x</b>" not in response.text


def test_other_chain_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/analyze/address", json={"address": WALLET, "chain_id": 56})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "unsupported_chain"


def test_rpc_url_cannot_be_supplied_by_client(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze/address", json={"address": WALLET, "rpc_url": "http://169.254.169.254"}
    )
    assert response.status_code == 422


def test_oversized_body_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/analyze/address",
        content=b'{"address":"' + b"a" * 20_000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_rpc_failure_maps_to_safe_error(node: FakeNode, client: TestClient) -> None:
    node.script(
        "eth_getBalance", rpc_error(-32000, "missing trie node deadbeef at /v2/SECRETKEY123")
    )
    response = client.post("/api/v1/analyze/address", json={"address": WALLET})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "historical_state_unavailable"
    assert "SECRETKEY123" not in response.text
    assert "Traceback" not in response.text


def test_rate_limiting(node: FakeNode) -> None:
    with rpc_client_for(node, rate_limit_per_minute=2) as c:
        assert c.get("/api/v1/status").status_code == 200
        assert c.get("/api/v1/status").status_code == 200
        limited = c.get("/api/v1/status")
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
        assert c.get("/api/v1/health").status_code == 200  # liveness is not limited


def test_cors_is_restricted(client: TestClient) -> None:
    allowed = client.options(
        "/api/v1/status",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    denied = client.get("/api/v1/status", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in denied.headers


def test_real_mode_without_rpc_never_falls_back_to_demo() -> None:
    app = create_app(make_settings(), repository=memory_repository())
    with TestClient(app) as c:
        status = c.get("/api/v1/status").json()
        assert status["rpc_configured"] is False
        assert status["simulated"] is False
        response = c.post("/api/v1/analyze/address", json={"address": WALLET})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "rpc_not_configured"
        assert "CRYPTOGUARD_MODE=demo" in response.json()["error"]["message"]
        assert c.get("/api/v1/demo/addresses").status_code == 404


def test_demo_mode_is_explicit_and_labelled() -> None:
    app = create_app(make_settings(mode="demo"), repository=memory_repository())
    with TestClient(app) as c:
        listing = c.get("/api/v1/demo/addresses").json()
        assert listing["simulated"] is True
        assert len(listing["addresses"]) == len(DEMO_ACCOUNTS)
        body = c.post(
            "/api/v1/analyze/address", json={"address": listing["addresses"][1]["address"]}
        ).json()
        assert body["inspection"]["simulated"] is True
        assert body["inspection"]["data_source"] == "demo_fixture"
        assert body["inspection"]["explorer"] is None
        outside = c.post("/api/v1/analyze/address", json={"address": WALLET})
        assert outside.status_code == 404
        assert outside.json()["error"]["code"] == "not_in_demo_fixtures"


def test_unexpected_errors_are_generic(node: FakeNode) -> None:
    class Boom(ObservationRepository):
        def ping(self) -> bool:
            raise RuntimeError("secret internal detail")

    engine = create_db_engine("sqlite://")
    init_schema(engine)
    app = create_app(make_settings(), repository=Boom(engine))
    with TestClient(app, raise_server_exceptions=False) as c:
        response = c.get("/api/v1/health")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_error",
        "message": "An internal error occurred.",
        "details": {},
    }
    assert "secret internal detail" not in response.text

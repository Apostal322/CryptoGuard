"""API boundary: DNS rebinding, CSRF-shaped requests and malformed input never reach work."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cryptoguard.core.config import Settings
from tests.integration.test_api import rpc_client_for
from tests.integration.test_campaign_api import SHADOW, W1, make_node, snapshots

RUNS = "/api/v1/campaigns/runs"


@pytest.fixture
def client() -> TestClient:
    with rpc_client_for(make_node(), **SHADOW) as c:
        snapshots(c)
        yield c  # type: ignore[misc]


def test_rebound_hostname_is_refused(client: TestClient) -> None:
    for host in ("evil.example", "127.0.0.1.evil.example", "localhost.evil"):
        r = client.get("/api/v1/status", headers={"Host": host})
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "invalid_host"
    assert client.get("/api/v1/status", headers={"Host": "localhost:8000"}).status_code == 200
    assert client.get("/api/v1/status", headers={"Host": "[::1]:8000"}).status_code == 200


@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", None],
)
def test_cross_site_simple_posts_cannot_trigger_work(
    client: TestClient, content_type: str | None
) -> None:
    headers = {"Content-Type": content_type} if content_type else {}
    r = client.post(RUNS, content=b"a=1", headers=headers)
    assert r.status_code == 415
    assert r.json()["error"]["code"] == "unsupported_media_type"
    assert client.get("/api/v1/campaigns").json()["error"]["code"] == "no_campaign_run"


def test_foreign_origin_is_refused_and_own_origins_are_allowed(client: TestClient) -> None:
    r = client.post(RUNS, json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "origin_not_allowed"
    assert (
        client.post(RUNS, json={}, headers={"Origin": "http://127.0.0.1:3000"}).status_code == 200
    )
    # The UI served by the same host as the API (same origin) is allowed too.
    same = client.post(RUNS, json={}, headers={"Origin": "http://127.0.0.1", "Host": "127.0.0.1"})
    assert same.status_code == 200
    # Acknowledging a finding (a state change with no body) is protected the same way.
    finding = client.get(f"/api/v1/wallets/{W1}/findings").json()["items"][0]["finding_id"]
    ack = client.post(
        f"/api/v1/findings/{finding}/acknowledge",
        content=b"",
        headers={"Content-Type": "text/plain"},
    )
    assert ack.status_code == 415


def test_settings_reject_wildcard_hosts() -> None:
    with pytest.raises(ValueError, match="explicit hostnames"):
        Settings(_env_file=None, allowed_hosts=["*"])  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/api/v1/wallets/0x123/findings", None),
        ("get", "/api/v1/wallets/" + "a" * 10_000 + "/findings", None),
        ("get", "/api/v1/campaigns?limit=0", None),
        ("get", "/api/v1/campaigns?limit=1000000000", None),
        ("get", "/api/v1/campaigns?offset=-1", None),
        ("get", f"/api/v1/wallets/{W1}/findings?status=bogus", None),
        ("get", "/api/v1/campaigns/cmp-%E2%98%83", None),
        ("get", "/api/v1/campaigns/" + "c" * 5000, None),
        ("get", "/api/v1/campaigns/cmp-" + "0" * 24 + "/graph?max_attempts=1000000", None),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b"{bad"),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b'{"rpc_url": "http://169.254.169.254"}'),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b'{"block": -5}'),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b'{"block": 1000000000000000000000000000000}'),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b'{"tokens": ["\\ud800"]}'),
        ("post", f"/api/v1/wallets/{W1}/snapshots", b'{"tokens": ["' + b"x" * 15_000 + b'"]}'),
        ("post", "/api/v1/replay/runs", b'{"case_id": "' + b"x" * 5000 + b'"}'),
        ("post", "/api/v1/analyze/address", b'{"address": "0x' + b"0" * 40 + b'", "chain_id": 56}'),
    ],
)
def test_malformed_requests_are_rejected_predictably(
    client: TestClient, method: str, path: str, body: bytes | None
) -> None:
    if method == "get":
        r = client.get(path)
    else:
        r = client.post(path, content=body, headers={"Content-Type": "application/json"})
    assert 400 <= r.status_code < 500, r.text
    payload = r.json()
    assert set(payload) == {"error"}
    assert payload["error"]["code"]
    assert "Traceback" not in r.text
    assert "SECRETKEY" not in r.text

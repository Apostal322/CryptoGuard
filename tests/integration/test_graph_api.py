from __future__ import annotations

from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from cryptoguard.services.demo import DEMO_ACCOUNTS
from tests.integration.test_api import WALLET, make_settings, memory_repository

PLAIN = next(a.address for a in DEMO_ACCOUNTS if a.label == "plain-wallet")
LOOKALIKE = next(a.address for a in DEMO_ACCOUNTS if a.label == "demo-lookalike")
FRIEND = next(a.address for a in DEMO_ACCOUNTS if a.label == "demo-friend")


def test_graph_requires_a_snapshot_and_reflects_stored_data() -> None:
    app = create_app(
        make_settings(mode="demo", snapshot_confirmations=0), repository=memory_repository()
    )
    with TestClient(app) as c:
        missing = c.get(f"/api/v1/wallets/{PLAIN}/graph")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "no_snapshot"

        assert c.post(f"/api/v1/wallets/{PLAIN}/snapshots", json={}).status_code == 200
        graph = c.get(f"/api/v1/wallets/{PLAIN}/graph").json()

    assert graph["simulated"] is True
    assert graph["snapshot_block"] == 1_000_000
    types = {e["type"] for e in graph["edges"]}
    assert {
        "APPROVED_SPENDER",
        "HOLDS_TOKEN",
        "TRANSFERRED_TO",
        "RECEIVED_FROM",
        "RESEMBLES",
    } <= types
    resembles = next(e for e in graph["edges"] if e["type"] == "RESEMBLES")
    assert (resembles["source"], resembles["target"]) == (LOOKALIKE, FRIEND)
    lookalike = next(n for n in graph["nodes"] if n["id"] == LOOKALIKE)
    assert [f["rule_id"] for f in lookalike["findings"]] == ["CG-POI-001"]
    assert all(e["evidence"] for e in graph["edges"])


def test_graph_parameter_validation() -> None:
    app = create_app(make_settings(mode="demo"), repository=memory_repository())
    with TestClient(app) as c:
        assert c.get(f"/api/v1/wallets/{WALLET}/graph?max_nodes=5").status_code == 422
        assert c.get(f"/api/v1/wallets/{WALLET}/graph?max_nodes=1000").status_code == 422
        assert c.get("/api/v1/wallets/0x12/graph").status_code == 422

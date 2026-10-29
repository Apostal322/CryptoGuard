"""Experimental ML endpoints: off by default, explicit about missing models, never findings."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cryptoguard.api.app import create_app
from cryptoguard.blockchain.provider import EthereumProvider, build_rpc_provider
from cryptoguard.core.config import Settings
from tests.conftest import SleepRecorder
from tests.fakenode import FakeNode
from tests.integration.test_api import (
    LOCAL,
    RPC_URL,
    make_settings,
    memory_repository,
    rpc_client_for,
)
from tests.integration.test_api import WALLET as API_WALLET
from tests.integration.test_api import node as api_node  # noqa: F401

TX = "0x" + "ab" * 32


def test_endpoints_are_off_by_default(api_node: FakeNode) -> None:  # noqa: F811
    with rpc_client_for(api_node) as client:
        scored = client.post("/api/v1/ml/transactions/score", json={"tx_hash": TX})
        status = client.get("/api/v1/ml/status")
    assert scored.status_code == 409
    assert scored.json()["error"]["code"] == "feature_disabled"
    assert status.status_code == 409


def test_shadow_without_a_promoted_model_says_so(api_node: FakeNode, tmp_path: Path) -> None:  # noqa: F811
    pytest.importorskip("sklearn")
    with rpc_client_for(
        api_node, ml_shadow="shadow", ml_registry_path=str(tmp_path / "none.json")
    ) as client:
        response = client.post("/api/v1/ml/transactions/score", json={"tx_hash": TX})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ml_unavailable"


def test_request_accepts_only_a_transaction_hash(api_node: FakeNode) -> None:  # noqa: F811
    with rpc_client_for(api_node, ml_shadow="shadow") as client:
        extra = client.post(
            "/api/v1/ml/transactions/score", json={"tx_hash": TX, "rpc_url": "https://evil.example"}
        )
        malformed = client.post("/api/v1/ml/transactions/score", json={"tx_hash": "0x1234"})
    assert extra.status_code == 422
    assert malformed.status_code == 422


def test_ml_shadow_mode_does_not_change_snapshot_findings(api_node: FakeNode) -> None:  # noqa: F811
    def events(**flags: object) -> list[tuple[str, str]]:
        with rpc_client_for(api_node, **flags) as client:
            response = client.post(f"/api/v1/wallets/{API_WALLET}/snapshots", json={})
            assert response.status_code == 200, response.text
            return sorted((e["rule_id"], e["to_status"]) for e in response.json()["finding_events"])

    off, shadow = events(), events(ml_shadow="shadow")
    assert off
    assert off == shadow


@pytest.fixture
def promoted(tmp_path: Path) -> tuple[Path, dict]:  # type: ignore[type-arg]
    pd = pytest.importorskip("pandas")
    pytest.importorskip("lightgbm")
    from cryptoguard.ml.dataset import build_table
    from cryptoguard.ml.registry import promote
    from cryptoguard.ml.splits import make_splits
    from cryptoguard.ml.train import promotion_gate, run_training, save_run
    from tests.ml_synthetic import make_records
    from tests.unit.test_ml_pipeline import SMALL_GRID

    labels, records = make_records()
    table = build_table(pd.DataFrame(labels), records)[0]
    split, _ = make_splits(table, records)
    out = run_training(table, split, SMALL_GRID)
    gate = {**promotion_gate(out["results"], out["selected"]), "validated_for_shadow": True}
    entry = {
        "run_id": "test-run",
        "config": {},
        "gate": gate,
        "selected": {"name": out["selected"].name, "threshold": out["selected"].threshold},
    }
    registry = tmp_path / "registry.json"
    promote(save_run(tmp_path / "run", entry, out), registry)
    return registry, records


def _client(records: dict, registry: Path, log: Path) -> TestClient:  # type: ignore[type-arg]
    from tests.ml_synthetic import FakeRpc

    fake = FakeRpc(records)
    settings: Settings = make_settings(
        rpc_url=RPC_URL,
        ml_shadow="shadow",
        ml_registry_path=str(registry),
        ml_score_log_path=str(log),
    )

    def factory(s: Settings) -> EthereumProvider:
        return build_rpc_provider(
            s, transport=fake.transport(), sleep=SleepRecorder(), rng=random.Random(0)
        )

    app = create_app(settings, provider_factory=factory, repository=memory_repository())
    return TestClient(app, base_url=LOCAL, raise_server_exceptions=False)


def test_scores_a_transaction_in_shadow_mode(promoted: tuple[Path, dict], tmp_path: Path) -> None:  # type: ignore[type-arg]
    registry, records = promoted
    tx_hash = next(iter(records))
    log = tmp_path / "scores.jsonl"
    with _client(records, registry, log) as client:
        response = client.post("/api/v1/ml/transactions/score", json={"tx_hash": tx_hash})
        missing = client.post("/api/v1/ml/transactions/score", json={"tx_hash": TX})
        status = client.get("/api/v1/ml/status")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["experimental"] is True
    assert body["status"] == "scored"
    assert 0.0 <= body["score"] <= 1.0
    assert body["run_id"] == "test-run"
    assert any("not a finding" in note for note in body["notes"])
    logged = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(logged) == 1
    assert logged[0]["tx_hash"] == tx_hash
    assert missing.json()["status"] == "not_found"
    assert status.status_code == 200
    assert status.json()["drift"]["status"] == "insufficient_data"

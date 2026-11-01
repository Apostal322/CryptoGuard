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


RUN = "20261101T120000Z-cccccccc"


def _trained_run(tmp_path: Path, *, holdout_passed: bool) -> tuple[Path, dict]:  # type: ignore[type-arg]
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
        "run_id": RUN,
        "config": {},
        "gate": gate,
        "selected": {"name": out["selected"].name, "threshold": out["selected"].threshold},
    }
    run_dir = save_run(tmp_path / "runs" / RUN, entry, out)
    approval = "research_only"
    if holdout_passed:  # synthetic stand-in for a real untouched-holdout evaluation record
        card_path = run_dir / "model_card.json"
        card = json.loads(card_path.read_text())
        card["holdout"] = {
            "untouched": True,
            "evaluated_once": True,
            "passed": True,
            "note": "synthetic test fixture, not evidence",
        }
        card_path.write_text(json.dumps(card))
        approval = "shadow_approved"
    registry = tmp_path / "registry.json"
    promote(run_dir, registry, approval=approval)  # type: ignore[arg-type]
    return registry, records


@pytest.fixture
def promoted(tmp_path: Path) -> tuple[Path, dict]:  # type: ignore[type-arg]
    return _trained_run(tmp_path, holdout_passed=True)


def _client(  # type: ignore[no-untyped-def]
    records: dict,  # type: ignore[type-arg]
    registry: Path,
    log: Path,
    **rpc: object,
) -> TestClient:
    from tests.ml_synthetic import FakeRpc

    fake = FakeRpc(records, **rpc)  # type: ignore[arg-type]
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
    assert body["run_id"] == RUN
    assert body["approval"] == "shadow_approved"
    assert body["observation"] == "post_inclusion"
    assert body["score_semantics"] == "uncalibrated_ranking"
    assert any("not a finding" in note for note in body["notes"])
    logged = [json.loads(line) for line in log.read_text().splitlines()]
    scored = [entry for entry in logged if entry["status"] == "scored"]
    assert len(scored) == 1
    assert scored[0]["tx_hash"] == tx_hash
    assert "latency_ms" in scored[0]
    assert missing.json()["status"] == "not_found"
    assert status.status_code == 200
    assert status.json()["approval"] == "shadow_approved"
    assert status.json()["drift"]["status"] == "insufficient_data"


def test_mixed_case_hash_is_accepted_and_normalised(promoted, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    registry, records = promoted
    tx_hash = next(iter(records))
    with _client(records, registry, tmp_path / "s.jsonl") as client:
        response = client.post(
            "/api/v1/ml/transactions/score", json={"tx_hash": tx_hash.upper().replace("0X", "0x")}
        )
    assert response.status_code == 200, response.text
    assert response.json()["tx_hash"] == tx_hash


def test_research_only_model_is_refused_by_the_api(tmp_path: Path) -> None:
    registry, records = _trained_run(tmp_path, holdout_passed=False)
    with _client(records, registry, tmp_path / "s.jsonl") as client:
        response = client.post(
            "/api/v1/ml/transactions/score", json={"tx_hash": next(iter(records))}
        )
        status = client.get("/api/v1/ml/status")
    assert response.status_code == 503
    assert "research only" in response.json()["error"]["message"]
    assert status.status_code == 200  # the status of a research-only model is still readable
    assert status.json()["approval"] == "research_only"


def test_a_provider_on_another_chain_is_refused(promoted, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    registry, records = promoted
    with _client(records, registry, tmp_path / "s.jsonl", chain_id=11155111) as client:
        response = client.post(
            "/api/v1/ml/transactions/score", json={"tx_hash": next(iter(records))}
        )
    assert response.status_code >= 400
    assert response.json()["error"]["code"] in ("chain_mismatch", "ml_unavailable")
    assert not (tmp_path / "s.jsonl").exists()  # nothing scored, nothing logged


def test_missing_receipt_is_incomplete_not_a_score(promoted, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    registry, records = promoted
    tx_hash = next(iter(records))
    with _client(records, registry, tmp_path / "s.jsonl", no_receipt={tx_hash}) as client:
        response = client.post("/api/v1/ml/transactions/score", json={"tx_hash": tx_hash})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "incomplete"
    assert response.json()["score"] is None


def test_rpc_failure_is_an_error_not_a_low_score(promoted, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    registry, records = promoted
    with _client(records, registry, tmp_path / "s.jsonl", fail={"eth_getCode"}) as client:
        response = client.post(
            "/api/v1/ml/transactions/score", json={"tx_hash": next(iter(records))}
        )
    assert response.status_code >= 500
    assert "score" not in response.json()


def test_scoring_writes_nothing_to_the_database(promoted, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sqlalchemy import inspect, text

    registry, records = promoted
    with _client(records, registry, tmp_path / "s.jsonl") as client:
        engine = client.app.state.cryptoguard.repository._engine  # type: ignore[attr-defined]

        def counts() -> dict[str, int]:
            with engine.connect() as conn:
                return {
                    t: conn.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar_one()  # noqa: S608
                    for t in inspect(engine).get_table_names()
                }

        before = counts()
        for tx_hash in list(records)[:3]:
            assert (
                client.post("/api/v1/ml/transactions/score", json={"tx_hash": tx_hash}).status_code
                == 200
            )
        assert counts() == before

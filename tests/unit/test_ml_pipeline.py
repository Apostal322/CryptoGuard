"""ML pipeline: source integrity, label parsing, sampling, leakage-safe splits, collector
budget, training smoke run, registry and monitoring. Synthetic data only."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("pandas")
pytest.importorskip("sklearn")
pytest.importorskip("lightgbm")
pytest.importorskip("pandera")
pytest.importorskip("openpyxl")

import pandas as pd

from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.ml import collect as collect_mod
from cryptoguard.ml.dataset import build_table, hubs
from cryptoguard.ml.features import parties
from cryptoguard.ml.labels import _PTX_HEADER_ROW, load_ptxphish
from cryptoguard.ml.monitoring import drift_report, log_score, psi, reference_bins
from cryptoguard.ml.registry import ModelRegistryError, load_shadow_model, promote
from cryptoguard.ml.sources import SOURCES, SourceIntegrityError, sha256_file, verify
from cryptoguard.ml.splits import make_splits
from cryptoguard.ml.train import promotion_gate, run_training, save_run
from tests.ml_synthetic import TOKEN, FakeRpc, make_records

# --- sources and labels ---------------------------------------------------------------------


def _write_ptx_sheet(path: Path, columns: dict[str, list[str]]) -> None:
    """A workbook shaped like PTXPhish: subtype headers on row 3, hashes below."""
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    for col, (header, values) in enumerate(columns.items(), start=1):
        ws.cell(row=_PTX_HEADER_ROW + 1, column=col, value=header)
        for i, value in enumerate(values):
            ws.cell(row=_PTX_HEADER_ROW + 2 + i, column=col, value=value)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)


ALL_SUBTYPES = [
    "Approve",
    "Permit",
    "SetApproveForAll",
    "Bulk transfer",
    "Proxy upgrade",
    "Free buy order",
    "Zero value transfer",
    "Fake token transfer",
    "Dust value transfer",
    "Airdrop function",
    "Wallet function",
    "Benign KOL",
    "Benign Developer",
]


def _fake_ptx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, columns: dict[str, list[str]]
) -> Path:
    path = tmp_path / "ptxphish" / "dataset" / "PTXPHISH.xlsx"
    _write_ptx_sheet(path, columns)
    files = tuple(
        type(f)(f.path, sha256_file(path) if f.path.endswith("PTXPHISH.xlsx") else f.sha256, 0)
        for f in SOURCES["ptxphish"].files[:1]
    )
    from dataclasses import replace

    monkeypatch.setitem(SOURCES, "ptxphish", replace(SOURCES["ptxphish"], files=files))
    return tmp_path


def test_ptxphish_sheet_becomes_one_validated_row_per_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    columns = {name: [] for name in ALL_SUBTYPES}
    columns["Approve"] = ["0x" + "AB" * 32]  # mixed case is normalised
    columns["Benign KOL"] = ["0x" + "cd" * 32, "0x" + "ef" * 32]
    columns["Source"] = ["https://example.invalid/report"]  # ignored column
    labels = load_ptxphish(_fake_ptx(tmp_path, monkeypatch, columns))
    assert list(labels.columns) == ["tx_hash", "family", "subtype", "label"]
    assert labels.set_index("tx_hash").loc["0x" + "ab" * 32, "family"] == "ice_phishing"
    assert labels["label"].tolist().count(0) == 2


def test_malformed_hash_or_layout_change_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = {name: [] for name in ALL_SUBTYPES}
    bad["Permit"] = ["not-a-hash"]
    with pytest.raises(ValueError, match="not a tx hash"):
        load_ptxphish(_fake_ptx(tmp_path / "a", monkeypatch, bad))
    renamed = {name: [] for name in ALL_SUBTYPES if name != "Permit"} | {"Permit v2": []}
    with pytest.raises(ValueError, match="unexpected PTXPhish layout"):
        load_ptxphish(_fake_ptx(tmp_path / "b", monkeypatch, renamed))


def test_a_tampered_source_file_is_refused(tmp_path: Path) -> None:
    source = SOURCES["forta"]
    for f in source.files:
        p = tmp_path / source.name / f.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("tampered")
    with pytest.raises(SourceIntegrityError):
        verify(tmp_path, source)


# --- sampling ------------------------------------------------------------------------------


def test_sample_is_deterministic_and_keeps_every_poisoning_row() -> None:
    rows = [
        ("0x" + f"{i:064x}", fam, sub, int(fam != "benign"))
        for i, (fam, sub) in enumerate(
            [("address_poisoning", "zero_value_transfer")] * 10
            + [("ice_phishing", "approve")] * 300
            + [("benign", "benign_kol")] * 400
        )
    ]
    labels = pd.DataFrame(rows, columns=["tx_hash", "family", "subtype", "label"])
    plan = collect_mod.SamplePlan(phishing=60, benign=50)
    a, b = collect_mod.draw_sample(labels, plan), collect_mod.draw_sample(labels, plan)
    assert a.equals(b)
    assert (a["family"] == "address_poisoning").sum() == 10
    assert (a["label"] == 0).sum() == 50
    assert len(a) == 110


# --- splits --------------------------------------------------------------------------------


def _table() -> tuple[pd.DataFrame, dict]:  # type: ignore[type-arg]
    labels, records = make_records()
    return build_table(pd.DataFrame(labels), records)[0], records


def test_splits_are_time_ordered_and_share_no_account() -> None:
    table, records = _table()
    split, summary = make_splits(table, records)
    blocks = {s: table.loc[split == s, "block_number"] for s in ("train", "validation", "test")}
    assert blocks["train"].max() < blocks["validation"].min()
    assert blocks["validation"].max() < blocks["test"].min()
    train_hubs = hubs({h: records[h] for h in table.loc[split == "train", "tx_hash"]})

    def accounts(name: str) -> set[str]:
        out: set[str] = set()
        for h in table.loc[split == name, "tx_hash"]:
            out |= parties(records[h]) - train_hubs
        return out

    assert not accounts("train") & accounts("validation")
    assert not (accounts("train") | accounts("validation")) & accounts("test")
    assert summary["counts"]["test"]  # something survives the purge


def test_reused_attacker_contract_cannot_reach_the_test_split() -> None:
    """Leakage regression: the synthetic drainer contract is used before and after the
    test boundary; every later use must be purged."""
    from collections import Counter

    table, records = _table()
    split, _ = make_splits(table, records)
    targets = Counter(r["tx"]["to"] for r in records.values() if r["tx"]["to"] != TOKEN)
    drainer, uses = targets.most_common(1)[0]
    assert uses >= 10  # called by many different senders, like a popular contract
    rows = table.index[[records[h]["tx"]["to"] == drainer for h in table["tx_hash"]]]
    assert (split[rows] == "train").any()
    assert not split[rows].isin(["validation", "test"]).any()


# --- collector -----------------------------------------------------------------------------


def _client(fake: FakeRpc) -> JsonRpcClient:
    async def no_sleep(_: float) -> None:
        return None

    return JsonRpcClient(
        "https://rpc.invalid",
        transport=fake.transport(),
        retry=RetryPolicy(max_retries=1),
        sleep=no_sleep,
        max_concurrency=1,
    )


def test_collector_respects_the_request_cap_and_resumes(tmp_path: Path) -> None:
    labels, records = make_records(n=40)
    sample = pd.DataFrame(labels)
    out = tmp_path / "chain.jsonl"
    fake = FakeRpc(records)
    stats = asyncio.run(
        collect_mod.collect(
            sample, out, rpc_url="unused", max_requests=60, concurrency=1, client=_client(fake)
        )
    )
    assert len(fake.calls) <= 60
    assert collect_mod.requests_used(out) == len(fake.calls)  # recorded as it went
    assert stats["skipped_budget"] > 0
    first = len(collect_mod.load_collected(out))
    fake2 = FakeRpc(records)
    asyncio.run(
        collect_mod.collect(
            sample, out, rpc_url="unused", max_requests=10_000, concurrency=1, client=_client(fake2)
        )
    )
    assert len(collect_mod.load_collected(out)) == 40
    assert len(fake2.calls) == (40 - first) * collect_mod.REQUESTS_PER_TX  # no refetching


def test_collector_records_failures_and_retries_them_later(tmp_path: Path) -> None:
    labels, records = make_records(n=3)
    out = tmp_path / "chain.jsonl"
    asyncio.run(
        collect_mod.collect(
            pd.DataFrame(labels),
            out,
            rpc_url="unused",
            max_requests=1_000,
            concurrency=1,
            client=_client(FakeRpc(records, fail={"eth_getCode"})),
        )
    )
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert {r["status"] for r in rows} == {"error"}
    assert collect_mod.load_collected(out) == {}


# --- training, gate, registry, monitoring --------------------------------------------------


# One candidate per family keeps the smoke run fast; the code path is the full one.
SMALL_GRID = [
    ("logistic_regression", {"C": 1.0}),
    ("random_forest", {"min_samples_leaf": 3}),
    ("lightgbm", {"num_leaves": 7, "min_child_samples": 5}),
]


@pytest.fixture(scope="module")
def trained() -> dict:  # type: ignore[type-arg]
    labels, records = make_records()
    table = build_table(pd.DataFrame(labels), records)[0]
    split, _ = make_splits(table, records)
    out = run_training(table, split, SMALL_GRID)
    return {"out": out, "table": table, "split": split}


def test_smoke_training_scores_every_model_on_the_same_test_rows(trained: dict) -> None:  # type: ignore[type-arg]
    out = trained["out"]
    names = {r.name for r in out["results"]}
    assert {
        "majority",
        "stratified",
        "rule_phishing_shape",
        "rule_cryptoguard_signals",
        "logistic_regression",
        "random_forest",
        "lightgbm",
    } <= names
    rows = {r.test["rows"] for r in out["results"]}
    assert len(rows) == 1  # identical test rows for baselines and models
    majority = next(r for r in out["results"] if r.name == "majority")
    assert majority.test["roc_auc"] == 0.5
    assert out["selected"].kind == "learned"
    assert out["selected"].test["average_precision"] > majority.test["average_precision"]


def test_training_is_deterministic(trained: dict) -> None:  # type: ignore[type-arg]
    again = run_training(trained["table"], trained["split"], SMALL_GRID)
    first = [
        (r.name, r.feature_set, r.test["average_precision"]) for r in trained["out"]["results"]
    ]
    second = [(r.name, r.feature_set, r.test["average_precision"]) for r in again["results"]]
    assert first == second


def test_registry_refuses_ungated_and_tampered_models(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    out = trained["out"]
    gate = promotion_gate(out["results"], out["selected"])
    entry = {
        "run_id": "r1",
        "config": {},
        "gate": {**gate, "validated_for_shadow": False},
        "selected": {"threshold": out["selected"].threshold},
    }
    run_dir = save_run(tmp_path / "r1", entry, out)
    with pytest.raises(ModelRegistryError, match="did not pass"):
        promote(run_dir, tmp_path / "registry.json")
    entry["gate"]["validated_for_shadow"] = True
    run_dir = save_run(tmp_path / "r2", {**entry, "run_id": "r2"}, out)
    registry = tmp_path / "registry.json"
    promote(run_dir, registry)
    assert load_shadow_model(registry).run_id == "r2"
    (run_dir / "model.joblib").write_bytes(b"not the trained model")
    with pytest.raises(ModelRegistryError, match="hash mismatch"):
        load_shadow_model(registry)


def test_fast_average_precision_matches_sklearn_including_ties() -> None:
    import numpy as np
    from sklearn.metrics import average_precision_score

    from cryptoguard.ml.train import fast_average_precision

    rng = np.random.default_rng(0)
    for _ in range(50):
        y = rng.integers(0, 2, 60)
        y[0], y[1] = 0, 1
        score = rng.integers(0, 6, 60) / 5  # many ties
        assert fast_average_precision(y, score) == pytest.approx(
            average_precision_score(y, score), abs=1e-12
        )


def test_psi_is_small_for_training_like_data_and_large_for_shifted_data() -> None:
    train = [float(i % 10) for i in range(1_000)]
    ref = reference_bins(train)
    assert psi(ref, train) < 0.01
    assert psi(ref, [9.0] * 200) > 1.0
    binary = reference_bins([0.0] * 900 + [1.0] * 100)  # tied deciles
    assert psi(binary, [0.0] * 90 + [1.0] * 10) < 0.01
    assert psi(binary, [1.0] * 100) > 1.0


def test_drift_report_needs_enough_rows(tmp_path: Path) -> None:
    card = {
        "run_id": "r",
        "feature_columns": ["x"],
        "reference_bins": {"x": reference_bins([0.0, 1.0] * 50)},
    }
    log = tmp_path / "scores.jsonl"
    assert drift_report(card, log)["status"] == "insufficient_data"
    for i in range(40):
        log_score({"run_id": "r", "features": {"x": 5.0 + i}}, log)
    report = drift_report(card, log)
    assert report["status"] == "ok"
    assert report["shifted"] == ["x"]

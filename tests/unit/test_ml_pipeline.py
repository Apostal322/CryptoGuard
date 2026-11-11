"""ML pipeline: source integrity, label parsing, sampling, leakage-safe splits, training
smoke run, registry and monitoring. Synthetic data only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pandas")
pytest.importorskip("sklearn")
pytest.importorskip("lightgbm")
pytest.importorskip("pandera")
pytest.importorskip("openpyxl")

import pandas as pd

from cryptoguard.ml import collect as collect_mod
from cryptoguard.ml.dataset import build_table, hubs
from cryptoguard.ml.features import parties
from cryptoguard.ml.labels import _PTX_HEADER_ROW, load_ptxphish
from cryptoguard.ml.monitoring import drift_report, log_score, psi, reference_bins
from cryptoguard.ml.registry import ModelRegistryError, load_registered_model, promote
from cryptoguard.ml.sources import SOURCES, SourceIntegrityError, sha256_file, verify
from cryptoguard.ml.splits import make_splits
from cryptoguard.ml.train import promotion_gate, run_training, save_run
from tests.ml_synthetic import TOKEN, make_records

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


def test_a_hash_in_two_categories_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Conflicting labels (same transaction, two categories, any casing) fail validation."""
    import pandera.errors

    columns: dict[str, list[str]] = {name: [] for name in ALL_SUBTYPES}
    columns["Approve"] = ["0x" + "ab" * 32]
    columns["Benign KOL"] = ["0x" + "AB" * 32]
    with pytest.raises(pandera.errors.SchemaError):
        load_ptxphish(_fake_ptx(tmp_path, monkeypatch, columns))


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


def _rec(tx_hash: str, block: int, sender: str, to: str, logs: list[dict] | None = None) -> dict:  # type: ignore[type-arg]
    return {
        "tx_hash": tx_hash,
        "status": "ok",
        "tx": {
            "blockNumber": hex(block),
            "from": sender,
            "to": to,
            "value": "0x0",
            "gas": hex(60_000),
            "gasPrice": hex(10**9),
            "input": "0xa9059cbb" + "00" * 64,
        },
        "receipt": {"status": "0x1", "gasUsed": hex(50_000), "logs": logs or []},
        "from_nonce_before": "0x1",
        "to_code_before": {"size": 100, "prefix": "0x608060"},
    }


def _transfer_log(token: str, src: str, dst: str) -> dict:  # type: ignore[type-arg]
    from cryptoguard.ml.features import TRANSFER

    return {
        "address": token,
        "topics": [TRANSFER, "0x" + "0" * 24 + src[2:], "0x" + "0" * 24 + dst[2:]],
        "data": "0x" + "00" * 32,
    }


def _scenario(rows: list[tuple[str, int, str, str, int, list[dict] | None]]):  # type: ignore[no-untyped-def,type-arg]
    """Build a table from (hash, block, sender, to, label, logs) rows and split it."""
    records = {h: _rec(h, b, s, t, logs) for h, b, s, t, _, logs in rows}
    labels = pd.DataFrame(
        [
            {
                "tx_hash": h,
                "family": "ice_phishing" if y else "benign",
                "subtype": "approve" if y else "benign_kol",
                "label": y,
            }
            for h, _, _, _, y, _ in rows
        ]
    )
    table = build_table(labels, records)[0]
    split, _ = make_splits(table, records)
    return dict(zip(table["tx_hash"], split, strict=True))


def _h(i: int) -> str:
    return "0x" + f"{i:064x}"


def _a(i: int) -> str:
    return "0x" + f"{i:040x}"


USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # in the public-infrastructure registry


def _background(n: int = 40, start: int = 1_000) -> list[tuple[str, int, str, str, int, None]]:
    """Unrelated rows of both classes spread over time, so every split has both labels."""
    return [
        (_h(10_000 + i), 15_000_000 + start + i * 100, _a(50_000 + i), _a(60_000 + i), i % 2, None)
        for i in range(n)
    ]


# Row 1 sits early inside the study window (both classes occur before it); row 2 late but
# still inside (the background's benign rows end at block 15_004_800, which closes the window).
EARLY, LATE = 15_001_150, 15_004_750
PURGED = "excluded:shares_account_with_earlier_split"


def test_shared_attacker_signer_never_spans_splits() -> None:
    signer = _a(1)
    rows = [
        *_background(),
        (_h(1), EARLY, signer, _a(2), 1, None),
        (_h(2), LATE, signer, _a(3), 1, None),
    ]
    split = _scenario(rows)
    assert split[_h(1)] == "train"
    assert split[_h(2)].startswith(PURGED)


def test_shared_lookalike_recipient_never_spans_splits() -> None:
    lookalike = _a(7)
    rows = [
        *_background(),
        (_h(1), EARLY, _a(5), USDT, 1, [_transfer_log(USDT, _a(8), lookalike)]),
        (_h(2), LATE, _a(6), USDT, 1, [_transfer_log(USDT, _a(9), lookalike)]),
    ]
    split = _scenario(rows)
    assert split[_h(1)] == "train"
    assert split[_h(2)].startswith(PURGED)


def test_public_token_alone_does_not_link_unrelated_wallets() -> None:
    rows = [
        *_background(),
        (_h(1), EARLY, _a(5), USDT, 0, None),
        (_h(2), LATE, _a(6), USDT, 0, None),
    ]
    split = _scenario(rows)
    assert split[_h(1)] == "train"
    assert split[_h(2)] == "test"  # USDT is registry infrastructure; nothing else is shared


def test_mixed_case_addresses_are_the_same_entity() -> None:
    signer = "0x" + "ab" * 20
    rows = [
        *_background(),
        (_h(1), EARLY, signer, _a(2), 1, None),
        (_h(2), LATE, signer.upper().replace("0X", "0x"), _a(3), 1, None),
    ]
    split = _scenario(rows)
    assert split[_h(1)] == "train"
    assert split[_h(2)].startswith(PURGED)


# Collector and request-budget tests: tests/unit/test_ml_collector.py.

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


RUN_A = "20261101T000000Z-aaaaaaaa"
RUN_B = "20261101T000001Z-bbbbbbbb"


def _saved(trained: dict, runs: Path, run_id: str, gate_ok: bool) -> Path:  # type: ignore[type-arg]
    out = trained["out"]
    gate = {**promotion_gate(out["results"], out["selected"]), "validated_for_shadow": gate_ok}
    entry = {
        "run_id": run_id,
        "config": {},
        "gate": gate,
        "selected": {"threshold": out["selected"].threshold},
    }
    return save_run(runs / run_id, entry, out)


def test_registry_refuses_ungated_and_tampered_models(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    runs, registry = tmp_path / "runs", tmp_path / "registry.json"
    with pytest.raises(ModelRegistryError, match="did not pass"):
        promote(_saved(trained, runs, RUN_A, gate_ok=False), registry)
    run_dir = _saved(trained, runs, RUN_B, gate_ok=True)
    promote(run_dir, registry)
    loaded = load_registered_model(registry)
    assert loaded.run_id == RUN_B
    assert loaded.approval == "research_only"  # the default: a development benchmark only
    model_file = next(run_dir.glob("model.*"))
    model_file.write_bytes(model_file.read_bytes() + b"\n")
    with pytest.raises(ModelRegistryError, match="hash mismatch"):
        load_registered_model(registry)


def test_shadow_approval_needs_an_untouched_holdout(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    run_dir = _saved(trained, tmp_path / "runs", RUN_A, gate_ok=True)
    with pytest.raises(ModelRegistryError, match="untouched"):
        promote(run_dir, tmp_path / "registry.json", approval="shadow_approved")


def test_lightgbm_is_stored_as_text_and_scores_identically(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    """No pickle for LightGBM: the text model must reproduce the trained classifier's scores."""
    import numpy as np

    from cryptoguard.ml.registry import _verified_model
    from cryptoguard.ml.train import make_model

    table, split = trained["table"], trained["split"]
    train = table[split == "train"]
    cols = list(trained["out"]["feature_columns"])
    model = make_model("lightgbm", {"num_leaves": 7, "min_child_samples": 5})
    model.fit(train[cols], train["label"])
    out = {**trained["out"], "model": model, "feature_columns": cols}
    entry = {
        "run_id": RUN_A,
        "config": {},
        "gate": {"validated_for_shadow": True},
        "selected": {"threshold": 0.5},
    }
    run_dir = save_run(tmp_path / "runs" / RUN_A, entry, out)
    assert (run_dir / "model.txt").exists()
    assert not (run_dir / "model.joblib").exists()
    _, loaded = _verified_model(run_dir)
    rows = table[split == "test"][cols]
    assert np.allclose(loaded.predict_proba(rows), model.predict_proba(rows), atol=1e-12)


def test_registry_rejects_paths_and_malformed_entries(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    from cryptoguard.ml.registry import run_dir_for

    runs = tmp_path / "runs"
    for bad in ("../outside", "20261101T000000Z-aaaaaaaa/../x", "r1", ""):
        with pytest.raises(ModelRegistryError, match="invalid run id"):
            run_dir_for(bad, runs)
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"shadow": {"run_dir": "C:/anything"}}))  # Phase 11 format
    with pytest.raises(ModelRegistryError, match="malformed"):
        load_registered_model(registry)
    registry.write_text(json.dumps({"model": {"run_id": "../../etc", "approval": "research_only"}}))
    with pytest.raises(ModelRegistryError, match="invalid run id"):
        load_registered_model(registry, runs)


def test_registry_refuses_cards_that_do_not_match_this_code(trained: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    from cryptoguard.ml.registry import _verified_model

    run_dir = _saved(trained, tmp_path / "runs", RUN_A, gate_ok=True)
    card_path = run_dir / "model_card.json"
    card = json.loads(card_path.read_text())
    for change, message in (
        ({"feature_set_version": "ptx-features/0"}, "features"),
        ({"feature_columns": ["not_a_feature"]}, "feature columns"),
        ({"threshold": 7}, "threshold"),
        ({"versions": {**card["versions"], "lightgbm": "1.0.0"}}, "lightgbm"),
        ({"task": "poisoning-attempt/1"}, "transaction scorer"),  # another task's model
    ):
        card_path.write_text(json.dumps({**card, **change}))
        with pytest.raises(ModelRegistryError, match=message):
            _verified_model(run_dir)
    card_path.write_text("{not json")
    with pytest.raises(ModelRegistryError, match="unreadable"):
        _verified_model(run_dir)


def test_training_records_predictions_for_every_model(trained: dict) -> None:  # type: ignore[type-arg]
    preds = trained["out"]["predictions"]
    assert set(preds["split"]) == {"validation", "test"}
    assert {"lightgbm/full", "rule_phishing_shape"} <= set(preds.columns)
    assert len(preds) == int(trained["split"].isin(["validation", "test"]).sum())


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
        "threshold": 0.5,
        "feature_columns": ["x"],
        "reference_bins": {"x": reference_bins([0.0, 1.0] * 50)},
    }
    log = tmp_path / "scores.jsonl"
    assert drift_report(card, log)["status"] == "insufficient_data"
    for i in range(40):
        log_score(
            {
                "run_id": "r",
                "status": "scored",
                "score": i / 40,
                "latency_ms": 10 + i,
                "features": {"x": 5.0 + i},
            },
            log,
        )
    log_score({"run_id": "r", "status": "incomplete", "latency_ms": 3}, log)
    log_score({"run_id": "r", "status": "scored", "score": 0.1, "features": {"y": 1.0}}, log)
    with log.open("a") as fh:
        fh.write("{cut off\n")
    report = drift_report(card, log)
    assert report["status"] == "ok"
    assert report["shifted"] == ["x"]
    assert report["status_counts"] == {"scored": 41, "incomplete": 1}
    assert report["schema_mismatches"] == 1  # a vector for other features is not compared
    assert report["unreadable_lines"] == 1
    assert report["share_above_threshold"] == 0.5
    assert report["latency_ms"] is not None

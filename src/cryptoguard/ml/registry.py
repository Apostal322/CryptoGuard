"""Model registry: which trained run is approved for what, and safe loading of it.

Trust boundary: the local ``data/ml`` directory. A SHA-256 check proves that the model file
is the one its card describes; it does not prove the card itself is trustworthy, so a model
is only ever loaded from the local runs directory, by a validated run id, never from a path
or URL supplied by a request or a registry entry.

Approval levels (separate from "the artifact is valid"):

- ``research_only``: the run passed its promotion gate on a development benchmark. Offline
  use and explicit CLI scoring only.
- ``shadow_approved``: additionally evaluated once on an untouched holdout and passed there.
  Required for the API's shadow scoring. Never a production detector: nothing here creates
  findings.

Serialization: LightGBM models are stored in LightGBM's own text format (no pickle). Other
model families fall back to joblib (a pickle: unpickling runs code), loaded only after the
hash check.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptoguard.ml import FEATURE_SET_VERSION, TRANSACTION_TASK_ID
from cryptoguard.ml.features import FEATURES

DEFAULT_REGISTRY = Path("data") / "ml" / "registry.json"
RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
MAX_MODEL_BYTES = 50 * 1024 * 1024
Approval = Literal["research_only", "shadow_approved"]
CARD_KEYS = {
    "run_id",
    "feature_set_version",
    "feature_columns",
    "threshold",
    "gate",
    "model_sha256",
}


class ModelRegistryError(RuntimeError):
    """No usable model (none promoted, invalid entry, files missing, integrity failure)."""


@dataclass(frozen=True)
class LoadedModel:
    run_id: str
    model: Any
    card: dict[str, Any]
    approval: Approval

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    @property
    def columns(self) -> list[str]:
        return list(self.card["feature_columns"])


class BoosterModel:
    """A LightGBM booster loaded from text, with the sklearn ``predict_proba`` contract."""

    def __init__(self, booster: Any) -> None:
        self.booster = booster

    def predict_proba(self, frame: Any) -> Any:
        import numpy as np

        p = np.asarray(self.booster.predict(frame), dtype=float)
        return np.column_stack([1 - p, p])


def model_file(run_dir: Path, card: dict[str, Any]) -> Path:
    return run_dir / (
        "model.txt" if card.get("serialization") == "lightgbm-text" else "model.joblib"
    )


def _check_card(card: Any) -> dict[str, Any]:
    if not isinstance(card, dict) or not set(card) >= CARD_KEYS:
        raise ModelRegistryError(f"model card lacks {sorted(CARD_KEYS - set(card or {}))}")
    if not RUN_ID.match(str(card["run_id"])):
        raise ModelRegistryError(f"invalid run id {card['run_id']!r}")
    if card.get("task", TRANSACTION_TASK_ID) != TRANSACTION_TASK_ID:
        raise ModelRegistryError(
            f"model task {card.get('task')!r} cannot be served by the transaction scorer"
        )
    if card["feature_set_version"] != FEATURE_SET_VERSION:
        raise ModelRegistryError(
            f"model features {card['feature_set_version']} != code {FEATURE_SET_VERSION}"
        )
    columns = card["feature_columns"]
    if not isinstance(columns, list) or not columns or not set(columns) <= set(FEATURES):
        raise ModelRegistryError("model card feature columns do not match this code")
    if not isinstance(card["threshold"], (int, float)) or not 0 <= card["threshold"] <= 1:
        raise ModelRegistryError("model card threshold must be a number in [0, 1]")
    return card


def _training_versions(run_dir: Path, card: dict[str, Any]) -> dict[str, str]:
    if isinstance(card.get("versions"), dict):
        return dict(card["versions"])
    run = run_dir / "run.json"  # cards written before versions were recorded in them
    if run.exists():
        return dict(json.loads(run.read_text(encoding="utf-8")).get("versions") or {})
    return {}


def _check_versions(trained: dict[str, str]) -> None:
    """Refuse a model trained with another major.minor of the libraries that load it."""
    import importlib.metadata as md

    for pkg in ("lightgbm", "scikit-learn"):
        want = trained.get(pkg)
        if not want or want == "missing":
            raise ModelRegistryError(f"training run does not record its {pkg} version")
        have = md.version(pkg)
        if want.split(".")[:2] != have.split(".")[:2]:
            raise ModelRegistryError(f"model trained with {pkg} {want}, installed {have}")


def run_dir_for(run_id: str, runs_root: Path) -> Path:
    if not RUN_ID.match(run_id):
        raise ModelRegistryError(f"invalid run id {run_id!r}")
    path = (runs_root / run_id).resolve()
    if path.parent != runs_root.resolve():
        raise ModelRegistryError("run directory outside the runs root")
    return path


def _verified_model(
    run_dir: Path, expected_sha256: str | None = None
) -> tuple[dict[str, Any], Any]:
    """Validate a run's card, versions, size and hash, then load its model."""
    try:
        card = _check_card(json.loads((run_dir / "model_card.json").read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise ModelRegistryError(f"unreadable model card in {run_dir.name}: {exc}") from None
    _check_versions(_training_versions(run_dir, card))
    path = model_file(run_dir, card)
    if not path.exists():
        raise ModelRegistryError(f"{path.name} missing in {run_dir.name}")
    if path.stat().st_size > MAX_MODEL_BYTES:
        raise ModelRegistryError(f"{path.name} exceeds {MAX_MODEL_BYTES} bytes")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != card["model_sha256"] or (expected_sha256 and digest != expected_sha256):
        raise ModelRegistryError(f"{path.name}: hash mismatch, refusing to load")
    if card.get("serialization") == "lightgbm-text":
        import lightgbm

        return card, BoosterModel(lightgbm.Booster(model_str=data.decode("utf-8")))
    import io

    import joblib

    return card, joblib.load(io.BytesIO(data))  # hash-checked pickle (non-LightGBM models)


def promote(
    run_dir: Path, registry: Path = DEFAULT_REGISTRY, approval: Approval = "research_only"
) -> dict[str, Any]:
    """Record a run in the registry at an approval level it has evidence for."""
    card, _ = _verified_model(run_dir)
    if not card["gate"].get("validated_for_shadow"):
        raise ModelRegistryError(f"run {card['run_id']} did not pass its promotion gate")
    if approval == "shadow_approved":
        holdout = card.get("holdout") or {}
        if not (
            holdout.get("untouched") and holdout.get("evaluated_once") and holdout.get("passed")
        ):
            raise ModelRegistryError(
                "shadow approval needs a pass on an untouched, once-evaluated holdout; this run "
                "has none (its test split is a development benchmark)"
            )
    entry = {
        "run_id": card["run_id"],
        "model_sha256": card["model_sha256"],
        "feature_set_version": card["feature_set_version"],
        "approval": approval,
    }
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps({"model": entry}, indent=1), encoding="utf-8")
    return entry


def load_registered_model(
    registry: Path = DEFAULT_REGISTRY, runs_root: Path | None = None
) -> LoadedModel:
    if not registry.exists():
        raise ModelRegistryError("no model promoted (cryptoguard ml promote <run>)")
    try:
        entry = json.loads(registry.read_text(encoding="utf-8"))["model"]
        run_id, approval = str(entry["run_id"]), entry["approval"]
    except (ValueError, KeyError, TypeError):
        raise ModelRegistryError("registry entry is malformed; promote the run again") from None
    if approval not in ("research_only", "shadow_approved"):
        raise ModelRegistryError(f"unknown approval {approval!r}")
    root = runs_root or registry.parent / "runs"
    card, model = _verified_model(run_dir_for(run_id, root), entry.get("model_sha256"))
    return LoadedModel(run_id, model, card, approval)

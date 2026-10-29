"""Model registry: which trained run is the shadow-mode model, and safe loading of it.

Model files are pickles (joblib), and unpickling executes code. A model is therefore loaded
only from the local registry, and only if its SHA-256 matches the hash recorded in its model
card when it was trained; anything else is refused.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptoguard.ml import FEATURE_SET_VERSION

DEFAULT_REGISTRY = Path("data") / "ml" / "registry.json"


class ModelRegistryError(RuntimeError):
    """No usable shadow model (none promoted, files missing, or integrity check failed)."""


@dataclass(frozen=True)
class LoadedModel:
    run_id: str
    model: Any
    card: dict[str, Any]

    @property
    def threshold(self) -> float:
        return float(self.card["threshold"])

    @property
    def columns(self) -> list[str]:
        return list(self.card["feature_columns"])


def promote(run_dir: Path, registry: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    """Make a run the shadow model. Refused unless its promotion gate passed."""
    card = json.loads((run_dir / "model_card.json").read_text(encoding="utf-8"))
    if not card["gate"]["validated_for_shadow"]:
        raise ModelRegistryError(f"run {card['run_id']} did not pass its promotion gate")
    entry = {
        "run_id": card["run_id"],
        "run_dir": run_dir.as_posix(),
        "model_sha256": card["model_sha256"],
        "feature_set_version": card["feature_set_version"],
    }
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps({"shadow": entry}, indent=1), encoding="utf-8")
    return entry


def load_shadow_model(registry: Path = DEFAULT_REGISTRY) -> LoadedModel:
    if not registry.exists():
        raise ModelRegistryError("no shadow model promoted (cryptoguard ml promote <run>)")
    entry = json.loads(registry.read_text(encoding="utf-8"))["shadow"]
    run_dir = Path(entry["run_dir"])
    card = json.loads((run_dir / "model_card.json").read_text(encoding="utf-8"))
    if card["feature_set_version"] != FEATURE_SET_VERSION:
        raise ModelRegistryError(
            f"model features {card['feature_set_version']} != code {FEATURE_SET_VERSION}"
        )
    model_path = run_dir / "model.joblib"
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if digest != entry["model_sha256"] or digest != card["model_sha256"]:
        raise ModelRegistryError(f"{model_path}: hash mismatch, refusing to load")
    import joblib

    return LoadedModel(entry["run_id"], joblib.load(model_path), card)

"""Shadow-mode scoring of one transaction (experimental; never a finding).

Reads the same four point-in-time items as training (transaction, receipt, sender nonce and
target code at the previous block), extracts the same features, scores them with the
promoted, hash-verified model, and logs the vector for drift monitoring.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from cryptoguard.blockchain.rpc import JsonRpcClient
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import FeatureDisabledError, MlUnavailableError
from cryptoguard.core.hexutil import parse_hash32

DISABLED = (
    "ML scoring is disabled. Set CRYPTOGUARD_ML_SHADOW=shadow (and promote a validated model, "
    "see ML.md) to score transactions for review."
)
NOT_A_FINDING = (
    "Experimental shadow-mode score from a model trained on one public dataset (PTXPhish). "
    "It is not a finding, does not change any severity, and has a high false-positive rate "
    "on ordinary traffic (see ML_EVALUATION.md)."
)


class ShadowScore(BaseModel):
    experimental: Literal[True] = True
    status: Literal["scored", "not_found"]
    tx_hash: str
    run_id: str
    score: float | None = None
    threshold: float
    above_threshold: bool | None = None
    block_number: int | None = None
    notes: list[str]


@lru_cache(maxsize=4)
def _load(registry: str, mtime: float) -> Any:
    from cryptoguard.ml.registry import load_shadow_model

    return load_shadow_model(Path(registry))


def loaded_model(settings: Settings) -> Any:
    from cryptoguard.ml import ml_available
    from cryptoguard.ml.registry import ModelRegistryError

    if settings.ml_shadow == "off":
        raise FeatureDisabledError(DISABLED)
    if not ml_available():
        raise MlUnavailableError("The ml extra is not installed (uv sync --extra ml).")
    path = settings.ml_registry_path
    try:
        return _load(path, os.path.getmtime(path) if os.path.exists(path) else 0.0)
    except (ModelRegistryError, FileNotFoundError) as exc:
        raise MlUnavailableError(str(exc)) from None


async def score_transaction(client: JsonRpcClient, tx_hash: str, settings: Settings) -> ShadowScore:
    import pandas as pd

    from cryptoguard.ml.collect import collect_one
    from cryptoguard.ml.features import extract
    from cryptoguard.ml.monitoring import log_score

    model = loaded_model(settings)
    tx_hash = parse_hash32(tx_hash)
    record = await collect_one(client, tx_hash)
    if record["status"] != "ok":
        return ShadowScore(
            status="not_found",
            tx_hash=tx_hash,
            run_id=model.run_id,
            threshold=model.threshold,
            notes=["The transaction is not (or not yet) included in a block.", NOT_A_FINDING],
        )
    features = extract(record)
    row = pd.DataFrame([[features[c] for c in model.columns]], columns=model.columns)
    score = float(model.model.predict_proba(row)[0, 1])
    log_score(
        {
            "at": datetime.now(UTC).isoformat(),
            "run_id": model.run_id,
            "tx_hash": tx_hash,
            "score": score,
            "features": {c: features[c] for c in model.columns},
        },
        Path(settings.ml_score_log_path),
    )
    return ShadowScore(
        status="scored",
        tx_hash=tx_hash,
        run_id=model.run_id,
        score=score,
        threshold=model.threshold,
        above_threshold=score >= model.threshold,
        block_number=int(record["tx"]["blockNumber"], 16),
        notes=[NOT_A_FINDING],
    )

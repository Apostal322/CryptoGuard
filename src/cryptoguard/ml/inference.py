"""Shadow-mode scoring of one transaction (experimental; never a finding).

Reads the same four point-in-time items as training (transaction, receipt, sender nonce and
target code at the previous block), extracts the same features, scores them with the
registered, hash-verified model, and logs the vector for drift monitoring.

Observation boundary: **post-inclusion**. The transaction must be mined and its receipt
available; the score describes an executed transaction, it is not a pre-signing warning.
The score is an uncalibrated ranking score, not a probability of fraud.
"""

from __future__ import annotations

import asyncio
import os
import time
import weakref
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from cryptoguard.blockchain.rpc import JsonRpcClient
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import FeatureDisabledError, MlUnavailableError, RpcTimeoutError
from cryptoguard.core.hexutil import parse_hash32

TRAINED_CHAIN_ID = 1  # PTXPhish is Ethereum mainnet
SCORE_TIMEOUT_SECONDS = 30.0
_SCORING: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
    weakref.WeakKeyDictionary()
)


def _scoring_slot() -> asyncio.Semaphore:
    """One scoring at a time per event loop (bounded RPC load). Per loop, because an asyncio
    semaphore is bound to the loop it first waits on."""
    loop = asyncio.get_running_loop()
    if loop not in _SCORING:
        _SCORING[loop] = asyncio.Semaphore(1)
    return _SCORING[loop]


DISABLED = (
    "ML scoring is disabled. Set CRYPTOGUARD_ML_SHADOW=shadow (and register an approved model, "
    "see ML.md) to score transactions for review."
)
NOT_A_FINDING = (
    "Experimental shadow-mode score from a model trained on one public dataset (PTXPhish). "
    "It is not a finding, does not change any severity, and has a high false-positive rate "
    "on ordinary traffic (see ML_GENERALIZATION_AUDIT.md)."
)
UNCALIBRATED = (
    "Uncalibrated ranking score in [0, 1], not a probability: the training data were 82% "
    "phishing, far from real-world rates."
)


class ShadowScore(BaseModel):
    experimental: Literal[True] = True
    task: Literal["ptxphish-transaction-phishing/1"] = "ptxphish-transaction-phishing/1"
    status: Literal["scored", "not_found", "incomplete"]
    tx_hash: str
    run_id: str
    approval: Literal["research_only", "shadow_approved"]
    observation: Literal["post_inclusion"] = "post_inclusion"
    score_semantics: Literal["uncalibrated_ranking"] = "uncalibrated_ranking"
    score: float | None = None
    threshold: float
    above_threshold: bool | None = None
    block_number: int | None = None
    notes: list[str]


@lru_cache(maxsize=4)
def _load(registry: str, mtime: float) -> Any:
    from cryptoguard.ml.registry import load_registered_model

    return load_registered_model(Path(registry))


def loaded_model(settings: Settings, *, require_shadow_approval: bool = True) -> Any:
    """The registered model, or a clear refusal (409 off, 503 unavailable/not approved)."""
    from cryptoguard.ml import ml_available
    from cryptoguard.ml.registry import ModelRegistryError

    if settings.ml_shadow == "off":
        raise FeatureDisabledError(DISABLED)
    if not ml_available():
        raise MlUnavailableError("The ml extra is not installed (uv sync --extra ml).")
    path = settings.ml_registry_path
    try:
        model = _load(path, os.path.getmtime(path) if os.path.exists(path) else 0.0)
    except (ModelRegistryError, FileNotFoundError) as exc:
        raise MlUnavailableError(str(exc)) from None
    if require_shadow_approval and model.approval != "shadow_approved":
        raise MlUnavailableError(
            f"Model {model.run_id} is approved for research only: its benchmark is not an "
            "untouched holdout (see ML_GENERALIZATION_AUDIT.md). Shadow scoring is refused."
        )
    return model


async def score_transaction(
    client: JsonRpcClient,
    tx_hash: str,
    settings: Settings,
    *,
    chain_id: int,
    require_shadow_approval: bool = True,
) -> ShadowScore:
    """Score one mined transaction. ``chain_id`` must come from a verified provider."""
    model = loaded_model(settings, require_shadow_approval=require_shadow_approval)
    if chain_id != TRAINED_CHAIN_ID:
        raise MlUnavailableError(
            f"The model was trained on chain {TRAINED_CHAIN_ID}; the provider serves {chain_id}."
        )
    tx_hash = parse_hash32(tx_hash)
    started = time.perf_counter()
    try:
        async with _scoring_slot():
            return await asyncio.wait_for(
                _score(client, tx_hash, settings, model, started), SCORE_TIMEOUT_SECONDS
            )
    except TimeoutError:
        raise RpcTimeoutError(
            f"ML scoring did not finish within {SCORE_TIMEOUT_SECONDS:.0f} s."
        ) from None


async def _score(
    client: JsonRpcClient, tx_hash: str, settings: Settings, model: Any, started: float
) -> ShadowScore:
    import pandas as pd

    from cryptoguard.ml.collect import collect_one
    from cryptoguard.ml.features import extract
    from cryptoguard.ml.monitoring import log_score

    base = {
        "tx_hash": tx_hash,
        "run_id": model.run_id,
        "approval": model.approval,
        "threshold": model.threshold,
    }
    record = await collect_one(client, tx_hash)
    if record["status"] != "ok":
        reason = (
            "The transaction is not (or not yet) included in a block."
            if record["status"] == "not_found"
            else "The provider returned no receipt for a mined transaction; nothing was scored."
        )
        log_score(
            {
                "at": datetime.now(UTC).isoformat(),
                "run_id": model.run_id,
                "status": record["status"],
                "latency_ms": round((time.perf_counter() - started) * 1000),
            },
            Path(settings.ml_score_log_path),
        )
        return ShadowScore(status=record["status"], notes=[reason, NOT_A_FINDING], **base)
    features = extract(record)
    row = pd.DataFrame([[features[c] for c in model.columns]], columns=model.columns)
    score = float(model.model.predict_proba(row)[0, 1])
    log_score(
        {
            "at": datetime.now(UTC).isoformat(),
            "run_id": model.run_id,
            "status": "scored",
            "tx_hash": tx_hash,
            "score": score,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "features": {c: features[c] for c in model.columns},
        },
        Path(settings.ml_score_log_path),
    )
    return ShadowScore(
        status="scored",
        score=score,
        above_threshold=score >= model.threshold,
        block_number=int(record["tx"]["blockNumber"], 16),
        notes=[NOT_A_FINDING, UNCALIBRATED],
        **base,
    )

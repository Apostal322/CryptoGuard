"""Experimental ML endpoints (``CRYPTOGUARD_ML_SHADOW=shadow``).

With the setting ``off`` (default) both endpoints answer 409 ``feature_disabled``. Scores are
returned for review and logged for drift monitoring only: nothing here writes findings,
severities or snapshots. The RPC endpoint is the operator's configured provider; requests
carry only a transaction hash.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.api.state import get_state
from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.errors import MlUnavailableError
from cryptoguard.ml.inference import ShadowScore, loaded_model, score_transaction
from cryptoguard.services.providers import require_provider

router = APIRouter(prefix="/api/v1")


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tx_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")


class MlStatus(BaseModel):
    experimental: bool = True
    run_id: str
    selected: dict[str, Any]
    gate: dict[str, Any]
    drift: dict[str, Any]


@router.post("/ml/transactions/score", response_model=ShadowScore)
async def score(request: Request, body: ScoreRequest) -> ShadowScore:
    """EXPERIMENTAL: shadow-mode phishing score for one transaction (never a finding)."""
    state = get_state(request)
    loaded_model(state.settings)  # 409 / 503 before any RPC call
    provider = require_provider(state.provider)
    if not isinstance(provider, RpcEthereumProvider):
        raise MlUnavailableError("ML scoring needs a real RPC provider (not demo fixtures).")
    return await score_transaction(provider.client, body.tx_hash, state.settings)


@router.get("/ml/status", response_model=MlStatus)
async def status(request: Request) -> MlStatus:
    """EXPERIMENTAL: the promoted shadow model, its promotion gate and feature drift."""
    from cryptoguard.ml.monitoring import drift_report

    settings = get_state(request).settings
    model = loaded_model(settings)
    return MlStatus(
        run_id=model.run_id,
        selected=model.card["selected"],
        gate=model.card["gate"],
        drift=drift_report(model.card, Path(settings.ml_score_log_path)),
    )

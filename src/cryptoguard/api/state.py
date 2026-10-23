"""Per-application state shared by the route modules, and the common error response."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse

from cryptoguard.api.schemas import ErrorBody, ErrorResponse
from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.chains import ChainInfo
from cryptoguard.core.config import Settings
from cryptoguard.database.history import HistoryRepository


@dataclass
class AppState:
    settings: Settings
    chain: ChainInfo
    provider: EthereumProvider | None
    repository: HistoryRepository


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.cryptoguard
    return state


def error_response(status: int, code: str, message: str, **details: object) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=dict(details)))
    return JSONResponse(status_code=status, content=body.model_dump(mode="json"))

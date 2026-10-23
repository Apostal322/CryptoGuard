"""Request/response schemas specific to the HTTP layer."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.services.inspection import AddressInspection


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    database: Literal["ok", "error"]


class RpcMetricsView(BaseModel):
    requests: int
    failures: int
    retries: int
    requests_by_method: dict[str, int]
    last_error_code: str | None
    last_error_at: datetime | None


class StatusResponse(BaseModel):
    version: str
    mode: Literal["real", "demo"]
    simulated: bool
    chain_id: int
    chain_name: str
    rpc_configured: bool
    provider: str | None = Field(description="Redacted endpoint (scheme, host, port only).")
    chain_verified: bool | None
    head_block: int | None
    provider_error: ErrorBody | None
    rpc_metrics: RpcMetricsView | None
    checked_at: datetime


class AnalyzeAddressRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str = Field(max_length=64, examples=["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"])
    chain_id: int | None = Field(
        default=None, description="Optional; must equal the server's configured chain."
    )


class AnalyzeAddressResponse(BaseModel):
    inspection: AddressInspection
    persistence: Literal["stored", "already_stored", "failed"]


class ObservationItem(BaseModel):
    id: int
    block_number: int
    block_hash: str
    block_timestamp: datetime
    observed_at: datetime
    observation_type: str
    schema_version: str
    data_source: str
    payload: dict[str, Any]


class ObservationPage(BaseModel):
    items: list[ObservationItem]
    total: int
    limit: int
    offset: int


class DemoAddress(BaseModel):
    label: str
    description: str
    address: str


class DemoAddressList(BaseModel):
    simulated: Literal[True] = True
    notice: str
    addresses: list[DemoAddress]

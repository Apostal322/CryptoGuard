"""FastAPI application factory, middleware and routes."""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cryptoguard import __version__
from cryptoguard.api.campaign_routes import router as campaign_router
from cryptoguard.api.history_routes import router as history_router
from cryptoguard.api.ratelimit import TokenBucketLimiter
from cryptoguard.api.replay_routes import router as replay_router
from cryptoguard.api.schemas import (
    AnalyzeAddressRequest,
    AnalyzeAddressResponse,
    ApprovalScanPersistence,
    ApprovalScanRequest,
    ApprovalScanResponse,
    DemoAddress,
    DemoAddressList,
    ErrorBody,
    HealthResponse,
    ObservationItem,
    ObservationPage,
    RpcMetricsView,
    StatusResponse,
)
from cryptoguard.api.state import AppState, error_response, get_state
from cryptoguard.blockchain.provider import EthereumProvider, RpcEthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.chains import get_chain
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import CryptoGuardError, UnsupportedChainError
from cryptoguard.database.history import HistoryRepository
from cryptoguard.database.repository import open_repository
from cryptoguard.services.approvals import (
    APPROVAL_SCAN_OBSERVATION_TYPE,
    ApprovalScanReport,
    ScanLimits,
    scan_approvals,
)
from cryptoguard.services.demo import DEMO_ACCOUNTS
from cryptoguard.services.inspection import inspect_address
from cryptoguard.services.providers import build_provider, require_provider

logger = logging.getLogger(__name__)

ProviderFactory = Callable[[Settings], EthereumProvider | None]

_UNLIMITED_PATHS = frozenset({"/api/v1/health"})
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
}


_state = get_state
_error = error_response

router = APIRouter(prefix="/api/v1")


@router.get("/health", response_model=HealthResponse)
async def health(request: Request, response: Response) -> HealthResponse:
    database_ok = await asyncio.to_thread(_state(request).repository.ping)
    if not database_ok:
        response.status_code = 503
    return HealthResponse(
        status="ok" if database_ok else "degraded", database="ok" if database_ok else "error"
    )


@router.get("/status", response_model=StatusResponse)
async def status(request: Request) -> StatusResponse:
    state = _state(request)
    provider = state.provider
    chain_verified: bool | None = None
    head: int | None = None
    provider_error: ErrorBody | None = None
    if provider is not None:
        try:
            await provider.verify_chain()
            # Demo fixtures are not a chain: there is nothing to verify.
            chain_verified = True if provider.source == "rpc" else None
            head = await provider.block_number()
        except CryptoGuardError as exc:
            chain_verified = False if exc.code == "chain_mismatch" else None
            provider_error = ErrorBody(code=exc.code, message=exc.message)
    metrics = None
    if isinstance(provider, RpcEthereumProvider):
        m = provider.client.metrics
        metrics = RpcMetricsView(
            requests=m.requests,
            failures=m.failures,
            retries=m.retries,
            requests_by_method=dict(m.requests_by_method),
            last_error_code=m.last_error_code,
            last_error_at=m.last_error_at,
        )
    return StatusResponse(
        version=__version__,
        mode=state.settings.mode,
        simulated=state.settings.mode == "demo",
        chain_id=state.chain.chain_id,
        chain_name=state.chain.name,
        rpc_configured=state.settings.rpc_url is not None,
        provider=provider.endpoint_display if provider is not None else None,
        chain_verified=chain_verified,
        head_block=head,
        provider_error=provider_error,
        rpc_metrics=metrics,
        checked_at=datetime.now(UTC),
    )


@router.post("/analyze/address", response_model=AnalyzeAddressResponse)
async def analyze_address(request: Request, body: AnalyzeAddressRequest) -> AnalyzeAddressResponse:
    state = _state(request)
    if body.chain_id is not None and body.chain_id != state.chain.chain_id:
        raise UnsupportedChainError(
            f"This server is configured for chain id {state.chain.chain_id}; "
            f"requests for chain id {body.chain_id} are not served."
        )
    provider = require_provider(state.provider)
    inspection = await inspect_address(provider, body.address, chain=state.chain)
    persistence: Literal["stored", "already_stored", "failed"]
    try:
        stored = await asyncio.to_thread(state.repository.save_inspection, inspection)
        persistence = "stored" if stored else "already_stored"
    except Exception:
        logger.exception("failed to persist inspection")
        persistence = "failed"
    return AnalyzeAddressResponse(inspection=inspection, persistence=persistence)


@router.get("/wallets/{address}/observations", response_model=ObservationPage)
async def list_observations(
    request: Request,
    address: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> ObservationPage:
    state = _state(request)
    checksummed = to_checksum_address(address)
    rows, total = await asyncio.to_thread(
        state.repository.list_for_address,
        state.chain.chain_id,
        checksummed,
        limit=limit,
        offset=offset,
    )
    return ObservationPage(
        items=[
            ObservationItem(
                id=row.id,
                block_number=row.block_number,
                block_hash=row.block_hash,
                block_timestamp=row.block_timestamp,
                observed_at=row.observed_at,
                observation_type=row.observation_type,
                schema_version=row.schema_version,
                data_source=row.data_source,
                payload=row.payload,
            )
            for row in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/wallets/{address}/approvals/scan", response_model=ApprovalScanResponse)
async def scan_wallet_approvals(
    request: Request, address: str, body: ApprovalScanRequest
) -> ApprovalScanResponse:
    """Discover ERC-20 approvals in a bounded block window and verify current allowances."""
    state = _state(request)
    owner = to_checksum_address(address)
    provider = require_provider(state.provider)
    scan = await scan_approvals(
        provider,
        owner,
        chain=state.chain,
        limits=ScanLimits.from_settings(state.settings),
        from_block=body.from_block,
        lookback_blocks=body.lookback_blocks,
        tokens=body.tokens,
    )
    try:
        stored, new_events = await asyncio.to_thread(
            state.repository.save_approval_scan, scan.report, scan.events
        )
        persistence = ApprovalScanPersistence(
            report="stored" if stored else "already_stored", new_events=new_events
        )
    except Exception:
        logger.exception("failed to persist approval scan")
        persistence = ApprovalScanPersistence(report="failed", new_events=0)
    return ApprovalScanResponse(report=scan.report, persistence=persistence)


@router.get("/wallets/{address}/approvals", response_model=ApprovalScanReport)
async def latest_wallet_approvals(
    request: Request, address: str
) -> ApprovalScanReport | JSONResponse:
    """The most recent stored approval scan. Its block and coverage say how current it is."""
    state = _state(request)
    owner = to_checksum_address(address)
    payload = await asyncio.to_thread(
        state.repository.latest_payload,
        state.chain.chain_id,
        owner,
        APPROVAL_SCAN_OBSERVATION_TYPE,
    )
    if payload is None:
        return _error(
            404,
            "no_approval_scan",
            "No approval scan is stored for this address. "
            f"POST /api/v1/wallets/{owner}/approvals/scan to run one.",
        )
    return ApprovalScanReport.model_validate(payload)


@router.get("/demo/addresses", response_model=DemoAddressList)
async def demo_addresses(request: Request) -> DemoAddressList | JSONResponse:
    if _state(request).settings.mode != "demo":
        return _error(404, "not_in_demo_mode", "Demo fixtures are only served in demo mode.")
    return DemoAddressList(
        notice="Fictional fixtures for demonstration. They do not describe Ethereum state.",
        addresses=[
            DemoAddress(label=a.label, description=a.description, address=a.address)
            for a in DEMO_ACCOUNTS
        ],
    )


def create_app(
    settings: Settings | None = None,
    *,
    provider_factory: ProviderFactory = build_provider,
    repository: HistoryRepository | None = None,
) -> FastAPI:
    settings = settings or Settings()
    chain = get_chain(settings.chain_id)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        repo = repository or open_repository(settings.database_url)
        provider = provider_factory(settings)
        app.state.cryptoguard = AppState(settings, chain, provider, repo)
        logger.info(
            "cryptoguard api started",
            extra={
                "ctx": {
                    "mode": settings.mode,
                    "chain_id": chain.chain_id,
                    "provider": provider.endpoint_display if provider else None,
                }
            },
        )
        try:
            yield
        finally:
            if provider is not None:
                await provider.aclose()

    app = FastAPI(
        title="CryptoGuard API",
        version=__version__,
        description="Read-only, explainable Ethereum wallet security analysis.",
        lifespan=lifespan,
    )
    limiter = TokenBucketLimiter(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await _enforce_limits(request, call_next, settings, limiter)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Content-Security-Policy", "default-src 'none'")
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )

    @app.exception_handler(CryptoGuardError)
    async def _domain_error(request: Request, exc: CryptoGuardError) -> JSONResponse:
        return _error(exc.http_status, exc.code, exc.message, **exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Input values are deliberately not echoed back.
        fields = [
            {"loc": [str(part) for part in err.get("loc", ())], "msg": str(err.get("msg", ""))}
            for err in exc.errors()[:20]
        ]
        return _error(422, "invalid_request", "Request validation failed.", fields=fields)

    @app.exception_handler(Exception)
    async def _unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error", extra={"ctx": {"path": request.url.path}})
        return _error(500, "internal_error", "An internal error occurred.")

    app.include_router(router)
    app.include_router(history_router)
    app.include_router(replay_router)
    app.include_router(campaign_router)
    return app


def _origin_allowed(origin: str, request: Request, settings: Settings) -> bool:
    """A configured CORS origin, or the API's own origin (UI served from the same host)."""
    if origin in settings.cors_origins:
        return True
    parts = urlsplit(origin)
    return parts.scheme in ("http", "https") and parts.netloc == request.headers.get("host", "")


async def _enforce_limits(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
    settings: Settings,
    limiter: TokenBucketLimiter,
) -> Response:
    # DNS rebinding: a hostile page can point its own hostname at 127.0.0.1; the browser then
    # treats this API as same-origin with it. Only answer to the configured hostnames.
    host = urlsplit("//" + request.headers.get("host", "")).hostname or ""
    if host.lower() not in settings.allowed_hosts:
        return _error(400, "invalid_host", "This API only answers to its configured hostnames.")
    if request.method == "POST":
        # CSRF: cross-site pages can send "simple" POSTs (text/plain, form encodings) without a
        # CORS preflight, and CORS only hides the response, it does not stop the request.
        # Requiring JSON forces a preflight; the Origin check rejects foreign pages outright.
        origin = request.headers.get("origin")
        if origin is not None and not _origin_allowed(origin, request, settings):
            return _error(403, "origin_not_allowed", "Requests from this origin are not allowed.")
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return _error(
                415,
                "unsupported_media_type",
                "POST requests must send Content-Type: application/json.",
            )
        length = request.headers.get("content-length")
        if length is None:
            return _error(411, "length_required", "POST requests must send Content-Length.")
        if not length.isdigit() or int(length) > settings.max_request_body_bytes:
            return _error(
                413,
                "request_too_large",
                f"Request body exceeds {settings.max_request_body_bytes} bytes.",
            )
    if request.url.path.startswith("/api/") and request.url.path not in _UNLIMITED_PATHS:
        client = request.client.host if request.client else "unknown"
        wait = limiter.acquire(client)
        if wait > 0:
            response = _error(429, "rate_limited", "Too many requests; slow down.")
            response.headers["Retry-After"] = str(math.ceil(wait))
            return response
    return await call_next(request)

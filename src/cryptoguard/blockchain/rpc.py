"""Hardened JSON-RPC 2.0 client.

- Bounded retries with capped exponential backoff and full jitter, honouring ``Retry-After``.
- Bounded concurrency (semaphore) and bounded response size (streamed read).
- Strict response validation (envelope, matching id, result-or-error).
- Error classification into retryable / non-retryable domain errors.
- Never logs or raises with the endpoint URL (it often contains an API key).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from cryptoguard import __version__
from cryptoguard.core.errors import (
    BlockNotAvailableError,
    HistoricalStateUnavailableError,
    RpcError,
    RpcInvalidResponseError,
    RpcRateLimitedError,
    RpcRequestRejectedError,
    RpcTimeoutError,
    RpcUnavailableError,
    RpcUnsupportedMethodError,
)

logger = logging.getLogger(__name__)

MAX_RETRY_AFTER_SECONDS = 30.0

_HISTORICAL_STATE_MARKERS = (
    "missing trie node",
    "historical state",
    "state not available",
    "state is not available",
    "pruned",
    "archive",
)
_UNKNOWN_BLOCK_MARKERS = ("header not found", "unknown block", "block not found")
_RATE_LIMIT_MARKERS = ("rate limit", "too many requests", "throughput", "compute units")


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0

    def backoff(self, attempt: int, rng: random.Random) -> float:
        """Full-jitter delay before retry number ``attempt`` (0-based)."""
        ceiling: float = min(self.max_delay, self.base_delay * (2**attempt))
        return rng.uniform(0.0, ceiling)


@dataclass
class RpcMetrics:
    requests: int = 0
    failures: int = 0
    retries: int = 0
    requests_by_method: dict[str, int] = field(default_factory=dict)
    last_error_code: str | None = None
    last_error_at: datetime | None = None

    def record_request(self, method: str) -> None:
        self.requests += 1
        self.requests_by_method[method] = self.requests_by_method.get(method, 0) + 1

    def record_failure(self, code: str) -> None:
        self.failures += 1
        self.last_error_code = code
        self.last_error_at = datetime.now(UTC)


def _parse_retry_after(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        return None  # HTTP-date form is rare for RPC providers; fall back to backoff.
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


def classify_rpc_error(method: str, error: object) -> RpcError:
    """Map a JSON-RPC ``error`` object to a domain error. Provider text is not echoed to users."""
    if not isinstance(error, dict):
        return RpcInvalidResponseError(f"Malformed error object in response to {method}.")
    code = error.get("code")
    message = str(error.get("message", "")).lower()[:500]
    details = {"method": method, "rpc_code": code if isinstance(code, int) else None}

    if any(marker in message for marker in _HISTORICAL_STATE_MARKERS):
        return HistoricalStateUnavailableError(
            "The RPC provider cannot serve state at the requested block (pruned or not archived).",
            details=details,
        )
    if code == -32601 or "not supported" in message or "method not found" in message:
        return RpcUnsupportedMethodError(
            f"The RPC provider does not support {method}.", details=details
        )
    if code in (-32005, 429) or any(marker in message for marker in _RATE_LIMIT_MARKERS):
        return RpcRateLimitedError("The RPC provider rate-limited the request.", details=details)
    if any(marker in message for marker in _UNKNOWN_BLOCK_MARKERS):
        return BlockNotAvailableError(
            "The RPC provider does not have the requested block yet.", details=details
        )
    if code == -32603:
        return RpcUnavailableError("The RPC provider reported an internal error.", details=details)
    return RpcRequestRejectedError(f"The RPC provider rejected {method}.", details=details)


class JsonRpcClient:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        retry: RetryPolicy | None = None,
        max_concurrency: int = 4,
        max_response_bytes: int = 10 * 1024 * 1024,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._url = url
        self._retry = retry or RetryPolicy()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter, not cryptography
        self._ids = itertools.count(1)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            transport=transport,
            follow_redirects=False,
            headers={"User-Agent": f"cryptoguard/{__version__}"},
        )
        self.metrics = RpcMetrics()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(self, method: str, params: list[Any]) -> Any:
        attempt = 0
        while True:
            try:
                return await self._call_once(method, params)
            except RpcError as exc:
                self.metrics.record_failure(exc.code)
                if not exc.retryable or attempt >= self._retry.max_retries:
                    logger.warning(
                        "rpc call failed",
                        extra={
                            "ctx": {"method": method, "code": exc.code, "attempts": attempt + 1}
                        },
                    )
                    raise
                delay = (
                    exc.retry_after
                    if exc.retry_after is not None
                    else self._retry.backoff(attempt, self._rng)
                )
                attempt += 1
                self.metrics.retries += 1
                logger.info(
                    "rpc call retrying",
                    extra={
                        "ctx": {
                            "method": method,
                            "code": exc.code,
                            "attempt": attempt,
                            "delay_s": round(delay, 3),
                        }
                    },
                )
                await self._sleep(delay)

    async def _call_once(self, method: str, params: list[Any]) -> Any:
        request_id = next(self._ids)
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        async with self._semaphore:
            self.metrics.record_request(method)
            try:
                async with self._client.stream("POST", self._url, json=payload) as response:
                    status = response.status_code
                    retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                    body = await self._read_limited(response, method)
            except httpx.TimeoutException:
                raise RpcTimeoutError(f"RPC request {method} timed out.") from None
            except httpx.TransportError:
                raise RpcUnavailableError("The RPC provider could not be reached.") from None

        if status == 429:
            raise RpcRateLimitedError(
                "The RPC provider rate-limited the request.", retry_after=retry_after
            )
        if status >= 500:
            raise RpcUnavailableError(f"The RPC provider returned HTTP {status}.")
        if status in (401, 403):
            raise RpcRequestRejectedError(
                f"The RPC provider refused access (HTTP {status}); "
                "check the configured credentials."
            )
        if status != 200:
            raise RpcRequestRejectedError(f"The RPC provider returned HTTP {status}.")
        return self._extract_result(body, request_id, method)

    async def _read_limited(self, response: httpx.Response, method: str) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self._max_response_bytes:
                raise RpcInvalidResponseError(
                    f"Response to {method} exceeded the {self._max_response_bytes}-byte limit."
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _extract_result(raw: bytes, request_id: int, method: str) -> Any:
        try:
            body = json.loads(raw)
        except ValueError:
            raise RpcInvalidResponseError(f"Response to {method} is not valid JSON.") from None
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            raise RpcInvalidResponseError(f"Response to {method} is not a JSON-RPC 2.0 object.")
        if body.get("id") != request_id:
            raise RpcInvalidResponseError(f"Response to {method} has a mismatched id.")
        if body.get("error") is not None:
            raise classify_rpc_error(method, body["error"])
        if "result" not in body:
            raise RpcInvalidResponseError(f"Response to {method} has neither result nor error.")
        return body["result"]

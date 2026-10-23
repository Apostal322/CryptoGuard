"""Error taxonomy.

Every error carries a stable machine-readable ``code`` and a message that is safe to show to
users: messages never contain RPC URLs, credentials, stack traces or raw provider output.
"""

from __future__ import annotations

from typing import Any


class CryptoGuardError(Exception):
    code = "internal_error"
    http_status = 500
    retryable = False

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvalidAddressError(CryptoGuardError):
    code = "invalid_address"
    http_status = 422


class UnsupportedChainError(CryptoGuardError):
    code = "unsupported_chain"
    http_status = 422


class BlockRangeTooLargeError(CryptoGuardError):
    code = "block_range_too_large"
    http_status = 422


class RpcNotConfiguredError(CryptoGuardError):
    code = "rpc_not_configured"
    http_status = 503


class NotInDemoFixturesError(CryptoGuardError):
    code = "not_in_demo_fixtures"
    http_status = 404


class ChainMismatchError(CryptoGuardError):
    code = "chain_mismatch"
    http_status = 502


class ReorgDetectedError(CryptoGuardError):
    code = "reorg_detected"
    http_status = 503
    retryable = True


class RpcError(CryptoGuardError):
    code = "rpc_error"
    http_status = 502

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.retry_after = retry_after


class RpcTimeoutError(RpcError):
    code = "rpc_timeout"
    http_status = 504
    retryable = True


class RpcRateLimitedError(RpcError):
    code = "rpc_rate_limited"
    http_status = 503
    retryable = True


class RpcUnavailableError(RpcError):
    code = "rpc_unavailable"
    retryable = True


class BlockNotAvailableError(RpcError):
    """The provider does not (yet) know the requested block — often a lagging load-balanced node."""

    code = "block_not_available"
    retryable = True


class HistoricalStateUnavailableError(RpcError):
    """State at the requested block was pruned or is not served by this provider."""

    code = "historical_state_unavailable"


class RpcUnsupportedMethodError(RpcError):
    code = "rpc_unsupported_method"
    http_status = 501


class RpcRequestRejectedError(RpcError):
    code = "rpc_request_rejected"


class RpcInvalidResponseError(RpcError):
    code = "rpc_invalid_response"

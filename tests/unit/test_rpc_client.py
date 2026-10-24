from __future__ import annotations

import logging

import pytest

from cryptoguard.blockchain.rpc import RetryPolicy, classify_rpc_error
from cryptoguard.core.errors import (
    BlockNotAvailableError,
    HistoricalStateUnavailableError,
    RpcInvalidResponseError,
    RpcRateLimitedError,
    RpcRequestRejectedError,
    RpcTimeoutError,
    RpcUnavailableError,
    RpcUnsupportedMethodError,
)
from tests.conftest import SleepRecorder, make_client
from tests.fakenode import FakeNode, http_status, raw_body, result, rpc_error, timeout


async def test_successful_call(node: FakeNode, sleeps: SleepRecorder) -> None:
    client = make_client(node, sleeps)
    assert await client.call("eth_chainId", []) == "0x1"
    assert client.metrics.requests == 1
    assert client.metrics.failures == 0
    await client.aclose()


async def test_rate_limit_then_success_honours_retry_after(
    node: FakeNode, sleeps: SleepRecorder
) -> None:
    node.script("eth_blockNumber", http_status(429, {"Retry-After": "2"}))
    client = make_client(node, sleeps)
    assert await client.call("eth_blockNumber", []) == hex(node.head)
    assert sleeps.delays == [2.0]
    assert client.metrics.retries == 1
    assert client.metrics.requests == 2
    await client.aclose()


async def test_retry_after_is_capped(node: FakeNode, sleeps: SleepRecorder) -> None:
    node.script("eth_blockNumber", http_status(429, {"Retry-After": "99999"}))
    client = make_client(node, sleeps)
    await client.call("eth_blockNumber", [])
    assert sleeps.delays == [30.0]
    await client.aclose()


async def test_timeouts_exhaust_bounded_retries(node: FakeNode, sleeps: SleepRecorder) -> None:
    node.script("eth_blockNumber", *[timeout() for _ in range(10)])
    client = make_client(node, sleeps, max_retries=3)
    with pytest.raises(RpcTimeoutError):
        await client.call("eth_blockNumber", [])
    assert client.metrics.requests == 4  # 1 attempt + 3 retries
    assert len(sleeps.delays) == 3
    # Full jitter: each delay within its exponential ceiling (0.5, 1.0, 2.0).
    for attempt, delay in enumerate(sleeps.delays):
        assert 0 <= delay <= min(4.0, 0.5 * 2**attempt)
    await client.aclose()


async def test_server_errors_are_retried(node: FakeNode, sleeps: SleepRecorder) -> None:
    node.script("eth_chainId", http_status(502), http_status(503))
    client = make_client(node, sleeps)
    assert await client.call("eth_chainId", []) == "0x1"
    assert client.metrics.retries == 2
    await client.aclose()


@pytest.mark.parametrize(
    ("responder", "error"),
    [
        (rpc_error(-32601, "the method eth_foo does not exist"), RpcUnsupportedMethodError),
        (rpc_error(-32602, "invalid argument 0"), RpcRequestRejectedError),
        (rpc_error(-32000, "missing trie node abc"), HistoricalStateUnavailableError),
        (http_status(401), RpcRequestRejectedError),
        (http_status(404), RpcRequestRejectedError),
    ],
)
async def test_non_retryable_errors_fail_fast(
    node: FakeNode, sleeps: SleepRecorder, responder: object, error: type[Exception]
) -> None:
    node.script("eth_getBalance", responder)  # type: ignore[arg-type]
    client = make_client(node, sleeps)
    with pytest.raises(error):
        await client.call("eth_getBalance", ["0x" + "11" * 20, "latest"])
    assert sleeps.delays == []
    await client.aclose()


@pytest.mark.parametrize(
    "responder",
    [
        raw_body(b"<html>gateway</html>"),
        raw_body(b"[]"),
        raw_body(b'{"jsonrpc":"1.0","id":1,"result":"0x1"}'),
        raw_body(b'{"jsonrpc":"2.0","id":1}'),
        result("0x1", id_override=999),
        raw_body(b'{"jsonrpc":"2.0","id":1,"error":"boom"}'),
    ],
)
async def test_malformed_responses_are_rejected(
    node: FakeNode, sleeps: SleepRecorder, responder: object
) -> None:
    node.script("eth_chainId", responder)  # type: ignore[arg-type]
    client = make_client(node, sleeps)
    with pytest.raises(RpcInvalidResponseError):
        await client.call("eth_chainId", [])
    await client.aclose()


async def test_oversized_response_is_rejected(node: FakeNode, sleeps: SleepRecorder) -> None:
    node.script("eth_getCode", result("0x" + "00" * 600_000))
    client = make_client(node, sleeps)
    client._max_response_bytes = 100_000
    with pytest.raises(RpcInvalidResponseError, match="limit"):
        await client.call("eth_getCode", [])
    await client.aclose()


async def test_error_body_on_http_403_is_classified(node: FakeNode, sleeps: SleepRecorder) -> None:
    # Regression: publicnode answers archive queries with HTTP 403 and a JSON-RPC error body.
    def respond(payload):  # type: ignore[no-untyped-def]
        import httpx

        return httpx.Response(
            403,
            json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": -32602, "message": "Archive requests require a personal token."},
            },
        )

    node.script("eth_getLogs", respond)
    client = make_client(node, sleeps)
    with pytest.raises(HistoricalStateUnavailableError):
        await client.call("eth_getLogs", [{}])
    assert sleeps.delays == []
    await client.aclose()


def test_error_classification() -> None:
    assert isinstance(
        classify_rpc_error("m", {"code": -32005, "message": "x"}), RpcRateLimitedError
    )
    assert isinstance(
        classify_rpc_error("m", {"code": -32000, "message": "header not found"}),
        BlockNotAvailableError,
    )
    assert isinstance(
        classify_rpc_error("m", {"code": -32603, "message": "x"}), RpcUnavailableError
    )
    assert isinstance(classify_rpc_error("m", "nonsense"), RpcInvalidResponseError)
    # Provider-supplied text is not echoed in user-facing messages.
    err = classify_rpc_error("m", {"code": -1, "message": "<img src=x onerror=alert(1)>"})
    assert "<img" not in err.message


def test_backoff_is_bounded() -> None:
    import random

    policy = RetryPolicy(max_retries=8, base_delay=0.5, max_delay=8.0)
    rng = random.Random(1)
    for attempt in range(20):
        assert 0 <= policy.backoff(attempt, rng) <= 8.0


async def test_rpc_url_never_logged(
    node: FakeNode, sleeps: SleepRecorder, caplog: pytest.LogCaptureFixture
) -> None:
    node.script("eth_chainId", *[timeout() for _ in range(5)])
    client = make_client(node, sleeps, max_retries=2)
    with caplog.at_level(logging.DEBUG), pytest.raises(RpcTimeoutError) as excinfo:
        await client.call("eth_chainId", [])
    assert "SECRETKEY123" not in caplog.text
    assert "SECRETKEY123" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    await client.aclose()

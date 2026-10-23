from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from cryptoguard.api.ratelimit import TokenBucketLimiter
from cryptoguard.core.config import Settings, redact_url, secret_fragments
from cryptoguard.core.logging import REDACTED, RedactingFormatter


def settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_defaults_are_real_mode_without_rpc() -> None:
    s = settings()
    assert s.mode == "real"
    assert s.rpc_url is None
    assert s.chain_id == 1


def test_blank_rpc_url_counts_as_unset() -> None:
    assert settings(rpc_url="  ").rpc_url is None


@pytest.mark.parametrize(
    "url",
    [
        "http://rpc.example.com",  # plain http to a remote host
        "file:///etc/passwd",
        "ftp://example.com",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "https://",
        "https://rpc.example.com/#frag",
        "javascript:alert(1)",
    ],
)
def test_unsafe_rpc_urls_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        settings(rpc_url=url)


@pytest.mark.parametrize("url", ["https://rpc.example.com/v2/key", "http://127.0.0.1:8545"])
def test_safe_rpc_urls_accepted(url: str) -> None:
    assert settings(rpc_url=url).rpc_url is not None


def test_unsupported_chain_rejected() -> None:
    with pytest.raises(ValidationError):
        settings(chain_id=56)


@pytest.mark.parametrize("origins", [["*"], ["https://*.example.com"], ["null"]])
def test_unsafe_cors_rejected(origins: list[str]) -> None:
    with pytest.raises(ValidationError):
        settings(cors_origins=origins)


def test_url_redaction_drops_credentials() -> None:
    url = "https://user:pass@eth-mainnet.example.com:8443/v2/SECRETKEY123?apikey=QUERYSECRET"
    shown = redact_url(url)
    assert shown == "https://eth-mainnet.example.com:8443/…"
    for secret in ("SECRETKEY123", "QUERYSECRET", "pass", "user"):
        assert secret not in shown
    s = settings(rpc_url=url)
    assert s.rpc_endpoint_display == shown
    assert "SECRETKEY123" not in repr(s)


def test_log_formatter_redacts_secrets() -> None:
    url = "https://rpc.example.com/v2/SECRETKEY123"
    formatter = RedactingFormatter(secret_fragments(url), as_json=True)
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed for %s", (url,), None)
    record.ctx = {"note": "key /v2/SECRETKEY123"}
    text = formatter.format(record)
    assert "SECRETKEY123" not in text
    assert REDACTED in text


def test_token_bucket() -> None:
    now = [0.0]
    limiter = TokenBucketLimiter(per_minute=3, clock=lambda: now[0])
    assert [limiter.acquire("a") for _ in range(3)] == [0.0, 0.0, 0.0]
    wait = limiter.acquire("a")
    assert wait == pytest.approx(20.0)
    assert limiter.acquire("b") == 0.0  # keys are independent
    now[0] = 20.0
    assert limiter.acquire("a") == 0.0


def test_token_bucket_memory_is_bounded() -> None:
    limiter = TokenBucketLimiter(per_minute=10, max_keys=100)
    for i in range(1000):
        limiter.acquire(f"client-{i}")
    assert len(limiter._buckets) == 100

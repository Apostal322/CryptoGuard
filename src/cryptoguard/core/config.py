"""Application settings, loaded only from environment variables / a local ``.env`` file.

The RPC endpoint is operator configuration. It can never be supplied through the HTTP API,
which rules out server-side request forgery via user-chosen RPC URLs.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from cryptoguard.core.chains import SUPPORTED_CHAINS

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_rpc_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"https", "http"}:
        raise ValueError("RPC URL must use https (or http for a local node)")
    if not parts.hostname:
        raise ValueError("RPC URL must include a host")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS:
        raise ValueError("plain http is only allowed for localhost nodes; use https")
    if parts.fragment:
        raise ValueError("RPC URL must not contain a fragment")
    return url


def redact_url(url: str) -> str:
    """Keep only scheme, host and port: API keys commonly live in the path, query or userinfo."""
    parts = urlsplit(url)
    host = parts.hostname or "unknown"
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    suffix = "/…" if parts.path not in {"", "/"} or parts.query else ""
    return f"{parts.scheme}://{host}{port}{suffix}"


def secret_fragments(url: str) -> list[str]:
    """Substrings of the RPC URL that must never appear in logs."""
    parts = urlsplit(url)
    fragments = [url, parts.path, parts.query, parts.password or "", parts.username or ""]
    return [fragment for fragment in fragments if len(fragment) >= 6]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CRYPTOGUARD_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    mode: Literal["real", "demo"] = "real"
    rpc_url: SecretStr | None = None
    chain_id: int = 1

    rpc_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    rpc_max_retries: int = Field(default=3, ge=0, le=8)
    rpc_backoff_base_seconds: float = Field(default=0.5, gt=0, le=10)
    rpc_backoff_max_seconds: float = Field(default=8.0, gt=0, le=60)
    rpc_max_concurrency: int = Field(default=4, ge=1, le=32)
    rpc_max_response_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    max_log_block_range: int = Field(default=1000, ge=1, le=100_000)

    # Approval discovery scans an explicit block window, never the whole chain.
    approval_default_lookback_blocks: int = Field(default=10_000, ge=1, le=5_000_000)
    approval_max_scan_blocks: int = Field(default=200_000, ge=1, le=5_000_000)
    approval_max_log_requests: int = Field(default=300, ge=1, le=10_000)
    approval_max_pairs: int = Field(default=200, ge=1, le=5_000)

    # Snapshots are taken this many blocks behind the head, so shallow reorgs rarely
    # invalidate them (reorgs that do happen are detected and rebased).
    snapshot_confirmations: int = Field(default=12, ge=0, le=128)

    database_url: str = "sqlite:///./data/cryptoguard.db"

    cors_origins: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10_000)
    max_request_body_bytes: int = Field(default=16 * 1024, ge=256, le=1024 * 1024)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    @field_validator("rpc_url", mode="before")
    @classmethod
    def _blank_rpc_url_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("rpc_url")
    @classmethod
    def _check_rpc_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            validate_rpc_url(value.get_secret_value())
        return value

    @field_validator("chain_id")
    @classmethod
    def _check_chain(cls, value: int) -> int:
        if value not in SUPPORTED_CHAINS:
            raise ValueError(f"unsupported chain id {value}; supported: {sorted(SUPPORTED_CHAINS)}")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _check_cors(cls, value: list[str]) -> list[str]:
        for origin in value:
            if "*" in origin:
                raise ValueError("wildcard CORS origins are not allowed")
            if urlsplit(origin).scheme not in {"http", "https"}:
                raise ValueError(f"invalid CORS origin: {origin!r}")
        return value

    @property
    def rpc_endpoint_display(self) -> str | None:
        return redact_url(self.rpc_url.get_secret_value()) if self.rpc_url else None

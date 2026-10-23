"""Structured logging with secret redaction.

Structured fields are passed as ``logger.info("msg", extra={"ctx": {...}})``. Every formatted
record is scrubbed of configured secret fragments (e.g. an API key in the RPC URL path).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime

REDACTED = "[REDACTED]"


class RedactingFormatter(logging.Formatter):
    def __init__(self, secrets: Iterable[str], *, as_json: bool) -> None:
        super().__init__()
        # Longest first, so a full URL is replaced before its path fragment.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)
        self._as_json = as_json

    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat()
        ctx = getattr(record, "ctx", None)
        if self._as_json:
            payload: dict[str, object] = {
                "ts": timestamp,
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            if isinstance(ctx, dict):
                payload["ctx"] = ctx
            if record.exc_info:
                payload["exc"] = self.formatException(record.exc_info)
            text = json.dumps(payload, default=str)
        else:
            text = f"{timestamp} {record.levelname:<7} {record.name}: {record.getMessage()}"
            if isinstance(ctx, dict) and ctx:
                text += " " + json.dumps(ctx, default=str)
            if record.exc_info:
                text += "\n" + self.formatException(record.exc_info)
        return self._redact(text)


def configure_logging(level: str, *, as_json: bool, secrets: Iterable[str] = ()) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(secrets, as_json=as_json))
    root = logging.getLogger("cryptoguard")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
    # httpx logs full request URLs at INFO, which would include RPC API keys.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

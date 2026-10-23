"""An in-memory JSON-RPC node for tests, served through ``httpx.MockTransport``.

It implements the subset of methods CryptoGuard uses, with real JSON-RPC envelopes, so the
client's parsing, validation and retry logic are exercised end to end. Failures can be
scripted per method.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Any

import httpx

from cryptoguard.core.hashing import keccak256

Responder = Callable[[dict[str, Any]], httpx.Response]


def block_hash(number: int, fork: str = "main") -> str:
    return "0x" + keccak256(f"test-block:{fork}:{number}".encode()).hex()


class FakeNode:
    def __init__(self, *, chain_id: int = 1, head: int = 20_000_000) -> None:
        self.chain_id = chain_id
        self.head = head
        self.finalized: int | None = head - 64
        self.balances: dict[str, int] = {}
        self.code: dict[str, bytes] = {}
        self.fork = "main"
        self.calls: list[str] = []
        self.requests: list[tuple[str, list[Any]]] = []
        self.scripted: dict[str, deque[Responder]] = defaultdict(deque)
        self.on_call: Callable[[str], None] | None = None

    # -- helpers ---------------------------------------------------------------------------
    def set_account(self, address: str, *, balance: int = 0, code: bytes = b"") -> None:
        self.balances[address.lower()] = balance
        self.code[address.lower()] = code

    def script(self, method: str, *responders: Responder) -> None:
        self.scripted[method].extend(responders)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # -- protocol --------------------------------------------------------------------------
    def handle(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method = payload["method"]
        self.calls.append(method)
        self.requests.append((method, payload["params"]))
        if self.on_call is not None:
            self.on_call(method)
        if self.scripted[method]:
            return self.scripted[method].popleft()(payload)
        try:
            result = self._dispatch(method, payload["params"])
        except LookupError as exc:
            return rpc_error(-32601, str(exc))(payload)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

    def _block(self, number: int) -> dict[str, Any]:
        return {
            "number": hex(number),
            "hash": block_hash(number, self.fork),
            "parentHash": block_hash(number - 1, self.fork),
            "timestamp": hex(1_700_000_000 + number * 12),
        }

    def _dispatch(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            tag = params[0]
            if tag == "finalized":
                if self.finalized is None:
                    raise LookupError("finalized tag not supported")
                return self._block(self.finalized)
            number = self.head if tag == "latest" else int(tag, 16)
            return self._block(number) if number <= self.head else None
        if method == "eth_getBalance":
            return hex(self.balances.get(params[0].lower(), 0))
        if method == "eth_getCode":
            return "0x" + self.code.get(params[0].lower(), b"").hex()
        if method == "eth_getLogs":
            return []
        raise LookupError(f"the method {method} does not exist/is not available")


def rpc_error(code: int, message: str) -> Responder:
    def respond(payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": payload["id"],
                "error": {"code": code, "message": message},
            },
        )

    return respond


def http_status(status: int, headers: dict[str, str] | None = None) -> Responder:
    def respond(payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(status, headers=headers, text="error")

    return respond


def raw_body(content: bytes) -> Responder:
    def respond(payload: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, content=content)

    return respond


def result(value: Any, *, id_override: Any = None) -> Responder:
    def respond(payload: dict[str, Any]) -> httpx.Response:
        rid = payload["id"] if id_override is None else id_override
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": value})

    return respond


def timeout() -> Responder:
    def respond(payload: dict[str, Any]) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    return respond

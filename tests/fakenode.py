"""An in-memory JSON-RPC node for tests, served through ``httpx.MockTransport``.

It implements the subset of methods CryptoGuard uses, with real JSON-RPC envelopes, so the
client's parsing, validation and retry logic are exercised end to end. Failures can be
scripted per method.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    SEL_BALANCE_OF,
    SEL_DECIMALS,
    SEL_SYMBOL,
    TRANSFER_TOPIC,
    address_topic,
    decode_address_word,
)
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.hashing import keccak256
from cryptoguard.services.demo import topics_match

Responder = Callable[[dict[str, Any]], httpx.Response]


def block_hash(number: int, fork: str = "main") -> str:
    return "0x" + keccak256(f"test-block:{fork}:{number}".encode()).hex()


def abi_string(text: bytes) -> bytes:
    padded = text.ljust((len(text) + 31) // 32 * 32 or 32, b"\0")
    return (32).to_bytes(32, "big") + len(text).to_bytes(32, "big") + padded


@dataclass
class FakeToken:
    """An ERC-20 contract. ``reverts`` lists selectors that revert; ``returns`` overrides output."""

    balances: dict[str, int] = field(default_factory=dict)
    allowances: dict[tuple[str, str], int] = field(default_factory=dict)
    decimals: int = 18
    symbol: bytes = field(default_factory=lambda: abi_string(b"TKN"))
    reverts: set[bytes] = field(default_factory=set)
    returns: dict[bytes, bytes] = field(default_factory=dict)

    def call(self, data: bytes) -> bytes | None:
        """Return output bytes, or None to signal a revert."""
        sel, words = data[:4], [data[4 + i : 36 + i] for i in range(0, len(data) - 4, 32)]
        if sel in self.reverts:
            return None
        if sel in self.returns:
            return self.returns[sel]
        if sel == SEL_DECIMALS:
            return self.decimals.to_bytes(32, "big")
        if sel == SEL_SYMBOL:
            return self.symbol
        if sel == SEL_BALANCE_OF:
            return self.balances.get(decode_address_word(words[0]), 0).to_bytes(32, "big")
        if sel == SEL_ALLOWANCE:
            key = (decode_address_word(words[0]), decode_address_word(words[1]))
            return self.allowances.get(key, 0).to_bytes(32, "big")
        return None


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
        self.tokens: dict[str, FakeToken] = {}
        self.logs: list[dict[str, Any]] = []
        self.max_log_range: int | None = None  # emulate a provider's eth_getLogs range cap
        self.require_log_address = False  # emulate providers that reject address-less queries
        self.tx_senders: dict[str, str] = {}  # tx hash -> signer, served by getTransactionByHash
        self.sent_txs: list[dict[str, Any]] = []  # full transactions, for nonce and block reads
        # Emulate a non-archive node: nonces older than this many blocks are unavailable.
        self.state_history: int | None = None

    def send_native(self, sender: str, to: str, value: int, *, block: int) -> str:
        """Record a transaction signed by ``sender`` (nonces assigned in order)."""
        sender = sender.lower()
        nonce = sum(1 for t in self.sent_txs if t["from"] == sender)
        tx_hash = "0x" + keccak256(f"native:{sender}:{nonce}".encode()).hex()
        self.sent_txs.append(
            {
                "hash": tx_hash,
                "from": sender,
                "to": to.lower(),
                "value": hex(value),
                "nonce": hex(nonce),
                "blockNumber": hex(block),
                "blockHash": block_hash(block, self.fork),
                "transactionIndex": "0x0",
            }
        )
        self.tx_senders[tx_hash] = sender
        return tx_hash

    # -- helpers ---------------------------------------------------------------------------
    def set_account(self, address: str, *, balance: int = 0, code: bytes = b"") -> None:
        self.balances[address.lower()] = balance
        self.code[address.lower()] = code

    def add_token(self, address: str, token: FakeToken | None = None) -> FakeToken:
        token = token or FakeToken()
        self.tokens[address.lower()] = token
        self.code.setdefault(address.lower(), bytes.fromhex("6080604052"))
        return token

    def add_transfer_log(
        self,
        token: str,
        sender: str,
        recipient: str,
        value: int,
        *,
        block: int,
        signer: str,
        log_index: int = 0,
    ) -> dict[str, Any]:
        """Add an ERC-20 Transfer log and record ``signer`` as its transaction's ``from``."""
        tx_hash = "0x" + keccak256(f"transfer-tx:{block}:{log_index}".encode()).hex()
        log = {
            "address": to_checksum_address(token).lower(),
            "topics": [TRANSFER_TOPIC, address_topic(sender), address_topic(recipient)],
            "data": "0x" + value.to_bytes(32, "big").hex(),
            "blockNumber": hex(block),
            "blockHash": block_hash(block, self.fork),
            "transactionHash": tx_hash,
            "transactionIndex": "0x0",
            "logIndex": hex(log_index),
            "removed": False,
        }
        self.logs.append(log)
        self.tx_senders[tx_hash] = signer.lower()
        return log

    def add_approval_log(
        self,
        token: str,
        owner: str,
        spender: str,
        value: int,
        *,
        block: int,
        log_index: int = 0,
        removed: bool = False,
        nft_token_id: int | None = None,
    ) -> dict[str, Any]:
        """Add an Approval log; ``nft_token_id`` makes it ERC-721-shaped (4 topics, no data)."""
        topics = [APPROVAL_TOPIC, address_topic(owner), address_topic(spender)]
        data = "0x" + value.to_bytes(32, "big").hex()
        if nft_token_id is not None:
            topics.append("0x" + nft_token_id.to_bytes(32, "big").hex())
            data = "0x"
        log = {
            "address": to_checksum_address(token).lower(),
            "topics": topics,
            "data": data,
            "blockNumber": hex(block),
            "blockHash": block_hash(block, self.fork),
            "transactionHash": "0x" + keccak256(f"tx:{block}:{log_index}".encode()).hex(),
            "transactionIndex": "0x0",
            "logIndex": hex(log_index),
            "removed": removed,
        }
        self.logs.append(log)
        return log

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
        except _Revert:
            return rpc_error(3, "execution reverted")(payload)
        except _TooLarge:
            # Infura-style: -32005 is also used for rate limiting, so the message decides.
            return rpc_error(-32005, "query returned more than 10000 results")(payload)
        except _NoHistory:
            return rpc_error(-32000, "missing trie node (state is not available)")(payload)
        except _AddressRequired:
            # The wording publicnode.com returned in a live check (2026-10-23).
            return rpc_error(-32701, "Please specify an address in your request")(payload)
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
            if number > self.head:
                return None
            block = self._block(number)
            if len(params) > 1 and params[1] is True:
                block["transactions"] = [
                    t for t in self.sent_txs if int(t["blockNumber"], 16) == number
                ]
            return block
        if method == "eth_getTransactionCount":
            sender, number = params[0].lower(), int(params[1], 16)
            if self.state_history is not None and number < self.head - self.state_history:
                raise _NoHistory
            return hex(
                sum(
                    1
                    for t in self.sent_txs
                    if t["from"] == sender and int(t["blockNumber"], 16) <= number
                )
            )
        if method == "eth_getBalance":
            return hex(self.balances.get(params[0].lower(), 0))
        if method == "eth_getCode":
            return "0x" + self.code.get(params[0].lower(), b"").hex()
        if method == "eth_getLogs":
            return self._get_logs(params[0])
        if method == "eth_getTransactionByHash":
            sender = self.tx_senders.get(params[0])
            return {"hash": params[0], "from": sender} if sender else None
        if method == "eth_call":
            token = self.tokens.get(params[0]["to"].lower())
            output = token.call(bytes.fromhex(params[0]["data"][2:])) if token else None
            if output is None:
                raise _Revert
            return "0x" + output.hex()
        raise LookupError(f"the method {method} does not exist/is not available")

    @staticmethod
    def _address_filter(query: dict[str, Any]) -> set[str]:
        wanted = query["address"]
        return {a.lower() for a in ([wanted] if isinstance(wanted, str) else wanted)}

    def _get_logs(self, query: dict[str, Any]) -> list[dict[str, Any]]:
        if self.require_log_address and "address" not in query:
            raise _AddressRequired
        low, high = int(query["fromBlock"], 16), int(query["toBlock"], 16)
        if self.max_log_range is not None and high - low + 1 > self.max_log_range:
            raise _TooLarge
        return [
            log
            for log in self.logs
            if low <= int(log["blockNumber"], 16) <= high
            and ("address" not in query or log["address"] in self._address_filter(query))
            and topics_match(log["topics"], query.get("topics"))
        ]


class _Revert(Exception):
    pass


class _TooLarge(Exception):
    pass


class _AddressRequired(Exception):
    pass


class _NoHistory(Exception):
    pass


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

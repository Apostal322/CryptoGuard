"""Synthetic, fictional transaction records for ML tests (no real chain data, no labels
from any dataset). The two classes differ in transaction shape, with label noise, so a model
can learn something without the tests depending on PTXPhish."""

from __future__ import annotations

import json
import random
from typing import Any

import httpx

from cryptoguard.ml.features import APPROVAL, TRANSFER

TOKEN = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # USDT: public infrastructure


def _addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def _topic(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def _hash(i: int) -> str:
    return "0x" + f"{i:064x}"


def make_records(
    n: int = 360, seed: int = 7
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """(label rows, records by tx hash). Phishing rows: delegated transfers by attacker
    accounts, a few sharing one drainer contract; benign rows: swaps and plain transfers."""
    rng = random.Random(seed)
    drainer = _addr(rng)
    labels, records = [], {}
    for i in range(n):
        phishing = i % 2 == 0
        block = 15_000_000 + i * 1_000 + rng.randrange(500)
        sender = _addr(rng)
        target = drainer if phishing and rng.random() < 0.15 else TOKEN if phishing else _addr(rng)
        victim, recipient = _addr(rng), _addr(rng)
        noisy = rng.random() < 0.08  # label noise
        shape_phish = phishing != noisy
        if shape_phish:
            data = "0x23b872dd" + "00" * 96
            logs = [
                {
                    "address": TOKEN,
                    "topics": [TRANSFER, _topic(victim), _topic(recipient)],
                    "data": "0x" + f"{rng.randrange(1, 10**9):064x}",
                }
            ]
            value, nonce = 0, rng.randrange(0, 30)
        else:
            data = "0x" + rng.choice(["7ff36ab5", "a9059cbb", "38ed1739"]) + "00" * 128
            logs = [
                {
                    "address": TOKEN,
                    "topics": [TRANSFER, _topic(sender), _topic(recipient)],
                    "data": "0x" + f"{rng.randrange(1, 10**9):064x}",
                },
                {
                    "address": TOKEN,
                    "topics": [APPROVAL, _topic(sender), _topic(target)],
                    "data": "0x" + f"{rng.randrange(1, 10**6):064x}",
                },
            ]
            value, nonce = rng.randrange(0, 10**18), rng.randrange(100, 5_000)
        tx_hash = _hash(i + 1)
        records[tx_hash] = {
            "tx_hash": tx_hash,
            "status": "ok",
            "tx": {
                "blockNumber": hex(block),
                "from": sender,
                "to": target,
                "value": hex(value),
                "gas": hex(rng.randrange(50_000, 400_000)),
                "gasPrice": hex(30 * 10**9),
                "maxFeePerGas": None,
                "maxPriorityFeePerGas": None,
                "nonce": hex(nonce),
                "type": "0x0",
                "input": data,
            },
            "receipt": {
                "status": "0x1",
                "gasUsed": hex(40_000),
                "contractAddress": None,
                "logs": logs,
            },
            "from_nonce_before": hex(nonce),
            "to_code_before": {"size": 2_000, "prefix": "0x608060"},
        }
        labels.append(
            {
                "tx_hash": tx_hash,
                "family": "ice_phishing" if phishing else "benign",
                "subtype": "approve" if phishing else "benign_kol",
                "label": int(phishing),
            }
        )
    return labels, records


class FakeRpc:
    """JSON-RPC over httpx.MockTransport serving the four methods the collector uses."""

    def __init__(
        self,
        records: dict[str, dict[str, Any]],
        *,
        fail: set[str] | None = None,
        chain_id: int = 1,
        no_receipt: set[str] | None = None,
    ):
        self.records = records
        self.fail = fail or set()
        self.chain_id = chain_id
        self.no_receipt = no_receipt or set()
        self.calls: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method, params = payload["method"], payload["params"]
        self.calls.append(method)
        if method in self.fail:
            return httpx.Response(503, text="unavailable")
        result: Any = None
        if method == "eth_chainId":
            result = hex(self.chain_id)
        elif method == "eth_getTransactionByHash":
            rec = self.records.get(params[0])
            result = None if rec is None else {**rec["tx"], "hash": params[0]}
        elif method == "eth_getTransactionReceipt":
            rec = self.records.get(params[0])
            result = None if rec is None or params[0] in self.no_receipt else rec["receipt"]
        elif method == "eth_getTransactionCount":
            rec = next(r for r in self.records.values() if r["tx"]["from"] == params[0])
            result = rec["from_nonce_before"]
        elif method == "eth_getCode":
            result = "0x6080604052" + "00" * 10
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

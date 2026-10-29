"""Budgeted, resumable collection of point-in-time chain data for labelled transactions.

For each sampled transaction the collector reads, from one RPC endpoint:

1. the transaction (``eth_getTransactionByHash``),
2. its receipt (``eth_getTransactionReceipt``: status, gas used, logs),
3. the sender's nonce at the block *before* the transaction's block
   (``eth_getTransactionCount``), and
4. the target's code at that same earlier block (``eth_getCode``; skipped for contract
   creations).

Nothing after the transaction's own block is read, so features describe what was knowable
when the transaction executed. Labels are never sent anywhere: the sample order is fixed by
a seed before collection starts. Every HTTP attempt counts against ``max_requests``
(retries included); the run stops cleanly before exceeding it and resumes from its JSONL
checkpoint, skipping transactions already collected.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptoguard.blockchain.rpc import JsonRpcClient, RetryPolicy
from cryptoguard.core.errors import RpcError

if TYPE_CHECKING:
    import pandas as pd

REQUESTS_PER_TX = 4
SAMPLE_SEED = 20261029


@dataclass(frozen=True)
class SamplePlan:
    phishing: int = 1_350  # all address-poisoning rows, the rest stratified by subtype
    benign: int = 1_350  # stratified by subtype
    seed: int = SAMPLE_SEED


DEFAULT_PLAN = SamplePlan()


def draw_sample(labels: pd.DataFrame, plan: SamplePlan = DEFAULT_PLAN) -> pd.DataFrame:
    """Deterministic stratified sample, returned in collection order (shuffled, so a
    partial collection stays stratified)."""
    import pandas as pd

    rng = random.Random(plan.seed)  # noqa: S311 - reproducible sampling, not cryptography
    chosen: list[pd.DataFrame] = []

    def stratified(frame: pd.DataFrame, n: int) -> pd.DataFrame:
        counts = frame["subtype"].value_counts().sort_index()
        quotas = (counts / counts.sum() * n).round().astype(int).clip(upper=counts)
        parts = []
        for subtype, quota in quotas.items():
            rows = frame[frame["subtype"] == subtype].sort_values("tx_hash")
            idx = sorted(rng.sample(range(len(rows)), int(quota)))
            parts.append(rows.iloc[idx])
        return pd.concat(parts)

    poisoning = labels[labels["family"] == "address_poisoning"]
    chosen.append(poisoning)
    other = labels[(labels["label"] == 1) & (labels["family"] != "address_poisoning")]
    chosen.append(stratified(other, max(plan.phishing - len(poisoning), 0)))
    chosen.append(stratified(labels[labels["label"] == 0], plan.benign))
    sample = pd.concat(chosen).sort_values("tx_hash").reset_index(drop=True)
    order = list(range(len(sample)))
    rng.shuffle(order)
    sample = sample.iloc[order].reset_index(drop=True)
    sample.insert(0, "order", range(len(sample)))
    return sample


def _done(path: Path) -> set[str]:
    if not path.exists():
        return set()
    done = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row["status"] in ("ok", "not_found"):
                done.add(row["tx_hash"])
    return done


async def _collect_one(client: JsonRpcClient, tx_hash: str) -> dict[str, Any]:
    tx = await client.call("eth_getTransactionByHash", [tx_hash])
    if tx is None or tx.get("blockNumber") is None:
        return {"tx_hash": tx_hash, "status": "not_found"}
    receipt = await client.call("eth_getTransactionReceipt", [tx_hash])
    before = hex(int(tx["blockNumber"], 16) - 1)
    nonce = await client.call("eth_getTransactionCount", [tx["from"], before])
    code = "0x"
    if tx.get("to"):
        code = await client.call("eth_getCode", [tx["to"], before])
    logs = receipt.get("logs", []) if receipt else []
    return {
        "tx_hash": tx_hash,
        "status": "ok",
        "tx": {
            k: tx.get(k)
            for k in (
                "blockNumber",
                "from",
                "to",
                "value",
                "gas",
                "gasPrice",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "nonce",
                "type",
                "input",
            )
        },
        "receipt": None
        if receipt is None
        else {
            "status": receipt.get("status"),
            "gasUsed": receipt.get("gasUsed"),
            "contractAddress": receipt.get("contractAddress"),
            "logs": [
                {"address": log["address"], "topics": log["topics"], "data": log["data"]}
                for log in logs
            ],
        },
        "from_nonce_before": nonce,
        "to_code_before": {"size": (len(code) - 2) // 2, "prefix": code[:8]},
    }


async def collect(
    sample: pd.DataFrame,
    out: Path,
    *,
    rpc_url: str,
    max_requests: int,
    concurrency: int = 3,
    client: JsonRpcClient | None = None,
) -> dict[str, int]:
    """Collect chain data for the sample in order until done or the budget is spent."""
    out.parent.mkdir(parents=True, exist_ok=True)
    done = _done(out)
    todo = [h for h in sample["tx_hash"] if h not in done]
    retry = RetryPolicy(max_retries=4)
    rpc = client or JsonRpcClient(rpc_url, timeout=20, retry=retry, max_concurrency=concurrency)
    # Worst case still in flight when a worker checks: every worker's transaction with every
    # call retried to the limit. Stopping this far below the cap makes it a hard cap.
    margin = concurrency * REQUESTS_PER_TX * (retry.max_retries + 1)
    stats = {"already": len(done), "ok": 0, "not_found": 0, "error": 0, "skipped_budget": 0}
    lock = asyncio.Lock()
    queue: asyncio.Queue[str] = asyncio.Queue()
    for h in todo:
        queue.put_nowait(h)
    recorded = 0

    def flush_budget() -> None:
        # Written after every transaction, so an interrupted run never loses its count.
        nonlocal recorded
        delta = rpc.metrics.requests - recorded
        if delta:
            record_requests(out, delta)
            recorded += delta

    async def worker() -> None:
        while not queue.empty():
            tx_hash = queue.get_nowait()
            if rpc.metrics.requests + margin > max_requests:
                stats["skipped_budget"] += 1
                continue
            try:
                row = await _collect_one(rpc, tx_hash)
            except RpcError as exc:
                row = {"tx_hash": tx_hash, "status": "error", "error": exc.code}
            async with lock:
                stats[row["status"]] += 1
                with out.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, separators=(",", ":")) + "\n")
                flush_budget()

    try:
        await asyncio.gather(*(worker() for _ in range(concurrency)))
    finally:
        flush_budget()
        stats["requests"] = rpc.metrics.requests
        stats["retries"] = rpc.metrics.retries
        if client is None:
            await rpc.aclose()
    return stats


def budget_path(out: Path) -> Path:
    return out.with_name(out.name + ".budget.json")


def requests_used(out: Path) -> int:
    """Cumulative RPC attempts over every run that wrote ``out`` (the cap is a total)."""
    path = budget_path(out)
    return int(json.loads(path.read_text(encoding="utf-8"))["requests"]) if path.exists() else 0


def record_requests(out: Path, requests: int, note: str | None = None) -> int:
    path = budget_path(out)
    state: dict[str, Any] = (
        json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"requests": 0}
    )
    state["requests"] = int(state["requests"]) + requests
    if note:
        notes: list[str] = state.setdefault("notes", [])
        notes.append(note)
    path.write_text(json.dumps(state, indent=1), encoding="utf-8")
    return int(state["requests"])


def load_collected(path: Path) -> dict[str, dict[str, Any]]:
    """Latest successful record per transaction."""
    rows: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row["status"] in ("ok", "not_found"):
                rows[row["tx_hash"]] = row
    return rows

"""Cost planner for a proposed wallet-history collection job. It never collects anything.

Inputs are explicit assumptions (provider log range, transactions signed per wallet-window,
retry overhead); the output is a reproducible plan with a conservative request estimate that
is rejected when it exceeds the configured cap. Running a plan needs a separate, explicit
authorization; this module has no network code.

Default assumptions come from the option A pilot on ``eth.drpc.org`` (free plan, 2026-11-01;
ML_PILOT_AUDIT.md) and do not describe other providers.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

PLAN_SCHEMA = "collection-plan/1"


class CollectionAssumptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    log_range_blocks: int = Field(100, ge=1)  # largest accepted eth_getLogs range
    log_queries_per_chunk: int = Field(2, ge=1)  # incoming and outgoing transfer scans
    requests_per_signed_tx: float = Field(26.0, gt=0)  # nonce bisection + block + decode
    fixed_requests_per_wallet: int = Field(10, ge=0)  # chain check, nonces, code, timestamps
    signed_tx_per_wallet_window_p90: float = Field(30.0, ge=0)
    retry_overhead: float = Field(0.10, ge=0)  # fraction added for retries
    requests_per_second: float = Field(4.0, gt=0)
    source: str = "option A pilot, eth.drpc.org free plan, 2026-11-01"


class CollectionJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    wallets: int = Field(ge=1, le=100_000)
    window_blocks: int = Field(ge=1, le=2_628_000)  # at most about a year
    request_cap: int = Field(ge=0)
    expected_coverage: float = Field(0.8, gt=0, le=1)  # share of wallets fully resolved


class PlanRejected(ValueError):
    pass


def plan(job: CollectionJob, a: CollectionAssumptions | None = None) -> dict[str, Any]:
    """Conservative estimate; raises ``PlanRejected`` above the cap."""
    a = a or CollectionAssumptions()
    chunks = math.ceil(job.window_blocks / a.log_range_blocks)
    per_wallet = (
        chunks * a.log_queries_per_chunk
        + a.signed_tx_per_wallet_window_p90 * a.requests_per_signed_tx
        + a.fixed_requests_per_wallet
    )
    per_wallet_with_retries = math.ceil(per_wallet * (1 + a.retry_overhead))
    total = per_wallet_with_retries * job.wallets
    body: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "job": job.model_dump(),
        "assumptions": a.model_dump(),
        "estimate": {
            "log_requests_per_wallet": chunks * a.log_queries_per_chunk,
            "requests_per_wallet_conservative": per_wallet_with_retries,
            "total_requests_conservative": total,
            "expected_fully_resolved_wallets": math.floor(job.wallets * job.expected_coverage),
            "hours_at_assumed_throughput": round(total / a.requests_per_second / 3600, 2),
        },
        "within_cap": total <= job.request_cap,
        "executes": False,
        "requires": "explicit user authorization of this plan's request cap before any run",
    }
    body["plan_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    if total > job.request_cap:
        raise PlanRejected(
            f"estimated {total} requests exceed the cap of {job.request_cap}: "
            + json.dumps(body["estimate"])
        )
    return body

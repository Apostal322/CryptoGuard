"""Typed pilot records and an offline reconstruction of the option A pilot (0 RPC requests).

The pilot script that collected ``data/ml/pilot/`` lived outside the package: it read
untyped dictionaries and one attribute, ``fixture.transactions``, that does not exist (the
replay model's field is ``wallet_transactions``). The ``AttributeError`` was caught by a
broad handler, so three completed wallet recordings were logged as errors and their contents
were never written. This module is the fix:

- every record is a versioned pydantic model (``extra="forbid"``): a misspelled or missing
  field is a validation error, never an empty list or a zero;
- ``summarize_fixture`` reads ``ReplayFixture`` through typed attributes that mypy checks;
- legacy (unversioned) pilot lines are migrated explicitly, with what could not be recovered
  recorded as ``None`` and a reason, never invented;
- outcomes use explicit coverage terms: a victim with no observed payment is not "benign".
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cryptoguard.replay.models import ReplayFixture

YIELD_SCHEMA = "pilot-yield/2"
COST_SCHEMA = "pilot-cost/2"
FIXTURE_SUMMARY_SCHEMA = "pilot-fixture-summary/1"

Outcome = Literal[
    "confirmed_direct_payment",
    "no_direct_payment_observed_with_complete_declared_coverage",
    "partial_coverage",
    "unresolved",
    "not_evaluated",
]
DECLARED_COVERAGE = (
    "victim-signed transactions in [planting_block + 1, planting_block + 50400]: native ETH "
    "sends and ERC-20 transfer(recipient, amount) calls"
)
NOT_COVERED = (
    "transferFrom by a spender, router or aggregator payments, contract-wallet (relayed) "
    "payments, permit-based transfers, payments after the window"
)


class PilotRecordError(ValueError):
    """A pilot record does not match any known schema version: refuse to guess."""


class PaymentObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tx: str
    kind: Literal["eth", "token"]
    token: str | None = None
    succeeded: bool | None


class YieldRecord(BaseModel):
    """Payment check for one Poison-Hunter row (victim, lookalike, planting block)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pilot-yield/2"] = "pilot-yield/2"
    source_line: int | None  # Poison-Hunter CSV line; None when it cannot be matched
    victim: str
    lookalike: str
    subtype: str
    window_from: int
    window_to: int
    nonce_before: int | None
    signed_in_window: int | None
    located_complete: bool | None  # None = location not attempted
    payments_to_lookalike: tuple[PaymentObservation, ...] | None  # None = not inspected
    error: str | None = None
    skipped: str | None = None
    requests: int = Field(ge=0)
    migrated_from: str | None = None

    @property
    def outcome(self) -> Outcome:
        if self.error is not None:
            return "unresolved"
        if self.signed_in_window is None:
            return "not_evaluated"
        if any(p.succeeded is not False for p in self.payments_to_lookalike or ()):
            # Calldata-level evidence only; see payments.verify_* for the stricter verifier.
            return "confirmed_direct_payment"
        if self.signed_in_window == 0:
            return "no_direct_payment_observed_with_complete_declared_coverage"
        if self.payments_to_lookalike is None:
            return "not_evaluated" if self.skipped else "unresolved"
        if self.located_complete:
            return "no_direct_payment_observed_with_complete_declared_coverage"
        return "partial_coverage"


class CostRecord(BaseModel):
    """One random-wallet draw of the cost phase."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pilot-cost/2"] = "pilot-cost/2"
    draw: int
    block: int
    wallet_sha: str | None
    has_code: bool | None
    nonce_end: int | None
    signed_in_window: int | None
    result: Literal[
        "recorded",
        "recorded_contents_lost",
        "ineligible",
        "too_many_sends_for_pilot",
        "skipped_budget",
        "empty_block",
        "error",
    ]
    error: str | None = None
    requests: int = Field(ge=0)
    record_requests: int | None  # requests spent inside record_window
    transfers: int | None  # None = unknown, never "zero"
    wallet_transactions: int | None
    outgoing_payments: int | None
    scan_complete: bool | None
    migrated_from: str | None = None


class FixtureSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pilot-fixture-summary/1"] = "pilot-fixture-summary/1"
    transfers: int
    wallet_transactions: int
    outgoing_payments: int
    scan_complete: bool


def summarize_fixture(fx: ReplayFixture) -> FixtureSummary:
    """Counts from a recorded window (the corrected version of the pilot's post-processing).

    Outgoing payments: the wallet's own ETH-carrying transactions that did not revert, plus
    token transfers out of the wallet in transactions the wallet signed (spoofed
    ``transferFrom`` logs and zero-value plantings are not payments)."""
    wallet = fx.wallet.lower()
    eth = sum(1 for t in fx.wallet_transactions if int(t.value) > 0 and t.succeeded is not False)
    tokens = sum(
        1
        for t in fx.transfers
        if t.sender.lower() == wallet and (t.tx_sender or "").lower() == wallet and int(t.value) > 0
    )
    return FixtureSummary(
        transfers=len(fx.transfers),
        wallet_transactions=len(fx.wallet_transactions),
        outgoing_payments=eth + tokens,
        scan_complete=fx.transfer_scan_complete and fx.sender_lookups_skipped == 0,
    )


def summarize_fixture_json(data: dict[str, Any]) -> FixtureSummary:
    """Summary of a stored fixture; a schema mismatch (e.g. ``transactions`` instead of
    ``wallet_transactions``) raises instead of being read as zero transactions."""
    try:
        return summarize_fixture(ReplayFixture.model_validate(data))
    except ValidationError as exc:
        raise PilotRecordError(f"stored fixture does not match ReplayFixture: {exc}") from None


# --- loading and migration -------------------------------------------------------------

_LEGACY_YIELD_KEYS = {"victim", "attacker", "type", "lo", "hi", "requests"}
_LEGACY_COST_KEYS = {"draw", "block", "requests", "result"}
_LOST_CONTENTS = "AttributeError: 'ReplayFixture' object has no attribute 'transactions'"
# Requests spent before record_window in a legacy draw: block, code, nonce at end and start.
_LEGACY_ELIGIBILITY_REQUESTS = 4


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], bool]:
    """Lines as objects. A cut-off final line (crash while writing) is reported and skipped;
    a corrupt line elsewhere is an error."""
    lines = path.read_text(encoding="utf-8").split("\n")
    truncated = False
    out: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:  # no newline after it: the write was cut off
                truncated = True
                continue
            raise PilotRecordError(f"{path}: corrupt line {i + 1}") from None
        if not isinstance(obj, dict):
            raise PilotRecordError(f"{path}: line {i + 1} is not an object")
        out.append(obj)
    return out, truncated


def yield_record(obj: dict[str, Any], source_line: int | None = None) -> YieldRecord:
    version = obj.get("schema_version")
    if version == YIELD_SCHEMA:
        return YieldRecord.model_validate(obj)
    if version is not None:
        raise PilotRecordError(f"unsupported yield schema {version!r}")
    if not obj.keys() >= _LEGACY_YIELD_KEYS:
        missing = sorted(_LEGACY_YIELD_KEYS - obj.keys())
        raise PilotRecordError(f"legacy yield line lacks {missing}")
    known = _LEGACY_YIELD_KEYS | {
        "n0",
        "sent_in_window",
        "resolved",
        "paid_attacker",
        "error",
        "skipped",
    }
    if extra := sorted(obj.keys() - known):
        raise PilotRecordError(f"legacy yield line has unknown fields {extra}")
    paid = obj.get("paid_attacker")
    located = None if paid is None else bool(obj.get("resolved"))
    return YieldRecord(
        source_line=source_line,
        victim=obj["victim"],
        lookalike=obj["attacker"],
        subtype=obj["type"],
        window_from=obj["lo"],
        window_to=obj["hi"],
        nonce_before=obj.get("n0"),
        signed_in_window=obj.get("sent_in_window"),
        located_complete=located,
        payments_to_lookalike=None
        if paid is None
        else tuple(PaymentObservation.model_validate(p) for p in paid),
        error=obj.get("error"),
        skipped=obj.get("skipped"),
        requests=obj["requests"],
        migrated_from="pilot-yield/legacy-1",
    )


def cost_record(obj: dict[str, Any]) -> CostRecord:
    version = obj.get("schema_version")
    if version == COST_SCHEMA:
        return CostRecord.model_validate(obj)
    if version is not None:
        raise PilotRecordError(f"unsupported cost schema {version!r}")
    if not obj.keys() >= _LEGACY_COST_KEYS:
        raise PilotRecordError(f"legacy cost line lacks {sorted(_LEGACY_COST_KEYS - obj.keys())}")
    lost = obj.get("error") == _LOST_CONTENTS
    recorded = obj["result"] == "recorded"
    return CostRecord(
        draw=obj["draw"],
        block=obj["block"],
        wallet_sha=obj.get("wallet_sha"),
        has_code=obj.get("has_code"),
        nonce_end=obj.get("nonce_end"),
        signed_in_window=obj.get("sends"),  # nonce difference: recoverable from the log
        result="recorded_contents_lost" if lost else obj["result"],
        error=None if lost else obj.get("error"),
        requests=obj["requests"],
        record_requests=obj["requests"] - _LEGACY_ELIGIBILITY_REQUESTS
        if lost
        else obj.get("record_requests"),
        transfers=obj.get("transfers") if recorded else None,
        wallet_transactions=obj.get("transactions") if recorded else None,
        outgoing_payments=obj.get("outgoing_payments") if recorded else None,
        scan_complete=obj.get("scan_complete") if recorded else None,
        migrated_from="pilot-cost/legacy-1",
    )


# --- reconstruction --------------------------------------------------------------------


def wilson_upper(k: int, n: int, z: float = 1.959964) -> float | None:
    if n == 0:
        return None
    if k == 0:
        return z * z / (n + z * z)
    p = k / n
    centre = p + z * z / (2 * n)
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + spread) / (1 + z * z / n)


def load_yield(
    pilot_dir: Path, candidates: list[tuple[int, str, str]] | None = None
) -> tuple[list[YieldRecord], bool]:
    """Typed yield records (and whether a truncated tail was skipped).

    ``candidates``: ``(source_line, victim, lookalike)`` of the parser's valid rows in file
    order; the yield file is checked against it row by row."""
    yield_raw, truncated = read_jsonl(pilot_dir / "yield.jsonl")
    if candidates is not None:
        if len(candidates) != len(yield_raw):
            raise PilotRecordError(
                f"{len(yield_raw)} yield lines for {len(candidates)} candidate rows"
            )
        for (_, victim, lookalike), obj in zip(candidates, yield_raw, strict=True):
            if (obj.get("victim"), obj.get("attacker", obj.get("lookalike"))) != (
                victim,
                lookalike,
            ):
                raise PilotRecordError("yield lines are not in candidate order")
    lines = [c[0] for c in candidates] if candidates else [None] * len(yield_raw)
    return [yield_record(o, line) for o, line in zip(yield_raw, lines, strict=True)], truncated


def reconstruct(
    pilot_dir: Path, candidates: list[tuple[int, str, str]] | None = None
) -> dict[str, Any]:
    """Recompute the pilot report from its raw outputs (``candidates`` as in ``load_yield``)."""
    ys, y_trunc = load_yield(pilot_dir, candidates)
    cost_raw, c_trunc = read_jsonl(pilot_dir / "cost.jsonl")
    cs = [cost_record(o) for o in cost_raw]
    budget = json.loads((pilot_dir / "budget.json").read_text(encoding="utf-8"))
    summary = json.loads((pilot_dir / "summary.json").read_text(encoding="utf-8"))
    plan_sha = hashlib.sha256((pilot_dir / "plan.json").read_bytes()).hexdigest()

    outcomes = Counter(y.outcome for y in ys)
    events = Counter((y.victim, y.lookalike, y.window_from) for y in ys)
    signed = [y.signed_in_window for y in ys if y.signed_in_window is not None]
    complete = outcomes["no_direct_payment_observed_with_complete_declared_coverage"]
    confirmed = outcomes["confirmed_direct_payment"]
    located = [y for y in ys if y.payments_to_lookalike is not None]
    yield_requests = sum(y.requests for y in ys)
    cost_requests = sum(c.requests for c in cs)
    recorded = [c for c in cs if c.result in ("recorded", "recorded_contents_lost")]
    eligible = [
        c
        for c in cs
        if c.has_code is False and c.nonce_end is not None and 20 <= c.nonce_end <= 2_000
    ]
    return {
        "plan_sha256": plan_sha,
        "truncated_tail": {"yield": y_trunc, "cost": c_trunc},
        "requests": {
            "ledger_total": int(budget["requests"]),
            "before_final_run": int(summary["started_used"]),
            "yield_phase": yield_requests,
            "cost_phase": cost_requests,
            "run_overhead": int(summary["ended_used"])
            - int(summary["started_used"])
            - yield_requests
            - cost_requests,
            "cap": 3_000,
        },
        "yield": {
            "rows": len(ys),
            "distinct_victim_events": len(events),
            "duplicate_rows": len(ys) - len(events),
            "distinct_victims": len({y.victim for y in ys}),
            "distinct_lookalikes": len({y.lookalike for y in ys}),
            "outcomes": {k: outcomes.get(k, 0) for k in Outcome.__args__},  # type: ignore[attr-defined]
            "signed_zero": sum(1 for v in signed if v == 0),
            "signed_1_8": sum(1 for v in signed if 1 <= v <= 8),
            "signed_9_100": sum(1 for v in signed if 9 <= v <= 100),
            "signed_over_100": sum(1 for v in signed if v > 100),
            "located_rows": len(located),
            "provider_errors": sum(1 for y in ys if y.error),
            "migrated": sum(1 for y in ys if y.migrated_from),
            "observed_complete": complete,
            "confirmed": confirmed,
            "conditional_wilson_upper_95": wilson_upper(confirmed, complete + confirmed),
            "conditional_on": (
                "only rows with complete declared coverage; they are the less active victims "
                "and not a random sample, so this bound does not extend to all 149 rows"
            ),
        },
        "cost": {
            "draws": len(cs),
            "results": dict(sorted(Counter(c.result for c in cs).items())),
            "eligible": len(eligible),
            "recorded_wallet_days": len(recorded),
            "record_requests": sorted(c.record_requests for c in recorded if c.record_requests),
            "recorded_signed_in_window": sorted(
                c.signed_in_window for c in recorded if c.signed_in_window is not None
            ),
            "contents_lost": sum(1 for c in cs if c.result == "recorded_contents_lost"),
            "unknown_payment_counts": sum(1 for c in recorded if c.outgoing_payments is None),
            "rate_limited": sum(1 for c in cs if c.error and "RateLimited" in c.error),
        },
        "seconds": summary.get("seconds"),
    }


def render_markdown(report: dict[str, Any]) -> str:
    y, c, r = report["yield"], report["cost"], report["requests"]
    out = [
        "| Quantity | Value | Source |",
        "|---|---|---|",
        f"| Ledger total (cap {r['cap']}) | {r['ledger_total']} | `budget.json` |",
        f"| Before the final run (smoke tests, probes) | {r['before_final_run']} "
        "| `summary.json` |",
        f"| Yield phase | {r['yield_phase']} | sum over `yield.jsonl` |",
        f"| Cost phase | {r['cost_phase']} | sum over `cost.jsonl` |",
        f"| Run overhead (chain check) | {r['run_overhead']} | difference |",
        f"| Candidate rows / distinct victim-events | {y['rows']} / "
        f"{y['distinct_victim_events']} | `yield.jsonl` |",
    ]
    for k, v in y["outcomes"].items():
        out.append(f"| Outcome `{k}` | {v} | derived |")
    out += [
        f"| Signed 0 / 1-8 / 9-100 / >100 in window | {y['signed_zero']} / {y['signed_1_8']} / "
        f"{y['signed_9_100']} / {y['signed_over_100']} | nonce differences |",
        f"| Cost draws / eligible / recorded wallet-days | {c['draws']} / {c['eligible']} / "
        f"{c['recorded_wallet_days']} | `cost.jsonl` |",
        f"| Requests per recorded wallet-day | {', '.join(map(str, c['record_requests']))} | "
        "`cost.jsonl` (minus 4 eligibility requests) |",
        f"| Recordings whose contents were lost | {c['contents_lost']} | migration |",
    ]
    bound = y["conditional_wilson_upper_95"]
    out.append(
        f"| Conditional Wilson 95% upper bound | {bound:.3f} | {y['confirmed']} of "
        f"{y['observed_complete'] + y['confirmed']} complete rows; not a population bound |"
        if bound is not None
        else "| Conditional bound | n/a | no complete rows |"
    )
    return "\n".join(out) + "\n"

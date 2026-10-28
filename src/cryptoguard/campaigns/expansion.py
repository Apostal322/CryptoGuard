"""Selective, budgeted expansion around planting infrastructure (``campaign-expansion/1``).

Standard JSON-RPC cannot list an address's history, and a campaign graph built only from the
victims CryptoGuard watches is shallow. This module tests concrete hypotheses around
entities that already appear in verified attempts, using only existing ingestion pieces
(``scan_logs``, ``locate_wallet_transactions``, receipts, code reads):

- **lookalike_logs**: "was this lookalike planted on other wallets too?" вЂ” Transfer logs to
  and from the lookalike in a window around the known attempt;
- **signer_transactions**: "did this planting key target other wallets?" вЂ” the signer's own
  transactions near the known attempt (nonce search) and their Transfer logs;
- **deployer**: "who created this fake token contract?" вЂ” the creation block by bisection on
  ``eth_getCode`` and the creating transaction, when it is a top-level deployment.

Victims are never expanded. Every discovered event is re-checked against the detector's
criterion before it counts as an attempt: within ``verify_window_blocks`` before it, the
candidate victim must have sent a Transfer to an address the lookalike resembles. Events
that fail or cannot be checked are kept as *unverified candidates*, never as attempts.

Everything is bounded: requests, wall time, entities, transactions per signer, logs per
transaction and new victims. Tasks have deterministic ids and their outcomes can be stored,
so an interrupted expansion resumes without refetching. All reads are at or before the
cutoff block: nothing later can enter a historical analysis.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from cryptoguard.blockchain.abi import TRANSFER_TOPIC, address_topic
from cryptoguard.blockchain.erc20 import LogShape, TransferEvent, classify_transfer_log
from cryptoguard.blockchain.logscan import Topics, scan_logs
from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.campaigns.attempts import EventType, PoisoningAttempt, attempt_id, dedupe
from cryptoguard.campaigns.cluster import Deployer
from cryptoguard.campaigns.relations import COMMON_CONTRACTS
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import (
    CryptoGuardError,
    HistoricalStateUnavailableError,
    InvalidAddressError,
    RpcError,
)
from cryptoguard.core.hashing import keccak256
from cryptoguard.detectors.poisoning import BURN_ADDRESSES, PoisoningConfig, is_lookalike
from cryptoguard.services.wallet_txs import locate_wallet_transactions

EXPANSION_VERSION = "campaign-expansion/1"
TaskKind = Literal["lookalike_logs", "signer_transactions", "deployer"]
TaskStatus = Literal["complete", "partial", "skipped", "failed"]
VerifyStatus = Literal["verified", "no_matching_payment", "not_checked"]


@dataclass(frozen=True)
class ExpansionBudget:
    max_requests: int = 600
    max_seconds: float = 600.0
    max_entities: int = 20
    lookalike_window_blocks: int = 1_000  # each side of the known attempt
    signer_window_blocks: int = 150
    max_signer_transactions: int = 6
    max_logs_per_transaction: int = 25
    verify_window_blocks: int = 100
    max_new_victims: int = 100
    max_deployer_lookups: int = 10
    max_verifications_per_task: int = 30
    chunk_blocks: int = 100


@dataclass(frozen=True)
class ExpansionTask:
    kind: TaskKind
    key: str
    from_block: int
    to_block: int
    # Block of the attempt that made this entity worth expanding. A historical analysis at
    # block H may use the task only if seed_block <= H: choosing *what* to expand from later
    # attempts would leak future knowledge even if every fetched event is older than H.
    seed_block: int

    @property
    def task_id(self) -> str:
        material = (
            f"{EXPANSION_VERSION}|{self.kind}|{self.key}|{self.from_block}|{self.to_block}"
            f"|{self.seed_block}"
        )
        return "0x" + keccak256(material.encode()).hex()[:32]


@dataclass(frozen=True)
class Candidate:
    """A Transfer log that might be a planting event on a wallet not watched by CryptoGuard."""

    victim: str
    lookalike: str
    event_type: EventType
    transaction_hash: str
    block_number: int
    block_hash: str
    transaction_index: int
    log_index: int
    contract: str
    log_from: str
    log_to: str
    value: int
    signer: str | None
    imitated: str | None = None
    status: VerifyStatus = "not_checked"
    note: str | None = None

    def as_attempt(self, chain_id: int) -> PoisoningAttempt:
        return PoisoningAttempt(
            block_number=self.block_number,
            transaction_index=self.transaction_index,
            log_index=self.log_index,
            attempt_id=attempt_id(
                chain_id, self.transaction_hash, self.log_index, self.victim, self.lookalike
            ),
            chain_id=chain_id,
            victim=self.victim,
            lookalike=self.lookalike,
            imitated=self.imitated,
            imitated_confirmed=False,  # the payment's signer is not checked during expansion
            event_type=self.event_type,
            transaction_hash=self.transaction_hash,
            block_hash=self.block_hash,
            contract=self.contract,
            log_from=self.log_from,
            log_to=self.log_to,
            value=self.value,
            signer=self.signer,
            rule_id="CG-POI-001",
            source="expansion",
        )


@dataclass
class TaskOutcome:
    task: ExpansionTask
    status: TaskStatus
    requests: int = 0
    candidates: list[Candidate] = field(default_factory=list)
    deployer: Deployer | None = None
    reason: str | None = None
    truncated: list[str] = field(default_factory=list)


@dataclass
class ExpansionResult:
    version: str
    chain_id: int
    cutoff_block: int
    budget: ExpansionBudget
    outcomes: list[TaskOutcome]
    requests: int
    seconds: float
    stopped: str | None  # why the expansion ended early, if it did

    @property
    def candidates(self) -> list[Candidate]:
        seen: dict[tuple[str, int, str], Candidate] = {}
        for o in self.outcomes:
            for c in o.candidates:
                seen.setdefault((c.transaction_hash.lower(), c.log_index, c.victim), c)
        return sorted(seen.values(), key=lambda c: (c.block_number, c.log_index, c.victim))

    def attempts(self) -> list[PoisoningAttempt]:
        return [c.as_attempt(self.chain_id) for c in self.candidates if c.status == "verified"]

    def deployers(self) -> dict[str, Deployer]:
        return {o.task.key: o.deployer for o in self.outcomes if o.deployer is not None}

    def usable_at(
        self, cutoff_block: int, known_since: Mapping[str, int] | None = None
    ) -> tuple[list[PoisoningAttempt], dict[str, Deployer]]:
        """What a system running at ``cutoff_block`` could have known: only tasks seeded by
        attempts at or before it, and only facts dated at or before it.

        ``known_since`` maps an entity to the first block at which an attempt involving it
        *qualified* (the detector can need later data to recognise an earlier planting).
        When given, a task is usable only once its entity was known; historical analyses
        must pass it, because a seed's block alone can predate its recognition."""
        attempts: list[PoisoningAttempt] = []
        deployers: dict[str, Deployer] = {}
        for o in self.outcomes:
            if o.task.seed_block > cutoff_block:
                continue
            if known_since is not None and known_since.get(o.task.key, 2**63) > cutoff_block:
                continue
            attempts += [
                c.as_attempt(self.chain_id)
                for c in o.candidates
                if c.status == "verified" and c.block_number <= cutoff_block
            ]
            if o.deployer is not None and o.deployer.creation_block <= cutoff_block:
                deployers[o.task.key] = o.deployer
        return dedupe(attempts), deployers

    def coverage(self) -> dict[str, object]:
        by_status: dict[str, int] = {}
        for o in self.outcomes:
            by_status[o.status] = by_status.get(o.status, 0) + 1
        return {
            "tasks": by_status,
            "requests": self.requests,
            "seconds": round(self.seconds, 1),
            "stopped": self.stopped,
            "failures": [
                {"task": o.task.kind, "key": o.task.key, "reason": o.reason}
                for o in self.outcomes
                if o.status in ("failed", "partial", "skipped")
            ],
            "not_attempted": [
                "funding sources of planting signers (incoming ETH is not visible over "
                "standard JSON-RPC)",
                "contracts created by other contracts (needs execution traces)",
                "activity of entities beyond one hop from a verified attempt",
            ],
        }


class _BudgetExhausted(Exception):
    pass


class _Meter:
    def __init__(self, counter: Callable[[], int], budget: ExpansionBudget) -> None:
        self.counter = counter
        self.start_requests = counter()
        self.start = time.perf_counter()
        self.budget = budget

    @property
    def used(self) -> int:
        return self.counter() - self.start_requests

    def check(self, reserve: int = 1) -> None:
        if self.used + reserve > self.budget.max_requests:
            raise _BudgetExhausted("request budget")
        if time.perf_counter() - self.start > self.budget.max_seconds:
            raise _BudgetExhausted("time budget")


def plan_tasks(
    attempts: Sequence[PoisoningAttempt],
    *,
    chain_id: int,
    cutoff_block: int,
    budget: ExpansionBudget,
) -> list[ExpansionTask]:
    """Deterministic, prioritised tasks: signers and lookalikes with the most attempts
    first, then narrow contracts. Only planting-side entities are ever expanded."""
    visible = [a for a in attempts if a.block_number <= cutoff_block]
    common = COMMON_CONTRACTS.get(chain_id, frozenset())

    def first_block(entities: dict[str, list[PoisoningAttempt]], key: str) -> int:
        return min(a.block_number for a in entities[key])

    signers: dict[str, list[PoisoningAttempt]] = {}
    lookalikes: dict[str, list[PoisoningAttempt]] = {}
    contracts: dict[str, list[PoisoningAttempt]] = {}
    for a in visible:
        if a.signer and a.signer not in (a.victim, a.lookalike):
            signers.setdefault(a.signer, []).append(a)
        lookalikes.setdefault(a.lookalike, []).append(a)
        if a.contract not in common:
            contracts.setdefault(a.contract, []).append(a)

    def ranked(entities: dict[str, list[PoisoningAttempt]]) -> list[str]:
        return sorted(entities, key=lambda k: (-len(entities[k]), k))

    tasks: list[ExpansionTask] = []
    for s in ranked(signers)[: budget.max_entities]:
        b = first_block(signers, s)
        w = budget.signer_window_blocks
        tasks.append(
            ExpansionTask("signer_transactions", s, max(0, b - w), min(b + w, cutoff_block), b)
        )
    for lk in ranked(lookalikes)[: budget.max_entities]:
        b = first_block(lookalikes, lk)
        w = budget.lookalike_window_blocks
        tasks.append(
            ExpansionTask("lookalike_logs", lk, max(0, b - w), min(b + w, cutoff_block), b)
        )
    for c in ranked(contracts)[: budget.max_deployer_lookups]:
        tasks.append(
            ExpansionTask("deployer", c, 0, first_block(contracts, c), first_block(contracts, c))
        )
    return tasks


def _request_counter(provider: EthereumProvider) -> Callable[[], int]:
    client = getattr(provider, "client", None)
    metrics = getattr(client, "metrics", None)
    if metrics is None:
        raise TypeError("expansion needs a provider that counts its RPC requests")
    return lambda: int(metrics.requests)


async def expand(
    provider: EthereumProvider,
    attempts: Sequence[PoisoningAttempt],
    *,
    chain_id: int,
    cutoff_block: int,
    budget: ExpansionBudget | None = None,
    completed: Mapping[str, TaskOutcome] | None = None,
    on_task: Callable[[TaskOutcome], None] | None = None,
    config: PoisoningConfig | None = None,
) -> ExpansionResult:
    """Run the planned tasks within the budget. ``completed`` (from an earlier, interrupted
    run with the same inputs) is reused; ``on_task`` is called after each task so the
    caller can checkpoint."""
    budget = budget or ExpansionBudget()
    config = config or PoisoningConfig()
    meter = _Meter(_request_counter(provider), budget)
    known_victims = {a.victim for a in attempts}
    outcomes: list[TaskOutcome] = []
    stopped: str | None = None
    new_victims: set[str] = set()
    for task in plan_tasks(attempts, chain_id=chain_id, cutoff_block=cutoff_block, budget=budget):
        if completed and task.task_id in completed and completed[task.task_id].status == "complete":
            outcomes.append(completed[task.task_id])
            continue
        if stopped:
            outcomes.append(TaskOutcome(task, "skipped", reason=f"stopped: {stopped}"))
            continue
        outcome = TaskOutcome(task, "complete")
        before = meter.used
        try:
            if task.kind == "deployer":
                outcome.deployer, outcome.reason = await _find_deployer(provider, task, meter)
            else:
                logs = (
                    await _signer_logs(provider, task, meter, budget, outcome)
                    if task.kind == "signer_transactions"
                    else await _lookalike_logs(provider, task, meter, budget, outcome)
                )
                await _candidates(
                    provider, task, logs, meter, budget, config, known_victims, new_victims, outcome
                )
        except _BudgetExhausted as exc:
            outcome.status, outcome.reason, stopped = "partial", str(exc), str(exc)
        except HistoricalStateUnavailableError:
            outcome.status = "failed"
            outcome.reason = "the provider does not serve historical state for this block range"
        except RpcError as exc:
            outcome.status, outcome.reason = "failed", f"{exc.code}: {exc.message}"
        except CryptoGuardError as exc:
            outcome.status, outcome.reason = "failed", f"{exc.code}: {exc.message}"
        outcome.requests = meter.used - before
        outcomes.append(outcome)
        if on_task is not None:
            on_task(outcome)
    return ExpansionResult(
        version=EXPANSION_VERSION,
        chain_id=chain_id,
        cutoff_block=cutoff_block,
        budget=budget,
        outcomes=outcomes,
        requests=meter.used,
        seconds=time.perf_counter() - meter.start,
        stopped=stopped,
    )


async def _lookalike_logs(
    provider: EthereumProvider,
    task: ExpansionTask,
    meter: _Meter,
    budget: ExpansionBudget,
    outcome: TaskOutcome,
) -> list[tuple[dict[str, Any], str | None]]:
    topic = address_topic(task.key)
    out: list[tuple[dict[str, Any], str | None]] = []
    queries: list[Topics] = [[TRANSFER_TOPIC, None, topic], [TRANSFER_TOPIC, topic]]
    for topics in queries:
        span = task.to_block - task.from_block + 1
        reserve = -(-span // budget.chunk_blocks)
        meter.check(reserve)
        scan = await scan_logs(
            provider,
            topics=topics,
            from_block=task.from_block,
            to_block=task.to_block,
            chunk_blocks=budget.chunk_blocks,
            max_requests=reserve * 4,
        )
        if not scan.complete:
            outcome.status = "partial"
            outcome.truncated.append(
                f"logs scanned only from block {scan.scanned_from} (request cap)"
            )
        out.extend((log, None) for log in scan.logs)
    return out


async def _signer_logs(
    provider: EthereumProvider,
    task: ExpansionTask,
    meter: _Meter,
    budget: ExpansionBudget,
    outcome: TaskOutcome,
) -> list[tuple[dict[str, Any], str | None]]:
    meter.check(20)
    found = await locate_wallet_transactions(
        provider,
        task.key,
        from_block=task.from_block,
        to_block=task.to_block,
        max_transactions=budget.max_signer_transactions,
    )
    if found.signed_in_window is None:
        outcome.status, outcome.reason = "failed", found.note
        return []
    if found.unlocated:
        outcome.status = "partial"
        outcome.truncated.append(
            f"{found.unlocated} of {found.signed_in_window} signed transactions in the window "
            f"not read (limit {budget.max_signer_transactions}; newest kept)"
        )
    out: list[tuple[dict[str, Any], str | None]] = []
    for tx in found.transactions:
        meter.check()
        receipt = await provider.get_transaction_receipt(tx.transaction_hash)
        logs = [entry for entry in (receipt or {}).get("logs", []) if isinstance(entry, dict)]
        if len(logs) > budget.max_logs_per_transaction:
            outcome.truncated.append(
                f"{tx.transaction_hash}: {len(logs)} logs, first "
                f"{budget.max_logs_per_transaction} examined"
            )
            logs = logs[: budget.max_logs_per_transaction]
        out.extend((entry, task.key) for entry in logs)
    return out


async def _candidates(
    provider: EthereumProvider,
    task: ExpansionTask,
    logs: list[tuple[dict[str, Any], str | None]],
    meter: _Meter,
    budget: ExpansionBudget,
    config: PoisoningConfig,
    known_victims: set[str],
    new_victims: set[str],
    outcome: TaskOutcome,
) -> None:
    events: list[tuple[TransferEvent, str | None]] = []
    for log, signer in logs:
        shape, event = classify_transfer_log(log)
        if shape is LogShape.ERC20 and event is not None and event.block_number <= task.to_block:
            events.append((event, signer))
    senders: dict[str, str | None] = {}
    verified: dict[tuple[str, str], tuple[str | None, VerifyStatus]] = {}
    for event, signer in sorted(events, key=lambda x: (x[0].position, x[0].transaction_hash)):
        hypotheses: list[tuple[str, str, bool]] = []  # (victim, lookalike, outgoing)
        if task.kind == "lookalike_logs":
            lookalike = task.key
            if event.recipient == lookalike:
                hypotheses.append((event.sender, lookalike, True))
            if event.sender == lookalike:
                hypotheses.append((event.recipient, lookalike, False))
        else:  # signer task: either side may be the victim
            hypotheses += [
                (event.sender, event.recipient, True),
                (event.recipient, event.sender, False),
            ]
        for victim, lookalike, outgoing in hypotheses:
            if victim in BURN_ADDRESSES or lookalike in BURN_ADDRESSES or victim == lookalike:
                continue
            if signer is not None and victim == signer:
                continue  # the signer moving its own tokens is not planting
            unseen = victim not in known_victims and victim not in new_victims
            if unseen and len(new_victims) >= budget.max_new_victims:
                outcome.truncated.append("new-victim limit reached")
                return
            tx_signer = signer
            if tx_signer is None and outgoing:
                if event.transaction_hash not in senders:
                    meter.check()
                    tx = await provider.get_transaction(event.transaction_hash)
                    try:
                        senders[event.transaction_hash] = to_checksum_address(
                            (tx or {}).get("from")
                        )
                    except InvalidAddressError:
                        senders[event.transaction_hash] = None
                tx_signer = senders[event.transaction_hash]
            if outgoing and tx_signer == victim:
                continue  # the victim really sent this: a payment, not a planting event
            kind: EventType = (
                "zero_value_transfer"
                if event.value == 0
                else "spoofed_outgoing_transfer"
                if outgoing
                else "unsolicited_incoming_transfer"
            )
            pair = (victim, lookalike)
            imitated: str | None
            status: VerifyStatus
            if pair in verified:
                imitated, status = verified[pair]
            elif len(verified) >= budget.max_verifications_per_task:
                imitated, status = None, "not_checked"
                if "verification limit reached" not in outcome.truncated:
                    outcome.truncated.append("verification limit reached")
            else:
                imitated, status = await _verify(
                    provider, victim, lookalike, event, meter, budget, config
                )
                verified[pair] = (imitated, status)
            if status == "verified" and victim not in known_victims:
                new_victims.add(victim)
            outcome.candidates.append(
                Candidate(
                    victim=victim,
                    lookalike=lookalike,
                    event_type=kind,
                    transaction_hash=event.transaction_hash,
                    block_number=event.block_number,
                    block_hash=event.block_hash,
                    transaction_index=event.transaction_index,
                    log_index=event.log_index,
                    contract=event.token,
                    log_from=event.sender,
                    log_to=event.recipient,
                    value=event.value,
                    signer=tx_signer,
                    imitated=imitated,
                    status=status,
                )
            )


async def _verify(
    provider: EthereumProvider,
    victim: str,
    lookalike: str,
    event: TransferEvent,
    meter: _Meter,
    budget: ExpansionBudget,
    config: PoisoningConfig,
) -> tuple[str | None, Literal["verified", "no_matching_payment"]]:
    """The detector's criterion, bounded: did the victim send to an address the lookalike
    resembles, shortly before the event?"""
    low = max(0, event.block_number - budget.verify_window_blocks)
    meter.check(2)
    scan = await scan_logs(
        provider,
        topics=[TRANSFER_TOPIC, address_topic(victim)],
        from_block=low,
        to_block=event.block_number,
        chunk_blocks=budget.chunk_blocks,
        max_requests=4,
    )
    for log in scan.logs:
        shape, payment = classify_transfer_log(log)
        if shape is not LogShape.ERC20 or payment is None or payment.value == 0:
            continue
        if payment.position >= event.position or payment.recipient == lookalike:
            continue
        if is_lookalike(lookalike, payment.recipient, config) is not None:
            return payment.recipient, "verified"
    return None, "no_matching_payment"


async def _find_deployer(
    provider: EthereumProvider, task: ExpansionTask, meter: _Meter
) -> tuple[Deployer | None, str | None]:
    contract = task.key
    low, high = task.from_block, task.to_block
    meter.check()
    if not await provider.get_code(contract, high):
        return None, f"no code at block {high}"
    while low < high:  # first block with code
        meter.check()
        mid = (low + high) // 2
        if await provider.get_code(contract, mid):
            high = mid
        else:
            low = mid + 1
    meter.check(2)
    for tx in await provider.get_block_transactions(low):
        if tx.get("to") not in (None, ""):
            continue
        meter.check()
        receipt = await provider.get_transaction_receipt(str(tx.get("hash")))
        created = (receipt or {}).get("contractAddress")
        try:
            if created and to_checksum_address(created) == contract:
                return (
                    Deployer(to_checksum_address(tx.get("from")), low, str(tx.get("hash"))),
                    None,
                )
        except InvalidAddressError:
            continue
    return None, (
        f"created in block {low} by another contract (internal creation); the deploying "
        "account needs execution traces, which standard JSON-RPC does not provide"
    )


# --- serialization (checkpoints and recorded fixtures) -------------------------------------


def outcome_to_dict(o: TaskOutcome) -> dict[str, Any]:
    return {
        "task": asdict(o.task),
        "status": o.status,
        "requests": o.requests,
        "candidates": [asdict(c) for c in o.candidates],
        "deployer": asdict(o.deployer) if o.deployer else None,
        "reason": o.reason,
        "truncated": o.truncated,
    }


def outcome_from_dict(d: Mapping[str, Any]) -> TaskOutcome:
    return TaskOutcome(
        task=ExpansionTask(**d["task"]),
        status=d["status"],
        requests=int(d["requests"]),
        candidates=[Candidate(**c) for c in d["candidates"]],
        deployer=Deployer(**d["deployer"]) if d.get("deployer") else None,
        reason=d.get("reason"),
        truncated=list(d.get("truncated", [])),
    )

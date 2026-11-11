"""Offline candidate generation and point-in-time event features (task ``poisoning-attempt/1``).

The generator turns a wallet's recorded observations into candidate poisoning events. It is
deliberately independent of the production detector (``detectors.poisoning``) and of any
model score: its rules are looser and purely structural, so a model scored on its output can
find events the detector never considered, and candidate recall can be measured separately
from classifier recall.

Rules (an event may match several; ``methods`` lists them):

- ``zero_value_in``: an incoming token transfer of value 0.
- ``spoofed_out``: a transfer out of the wallet in a transaction the wallet did not sign.
- ``lookalike_in``: an incoming transfer from an address that shares at least
  ``MIN_AFFIX`` leading+trailing hex characters (``MIN_SUFFIX`` trailing) with a counterparty
  the wallet itself chose before the event.
- ``untrusted_token_in``: an incoming transfer from a token outside the reviewed list whose
  sender matches ``lookalike_in`` (a fake-token planting).
- ``dust_in``: an incoming transfer of a reviewed stablecoin below ``DUST_MAX_BASE_UNITS``.

Cutoff: an event is scored after its own transaction executes and before anything later in
the same block (``history.Boundary`` ``pre_execution``, with the event's transaction
excluded). Features see only strictly earlier positions; the cross-wallet index sees only
earlier blocks.

``candidates/2`` (Phase 11.5) counts a counterparty as *chosen* only when the wallet's
signature is verified (``wallet_signed is True``). ``candidates/1`` also counted outgoing
transfers whose signer was unknown, so under partial coverage a spoofed transfer to a
lookalike could become the "imitated" counterparty. No recorded fixture has such a
transfer, so no published number changes. The generator is now one pass instead of one
history scan per transfer.

Known breadth (documented, not a defect): ``spoofed_out`` also fires on legitimate
transfers pulled by an approved spender (routers, settlement contracts, Permit2), and
``dust_in`` on genuine small test payments. These are hard-negative candidates, never
labels.
"""

from __future__ import annotations

import time
import tracemalloc
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from cryptoguard.detectors.poisoning import affix_match
from cryptoguard.ml.events import PoisoningEvent, Subtype
from cryptoguard.ml.history import (
    Coverage,
    HistoryFeatures,
    WalletEvent,
    events_from_fixture,
    history_features,
)
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.replay.models import ReplayFixture

CANDIDATE_VERSION = "candidates/2"
EVENT_FEATURE_VERSION = "event-features/1"
MIN_AFFIX = 6
MIN_SUFFIX = 3
DUST_MAX_BASE_UNITS = 10_000  # 0.01 of a 6-decimal stablecoin
STABLECOINS = frozenset(
    {"0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}
)
RECENT_BLOCKS = 7_200  # about one day


def similar(a: str, b: str) -> tuple[int, int] | None:
    """The ``lookalike_in`` similarity rule: (prefix, suffix) when it matches, else None."""
    if a == b:
        return None
    prefix, suffix = affix_match(a, b)
    return (prefix, suffix) if prefix + suffix >= MIN_AFFIX and suffix >= MIN_SUFFIX else None


def transfer_methods(
    *,
    incoming: bool,
    outgoing: bool,
    value: int,
    token: str,
    wallet_signed: bool | None,
    matched: bool,
) -> list[str]:
    """The candidate rules that fire for one transfer seen from the wallet (see the module
    docstring). ``wallet_signed`` is None when the transaction signer is unknown; ``matched`` is
    whether the counterparty passes ``similar`` against a counterparty chosen earlier."""
    methods: list[str] = []
    if incoming and value == 0:
        methods.append("zero_value_in")
    if outgoing and wallet_signed is False:
        methods.append("spoofed_out")
    if incoming and matched:
        methods.append("lookalike_in")
        if token not in TRUSTED_TOKENS:
            methods.append("untrusted_token_in")
    if incoming and token in STABLECOINS and 0 < value <= DUST_MAX_BASE_UNITS:
        methods.append("dust_in")
    return methods


@dataclass(frozen=True)
class Candidate:
    event: PoisoningEvent
    methods: tuple[str, ...]
    value: int
    best_match: tuple[int, int] | None  # (prefix, suffix) to the imitated counterparty


def _chosen_before(events: list[WalletEvent], position: tuple[int, int, int]) -> dict[str, int]:
    """Counterparties the wallet chose (outgoing events it verifiably signed) strictly before
    ``position``, with the block they were last chosen."""
    chosen: dict[str, int] = {}
    for e in sorted(events, key=lambda e: e.position):
        if e.position < position and _chose(e):
            chosen[e.counterparty.lower()] = e.block
    return chosen


def _chose(e: WalletEvent) -> bool:
    return e.direction == "out" and e.wallet_signed is True


def generate(fixture: ReplayFixture, *, chain_id: int = 1) -> list[Candidate]:
    """Candidate events from one recorded wallet window, in chain order."""
    wallet = fixture.wallet.lower()
    events, coverage = events_from_fixture(fixture)
    choices = sorted((e for e in events if _chose(e)), key=lambda e: e.position)
    status = "complete" if coverage.complete else "partial"
    out: list[Candidate] = []
    # Strictly earlier choices, bucketed by their last MIN_SUFFIX characters: ``similar``
    # needs at least that suffix in common, so no other bucket can ever match (exact).
    chosen: dict[str, dict[str, int]] = defaultdict(dict)
    next_choice = 0
    for t in sorted(
        fixture.transfers, key=lambda t: (t.block_number, t.transaction_index, t.log_index)
    ):
        position = (t.block_number, t.transaction_index, t.log_index)
        while next_choice < len(choices) and choices[next_choice].position < position:
            e = choices[next_choice]
            k = e.counterparty.lower()
            chosen[k[-MIN_SUFFIX:]][k] = e.block
            next_choice += 1
        incoming = t.recipient.lower() == wallet
        outgoing = t.sender.lower() == wallet
        if not (incoming or outgoing):
            continue
        token = t.token.lower()
        value = int(t.value)
        party = (t.sender if incoming else t.recipient).lower()
        match = max(
            ((k, m) for k in chosen.get(party[-MIN_SUFFIX:], {}) if (m := similar(party, k))),
            key=lambda km: (sum(km[1]), km[1][1], km[0]),
            default=None,
        )
        methods = transfer_methods(
            incoming=incoming,
            outgoing=outgoing,
            value=value,
            token=token,
            wallet_signed=None if t.tx_sender is None else t.tx_sender.lower() == wallet,
            matched=match is not None,
        )
        if not methods:
            continue
        out.append(
            Candidate(
                event=PoisoningEvent(
                    chain_id=chain_id,
                    victim=wallet,
                    lookalike=party,
                    imitated=match[0] if match else None,
                    planting_tx=t.transaction_hash.lower(),
                    planting_block=t.block_number,
                    planting_tx_index=t.transaction_index,
                    planting_log_index=t.log_index,
                    observation_timestamp=None,
                    subtype=_subtype(methods),
                    tx_signer=None if t.tx_sender is None else t.tx_sender.lower(),
                    log_contract=token,
                    token_contract=token if token in TRUSTED_TOKENS else None,
                    candidate_method=CANDIDATE_VERSION + ":" + "+".join(methods),
                    evidence_refs=(f"fixture:{fixture.case_id}",),
                    coverage=status,
                ),
                methods=tuple(methods),
                value=value,
                best_match=match[1] if match else None,
            )
        )
    return out


def _subtype(methods: list[str]) -> Subtype:
    if "spoofed_out" in methods:
        return "spoofed_transfer_from"
    if "zero_value_in" in methods:
        return "zero_value"
    if "untrusted_token_in" in methods:
        return "fake_token"
    if "dust_in" in methods:
        return "dust"
    return "other"


@dataclass
class PriorIndex:
    """Cross-wallet relations, queried strictly before a block (no same-block leakage)."""

    seen: dict[tuple[str, str], list[tuple[int, str]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def add(self, e: PoisoningEvent) -> None:
        for kind, key in (("lookalike", e.lookalike), ("signer", e.tx_signer)):
            if key:
                self.seen[(kind, key)].append((e.planting_block, e.victim))

    def distinct_victims_before(self, kind: str, key: str | None, block: int) -> int | None:
        if key is None:
            return None
        return len({v for b, v in self.seen.get((kind, key), []) if b < block})


@dataclass(frozen=True)
class EventFeatures:
    feature_version: str
    history: HistoryFeatures
    subtype: str
    value_is_zero: bool
    token_trusted: bool
    prefix_to_imitated: int | None
    suffix_to_imitated: int | None
    plausible_impersonated: int | None  # chosen counterparties the sender resembles
    blocks_since_imitated_chosen: int | None
    recent_unsolicited_in: int | None
    observed_blocks: int | None
    lookalike_victims_before: int | None
    signer_victims_before: int | None

    def as_model_row(self) -> dict[str, float]:
        row = self.history.as_model_row()
        for key, value in asdict(self).items():
            if key in ("feature_version", "history", "subtype"):
                continue
            row[key] = -1.0 if value is None else float(value)
        for sub in ("zero_value", "dust", "fake_token", "spoofed_transfer_from", "other"):
            row[f"subtype_{sub}"] = float(self.subtype == sub)
        return row


def event_features(
    c: Candidate,
    events: list[WalletEvent],
    coverage: Coverage | None,
    index: PriorIndex | None = None,
) -> EventFeatures:
    """Features of candidate ``c`` from events strictly before its transaction."""
    e = c.event
    tx_index = e.planting_tx_index if e.planting_tx_index is not None else 0
    hist = history_features(
        events,
        coverage,
        recipient=e.lookalike,
        block=e.planting_block,
        tx_index=tx_index,
        boundary="pre_execution" if e.planting_tx_index is not None else "pre_signing",
    )
    known = hist.history_status == "available"
    position = (e.planting_block, tx_index, -2)  # before the event's own transaction
    visible = [x for x in events if (x.block, x.tx_index) < (e.planting_block, tx_index)]
    chosen = _chosen_before(visible, position) if known else {}
    recent = (
        sum(
            1
            for x in visible
            if x.direction == "in" and not x.value and x.block > e.planting_block - RECENT_BLOCKS
        )
        if known
        else None
    )
    return EventFeatures(
        feature_version=EVENT_FEATURE_VERSION,
        history=hist,
        subtype=e.subtype,
        value_is_zero=c.value == 0,
        token_trusted=(e.log_contract or "") in TRUSTED_TOKENS,
        prefix_to_imitated=c.best_match[0] if c.best_match else None,
        suffix_to_imitated=c.best_match[1] if c.best_match else None,
        plausible_impersonated=sum(1 for k in chosen if similar(e.lookalike, k)) if known else None,
        blocks_since_imitated_chosen=(
            e.planting_block - chosen[e.imitated] if known and e.imitated in chosen else None
        ),
        recent_unsolicited_in=recent,
        observed_blocks=None if coverage is None else e.planting_block - coverage.from_block,
        lookalike_victims_before=None
        if index is None
        else index.distinct_victims_before("lookalike", e.lookalike, e.planting_block),
        signer_victims_before=None
        if index is None
        else index.distinct_victims_before("signer", e.tx_signer, e.planting_block),
    )


@dataclass(frozen=True)
class GenerationStats:
    candidates: int
    by_method: dict[str, int]
    duplicate_identities: int
    runtime_ms: float
    peak_kib: float


def generate_with_stats(fixture: ReplayFixture) -> tuple[list[Candidate], GenerationStats]:
    tracemalloc.start()
    t0 = time.perf_counter()
    cands = generate(fixture)
    runtime = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    by_method: dict[str, int] = defaultdict(int)
    for c in cands:
        for m in c.methods:
            by_method[m] += 1
    ids = [c.event.victim_event_id for c in cands]
    return cands, GenerationStats(
        candidates=len(cands),
        by_method=dict(sorted(by_method.items())),
        duplicate_identities=len(ids) - len(set(ids)),
        runtime_ms=round(runtime, 2),
        peak_kib=round(peak / 1024, 1),
    )

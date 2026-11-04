"""Shadow poisoning-candidate discovery (``poisoning-candidate-discovery/1``), research only.

Protocol 12.4 compares three variants on one wallet window, at one cutoff:

- **C0**: the frozen generator (``ml.candidates.generate``, ``candidates/2``) on the fixture
  trimmed to the cutoff. Unchanged.
- **C1**: C0's own rules (``similar``, ``zero_value_in``, ``spoofed_out``,
  ``untrusted_token_in``, ``dust_in``) applied to every class the window actually observed:
  ERC-20 transfers, and with ``observation/2`` also native ETH received and ERC-721-shaped
  transfers. No rule is new, so C1 minus C0 is what the extra observations buy.
- **C2**: C1 plus two semantic rules motivated by the Stage 2a miss (``motivated-by: P3``):
  *abstention* (when the wallet's references are not fully observed, say so instead of
  reporting "no candidate") and a *payment-time screen* (``screen_payment``): at the moment
  the wallet signs a payment, its recipient is checked against the wallet's own earlier
  references with the same similarity rule. The recipient there is the user's pending input,
  never an outcome label, and the screen needs no planting observation.

Observations keep their type and provenance: a counterfeit token emitting a Transfer "from"
the wallet is an ERC-20 log with a foreign signer, not a wallet-signed payment, and a
balance increase without an external sender (``unattributed_inbound``) names no one, so it
is reported but never becomes a candidate. Events are identified by (transaction hash, log
index), with -1 for a transaction's own value, and duplicates are dropped.

Nothing here is a probability or a verdict: a candidate is a *suspicious lookalike
candidate*. The production detector stays authoritative and is not called or changed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptoguard.ml.candidates import (
    DUST_MAX_BASE_UNITS,
    MIN_SUFFIX,
    STABLECOINS,
    similar,
)
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.replay.observation import coverage_of

DISCOVERY_VERSION = "poisoning-candidate-discovery/1"
SCOPED_HISTORY_VERSION = "wallet-history/2-scoped"
Kind = Literal["erc20", "native", "nft"]
Variant = Literal["C0", "C1", "C2"]
# Categories a complete *inbound* history needs: without them, "never received from X" is
# not an observed zero. Zero-value native transactions and internal transfers can never be
# fully observed here (no balance change; no traces), so even a complete inbound scope says
# nothing about them (``INBOUND_SCOPE``).
INBOUND_CATEGORIES = ("erc20_transfer_logs", "erc721_transfer_logs", "native_inbound_external")
INBOUND_SCOPE = (
    "ERC-20, ERC-721-shaped and nonzero native transfers; zero-value native transactions "
    "and internal transfers unobserved"
)
REFERENCE_CATEGORIES = (
    "erc20_transfer_logs",
    "erc20_outgoing_signers",
    "wallet_signed_transactions",
)


@dataclass(frozen=True)
class Observation:
    kind: Kind
    direction: Literal["in", "out"]
    counterparty: str
    value: int
    block: int
    tx_index: int
    log_index: int  # -1: the transaction's own value
    tx_hash: str
    signer: str | None  # the transaction's tx.from, when known
    wallet_signed: bool | None
    emitter: str | None  # the log's contract; None for a native value
    succeeded: bool | None  # None: not read (logs exist only for executed transactions)

    @property
    def identity(self) -> tuple[str, int]:
        return (self.tx_hash.lower(), self.log_index)

    @property
    def position(self) -> tuple[int, int, int]:
        return (self.block, self.tx_index, self.log_index)


def observations(fixture: Any) -> list[Observation]:
    """Every observed wallet event, typed, deduplicated by identity, in chain order."""
    wallet = fixture.wallet.lower()
    out: list[Observation] = []
    for t in fixture.transfers:
        s, r = t.sender.lower(), t.recipient.lower()
        if s == r:
            continue  # a self-transfer names no counterparty
        signer = None if t.tx_sender is None else t.tx_sender.lower()
        if s == wallet:
            direction, party = "out", r
        elif r == wallet:
            direction, party = "in", s
        else:
            continue
        out.append(
            Observation(
                "erc20",
                direction,  # type: ignore[arg-type]
                party,
                int(t.value),
                t.block_number,
                t.transaction_index,
                t.log_index,
                t.transaction_hash,
                signer,
                None if signer is None or direction == "in" else signer == wallet,
                t.token.lower(),
                None,
            )
        )
    for tx in fixture.wallet_transactions:
        if tx.to and int(tx.value):
            out.append(
                Observation(
                    "native",
                    "out",
                    tx.to.lower(),
                    int(tx.value),
                    tx.block_number,
                    tx.transaction_index,
                    -1,
                    tx.transaction_hash,
                    wallet,
                    True,
                    None,
                    tx.succeeded,
                )
            )
    for n in getattr(fixture, "native_inbound", None) or []:
        if n.sender.lower() == wallet:
            continue
        out.append(
            Observation(
                "native",
                "in",
                n.sender.lower(),
                int(n.value),
                n.block_number,
                n.transaction_index,
                -1,
                n.transaction_hash,
                n.sender.lower(),
                False,
                None,
                n.succeeded,
            )
        )
    for f in getattr(fixture, "nft_transfers", None) or []:
        s, r = f.sender.lower(), f.recipient.lower()
        if s == r or wallet not in (s, r):
            continue
        out.append(
            Observation(
                "nft",
                "out" if s == wallet else "in",
                r if s == wallet else s,
                0,
                f.block_number,
                f.transaction_index,
                f.log_index,
                f.transaction_hash,
                None,
                None,
                f.token.lower(),
                None,
            )
        )
    unique: dict[tuple[str, int], Observation] = {}
    for o in out:
        unique.setdefault(o.identity, o)
    return sorted(unique.values(), key=lambda o: (o.position, o.tx_hash))


@dataclass(frozen=True)
class DiscoveryCandidate:
    lookalike: str
    imitated: str | None
    methods: tuple[str, ...]
    kind: Kind
    evidence: str  # "tx:<hash>:<log index>"
    position: tuple[int, int, int]
    affix: tuple[int, int] | None
    description: str = "suspicious lookalike candidate"


@dataclass(frozen=True)
class DiscoveryResult:
    version: str
    variant: Variant
    cutoff: tuple[int, int]  # observations strictly before (block, tx index) are used
    candidates: list[DiscoveryCandidate]
    coverage: dict[str, str]
    missing_categories: list[str]
    abstain: str | None = None
    unattributed_inbound_blocks: list[int] = field(default_factory=list)

    @property
    def lookalikes(self) -> set[str]:
        return {c.lookalike for c in self.candidates}


def _before(o: Observation, cutoff: tuple[int, int]) -> bool:
    return (o.block, o.tx_index) < cutoff


def _methods(o: Observation, match: tuple[int, int] | None) -> list[str]:
    """C0's ``transfer_methods``, applied to any observed class (C1)."""
    m: list[str] = []
    if o.succeeded is False:
        return m  # a reverted transaction moved nothing
    if o.direction == "in" and o.value == 0 and o.kind != "nft":
        m.append("zero_value_in")
    if o.direction == "out" and o.kind == "erc20" and o.wallet_signed is False:
        m.append("spoofed_out")
    if o.direction == "in" and match is not None:
        m.append("lookalike_in")
        if o.kind == "erc20" and o.emitter not in TRUSTED_TOKENS:
            m.append("untrusted_token_in")
    if (
        o.direction == "in"
        and o.kind == "erc20"
        and o.emitter in STABLECOINS
        and 0 < o.value <= DUST_MAX_BASE_UNITS
    ):
        m.append("dust_in")
    return m


def _references(obs: Iterable[Observation]) -> dict[str, dict[str, int]]:
    """Counterparties the wallet verifiably chose, bucketed by their last MIN_SUFFIX
    characters (as C0 does): wallet-signed outgoing events, reverted sends included."""
    chosen: dict[str, dict[str, int]] = {}
    for o in obs:
        if o.direction == "out" and o.wallet_signed is True:
            chosen.setdefault(o.counterparty[-MIN_SUFFIX:], {})[o.counterparty] = o.block
    return chosen


def _match(party: str, chosen: dict[str, dict[str, int]]) -> tuple[str, tuple[int, int]] | None:
    best = None
    for k in chosen.get(party[-MIN_SUFFIX:], {}):
        m = similar(party, k)
        if m is not None and (
            best is None or (sum(m), m[1], k) > (sum(best[1]), best[1][1], best[0])
        ):
            best = (k, m)
    return best


def discover(fixture: Any, *, cutoff: tuple[int, int], variant: Variant = "C1") -> DiscoveryResult:
    """Candidates from observations strictly before ``cutoff`` = (block, tx index)."""
    cov = coverage_of(fixture)
    coverage: dict[str, str] = {k: str(v.status) for k, v in cov.categories.items()}
    missing = sorted(k for k, s in coverage.items() if s != "complete")
    if variant == "C0":
        return _c0(fixture, cutoff, coverage, missing)
    obs = [o for o in observations(fixture) if _before(o, cutoff)]
    chosen: dict[str, dict[str, int]] = {}
    found: list[DiscoveryCandidate] = []
    for o in obs:  # chain order: a reference counts only for later events
        match = _match(o.counterparty, chosen) if o.direction == "in" else None
        methods = _methods(o, match[1] if match else None)
        if methods:
            found.append(
                DiscoveryCandidate(
                    lookalike=o.counterparty,
                    imitated=match[0] if match else None,
                    methods=tuple(methods),
                    kind=o.kind,
                    evidence=f"tx:{o.tx_hash.lower()}:{o.log_index}",
                    position=o.position,
                    affix=match[1] if match else None,
                )
            )
        if o.direction == "out" and o.wallet_signed is True:
            chosen.setdefault(o.counterparty[-MIN_SUFFIX:], {})[o.counterparty] = o.block
    unattributed = sorted(
        u.block_number
        for u in getattr(fixture, "unattributed_inbound", None) or []
        if (u.block_number, 0) < cutoff
    )
    abstain = None
    if variant == "C2":
        if not cov.complete(*REFERENCE_CATEGORIES):
            abstain = "insufficient history: the wallet's own references are not fully observed"
        elif not chosen:
            abstain = (
                "no reference observed in the window; history before the window is unobserved, "
                "so this is not evidence of no earlier recipients"
            )
    return DiscoveryResult(
        DISCOVERY_VERSION, variant, cutoff, found, coverage, missing, abstain, unattributed
    )


def _c0(
    fixture: Any, cutoff: tuple[int, int], coverage: dict[str, str], missing: list[str]
) -> DiscoveryResult:
    from cryptoguard.ml import candidates as c0

    trimmed = fixture.model_copy(
        update={
            "transfers": [
                t for t in fixture.transfers if (t.block_number, t.transaction_index) < cutoff
            ],
            "wallet_transactions": [
                t
                for t in fixture.wallet_transactions
                if (t.block_number, t.transaction_index) < cutoff
            ],
        }
    )
    found = [
        DiscoveryCandidate(
            lookalike=c.event.lookalike,
            imitated=c.event.imitated,
            methods=c.methods,
            kind="erc20",
            evidence=f"tx:{c.event.planting_tx}:{c.event.planting_log_index}",
            position=(
                c.event.planting_block,
                c.event.planting_tx_index or 0,
                c.event.planting_log_index or 0,
            ),
            affix=c.best_match,
        )
        for c in c0.generate(trimmed)
    ]
    return DiscoveryResult(DISCOVERY_VERSION, "C0", cutoff, found, coverage, missing)


@dataclass(frozen=True)
class PaymentScreen:
    recipient: str
    flagged: bool | None  # None: abstained (references not fully observed)
    imitated: str | None
    affix: tuple[int, int] | None
    recipient_seen_before: bool | None  # None when inbound history is not fully observed
    reason: str


def screen_payment(fixture: Any, *, recipient: str, cutoff: tuple[int, int]) -> PaymentScreen:
    """C2's payment-time screen for a payment the wallet is about to sign to ``recipient``:
    does the recipient imitate one of the wallet's own earlier references, and has the
    wallet ever dealt with it? Uses observations strictly before ``cutoff`` only."""
    recipient = recipient.lower()
    cov = coverage_of(fixture)
    obs = [o for o in observations(fixture) if _before(o, cutoff)]
    chosen = _references(obs)
    if not cov.complete(*REFERENCE_CATEGORIES):
        return PaymentScreen(recipient, None, None, None, None, "abstain: references incomplete")
    if not chosen:
        return PaymentScreen(
            recipient, None, None, None, None, "abstain: no reference observed in the window"
        )
    if recipient in {k for b in chosen.values() for k in b}:
        return PaymentScreen(recipient, False, None, None, True, "a reference the wallet chose")
    match = _match(recipient, chosen)
    seen = any(o.counterparty == recipient for o in obs)
    seen_before: bool | None = (
        True if seen else False if cov.complete(*INBOUND_CATEGORIES) else None
    )
    if match is None:
        return PaymentScreen(recipient, False, None, None, seen_before, "no reference imitated")
    return PaymentScreen(
        recipient,
        True,
        match[0],
        match[1],
        seen_before,
        "recipient imitates an earlier reference"
        + ("" if seen_before is not None else "; earlier inbound contact not fully observable"),
    )


INBOUND_DEPENDENT = (
    "prior_interactions_with_recipient",
    "blocks_since_first_interaction",
    "blocks_since_last_interaction",
    "unsolicited_events_with_recipient",
    "lookalike_plantings_observed",
)


def scoped_history(fixture: Any, *, recipient: str, block: int, tx_index: int) -> dict[str, Any]:
    """``wallet-history/1`` features with category scope: a feature that counts inbound
    events is None unless every inbound category was fully observed (``/1`` reports those
    as observed counts whenever the ERC-20 scan was complete)."""
    from dataclasses import asdict

    from cryptoguard.ml.history import events_from_fixture, history_features

    events, window = events_from_fixture(fixture)
    feats = asdict(
        history_features(
            events,
            window,
            recipient=recipient,
            block=block,
            tx_index=tx_index,
            boundary="pre_execution",
        )
    )
    inbound_ok = coverage_of(fixture).complete(*INBOUND_CATEGORIES)
    if not inbound_ok:
        feats |= dict.fromkeys(INBOUND_DEPENDENT, None)
    feats["feature_version"] = SCOPED_HISTORY_VERSION
    feats["inbound_scope_complete"] = inbound_ok
    feats["inbound_scope"] = INBOUND_SCOPE if inbound_ok else None
    return feats


def compare(a: DiscoveryResult, b: DiscoveryResult) -> dict[str, list[str]]:
    """Candidate-set differences by lookalike address (protocol 12.4 §6)."""
    return {
        "added": sorted(b.lookalikes - a.lookalikes),
        "removed": sorted(a.lookalikes - b.lookalikes),
        "kept": sorted(a.lookalikes & b.lookalikes),
    }


def signer_links(results: Sequence[tuple[str, Any, DiscoveryResult]]) -> list[tuple[str, str, str]]:
    """Cross-wallet links between candidates only through a shared planting *signer* (never
    a shared token contract, which anyone can use): (wallet a, wallet b, signer)."""
    by_signer: dict[str, set[str]] = {}
    for wallet, fixture, res in results:
        evidence = {c.evidence for c in res.candidates}
        for o in observations(fixture):
            ref = f"tx:{o.tx_hash.lower()}:{o.log_index}"
            if ref in evidence and o.signer and o.signer != wallet.lower():
                by_signer.setdefault(o.signer, set()).add(wallet.lower())
    return sorted((a, b, s) for s, ws in by_signer.items() for a in ws for b in ws if a < b)

"""Evidence-preserving candidate groups and a bounded summary (``candidate-evidence/1``),
research only (protocol 12.6).

Every candidate is a group identified by (chain, victim, lookalike) that keeps **every**
distinct evidence record that caused it, in chain order, each with typed provenance:

- ``signer_status``: ``wallet``, ``foreign_known`` (looked-up signer, not the wallet),
  ``foreign_identity_unknown`` (rule R-SIG: the transaction is absent from the wallet's
  complete signed set and the wallet has no code, so the wallet did not sign it, but who did
  is unknown), ``lookalike_itself`` (a native transfer the lookalike sent) or ``unknown``.
  The event's ``from`` field is never taken as the signer.
- ``event_sender`` / ``event_recipient``: what the log or transaction reports.
- ``emitter``: the token contract (``None`` when unknown); never an attacker identity.
- ``receipt``: ``succeeded``, ``reverted``, ``implied_by_log`` (a log exists only for an
  executed transaction) or ``unknown``.

Evidence levels are categories, not probabilities: ``directly_verified``, ``supported``,
``partially_supported`` (see ``LEVELS``). Missing information lowers the support level and
is listed in ``missing``; it never raises suspicion. The summary shows a bounded top-k
with the totals, a truncation flag and the hidden identities: a display budget is not an
evidence budget, and hidden candidates are not assessed as safe. The production detector
is never consulted or changed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml.candidates import DUST_MAX_BASE_UNITS, MIN_SUFFIX, STABLECOINS, similar
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.replay.observation import coverage_of

EVIDENCE_VERSION = "candidate-evidence/1"
LEVELS = ("directly_verified", "supported", "partially_supported")
SignerStatus = Literal[
    "wallet", "foreign_known", "foreign_identity_unknown", "lookalike_itself", "unknown"
]
Receipt = Literal["succeeded", "reverted", "implied_by_log", "unknown"]
HIDDEN_NOTE = "hidden candidates are not assessed as safe; all evidence remains in the result"


@dataclass(frozen=True)
class EvidenceRecord:
    identity: str  # "tx:<hash>:<log index>", -1 for a transaction's own value
    kind: str
    direction: str
    block: int
    tx_index: int
    log_index: int
    mechanisms: tuple[str, ...]
    level: str
    signer_status: SignerStatus
    signer: str | None  # only a looked-up or self-evident address, never inferred
    event_sender: str
    event_recipient: str
    emitter: str | None
    receipt: Receipt
    value_zero: bool
    missing: tuple[str, ...]


@dataclass(frozen=True)
class CandidateGroup:
    identity: str  # "<chain>:<victim>:<lookalike>"
    chain_id: int
    victim: str
    lookalike: str
    references: tuple[tuple[str, int, int], ...]  # (imitated reference, prefix, suffix)
    mechanisms: tuple[str, ...]
    kinds: tuple[str, ...]
    level: str
    affix: int | None  # best prefix + suffix to an imitated reference
    first_position: tuple[int, int, int]
    last_position: tuple[int, int, int]
    evidence: tuple[EvidenceRecord, ...]
    missing: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceResult:
    version: str
    chain_id: int
    victim: str
    cutoff: tuple[int, int]
    groups: tuple[CandidateGroup, ...]  # in the research order
    raw_events: int  # observation records before deduplication
    evidence_records: int  # distinct records linked to groups
    signers_recovered: int  # unknown signers resolved by R-SIG
    unattributable_events: int  # records that could not be placed relative to the wallet
    abstain: str | None
    coverage: dict[str, str]


def _plain_eoa(fixture: Any, cutoff_block: int) -> bool:
    known = {int(b): c for b, c in fixture.wallet_code_hex.items() if int(b) <= cutoff_block}
    return bool(known) and known[max(known)] == "0x"


def raw_event_count(fixture: Any) -> int:
    """Wallet observation records before deduplication (what an ingestion produced)."""
    w = fixture.wallet.lower()
    n = sum(
        1
        for t in fixture.transfers
        if w in (t.sender.lower(), t.recipient.lower()) and t.sender.lower() != t.recipient.lower()
    )
    n += sum(1 for t in fixture.wallet_transactions if t.to and int(t.value))
    n += sum(1 for x in fixture.native_inbound or [] if x.sender.lower() != w)
    n += sum(1 for x in fixture.nft_transfers or [] if w in (x.sender.lower(), x.recipient.lower()))
    return n


def build(
    fixture: Any,
    *,
    cutoff: tuple[int, int],
    observations: Sequence[cd.Observation] | None = None,
    signed: Iterable[str] | None = None,
    wallet_tx_complete: bool | None = None,
) -> EvidenceResult:
    """Evidence groups from observations strictly before ``cutoff``. ``observations``,
    ``signed`` and ``wallet_tx_complete`` can be supplied (masking experiments); by default
    they come from the fixture."""
    cov = coverage_of(fixture)
    wallet = fixture.wallet.lower()
    obs = [
        o
        for o in (observations if observations is not None else cd.observations(fixture))
        if (o.block, o.tx_index) < cutoff
    ]
    signed_set = {
        h.lower()
        for h in (
            signed
            if signed is not None
            else (t.transaction_hash for t in fixture.wallet_transactions)
        )
    }
    complete = (
        cov.status("wallet_signed_transactions") == "complete"
        if wallet_tx_complete is None
        else wallet_tx_complete
    )
    plain = _plain_eoa(fixture, cutoff[0])
    refs_complete = complete and cov.complete("erc20_transfer_logs")
    chosen: dict[str, dict[str, int]] = {}
    records: dict[str, list[tuple[EvidenceRecord, list[tuple[str, int, int]]]]] = {}
    recovered = 0
    for o in obs:
        status, signer, rec = _signer(o, wallet, signed_set, complete and plain)
        recovered += rec
        match = _match(o.counterparty, chosen) if o.counterparty else None
        mechanisms, level, missing = _assess(o, status, match)
        if o.direction == "out" and status == "wallet":
            chosen.setdefault(o.counterparty[-MIN_SUFFIX:], {})[o.counterparty] = o.block
        if not mechanisms:
            continue
        receipt: Receipt = (
            "implied_by_log"
            if o.kind != "native"
            else "succeeded"
            if o.succeeded is True
            else "reverted"
            if o.succeeded is False
            else "unknown"
        )
        r = EvidenceRecord(
            identity=f"tx:{o.tx_hash.lower()}:{o.log_index}",
            kind=o.kind,
            direction=o.direction,
            block=o.block,
            tx_index=o.tx_index,
            log_index=o.log_index,
            mechanisms=mechanisms,
            level=level,
            signer_status=status,
            signer=signer,
            event_sender=wallet if o.direction == "out" else o.counterparty,
            event_recipient=o.counterparty if o.direction == "out" else wallet,
            emitter=o.emitter,
            receipt=receipt,
            value_zero=o.value == 0,
            missing=missing,
        )
        refs = [(match[0], match[1][0], match[1][1])] if match else []
        records.setdefault(o.counterparty, []).append((r, refs))
    groups = [
        _group(fixture.chain_id, wallet, look, items, refs_complete)
        for look, items in records.items()
    ]
    groups.sort(key=order_key)
    abstain = None
    if not refs_complete:
        abstain = "insufficient history: the wallet's own references are not fully observed"
    elif not chosen:
        abstain = (
            "no reference observed in the window; history before the window is unobserved, so "
            "this is not evidence of no earlier recipients"
        )
    return EvidenceResult(
        version=EVIDENCE_VERSION,
        chain_id=fixture.chain_id,
        victim=wallet,
        cutoff=cutoff,
        groups=tuple(groups),
        raw_events=raw_event_count(fixture),
        evidence_records=sum(len(g.evidence) for g in groups),
        signers_recovered=recovered,
        unattributable_events=0,
        abstain=abstain,
        coverage={k: str(v.status) for k, v in cov.categories.items()},
    )


def _signer(
    o: cd.Observation, wallet: str, signed: set[str], absence_ok: bool
) -> tuple[SignerStatus, str | None, int]:
    """(status, address, recovered?) for one observation. R-SIG: membership in the wallet's
    signed set proves the wallet signed; absence from a complete set of a code-less wallet
    proves it did not. The signer's address is never guessed."""
    if o.kind == "native" and o.direction == "in":
        return "lookalike_itself", o.counterparty, 0
    if o.kind == "native" and o.direction == "out":
        return "wallet", wallet, 0
    if o.direction != "out" or o.kind != "erc20":
        return "unknown", None, 0
    if o.signer is not None:
        return ("wallet", wallet, 0) if o.signer == wallet else ("foreign_known", o.signer, 0)
    if o.tx_hash.lower() in signed:
        return "wallet", wallet, 1
    if absence_ok:
        return "foreign_identity_unknown", None, 1
    return "unknown", None, 0


def _match(party: str, chosen: dict[str, dict[str, int]]) -> tuple[str, tuple[int, int]] | None:
    best = None
    for k in chosen.get(party[-MIN_SUFFIX:], {}):
        m = similar(party, k)
        if m is not None and (
            best is None or (sum(m), m[1], k) > (sum(best[1]), best[1][1], best[0])
        ):
            best = (k, m)
    return best


def _assess(
    o: cd.Observation, status: SignerStatus, match: tuple[str, tuple[int, int]] | None
) -> tuple[tuple[str, ...], str, tuple[str, ...]]:
    """(mechanisms, level, missing) for one observation; empty mechanisms: not evidence."""
    missing: list[str] = []
    if o.succeeded is False:
        return (), "", ()
    if o.direction == "out":
        if o.kind != "erc20" or status == "wallet":
            return (), "", ()
        if status in ("foreign_known", "foreign_identity_unknown"):
            if status == "foreign_identity_unknown":
                missing.append("signer_identity")
            return ("spoofed_out",), "directly_verified", tuple(missing)
        if match is not None:  # unknown signer: never asserted as a spoof
            return ("unverified_out_lookalike",), "partially_supported", ("signer",)
        return (), "", ()
    m: list[str] = []
    if o.kind == "native":
        if match is None:
            return (), "", ()  # anyone can send ETH: native evidence needs a lookalike
        if o.succeeded is None:
            missing.append("receipt")
        return (
            ("lookalike_in",),
            "directly_verified" if o.succeeded is True else "supported",
            tuple(missing),
        )
    if o.value == 0 and o.kind != "nft":
        m.append("zero_value_in")
    if match is not None:
        m.append("lookalike_in")
        if o.kind == "erc20":
            if o.emitter is None:
                missing.append("token_identity")  # unknown token: no "untrusted" claim
            elif o.emitter not in TRUSTED_TOKENS:
                m.append("untrusted_token_in")
    if o.kind == "erc20" and o.emitter in STABLECOINS and 0 < o.value <= DUST_MAX_BASE_UNITS:
        m.append("dust_in")
    if not m:
        return (), "", ()
    level = "supported" if match is not None else "partially_supported"
    return tuple(m), level, tuple(missing)


def _group(
    chain_id: int,
    wallet: str,
    look: str,
    items: list[tuple[EvidenceRecord, list[tuple[str, int, int]]]],
    refs_complete: bool,
) -> CandidateGroup:
    evidence = tuple(r for r, _ in items)
    refs = sorted({ref for _, rs in items for ref in rs})
    level = min((r.level for r in evidence), key=LEVELS.index)
    missing = sorted(
        {m for r in evidence for m in r.missing}
        | (set() if refs_complete else {"reference_history"})
    )
    positions = [(r.block, r.tx_index, r.log_index) for r in evidence]
    return CandidateGroup(
        identity=f"{chain_id}:{wallet}:{look}",
        chain_id=chain_id,
        victim=wallet,
        lookalike=look,
        references=tuple(refs),
        mechanisms=tuple(sorted({m for r in evidence for m in r.mechanisms})),
        kinds=tuple(sorted({r.kind for r in evidence})),
        level=level,
        affix=max((p + s for _, p, s in refs), default=None),
        first_position=min(positions),
        last_position=max(positions),
        evidence=evidence,
        missing=tuple(missing),
    )


def order_key(g: CandidateGroup) -> tuple[int, int, tuple[int, int, int], str]:
    """Support level first, then affix strength (costly to forge), then the latest
    planting, then the address. Missing information never moves a group up."""
    neg = (-g.last_position[0], -g.last_position[1], -g.last_position[2])
    return (LEVELS.index(g.level), -(g.affix or 0), neg, g.lookalike)


def summarize(result: EvidenceResult, k: int = 10) -> dict[str, Any]:
    """The bounded research summary. It discloses the totals and the truncation; it never
    deletes a group or a record."""
    shown = result.groups[:k]
    hidden = result.groups[k:]
    by_level: dict[str, int] = {}
    by_mechanism: dict[str, int] = {}
    for g in result.groups:
        by_level[g.level] = by_level.get(g.level, 0) + 1
        for m in g.mechanisms:
            by_mechanism[m] = by_mechanism.get(m, 0) + 1
    return {
        "version": result.version,
        "cutoff": list(result.cutoff),
        "total_groups": len(result.groups),
        "raw_events": result.raw_events,
        "evidence_records": result.evidence_records,
        "shown": len(shown),
        "truncated": bool(hidden),
        "hidden_identities": [g.identity for g in hidden],
        "by_level": dict(sorted(by_level.items(), key=lambda kv: LEVELS.index(kv[0]))),
        "by_mechanism": dict(sorted(by_mechanism.items())),
        "abstain": result.abstain,
        "note": HIDDEN_NOTE,
        "top": [
            {
                "identity": g.identity,
                "level": g.level,
                "mechanisms": list(g.mechanisms),
                "kinds": list(g.kinds),
                "references": [list(r) for r in g.references],
                "affix": g.affix,
                "first_block": g.first_position[0],
                "last_block": g.last_position[0],
                "evidence_count": len(g.evidence),
                "missing": list(g.missing),
                "explanation": explain(g),
            }
            for g in shown
        ],
    }


def explain(g: CandidateGroup) -> str:
    """Three separate dimensions: suspicion, support, and what is missing."""
    ref = f" imitating {g.references[0][0]} (affix {g.affix})" if g.references else ""
    gaps = f"; missing: {', '.join(g.missing)}" if g.missing else ""
    return (
        f"suspicion: {'+'.join(g.mechanisms)}{ref}; support: {g.level} "
        f"({len(g.evidence)} record(s)){gaps}; not a probability"
    )


def to_json(result: EvidenceResult) -> str:
    return json.dumps(asdict(result), sort_keys=True, default=list)


def mask(observations: Sequence[cd.Observation], what: str) -> list[cd.Observation]:
    """Controlled information loss for the S1-S5 experiments (never adds information)."""
    if what == "signer":
        return [replace(o, signer=None, wallet_signed=None) for o in observations]
    if what == "receipt":
        return [replace(o, succeeded=None) if o.kind == "native" else o for o in observations]
    if what == "token":
        return [replace(o, emitter=None) if o.kind == "erc20" else o for o in observations]
    raise ValueError(what)

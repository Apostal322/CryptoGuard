"""Evidence-preserving candidate groups and a bounded summary (``candidate-evidence/2``),
research only (protocols 12.6 and 12.6.1).

Every candidate is a group identified by (chain, victim, lookalike) that keeps **every**
distinct evidence record that caused it, in chain order, each with typed provenance:

- ``signer_status``: ``wallet``, ``foreign_known`` (looked-up signer, not the wallet),
  ``foreign_identity_unknown`` (rule R-SIG: the transaction is absent from the wallet's
  complete signed set, so the wallet did not *directly* sign it; who did is unknown),
  ``lookalike_itself`` (a native transfer the lookalike sent), ``conflicting`` (the looked-up
  signer and the signed set disagree) or ``unknown``. The event's ``from`` field is never
  taken as the signer.
- ``authorization``: whether the wallet authorized the value movement. ``direct_signature``
  (the wallet signed the transaction), ``not_required`` (a zero-value transfer moves nothing),
  ``unknown`` (the wallet did not sign the transaction, but an ERC-20 allowance, a permit or
  an EIP-7702 delegation can still authorize a pull, and a fabricated log needs none) or
  ``not_applicable`` (incoming records). R-SIG never proves an absence of authorization.
- ``event_sender`` / ``event_recipient``: what the log or transaction reports.
- ``emitter``: the token contract (``None`` when unknown); never an attacker identity.
- ``receipt``: ``succeeded``, ``reverted``, ``implied_by_log`` (a log exists only for an
  executed transaction) or ``unknown``.

R-SIG's absence inference runs only when ``absence_guard`` finds the signed set provably
complete for a plain externally owned account up to the cutoff (see its docstring).

Evidence levels are categories, not probabilities: ``directly_verified``, ``supported``,
``partially_supported`` (see ``LEVELS``). They describe how well the *observed facts* are
established, not how suspicious a candidate is, so they never move a candidate up or down
the presentation order (``presentation_key``: similarity, then recency, then address).
Missing information lowers the support level and is listed in ``missing``; it never raises
suspicion. Legitimacy is never assessed.

The summary is bounded by ``k``: it reports the totals, the hidden count, a truncation flag
and a digest of the full result; ``page`` and ``group_records`` give offset/limit access to
every group and every record. A display budget is not an evidence budget, and hidden
candidates are not assessed as safe. The production detector is never consulted or changed.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml.candidates import DUST_MAX_BASE_UNITS, MIN_SUFFIX, STABLECOINS, similar
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.replay.observation import coverage_of

EVIDENCE_VERSION = "candidate-evidence/2"  # /2: signer guards, authorization, bounded pages
LEVELS = ("directly_verified", "supported", "partially_supported")
SignerStatus = Literal[
    "wallet",
    "foreign_known",
    "foreign_identity_unknown",
    "lookalike_itself",
    "conflicting",
    "unknown",
]
Authorization = Literal["direct_signature", "not_required", "unknown", "not_applicable"]
Receipt = Literal["succeeded", "reverted", "implied_by_log", "unknown"]
HIDDEN_NOTE = "hidden candidates are not assessed as safe; all evidence remains in the result"
ORDER_NOTE = (
    "a deterministic presentation order (address similarity, then recency, then address); "
    "not a risk score or a probability; the support level is reported separately and never "
    "moves a candidate up or down"
)
RESEARCH_ORDER_NOTE = (
    "a research selection order (see order and order_config); not a risk score or a "
    "probability; the support level is reported separately and never moves a candidate"
)
MAX_PAGE = 1_000  # largest page a caller can request
MAX_REFERENCES_SHOWN = 3  # per summary item; the full list is in the result
DELEGATION_PREFIX = "0xef0100"  # EIP-7702 delegation designator


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
    authorization: Authorization
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
    level: str  # support for the observed facts, not suspicion
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
    groups: tuple[CandidateGroup, ...]  # in the presentation order
    raw_events: int  # observation records before deduplication
    evidence_records: int  # distinct records linked to groups
    signers_recovered: int  # unknown signers resolved by R-SIG
    unattributable_events: int  # records that could not be placed relative to the wallet
    abstain: str | None
    coverage: dict[str, str]
    absence_inference: bool  # whether R-SIG could infer "not signed by the wallet"
    absence_blocked_by: tuple[str, ...]  # why not (empty when allowed)
    order: str = "affix_then_recency"  # the ordering that produced ``groups``
    order_config: str | None = None  # hash of that ordering's configuration (12.7 selectors)


def absence_guard(
    fixture: Any, cutoff_block: int, *, signed_complete: bool | None = None
) -> tuple[str, ...]:
    """Why absence from the wallet's signed set does **not** prove that the wallet did not
    directly sign a transaction before ``cutoff_block``; empty when it does.

    Absence proves non-signing only if the set is every transaction the account signed in
    the window and the account could not act otherwise. So all of these must hold:

    1. the signed set is stated ``complete`` (a ``partial`` / ``truncated`` / ``unknown`` set
       proves nothing), with the stated count equal to the records held;
    2. a legacy (``observation/1``) fixture documents the nonce bisection its completeness
       claim rests on;
    3. the recorded nonces are unique and consecutive: a gap is a nonce the account used
       without a recorded transaction (a missing page, or an EIP-7702 authorization, which
       increments the authority's nonce inside someone else's transaction);
    4. every recorded transaction lies inside the window;
    5. the account's code is known at the window start and is empty (``0x``) at every sample
       up to the cutoff: an EIP-7702 delegation (``0xef0100...``) lets other senders execute
       code as the account, and a contract or smart wallet never signs at all. Samples after
       the cutoff are not used (no future information).

    Code between samples is not observed; condition 3 is what rules out a delegation set and
    cleared inside the window (both need an authorization, which uses a nonce). A complete
    signed set never says whether the wallet *authorized* a pull (allowance, permit): see
    ``Authorization``.
    """
    reasons: list[str] = []
    cov = coverage_of(fixture)
    entry = cov.categories.get("wallet_signed_transactions")
    status = cov.status("wallet_signed_transactions")
    complete = status == "complete" if signed_complete is None else signed_complete
    txs = list(fixture.wallet_transactions)
    if not complete:
        reasons.append(
            f"signed set not complete ({status if signed_complete is None else 'masked'})"
        )
    if entry is not None and entry.count is not None and entry.count != len(txs):
        reasons.append(f"signed-set count mismatch (stated {entry.count}, held {len(txs)})")
    if getattr(fixture, "observation", None) is None and not any(
        "nonce bisection" in m for m in getattr(fixture, "method", None) or []
    ):
        reasons.append("legacy fixture without a documented nonce bisection")
    nonces = sorted(t.nonce for t in txs)
    if len(set(nonces)) != len(nonces) or any(b - a != 1 for a, b in itertools.pairwise(nonces)):
        reasons.append("nonce gap or duplicate (missing page or EIP-7702 authorization)")
    if any(not fixture.from_block <= t.block_number <= fixture.to_block for t in txs):
        reasons.append("signed transaction outside the window")
    samples = {int(b): c.lower() for b, c in fixture.wallet_code_hex.items()}
    if not any(b <= fixture.from_block for b in samples):
        reasons.append("account code unknown at the window start")
    for b in sorted(samples):
        if b > cutoff_block:
            break
        if samples[b].startswith(DELEGATION_PREFIX):
            reasons.append(f"EIP-7702 delegation designator at block {b}")
        elif samples[b] != "0x":
            reasons.append(f"account has code at block {b} (contract or smart wallet)")
    return tuple(dict.fromkeys(reasons))


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
    they come from the fixture. Observations must be in chain order."""
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
    blocked = absence_guard(fixture, cutoff[0], signed_complete=wallet_tx_complete)
    complete = (
        cov.status("wallet_signed_transactions") == "complete"
        if wallet_tx_complete is None
        else wallet_tx_complete
    )
    refs_complete = complete and cov.complete("erc20_transfer_logs")
    chosen: dict[str, dict[str, int]] = {}
    records: dict[str, list[tuple[EvidenceRecord, list[tuple[str, int, int]]]]] = {}
    recovered = 0
    for o in obs:
        status, signer, rec = _signer(o, wallet, signed_set, not blocked)
        recovered += rec
        match = _match(o.counterparty, chosen) if o.counterparty else None
        mechanisms, level, missing, auth = _assess(o, status, match)
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
            authorization=auth,
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
    groups.sort(key=presentation_key)
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
        absence_inference=not blocked,
        absence_blocked_by=blocked,
    )


def _signer(
    o: cd.Observation, wallet: str, signed: set[str], absence_ok: bool
) -> tuple[SignerStatus, str | None, int]:
    """(status, address, recovered?) for one observation. R-SIG: membership in the wallet's
    signed set proves the wallet signed; absence, only when ``absence_guard`` allows it,
    proves it did not *directly* sign. A looked-up signer that contradicts the set is
    ``conflicting``. The signer's address is never guessed."""
    if o.kind == "native" and o.direction == "in":
        return "lookalike_itself", o.counterparty, 0
    if o.kind == "native" and o.direction == "out":
        return "wallet", wallet, 0
    if o.direction != "out" or o.kind != "erc20":
        return "unknown", None, 0
    in_set = o.tx_hash.lower() in signed
    if o.signer is not None:
        if o.signer == wallet:
            return ("conflicting", None, 0) if absence_ok and not in_set else ("wallet", wallet, 0)
        return ("conflicting", None, 0) if in_set else ("foreign_known", o.signer, 0)
    if in_set:
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
) -> tuple[tuple[str, ...], str, tuple[str, ...], Authorization]:
    """(mechanisms, level, missing, authorization) for one observation; empty mechanisms:
    not evidence."""
    missing: list[str] = []
    if o.succeeded is False:
        return (), "", (), "not_applicable"
    if o.direction == "out":
        if o.kind != "erc20" or status == "wallet":
            return (), "", (), "direct_signature"
        if status in ("foreign_known", "foreign_identity_unknown"):
            if status == "foreign_identity_unknown":
                missing.append("signer_identity")
            if o.value == 0:  # nothing moved: no authorization question, a display spoof
                return ("spoofed_out",), "directly_verified", tuple(missing), "not_required"
            # value moved without the wallet's signature: an allowance, a permit, a delegation
            # or a fabricated log; which one is not observed, so this is not called a spoof
            mech = ["foreign_initiated_out"]
            if o.emitter is None:
                missing.append("token_identity")
            elif o.emitter not in TRUSTED_TOKENS:
                mech.append("untrusted_token_out")
            missing.append("authorization")
            return tuple(mech), "directly_verified", tuple(missing), "unknown"
        if match is not None:  # unknown or conflicting signer: never asserted as a spoof
            gap = "signer_conflict" if status == "conflicting" else "signer"
            return ("unverified_out_lookalike",), "partially_supported", (gap,), "unknown"
        return (), "", (), "unknown"
    m: list[str] = []
    if o.kind == "native":
        if match is None:
            return (), "", (), "not_applicable"  # anyone can send ETH: needs a lookalike
        if o.succeeded is None:
            missing.append("receipt")
        return (
            ("lookalike_in",),
            "directly_verified" if o.succeeded is True else "supported",
            tuple(missing),
            "not_applicable",
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
        return (), "", (), "not_applicable"
    level = "supported" if match is not None else "partially_supported"
    return tuple(m), level, tuple(missing), "not_applicable"


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


# --- orders ---------------------------------------------------------------------------------


def presentation_key(g: CandidateGroup) -> tuple[int, tuple[int, int, int], str]:
    """The presentation order: affix strength (costly to forge), then the latest planting,
    then the address. It reads only suspicion indicators: the support level and the missing
    list are never consulted, so verifying a fact cannot move a candidate up, and missing a
    fact cannot move it up or down."""
    neg = (-g.last_position[0], -g.last_position[1], -g.last_position[2])
    return (-(g.affix or 0), neg, g.lookalike)


def evidence_order_key(g: CandidateGroup) -> tuple[int, int, tuple[int, int, int], str]:
    """The pre-registered protocol 12.6 order (support level first). It failed H5: cheap
    verified dust outranks costly lookalikes. Kept only to reproduce that result."""
    neg = (-g.last_position[0], -g.last_position[1], -g.last_position[2])
    return (LEVELS.index(g.level), -(g.affix or 0), neg, g.lookalike)


ORDERS: dict[str, Callable[[CandidateGroup], Any]] = {
    "affix_then_recency": presentation_key,
    "evidence_then_affix": evidence_order_key,  # H5 reproduction only
}


# --- bounded access -------------------------------------------------------------------------


def digest(result: EvidenceResult) -> str:
    """A content digest of the full result (every group and record identity, in order), so a
    page can be checked against the result it was cut from."""
    h = hashlib.sha256(
        f"{result.version}|{result.victim}|{result.cutoff}|{result.order}|{result.order_config}".encode()
    )
    for g in result.groups:
        h.update(g.identity.encode())
        h.update(g.level.encode())
        for r in g.evidence:
            h.update(r.identity.encode())
    return h.hexdigest()


def _bounded(n: int, name: str) -> int:
    if not 1 <= n <= MAX_PAGE:
        raise ValueError(f"{name} must be between 1 and {MAX_PAGE}")
    return n


def bucket_of(g: CandidateGroup) -> str:
    """The reference a group imitates best (ties: the smallest address), or, without a
    reference, its mechanism signature. The number of reference buckets is bounded by the
    victim's own payments, which an attacker cannot add to."""
    if g.references:
        return min(g.references, key=lambda r: (-(r[1] + r[2]), r[0]))[0]
    return "mech:" + "+".join(g.mechanisms)


def _bucket_sizes(result: EvidenceResult) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for g in result.groups:
        b = bucket_of(g)
        sizes[b] = sizes.get(b, 0) + 1
    return sizes


def _item(g: CandidateGroup, rank: int, sizes: dict[str, int] | None = None) -> dict[str, Any]:
    bucket = bucket_of(g)
    return {
        "rank": rank,
        "identity": g.identity,
        "reference_bucket": bucket,
        "bucket_size": None if sizes is None else sizes[bucket],
        "level": g.level,
        "mechanisms": list(g.mechanisms),
        "kinds": list(g.kinds),
        "references": [list(r) for r in g.references[:MAX_REFERENCES_SHOWN]],
        "references_total": len(g.references),
        "affix": g.affix,
        "first_block": g.first_position[0],
        "last_block": g.last_position[0],
        "evidence_count": len(g.evidence),
        "missing": list(g.missing),
        "legitimacy": "not_assessed",
        "explanation": explain(g),
    }


def summarize(result: EvidenceResult, k: int = 10) -> dict[str, Any]:
    """The bounded research summary: at most ``k`` groups, the totals, the hidden count, the
    truncation flag, the offset of the next page and the result digest. Its size does not
    grow with the number of groups or records; it never deletes a group or a record."""
    k = _bounded(k, "k")
    shown = result.groups[:k]
    by_level: dict[str, int] = {}
    by_mechanism: dict[str, int] = {}
    for g in result.groups:
        by_level[g.level] = by_level.get(g.level, 0) + 1
        for m in g.mechanisms:
            by_mechanism[m] = by_mechanism.get(m, 0) + 1
    hidden = len(result.groups) - len(shown)
    sizes = _bucket_sizes(result)
    return {
        "version": result.version,
        "cutoff": list(result.cutoff),
        "order": result.order,
        "order_config": result.order_config,
        "order_note": ORDER_NOTE if result.order == "affix_then_recency" else RESEARCH_ORDER_NOTE,
        "result_digest": digest(result),
        "total_groups": len(result.groups),
        "raw_events": result.raw_events,
        "evidence_records": result.evidence_records,
        "shown": len(shown),
        "hidden_count": hidden,
        "truncated": hidden > 0,
        "next_offset": len(shown) if hidden else None,
        "by_level": dict(sorted(by_level.items(), key=lambda kv: LEVELS.index(kv[0]))),
        "by_mechanism": dict(sorted(by_mechanism.items())),
        "absence_inference": result.absence_inference,
        "absence_blocked_by": list(result.absence_blocked_by),
        "abstain": result.abstain,
        "note": HIDDEN_NOTE,
        "top": [_item(g, i + 1, sizes) for i, g in enumerate(shown)],
    }


class StaleResultError(ValueError):
    """The page was requested against a different result than the caller's digest."""


def page(
    result: EvidenceResult, *, offset: int = 0, limit: int = 10, expect_digest: str | None = None
) -> dict[str, Any]:
    """Groups ``[offset, offset + limit)`` in the presentation order (``items`` / ``total`` /
    ``limit`` / ``offset``, the project's page convention). With ``expect_digest`` the page
    is refused if the result changed since the summary was made."""
    limit = _bounded(limit, "limit")
    if offset < 0:
        raise ValueError("offset must be >= 0")
    d = digest(result)
    if expect_digest is not None and expect_digest != d:
        raise StaleResultError("the result changed since this digest was issued")
    items = result.groups[offset : offset + limit]
    end = offset + len(items)
    sizes = _bucket_sizes(result)
    return {
        "items": [_item(g, offset + i + 1, sizes) for i, g in enumerate(items)],
        "total": len(result.groups),
        "limit": limit,
        "offset": offset,
        "next_offset": end if end < len(result.groups) else None,
        "order": result.order,
        "order_config": result.order_config,
        "result_digest": d,
    }


def group_records(
    result: EvidenceResult, identity: str, *, offset: int = 0, limit: int = 100
) -> dict[str, Any]:
    """Every record of one group, by reference (its identity), one bounded page at a time."""
    limit = _bounded(limit, "limit")
    for g in result.groups:
        if g.identity == identity:
            items = g.evidence[offset : offset + limit]
            end = offset + len(items)
            return {
                "identity": identity,
                "items": [asdict(r) for r in items],
                "total": len(g.evidence),
                "limit": limit,
                "offset": offset,
                "next_offset": end if end < len(g.evidence) else None,
            }
    raise KeyError(identity)


def rank_of(result: EvidenceResult, lookalike: str) -> int | None:
    """1-based position of a lookalike in the presentation order (None: not a candidate)."""
    look = lookalike.lower()
    return next((i + 1 for i, g in enumerate(result.groups) if g.lookalike == look), None)


def explain(g: CandidateGroup) -> str:
    """Three separate dimensions: suspicion indicators, support, and what is missing."""
    ref = f" imitating {g.references[0][0]} (affix {g.affix})" if g.references else ""
    gaps = f"; missing: {', '.join(g.missing)}" if g.missing else ""
    return (
        f"indicators: {'+'.join(g.mechanisms)}{ref}; support: {g.level} "
        f"({len(g.evidence)} record(s)){gaps}; not a probability; legitimacy not assessed"
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

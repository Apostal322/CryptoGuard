"""Reconciliation of Poison-Hunter rows, Tsuchiya et al. attempts and payoffs (offline).

Units (never mixed):

- **attempt**: one archive poisoning transfer, keyed ``(victim, lookalike, tx)``; the
  archive has no log index, so repeats of that key inside one transaction count once.
- **victim-event**: one Poison-Hunter row's ``(victim, lookalike, planting tx)``.
- **payoff**: one row of ``payoff_transfers_ethereum.csv`` (one transaction each).

Outcome levels (Stage H), each answered separately and never inferred from another:

- *attempt outcome*: the victim paid **this** lookalike after this planting;
- *victim outcome*: the victim paid **any** lookalike after this planting;
- *address outcome*: this lookalike received a payoff from **any** victim (before or after);
- *campaign outcome*: some lookalike in the row's campaign group received a payoff.

Temporal categories for a (planting, payment) pair: ``before_planting``,
``same_block_order_unknown`` (the archive has no transaction index), ``after_planting``,
and ``temporally_ambiguous`` (a block is missing). A payment before a planting is history
about the address, never an outcome of that planting.

Match levels for a Poison-Hunter row against the archive (strongest first):
``exact_tx_event`` > ``victim_lookalike_imitated`` > ``victim_lookalike`` >
``tx_only`` > ``shared_lookalike`` > ``competing_lookalike`` > ``victim_only`` > ``none``.
Weaker levels are reported, never converted into labels.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from cryptoguard.detectors.poisoning import affix_match
from cryptoguard.ml.events import PoisoningEvent, Subtype
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.ml.poison_hunter import PoisonHunterRecord
from cryptoguard.ml.review import ReviewPacket, packet
from cryptoguard.ml.tsuchiya import PayoffTransfer
from cryptoguard.ml.tsuchiya_archive import (
    COUNTERFEIT,
    PAYOFF,
    PAYOFF_UNCONFIRMED,
    POISONING,
    TINY,
    ZERO,
    ArchiveTransfer,
)

RECONCILE_VERSION = "reconcile/1"
WINDOW_BLOCKS = 50_400  # 7 days, the pilot's window

Temporal = Literal[
    "before_planting", "same_block_order_unknown", "after_planting", "temporally_ambiguous"
]
MatchLevel = Literal[
    "exact_tx_event",
    "victim_lookalike_imitated",
    "victim_lookalike",
    "tx_only",
    "shared_lookalike",
    "competing_lookalike",
    "victim_only",
    "none",
]
LEVELS: tuple[MatchLevel, ...] = MatchLevel.__args__  # type: ignore[attr-defined]
_PH_SUBTYPE = {"dust": TINY, "zero": ZERO, "fake": COUNTERFEIT}


def temporal(planting_block: int | None, payment_block: int | None) -> Temporal:
    if planting_block is None or payment_block is None:
        return "temporally_ambiguous"
    if payment_block < planting_block:
        return "before_planting"
    if payment_block == planting_block:
        return "same_block_order_unknown"
    return "after_planting"


@dataclass(frozen=True, slots=True)
class Attempt:
    victim: str
    lookalike: str
    tx: str
    block: int
    flags: int
    intended: str | None
    token: str = ""
    victim_sends: bool = False


class ArchiveIndex:
    """Hash indexes over the stored archive subset (attempts deduplicated by key)."""

    def __init__(self, rows: Iterable[ArchiveTransfer]) -> None:
        self.by_pair: dict[tuple[str, str], list[Attempt]] = defaultdict(list)
        self.by_victim: dict[str, list[Attempt]] = defaultdict(list)
        self.by_lookalike: dict[str, list[Attempt]] = defaultdict(list)
        self.by_tx: dict[str, list[Attempt]] = defaultdict(list)
        self.payoff_rows: dict[tuple[str, str, str], int] = {}
        self.repeated_attempt_rows = 0
        seen: set[tuple[str, str, str]] = set()
        for r in rows:
            victim, lookalike = r.victim, r.counterparty
            if r.flags & (PAYOFF | PAYOFF_UNCONFIRMED) and r.sender_is_victim:
                key = (r.tx, r.sender, r.receiver)
                self.payoff_rows[key] = self.payoff_rows.get(key, 0) | r.flags
            if not r.flags & POISONING or victim is None or lookalike is None:
                continue
            k = (victim, lookalike, r.tx)
            if k in seen:
                self.repeated_attempt_rows += 1
                continue
            seen.add(k)
            a = Attempt(
                victim, lookalike, r.tx, r.block, r.flags, r.intended, r.token, r.sender == victim
            )
            self.by_pair[(victim, lookalike)].append(a)
            self.by_victim[victim].append(a)
            self.by_lookalike[lookalike].append(a)
            self.by_tx[r.tx].append(a)
        for index in (self.by_pair, self.by_victim, self.by_lookalike, self.by_tx):
            for attempts in index.values():
                attempts.sort(key=lambda a: (a.block, a.tx, a.victim, a.lookalike))

    @property
    def attempts(self) -> int:
        return sum(len(v) for v in self.by_pair.values())


def _level(r: PoisonHunterRecord, ix: ArchiveIndex) -> tuple[MatchLevel, list[Attempt]]:
    same_tx = ix.by_tx.get(r.planting_tx, [])
    exact = [a for a in same_tx if (a.victim, a.lookalike) == (r.victim, r.lookalike)]
    if exact:
        return "exact_tx_event", exact
    pair = ix.by_pair.get((r.victim, r.lookalike), [])
    if any(a.intended == r.imitated for a in pair):
        return "victim_lookalike_imitated", pair
    if pair:
        return "victim_lookalike", pair
    if same_tx:
        return "tx_only", same_tx
    if ix.by_lookalike.get(r.lookalike):
        return "shared_lookalike", ix.by_lookalike[r.lookalike]
    competing = [
        a
        for a in ix.by_victim.get(r.victim, [])
        if a.intended == r.imitated and a.lookalike != r.lookalike
    ]
    if competing:
        return "competing_lookalike", competing
    if ix.by_victim.get(r.victim):
        return "victim_only", ix.by_victim[r.victim]
    return "none", []


def _distinct(values: Iterable[Any]) -> int:
    return len(set(values))


def _quantiles(values: list[int]) -> dict[str, float] | None:
    if not values:
        return None
    s = sorted(values)
    q = statistics.quantiles(s, n=4, method="inclusive") if len(s) > 1 else [s[0]] * 3
    return {"n": len(s), "min": s[0], "p25": q[0], "median": q[1], "p75": q[2], "max": s[-1]}


def ph_matches(
    ph: list[PoisonHunterRecord],
    ix: ArchiveIndex,
    poisoning_block_range: tuple[int, int] | None,
) -> dict[str, Any]:
    """Match level per Poison-Hunter row, with the reasons unmatched rows differ."""
    levels: Counter[str] = Counter()
    per_level: dict[str, list[PoisonHunterRecord]] = defaultdict(list)
    subtype_agreement: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    tx_only: Counter[str] = Counter()
    lines: dict[str, list[int]] = defaultdict(list)
    for r in ph:
        level, hits = _level(r, ix)
        levels[level] += 1
        per_level[level].append(r)
        lines[level].append(r.source_line)
        if level == "tx_only":
            with_victim = any(a.victim == r.victim for a in hits)
            tx_only[
                "victim_listed_with_another_lookalike" if with_victim else "victim_not_listed"
            ] += 1
        if level == "exact_tx_event":
            agree = any(a.flags & _PH_SUBTYPE.get(r.subtype, 0) for a in hits)
            subtype_agreement[f"{r.subtype}->{'agrees' if agree else _flags(hits)}"] += 1
        else:
            in_range = (
                poisoning_block_range is not None
                and r.block_number is not None
                and poisoning_block_range[0] <= r.block_number <= poisoning_block_range[1]
            )
            if not in_range:
                reasons["outside_archive_period"] += 1
            elif not r.tsuchiya_lookalike:
                reasons["below_3_plus_4_similarity"] += 1
            else:
                reasons["inside_period_and_definition"] += 1
    return {
        "unit": "Poison-Hunter row (149 valid rows; 6 duplicate victim-events)",
        "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
        "distinct_victims": {lv: _distinct(r.victim for r in per_level[lv]) for lv in LEVELS},
        "distinct_lookalikes": {lv: _distinct(r.lookalike for r in per_level[lv]) for lv in LEVELS},
        "distinct_planting_txs": {
            lv: _distinct(r.planting_tx for r in per_level[lv]) for lv in LEVELS
        },
        "lines": {lv: lines[lv] for lv in LEVELS if lines[lv]},
        "subtype_agreement_on_exact": dict(sorted(subtype_agreement.items())),
        "not_exact_reasons": dict(sorted(reasons.items())),
        "tx_only_detail": dict(sorted(tx_only.items())),
    }


def _flags(hits: list[Attempt]) -> str:
    names = {ZERO: "zero", TINY: "tiny", COUNTERFEIT: "counterfeit"}
    found = sorted({n for a in hits for b, n in names.items() if a.flags & b})
    return "+".join(found) or "other"


def payoff_linkage(payoffs: list[PayoffTransfer], ix: ArchiveIndex) -> dict[str, Any]:
    """For each payoff: is it in the archive, and which attempts preceded it?

    A payoff is *attempt-linked* when the archive holds a poisoning transfer between the
    same victim and the same lookalike in an earlier block. Same-block attempts are
    reported separately (order unknown); later ones are not causes."""
    status: Counter[str] = Counter()
    linked: Counter[str] = Counter()
    lead: list[int] = []
    competitors: list[int] = []
    competitors_same_intended: list[int] = []
    paid_most_similar = paid_most_recent = ranked = 0
    ranked_victims: set[str] = set()
    expected_similar = expected_recent = 0.0
    attempts_before: list[int] = []
    linked_victims: set[str] = set()
    linked_lookalikes: set[str] = set()
    linked_payoff_txs: set[str] = set()
    for p in payoffs:
        flags = ix.payoff_rows.get((p.tx_hash, p.payer, p.lookalike))
        if flags is None:
            status["payoff_not_in_archive_subset"] += 1
        elif flags & PAYOFF:
            status["archive_flag_payoff_confirmed"] += 1
        else:
            status["archive_flag_payoff_unconfirmed_only"] += 1
        pair = ix.by_pair.get((p.payer, p.lookalike), [])
        # From the payoff's side: attempts *before the payment* are candidate causes.
        before = [a for a in pair if p.block_number is not None and a.block < p.block_number]
        same = [a for a in pair if a.block == p.block_number]
        if before:
            linked["attempt_before_payoff"] += 1
            lead.append(p.block_number - before[-1].block)  # type: ignore[operator]
            attempts_before.append(len(before))
            linked_victims.add(p.payer)
            linked_lookalikes.add(p.lookalike)
            linked_payoff_txs.add(p.tx_hash)
        elif same:
            linked["same_block_only"] += 1
        elif pair:
            linked["attempts_only_after_payoff"] += 1
        else:
            linked["no_attempt_between_pair"] += 1
        if p.block_number is None:
            continue
        rivals = {
            a.lookalike: a
            for a in ix.by_victim.get(p.payer, [])
            if a.block < p.block_number and a.lookalike != p.lookalike
        }
        competitors.append(len(rivals))
        same_target = {
            lk: a for lk, a in rivals.items() if a.intended is not None and a.intended == p.intended
        }
        competitors_same_intended.append(len(same_target))
        if before and same_target:
            # Observational comparison among lookalikes of the same intended address that
            # reached this victim before the payment (no causal reading).
            # The null is a uniform choice among the k candidates; with ties, the chance of
            # picking one of the best is (number tied at the maximum) / k, not 1 / k.
            ranked += 1
            ranked_victims.add(p.payer)
            k = len(same_target) + 1
            scores = [sum(affix_match(lk, p.intended)) for lk in same_target]
            paid_score = sum(affix_match(p.lookalike, p.intended))
            best = max([paid_score, *scores])
            paid_most_similar += paid_score == best
            expected_similar += (
                1 + scores.count(best) if paid_score == best else scores.count(best)
            ) / k
            cutoff = p.block_number
            seen = [
                max(a.block for a in ix.by_pair.get((p.payer, lk), []) if a.block < cutoff)
                for lk in same_target
            ]
            paid_seen = before[-1].block
            latest = max([paid_seen, *seen])
            paid_most_recent += paid_seen == latest
            expected_recent += (
                1 + seen.count(latest) if paid_seen == latest else seen.count(latest)
            ) / k
    return {
        "unit": "payoff transfer (payoff_transfers_ethereum.csv row)",
        "payoffs": len(payoffs),
        "archive_status": dict(sorted(status.items())),
        "linkage": dict(sorted(linked.items())),
        "linked_distinct": {
            "victims": len(linked_victims),
            "lookalikes": len(linked_lookalikes),
            "payoff_txs": len(linked_payoff_txs),
        },
        "blocks_from_last_attempt_to_payoff": _quantiles(lead),
        "attempts_by_pair_before_payoff": _quantiles(attempts_before),
        "rival_lookalikes_before_payoff": _quantiles(competitors),
        "payoffs_with_rival_of_same_intended": sum(1 for c in competitors_same_intended if c),
        "rival_lookalikes_same_intended": _quantiles(competitors_same_intended),
        "similarity_recency_comparison": {
            "payoffs_compared": ranked,
            "distinct_victims_compared": len(ranked_victims),
            "paid_lookalike_most_similar": paid_most_similar,
            "expected_if_uniform": round(expected_similar, 1),
            "paid_lookalike_most_recent": paid_most_recent,
            "expected_if_uniform_recent": round(expected_recent, 1),
            "caveat": "observational; ties count as most similar or most recent and the "
            "uniform expectation accounts for them; one victim can appear in several "
            "payoffs; not a causal effect of similarity or recency",
        },
    }


def ph_outcomes(
    ph: list[PoisonHunterRecord],
    payoffs: list[PayoffTransfer],
    groups: dict[str, str] | None = None,
    window_blocks: int = WINDOW_BLOCKS,
) -> dict[str, Any]:
    """The four outcome levels for each Poison-Hunter row, with temporal categories.

    ``groups`` maps a lookalike to its campaign group id (``events.campaign_groups``)."""
    by_payer: dict[str, list[PayoffTransfer]] = defaultdict(list)
    by_lookalike: dict[str, list[PayoffTransfer]] = defaultdict(list)
    for p in payoffs:
        by_payer[p.payer].append(p)
        by_lookalike[p.lookalike].append(p)
    group_lookalikes: dict[str, set[str]] = defaultdict(set)
    for lk, g in (groups or {}).items():
        group_lookalikes[g].add(lk)
    out: Counter[str] = Counter()
    pairs: Counter[str] = Counter()
    for r in ph:
        b = r.block_number
        this = [p for p in by_payer.get(r.victim, []) if p.lookalike == r.lookalike]
        anyl = by_payer.get(r.victim, [])
        addr = by_lookalike.get(r.lookalike, [])
        for p in anyl + [q for q in addr if q.payer != r.victim]:
            who = "this_pair" if p in this else ("victim" if p in anyl else "address")
            pairs[f"{who}/{temporal(b, p.block_number)}"] += 1
        after = [p for p in this if temporal(b, p.block_number) == "after_planting"]
        out["attempt_outcome_paid_after"] += bool(after)
        out["attempt_outcome_paid_in_window"] += any(
            b is not None and p.block_number is not None and p.block_number - b <= window_blocks
            for p in after
        )
        out["victim_outcome_paid_any_lookalike_after"] += any(
            temporal(b, p.block_number) == "after_planting" for p in anyl
        )
        out["address_outcome_paid_by_anyone_before"] += any(
            temporal(b, p.block_number) == "before_planting" for p in addr
        )
        out["address_outcome_paid_by_anyone_after"] += any(
            temporal(b, p.block_number) == "after_planting" for p in addr
        )
        if groups is not None and r.lookalike in groups:
            mates = group_lookalikes[groups[r.lookalike]]
            out["campaign_outcome_paid_after"] += any(
                temporal(b, p.block_number) == "after_planting"
                for lk in mates
                for p in by_lookalike.get(lk, [])
            )
    return {
        "unit": "Poison-Hunter row",
        "rows": len(ph),
        "outcomes": dict(sorted(out.items())),
        "payment_pairs_by_temporal_category": dict(sorted(pairs.items())),
        "note": "a victim's loss to another lookalike is never credited to this attempt; "
        "payments before the planting are address history, not outcomes",
    }


def incident_case_studies(
    incidents: list[dict[str, Any]], ix: ArchiveIndex, block_range: tuple[int, int] | None
) -> list[dict[str, Any]]:
    out = []
    for inc in incidents:
        pair = ix.by_pair.get((inc["victim"], inc["recipient"]), [])
        out.append(
            {
                "case": inc["case"],
                "harm_in_archive_period": block_range is not None
                and block_range[0] <= inc["block"] <= block_range[1],
                "victim_attempts_in_archive": len(ix.by_victim.get(inc["victim"], [])),
                "harm_recipient_attempts_in_archive": len(
                    ix.by_lookalike.get(inc["recipient"], [])
                ),
                "pair_attempts_before_harm": sum(1 for a in pair if a.block < inc["block"]),
                "harm_tx_in_archive": any(k[0] == inc["tx"] for k in ix.payoff_rows)
                or inc["tx"] in ix.by_tx,
            }
        )
    return out


def reconcile(
    rows: Iterable[ArchiveTransfer],
    summary: dict[str, Any],
    ph: list[PoisonHunterRecord],
    payoffs: list[PayoffTransfer],
    incidents: list[dict[str, Any]],
    groups: dict[str, str] | None = None,
) -> dict[str, Any]:
    ix = ArchiveIndex(rows)
    prange = summary.get("poisoning_block_range")
    brange = summary.get("block_range")
    return {
        "version": RECONCILE_VERSION,
        "subset": {
            "attempts": ix.attempts,
            "repeated_attempt_rows": ix.repeated_attempt_rows,
            "victims": len(ix.by_victim),
            "lookalikes": len(ix.by_lookalike),
            "payoff_flag_rows": len(ix.payoff_rows),
        },
        "poison_hunter": ph_matches(ph, ix, tuple(prange) if prange else None),
        "payoffs": payoff_linkage(payoffs, ix),
        "outcomes": ph_outcomes(ph, payoffs, groups),
        "incidents": incident_case_studies(incidents, ix, tuple(brange) if brange else None),
    }


def _subtype(a: Attempt) -> Subtype:
    if a.flags & ZERO:
        return "spoofed_transfer_from" if a.victim_sends else "zero_value"
    if a.flags & COUNTERFEIT:
        return "fake_token"
    if a.flags & TINY:
        return "dust"
    return "unknown"


def payoff_review_packets(payoffs: list[PayoffTransfer], ix: ArchiveIndex) -> list[ReviewPacket]:
    """One review packet per payoff-linked attempt: the latest archive attempt by the same
    lookalike against the same victim before the payment. These are review candidates for
    ``verified_attempt``; nothing here assigns a label."""
    out: dict[str, ReviewPacket] = {}
    for p in payoffs:
        if p.block_number is None:
            continue
        before = [a for a in ix.by_pair.get((p.payer, p.lookalike), []) if a.block < p.block_number]
        if not before:
            continue
        a = before[-1]
        event = PoisoningEvent(
            chain_id=1,
            victim=a.victim,
            lookalike=a.lookalike,
            imitated=a.intended,
            planting_tx=a.tx,
            planting_block=a.block,
            planting_tx_index=None,
            planting_log_index=None,
            observation_timestamp=None,
            subtype=_subtype(a),
            tx_signer=None,
            log_contract=a.token or None,
            token_contract=a.token if a.token in TRUSTED_TOKENS else None,
            candidate_method="tsuchiya-archive:latest-attempt-before-payoff",
            evidence_refs=(f"tsuchiya-archive:{a.tx}", f"tsuchiya-payoff:{p.tx_hash}"),
            coverage="unavailable",
            dataset_version=RECONCILE_VERSION,
        )
        competing = {
            r.lookalike
            for r in ix.by_victim.get(p.payer, [])
            if r.block < p.block_number and r.lookalike != p.lookalike and r.intended == a.intended
        }
        out[event.victim_event_id] = packet(
            event,
            (f"tsuchiya-archive:{_subtype(a)}", "tsuchiya-payoff:confirmed"),
            f"Source-labelled poisoning transfer at block {a.block:,}; the victim paid this "
            f"lookalike {p.block_number - a.block:,} blocks later. {len(before)} attempt(s) by "
            "this lookalike preceded the payment.",
            competing=sorted(competing),
            payments=(f"{p.tx_hash} block {p.block_number} after_planting (confirmed payoff)",),
        )
    return [out[k] for k in sorted(out)]

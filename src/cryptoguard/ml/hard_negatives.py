"""Hard-negative candidate pool, contamination screen, matching design and review cohort
(Phase 11.5, offline, 0 RPC requests).

**Every candidate is ``unlabeled_candidate``.** A low score, absence from a threat list or
the absence of a later loss is not a benign label. Categories describe structure, never
intent:

| Category | Structural meaning |
|---|---|
| A_similarity_ordinary_value | lookalike of a prior counterparty, genuine token, above dust |
| B_first_time_counterparty | the counterparty never appears earlier in the observed window |
| C_low_value | dust-range or at most 1 USD |
| D_token_ambiguity | zero-value genuine token, or a token outside the reviewed list |
| E_contract_mediated | moved out of the wallet by a transaction it did not sign |
| F_shared_infrastructure | signed by an address on the reviewed public-infrastructure list |
| G_incomplete_observation | partial or no wallet history, or an unknown receipt status |
| H_near_threshold | similarity within one character of the rule's threshold |

**Frames.**
- ``fixture_background:<case>`` and ``fixture_incident:<case>``: generator outputs on the
  recorded replay windows. These are public chain data, recorded once.
- ``archive_uncategorized``: the source's uncategorized lookalike transfers (CC BY-NC-ND;
  local only).
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cryptoguard.ml import candidates as cg
from cryptoguard.ml.cohort import CohortDesign, FrameItem
from cryptoguard.ml.contamination import Coverage, KnownAttack, KnownIndex, Screened, screen
from cryptoguard.ml.dataset import PUBLIC_INFRASTRUCTURE
from cryptoguard.ml.events import PoisoningEvent
from cryptoguard.ml.grouping import GroupingPolicy, typed_groups
from cryptoguard.ml.payments import TRUSTED_TOKENS

HN_VERSION = "hard-negatives/1"
COHORT_VERSION = "hard-negative-candidates/1"
COHORT_SEED = "cryptoguard-hard-negative-candidates/1"  # fixed before the only draw
Frame = Literal["fixture_background", "fixture_incident", "archive_uncategorized"]
LabelStatus = Literal["unlabeled_candidate"]
ARCHIVE_RANGE = (15_053_226, 20_208_032)  # blocks in the Tsuchiya archive (Phase 11.3 scan)
NEAR = 1  # characters above the rule's threshold that count as "near"


@dataclass(frozen=True)
class HNCandidate:
    event: PoisoningEvent
    frame: str  # Frame, optionally ":<case>"
    methods: tuple[str, ...]
    categories: tuple[str, ...]
    token_trusted: bool
    value_base_units: float | None
    value_usd: float | None
    similarity: tuple[int, int] | None  # (prefix, suffix) matched characters
    coverage: str
    first_time_counterparty: bool | None
    receipt_known: bool | None
    context: tuple[Mapping[str, Any], ...] = ()  # pre-cutoff observations for reviewers
    label_status: LabelStatus = "unlabeled_candidate"
    screened: Screened | None = field(default=None, compare=False)

    @property
    def year(self) -> int:
        from cryptoguard.ml.review_sample import year

        return year(self.event.planting_block)


def categories(
    *,
    similarity: tuple[int, int] | None,
    threshold: int,
    token_trusted: bool,
    value_usd: float | None,
    methods: Sequence[str],
    signer: str | None,
    token: str,
    coverage: str,
    first_time: bool | None,
    receipt_known: bool | None,
    value_base_units: float | None,
) -> tuple[str, ...]:
    public = {a.lower() for a in PUBLIC_INFRASTRUCTURE}
    dustish = "dust_in" in methods or (value_usd is not None and 0 < value_usd <= 1)
    zero = value_base_units == 0 or "zero_value_in" in methods
    out = []
    if similarity and token_trusted and not dustish and not zero:
        out.append("A_similarity_ordinary_value")
    if first_time:
        out.append("B_first_time_counterparty")
    if dustish:
        out.append("C_low_value")
    if (zero and token_trusted) or not token_trusted:
        out.append("D_token_ambiguity")
    if "spoofed_out" in methods:
        out.append("E_contract_mediated")
    if signer and signer.lower() in public:  # common tokens alone are not infrastructure
        out.append("F_shared_infrastructure")
    if coverage != "complete" or receipt_known is False:
        out.append("G_incomplete_observation")
    if similarity and sum(similarity) <= threshold + NEAR:
        out.append("H_near_threshold")
    return tuple(out)


# --- frame 1: generator outputs on recorded wallet windows ---------------------------------


def fixture_candidates() -> list[HNCandidate]:
    from cryptoguard.ml.history import events_from_fixture
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases

    fixtures: list[tuple[str, Any]] = [
        (f"fixture_incident:{c.manifest.case_id}", c.fixture) for c in load_cases() if c.fixture
    ] + [
        (f"fixture_background:{b.manifest.case_id}", b.fixture)
        for b in load_background()
        if b.fixture
    ]
    out: list[HNCandidate] = []
    for frame, fx in fixtures:
        events, _ = events_from_fixture(fx)
        events.sort(key=lambda e: e.position)
        for c in cg.generate(fx):
            e = c.event
            pos = (e.planting_block, e.planting_tx_index or 0, e.planting_log_index or 0)
            earlier = [x for x in events if x.position < pos]
            first = all(x.counterparty.lower() != e.lookalike for x in earlier)
            trusted = e.log_contract in TRUSTED_TOKENS
            out.append(
                HNCandidate(
                    event=e,
                    frame=frame,
                    methods=c.methods,
                    categories=categories(
                        similarity=c.best_match,
                        threshold=cg.MIN_AFFIX,
                        token_trusted=trusted,
                        value_usd=None,
                        methods=c.methods,
                        signer=e.tx_signer,
                        token=e.log_contract or "",
                        coverage=e.coverage,
                        first_time=first,
                        receipt_known=True,  # a recorded Transfer log implies success
                        value_base_units=float(c.value),
                    ),
                    token_trusted=trusted,
                    value_base_units=float(c.value),
                    value_usd=None,
                    similarity=c.best_match,
                    coverage=e.coverage,
                    first_time_counterparty=first,
                    receipt_known=True,
                    context=tuple(
                        {
                            "block": x.block,
                            "direction": x.direction,
                            "counterparty": x.counterparty.lower(),
                            "value": str(x.value),
                        }
                        for x in earlier[-25:]
                    ),
                )
            )
    return out


# --- frame 2: the archive's uncategorized lookalike transfers -------------------------------


def archive_candidates(rows: Iterable[Mapping[str, Any]]) -> list[HNCandidate]:
    out: list[HNCandidate] = []
    for r in rows:
        victim, look = (
            (r["sender"], r["receiver"]) if r["sender_is_victim"] else (r["receiver"], r["sender"])
        )
        token = r["token"].lower()
        trusted = token in TRUSTED_TOKENS
        sim = (
            (r["first_digits"], r["last_digits"])
            if r["first_digits"] is not None and r["last_digits"] is not None
            else None
        )
        e = PoisoningEvent(
            chain_id=1,
            victim=victim,
            lookalike=look,
            imitated=r["intended"],
            planting_tx=r["tx"],
            planting_block=r["block"],
            planting_tx_index=None,
            planting_log_index=r["line"],  # the archive has no log index: its line number
            observation_timestamp=None,
            subtype="other",
            tx_signer=None,
            log_contract=token,
            token_contract=token if trusted else None,
            candidate_method="tsuchiya-archive:uncategorized",
            coverage="unavailable",
        )
        usd = r["value_usd"]
        out.append(
            HNCandidate(
                event=e,
                frame="archive_uncategorized",
                methods=("source_uncategorized",),
                categories=categories(
                    similarity=sim,
                    threshold=7,  # the source's 3+4 rule
                    token_trusted=trusted,
                    value_usd=usd,
                    methods=(),
                    signer=None,
                    token=token,
                    coverage="unavailable",
                    first_time=None,
                    receipt_known=True,  # the archive is built from emitted logs
                    value_base_units=r["value"],
                ),
                token_trusted=trusted,
                value_base_units=r["value"],
                value_usd=usd,
                similarity=sim,
                coverage="unavailable",
                first_time_counterparty=None,
                receipt_known=True,
            )
        )
    return out


# --- known positives ------------------------------------------------------------------------


def known_index(data_dir: Path, poisoning_dir: Path) -> tuple[KnownIndex, dict[str, int]]:
    """Every locally known poisoning record. Archive rows are streamed from SQLite.

    Screening *coverage* (a range in which absence of a match means something) comes only
    from the Tsuchiya archive, the one chain-wide detector here. Poison-Hunter is a sample,
    and the incidents are single cases: they can confirm an overlap but never vouch for its
    absence."""
    from cryptoguard.ml.poison_hunter import parse_sample
    from cryptoguard.ml.tsuchiya import parse_payoffs
    from cryptoguard.ml.tsuchiya_archive import COUNTERFEIT, PAYOFF_UNCONFIRMED, POISONING
    from cryptoguard.replay.models import load_cases

    ix = KnownIndex()
    added: Counter[str] = Counter()

    def add(k: KnownAttack) -> None:
        ix.add(k)
        added[k.source] += 1

    for db in (
        poisoning_dir / "archive_subset.sqlite",
        poisoning_dir / "hard_negative" / "context_subset.sqlite",
    ):
        if not db.exists():
            continue
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        query = (
            "select sender, receiver, sender_is_victim, tx, intended, token, flags "
            "from transfers where flags & ?"
        )
        for s, r, sv, tx, intended, token, flags in con.execute(
            query, (POISONING | PAYOFF_UNCONFIRMED,)
        ):
            victim, look = (s, r) if sv else (r, s)
            src = "tsuchiya-archive" if flags & POISONING else "tsuchiya-archive-unconfirmed-payoff"
            add(
                KnownAttack(src, victim, look, tx, intended, token if flags & COUNTERFEIT else None)
            )
        con.close()
    ix.coverage.append(Coverage("tsuchiya-archive", *ARCHIVE_RANGE))
    payoffs = parse_payoffs(data_dir / "tsuchiya2025" / "payoff_transfers_ethereum.csv").valid
    for p in payoffs:
        add(KnownAttack("tsuchiya-payoff", p.payer, p.lookalike, p.tx_hash))
    ph = parse_sample(data_dir / "poison-hunter" / "phishing_transfers_sample.csv").valid
    for r in ph:
        add(KnownAttack("poison-hunter", r.victim, r.lookalike, r.planting_tx, r.imitated))
    for case in load_cases():
        m = case.manifest
        add(
            KnownAttack(
                "incident",
                m.victim,
                m.harm.recipient,
                m.harm.transaction_hash,
                m.intended_recipient,
            )
        )
    return ix, dict(added)


def screen_all(cands: Sequence[HNCandidate], ix: KnownIndex) -> list[HNCandidate]:
    from dataclasses import replace

    return [
        replace(
            c,
            screened=screen(
                victim=c.event.victim,
                lookalike=c.event.lookalike,
                tx=c.event.planting_tx,
                block=c.event.planting_block,
                imitated=c.event.imitated,
                token=None if c.token_trusted else c.event.log_contract,
                index=ix,
            ),
        )
        for c in cands
    ]


# --- matching covariates --------------------------------------------------------------------


def value_bin(usd: float | None) -> str:
    if usd is None:
        return "missing"
    if usd == 0:
        return "zero"
    return "<=1" if usd <= 1 else "<=100" if usd <= 100 else ">100"


def similarity_bin(sim: tuple[int, int] | None) -> str:
    if sim is None:
        return "missing"
    total = sum(sim)
    return "7" if total <= 7 else "8-9" if total <= 9 else "10+"


# --- cohort ---------------------------------------------------------------------------------


def cohort_items(cands: Sequence[HNCandidate]) -> tuple[list[FrameItem], dict[str, int]]:
    """Eligible frame: every screened candidate except known-positive overlaps. Potential
    overlaps stay eligible, in their own stratum, so they are not silently dropped."""
    eligible = [c for c in cands if c.screened and c.screened.status != "known_positive_overlap"]
    excluded = Counter(c.frame.split(":")[0] for c in cands if c not in eligible)
    items: list[FrameItem] = []
    for frame in sorted({c.frame for c in eligible}):
        members = [c for c in eligible if c.frame == frame]
        policy = GroupingPolicy(
            exclude=frozenset({"shared_victim"}) if frame.startswith("fixture") else frozenset()
        )
        grouping = typed_groups([c.event for c in members], policy)
        for c in members:
            flag = (
                "yes" if c.screened and c.screened.status == "potential_positive_overlap" else "no"
            )
            items.append(
                FrameItem(
                    event_id=c.event.victim_event_id,
                    stratum=f"{frame}|{c.year}|{flag}",
                    group=f"{frame}/{grouping.group[c.event.victim_event_id]}",
                    sheet={
                        "chain_id": 1,
                        "wallet": c.event.victim,
                        "address_under_review": c.event.lookalike,
                        "transaction": c.event.planting_tx,
                        "block": c.event.planting_block,
                        "coverage_note": _coverage_note(c),
                        "context": [dict(x) for x in c.context],
                    },
                    key=key_record(c),
                )
            )
    return items, dict(excluded)


def _coverage_note(c: HNCandidate) -> str:
    if c.coverage == "complete":
        return (
            "The wallet's transfers in the recorded window are complete; earlier history was "
            "not recorded."
        )
    if c.coverage == "partial":
        return "The recorded window is incomplete: some transfers may be missing."
    return "No wallet history is included: use a block explorer, up to the block above."


def key_record(c: HNCandidate) -> dict[str, Any]:
    return {
        "event_id": c.event.victim_event_id,
        "frame": c.frame,
        "methods": list(c.methods),
        "categories": list(c.categories),
        "token": c.event.log_contract,
        "token_trusted": c.token_trusted,
        "value_usd": c.value_usd,
        "similarity": list(c.similarity) if c.similarity else None,
        "imitated": c.event.imitated,
        "screen_level": c.screened.level if c.screened else None,
        "screen_status": c.screened.status if c.screened else None,
        "screen_sources": list(c.screened.sources) if c.screened else [],
        "label_status": c.label_status,
    }


def cohort_design(items: Sequence[FrameItem]) -> CohortDesign:
    """Quotas fixed before the draw: 24 from the archive frame, 2 per recorded wallet."""
    quota: dict[str, int] = {"archive_uncategorized": 24}
    for frame in {i.stratum.split("|")[0] for i in items if i.stratum.startswith("fixture")}:
        quota[frame] = 2
    return CohortDesign(
        version=COHORT_VERSION,
        seed=COHORT_SEED,
        quota=quota,
        strata_names=("frame", "year", "potential_positive_overlap"),
        notes="Known-positive overlaps excluded; potential overlaps kept as their own stratum. "
        "Recorded-wallet frames are one stratum per wallet; the archive frame takes one item "
        "per typed campaign group.",
    )


def pool_summary(cands: Sequence[HNCandidate]) -> dict[str, Any]:
    by_frame: dict[str, Any] = {}
    for frame in sorted({c.frame.split(":")[0] for c in cands}):
        cs = [c for c in cands if c.frame.split(":")[0] == frame]
        by_frame[frame] = {
            "candidates": len(cs),
            "wallets": len({c.event.victim for c in cs}),
            "blocks": [
                min(c.event.planting_block for c in cs),
                max(c.event.planting_block for c in cs),
            ],
            "categories": dict(sorted(Counter(k for c in cs for k in c.categories).items())),
            "methods": dict(sorted(Counter(m for c in cs for m in c.methods).items())),
            "screen_level": dict(Counter(c.screened.level for c in cs if c.screened)),
            "screen_status": dict(Counter(c.screened.status for c in cs if c.screened)),
            "token_trusted": sum(c.token_trusted for c in cs),
            "value_usd_bins": dict(Counter(value_bin(c.value_usd) for c in cs)),
            "similarity_bins": dict(Counter(similarity_bin(c.similarity) for c in cs)),
            "duplicate_event_ids": len(cs) - len({c.event.victim_event_id for c in cs}),
        }
    return {"version": HN_VERSION, "label_status": "unlabeled_candidate", "frames": by_frame}


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, default=str)

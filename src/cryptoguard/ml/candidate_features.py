"""Point-in-time candidate features and an offline shadow ranking (protocol 12.5 §6).

``poisoning-candidate-features/1``: for each C2 candidate of a wallet window, features from
observations strictly before the cutoff, each a ``(value, status)`` pair. ``status`` is one of
``observed``, ``zero_observed`` (a real zero in a fully observed scope), ``unknown`` (the
source did not observe what the feature needs) and ``not_applicable``. A missing
observation is never a zero.

``poisoning-candidate-ranking/1``: orders C2 candidates by B4 (recency of the latest
evidence), the one signal with large-sample support, which is source-conditional (Phase 12.1,
archive payoff episodes). B3 (similarity), B5 (semantic channel) and B6 (familiarity) ranks
are reported beside it. Research only: disabled by default, called only from the research
CLI, never a probability, a severity, a suppression or a production finding.
"""

from __future__ import annotations

import itertools
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml.candidates import similar
from cryptoguard.ml.payments import TRUSTED_TOKENS
from cryptoguard.replay.observation import coverage_of

FEATURE_VERSION = "poisoning-candidate-features/1"
RANKING_VERSION = "poisoning-candidate-ranking/1"
DAY = 7_200
Status = Literal["observed", "zero_observed", "unknown", "not_applicable"]


@dataclass(frozen=True)
class FeatureValue:
    value: float | str | None
    status: Status


def _count(n: int, complete: bool) -> FeatureValue:
    if not complete:
        return FeatureValue(None, "unknown")
    return FeatureValue(float(n), "observed" if n else "zero_observed")


def candidate_features(
    fixture: Any, candidate: cd.DiscoveryCandidate, cutoff: tuple[int, int]
) -> dict[str, FeatureValue]:
    """Features of one candidate from observations strictly before ``cutoff``."""
    cov = coverage_of(fixture)
    obs = [o for o in cd.observations(fixture) if (o.block, o.tx_index) < cutoff]
    look = candidate.lookalike
    mine = [o for o in obs if o.counterparty == look]
    refs_complete = cov.complete(*cd.REFERENCE_CATEGORIES)
    chosen = [o for o in obs if o.direction == "out" and o.wallet_signed is True]
    matched = {o.counterparty for o in chosen if similar(look, o.counterparty)}
    first = mine[0] if mine else None
    f: dict[str, FeatureValue] = {}
    # address
    if candidate.affix is None:
        f["affix_prefix"] = f["affix_suffix"] = FeatureValue(None, "not_applicable")
    else:
        f["affix_prefix"] = FeatureValue(float(candidate.affix[0]), "observed")
        f["affix_suffix"] = FeatureValue(float(candidate.affix[1]), "observed")
    f["matched_references"] = _count(len(matched), refs_complete)
    ref_pays = [
        o
        for o in chosen
        if candidate.imitated and o.counterparty == candidate.imitated and o.succeeded is not False
    ]
    if candidate.imitated is None:
        f["reference_paid_before"] = FeatureValue(None, "not_applicable")
        f["blocks_since_reference_payment"] = FeatureValue(None, "not_applicable")
    elif not refs_complete:
        f["reference_paid_before"] = FeatureValue(None, "unknown")
        f["blocks_since_reference_payment"] = FeatureValue(None, "unknown")
    else:
        f["reference_paid_before"] = FeatureValue(float(bool(ref_pays)), "observed")
        f["blocks_since_reference_payment"] = (
            FeatureValue(float(cutoff[0] - ref_pays[-1].block), "observed")
            if ref_pays
            else FeatureValue(None, "not_applicable")
        )
    # semantics (of the earliest evidence)
    f["kind"] = FeatureValue(candidate.kind, "observed")
    f["channel"] = FeatureValue(
        "spoofed_out" if "spoofed_out" in candidate.methods else "inbound", "observed"
    )
    if first is None:
        f["zero_value"] = FeatureValue(None, "unknown")
        f["signer_role"] = FeatureValue(None, "unknown")
    else:
        f["zero_value"] = FeatureValue(float(first.value == 0), "observed")
        role = (
            "lookalike_itself"
            if first.kind == "native" and first.direction == "in"
            else "unknown"
            if first.signer is None
            else "wallet"
            if first.wallet_signed
            else "foreign"
        )
        f["signer_role"] = FeatureValue(role, "unknown" if role == "unknown" else "observed")
    if candidate.kind == "erc20" and first is not None:
        f["emitter_reviewed"] = FeatureValue(float(first.emitter in TRUSTED_TOKENS), "observed")
    else:
        f["emitter_reviewed"] = FeatureValue(None, "not_applicable")
    if candidate.kind == "native" and first is not None:
        f["receipt_status"] = (
            FeatureValue(float(first.succeeded), "observed")
            if first.succeeded is not None
            else FeatureValue(None, "unknown")
        )
    else:
        f["receipt_status"] = FeatureValue(None, "not_applicable")
    # temporal
    blocks = [o.block for o in mine]
    f["first_seen_block"] = (
        FeatureValue(float(blocks[0]), "observed") if blocks else FeatureValue(None, "unknown")
    )
    f["last_seen_block"] = (
        FeatureValue(float(blocks[-1]), "observed") if blocks else FeatureValue(None, "unknown")
    )
    f["events"] = FeatureValue(float(len(mine)), "observed")
    f["events_last_day"] = FeatureValue(
        float(sum(1 for b in blocks if b > cutoff[0] - DAY)), "observed"
    )
    gaps = [b - a for a, b in itertools.pairwise(blocks)]
    f["median_interarrival"] = (
        FeatureValue(float(statistics.median(gaps)), "observed")
        if gaps
        else FeatureValue(None, "not_applicable")
    )
    # graph (in-window only: no cross-wallet index is available for these windows)
    signers = {o.signer for o in mine if o.signer and o.signer != fixture.wallet.lower()}
    if not signers:
        f["signer_reuse_in_window"] = FeatureValue(None, "unknown")
    else:
        others = {o.counterparty for o in obs if o.signer in signers and o.counterparty != look}
        f["signer_reuse_in_window"] = FeatureValue(
            float(len(others)), "observed" if others else "zero_observed"
        )
    # completeness (statuses, never risk)
    for cat in ("erc20_transfer_logs", "native_inbound_external", "erc20_outgoing_signers"):
        f[f"coverage_{cat}"] = FeatureValue(cov.status(cat), "observed")
    return f


@dataclass(frozen=True)
class RankedCandidate:
    lookalike: str
    imitated: str | None
    methods: tuple[str, ...]
    kind: str
    evidence: str
    cutoff: tuple[int, int]
    rank: float  # the shadow order (B4), tie-averaged
    baseline_ranks: dict[str, float]
    features_available: int
    features_unknown: int
    completeness: dict[str, str]
    version: str
    explanation: str


def _ranks(scores: Mapping[str, tuple[float, ...]]) -> dict[str, float]:
    """1 is best; ties share the average rank."""
    order = sorted(scores, key=lambda c: scores[c], reverse=True)
    out: dict[str, float] = {}
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for c in order[i : j + 1]:
            out[c] = (i + j) / 2 + 1
        i = j + 1
    return out


def rank(fixture: Any, cutoff: tuple[int, int]) -> list[RankedCandidate]:
    """The offline shadow ranking of a window's C2 candidates at ``cutoff``."""
    res = cd.discover(fixture, cutoff=cutoff, variant="C2")
    feats = {c.lookalike: candidate_features(fixture, c, cutoff) for c in res.candidates}

    def val(c: str, k: str) -> float:
        v = feats[c][k].value
        return float(v) if isinstance(v, (int, float)) else float("-inf")

    b4 = {c: (val(c, "last_seen_block"),) for c in feats}
    b3 = {c: (val(c, "affix_prefix") + val(c, "affix_suffix"),) for c in feats}
    b5 = {
        c: (float(feats[c]["channel"].value == "spoofed_out"), val(c, "last_seen_block"))
        for c in feats
    }
    b6 = {c: (-val(c, "blocks_since_reference_payment"),) for c in feats}
    ranks = {"B4": _ranks(b4), "B3": _ranks(b3), "B5": _ranks(b5), "B6": _ranks(b6)}
    out = []
    for c in res.candidates:
        f = feats[c.lookalike]
        known = sum(1 for v in f.values() if v.status in ("observed", "zero_observed"))
        unknown = sum(1 for v in f.values() if v.status == "unknown")
        out.append(
            RankedCandidate(
                lookalike=c.lookalike,
                imitated=c.imitated,
                methods=c.methods,
                kind=c.kind,
                evidence=c.evidence,
                cutoff=cutoff,
                rank=ranks["B4"][c.lookalike],
                baseline_ranks={k: v[c.lookalike] for k, v in ranks.items()},
                features_available=known,
                features_unknown=unknown,
                completeness={
                    k.removeprefix("coverage_"): str(v.value)
                    for k, v in f.items()
                    if k.startswith("coverage_")
                },
                version=RANKING_VERSION,
                explanation=(
                    f"suspicious lookalike candidate ({'+'.join(c.methods)}, {c.kind}); "
                    f"ordered by recency of its latest evidence; not a probability"
                ),
            )
        )
    return sorted(out, key=lambda r: (r.rank, r.lookalike))


def serialize(ranked: Sequence[RankedCandidate]) -> list[dict[str, Any]]:
    return [asdict(r) for r in ranked]

"""Blind evaluation of candidate generation and ranking on recorded windows
(``blind-benchmark/1``, protocol 12.8). Research only; offline; the detector is untouched.

The flow keeps outcomes away from inference by construction:

1. ``predict(case, fixture)`` has no outcome parameter. It freezes the observation hash,
   the candidate identities and every registered frozen method's order, and digests them.
2. ``OutcomeVault.open`` refuses to release an outcome until that prediction is sealed.
3. ``score`` joins the sealed prediction with the outcome and assigns exactly one failure
   class; ``Ledger.record`` refuses a second scoring of a case with a different prediction.

Metrics keep their denominators explicit: conditional TopK is over cases whose candidate
was generated, end-to-end TopK is over all eligible cases and counts generation failures as
misses. A false-positive rate is refused without verified-legitimate labels.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptoguard.ml import adversarial_ranking as ar
from cryptoguard.ml import benchmark_contract as bc
from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_evidence as ce

RUN_VERSION = "blind-benchmark/1"
K_GRID = (1, 3, 5, 10)
PRIMARY_METHOD, PRIMARY_K = "B0", 10  # used only to name the failure class
ORDERS: dict[str, ar.Selector] = {
    "B0": ar.Selector("B0"),
    "B1": ar.Selector("B1"),
    "B4": ar.Selector("B4"),
    "P1": ar.Selector("P1"),
    "P1b": ar.Selector("P1", bucket_tie=True),
}
REGISTRY: tuple[dict[str, Any], ...] = (
    {
        "id": "C0",
        "kind": "generator",
        "version": "candidates/2",
        "requires": ["erc20_transfer_logs", "wallet_signed_transactions"],
        "missingness": "unknown signer: neither reference nor spoof",
        "status": "frozen; production-equivalent candidate rules",
    },
    {
        "id": "C1",
        "kind": "generator",
        "version": "poisoning-candidate-discovery/1",
        "requires": ["erc20_transfer_logs", "wallet_signed_transactions"],
        "missingness": "uses every observed class; asserts untrusted token when identity unknown",
        "status": "research; development cases only",
    },
    {
        "id": "C2",
        "kind": "generator",
        "version": "poisoning-candidate-discovery/1",
        "requires": ["erc20_transfer_logs", "wallet_signed_transactions"],
        "missingness": "abstains without complete reference history",
        "status": "research; drops evidence records (12.6)",
    },
    {
        "id": "E2",
        "kind": "generator",
        "version": ce.EVIDENCE_VERSION,
        "requires": ["erc20_transfer_logs", "wallet_signed_transactions"],
        "missingness": "missing facts lower the support level; never raise suspicion",
        "status": "research; used by this harness",
    },
    {
        "id": "B0",
        "kind": "order",
        "version": ar.SELECTOR_VERSION,
        "requires": [],
        "missingness": "reads affix and position only",
        "status": "current research default (similarity, then recency)",
    },
    {
        "id": "B1",
        "kind": "order",
        "version": ar.SELECTOR_VERSION,
        "requires": [],
        "missingness": "reads position only",
        "status": "baseline; defeated by newer decoys",
    },
    {
        "id": "B4",
        "kind": "order",
        "version": ar.SELECTOR_VERSION,
        "requires": [],
        "missingness": "reads affix, bucket and position",
        "status": "baseline; edged P1b on the 12.7.1 benchmark",
    },
    {
        "id": "P1",
        "kind": "order",
        "version": ar.SELECTOR_VERSION,
        "requires": [],
        "missingness": "reads affix and bucket; no time",
        "status": "comparison only",
    },
    {
        "id": "P1b",
        "kind": "order",
        "version": ar.SELECTOR_VERSION,
        "requires": [],
        "missingness": "reads affix and bucket; no time",
        "status": "failed the 12.7.1 debiased benchmark; comparison only, not preferred",
    },
    {
        "id": "M-LTR",
        "kind": "learned_order",
        "version": "adversarial-ranking-study/1",
        "requires": [],
        "missingness": "missing similarity flagged",
        "status": "learned recency; gate G failed (12.7); not registered for scoring",
    },
)


class UnblindingError(RuntimeError):
    """An outcome was requested before the prediction for its case was sealed."""


class RerunError(RuntimeError):
    """A case already in the ledger was scored again with a different prediction."""


# --- prediction (no outcome) ----------------------------------------------------------------


def observation_sha(fixture: Any) -> str:
    """A content hash of the recorded window (the recording time is not part of it)."""
    data = fixture.model_dump(mode="json", exclude={"recorded_at"})
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class Prediction:
    case_id: str
    run_version: str
    observation_sha256: str
    cutoff: tuple[int, int]
    coverage: dict[str, str]
    candidates: tuple[str, ...]  # lookalike addresses, sorted
    orders: dict[str, tuple[str, ...]]
    mechanisms: dict[str, tuple[str, ...]]
    kinds: dict[str, tuple[str, ...]]
    references: dict[str, tuple[str, ...]]
    abstain: str | None
    burden: dict[str, Any]
    fidelity: dict[str, Any]
    digest: str
    # Best-reference bucket per candidate (protocol 12.9, T5g). A deterministic function of
    # the observation and the cutoff, which the digest already binds; kept out of the digest
    # so that Phase 12.8 ledgers stay valid.
    buckets: dict[str, str] = field(default_factory=dict)


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=list).encode()).hexdigest()


def predict(case: bc.BenchmarkCase, fixture: Any) -> Prediction:
    """Candidates and every registered order from observations strictly before the cutoff.
    Takes the case and its recording only: no outcome can reach it."""
    result = ce.build(fixture, cutoff=case.cutoff)
    groups = list(result.groups)
    if any((r.block, r.tx_index) >= case.cutoff for g in groups for r in g.evidence):
        raise AssertionError("a post-cutoff record reached the candidates")
    orders = {
        name: tuple(g.lookalike for g in ar.order(groups, sel)) for name, sel in ORDERS.items()
    }
    known = {o.identity for o in cd.observations(fixture) if (o.block, o.tx_index) < case.cutoff}
    records = [r for g in groups for r in g.evidence]
    resolved = sum(
        1 for r in records if (r.identity.split(":")[1], r.log_index) in known and r.signer_status
    )
    days = max(1e-9, (min(case.cutoff[0], case.to_block + 1) - case.from_block) / 7_200)
    summary = ce.summarize(result, 10)
    burden = {
        "candidates": len(groups),
        "evidence_records": len(records),
        "wallet_days": round(days, 3),
        "candidates_per_wallet_day": round(len(groups) / days, 4),
        "records_per_candidate": round(len(records) / len(groups), 3) if groups else None,
        "summary_bytes": len(json.dumps(summary)),
    }
    fidelity = {"records": len(records), "resolved_pre_cutoff": resolved}
    obs_sha = observation_sha(fixture)
    candidates = tuple(sorted(g.lookalike for g in groups))
    body = {
        "case_id": case.case_id,
        "run_version": RUN_VERSION,
        "observation_sha256": obs_sha,
        "cutoff": list(case.cutoff),
        "candidates": candidates,
        "orders": orders,
    }
    return Prediction(
        case_id=case.case_id,
        run_version=RUN_VERSION,
        observation_sha256=obs_sha,
        cutoff=case.cutoff,
        coverage=bc.coverage_matrix(fixture),
        candidates=candidates,
        orders=orders,
        mechanisms={g.lookalike: g.mechanisms for g in groups},
        kinds={g.lookalike: g.kinds for g in groups},
        references={g.lookalike: tuple(r[0] for r in g.references) for g in groups},
        abstain=result.abstain,
        burden=burden,
        fidelity=fidelity,
        digest=_digest(body),
        buckets={g.lookalike: ce.bucket_of(g) for g in groups},
    )


# --- outcome isolation ----------------------------------------------------------------------


class OutcomeVault:
    """Holds the sealed outcomes. ``open`` works only for a prediction sealed here first."""

    def __init__(self, outcomes: Mapping[str, bc.Outcome]) -> None:
        self._outcomes = dict(outcomes)
        self._sealed: dict[str, str] = {}

    def seal(self, prediction: Prediction) -> str:
        prior = self._sealed.get(prediction.case_id)
        if prior is not None and prior != prediction.digest:
            raise RerunError(f"{prediction.case_id}: a different prediction is already sealed")
        self._sealed[prediction.case_id] = prediction.digest
        return prediction.digest

    def open(self, prediction: Prediction) -> bc.Outcome | None:
        if self._sealed.get(prediction.case_id) != prediction.digest:
            raise UnblindingError(f"{prediction.case_id}: seal the prediction before unblinding")
        return self._outcomes.get(prediction.case_id)


class Ledger:
    """Append-only record of scored cases. A case is scored once: the same prediction
    returns the stored result; a different prediction is refused and the attempt logged."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.entries: dict[str, dict[str, Any]] = {}
        self.refused: list[dict[str, str]] = []
        if path is not None and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row.get("event") == "scored":
                    self.entries[row["case_id"]] = row
                elif row.get("event") == "rerun_refused":
                    self.refused.append(row)

    def _append(self, row: Mapping[str, Any]) -> None:
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True, default=list) + "\n")

    def record(self, prediction: Prediction, result: Mapping[str, Any]) -> dict[str, Any]:
        prior = self.entries.get(prediction.case_id)
        if prior is not None:
            if prior["prediction_digest"] == prediction.digest:
                return dict(prior["result"])
            row = {
                "event": "rerun_refused",
                "case_id": prediction.case_id,
                "prediction_digest": prediction.digest,
                "recorded_digest": prior["prediction_digest"],
            }
            self.refused.append(row)
            self._append(row)
            raise RerunError(f"{prediction.case_id} is already scored with another prediction")
        row = json.loads(
            json.dumps(
                {
                    "event": "scored",
                    "case_id": prediction.case_id,
                    "prediction_digest": prediction.digest,
                    "run_version": RUN_VERSION,
                    "result": dict(result),
                },
                sort_keys=True,
                default=list,
            )
        )  # JSON-native, so a stored result equals a fresh one
        self.entries[prediction.case_id] = row
        self._append(row)
        return dict(row["result"])


# --- scoring (the only place an outcome is read) --------------------------------------------


def _labelled(outcome: bc.Outcome, dimension: str) -> str | None:
    vals = [x.value for x in outcome.labels if x.dimension == dimension]
    return vals[0] if len(set(vals)) == 1 else None


def mechanism_identified(label: str, mechanisms: Sequence[str], kinds: Sequence[str]) -> bool:
    """Does the candidate's own evidence show the labelled mechanism?"""
    if label == "native_dust":
        return "native" in kinds
    if label == "zero_value_token":
        return "zero_value_in" in mechanisms
    if label == "fake_token":
        return "untrusted_token_in" in mechanisms or "untrusted_token_out" in mechanisms
    if label == "spoofed_transfer":
        return "spoofed_out" in mechanisms or "foreign_initiated_out" in mechanisms
    raise ValueError(label)


def reference_group_exposure(
    prediction: Prediction, outcome: bc.Outcome
) -> dict[str, dict[str, bool]] | None:
    """T5g (protocol 12.9): within K, is there a candidate whose best-reference bucket is the
    intended recipient? Reported apart from address exposure (T4); not assessable (None)
    without an intended recipient."""
    if not outcome.intended_recipient:
        return None
    intended = outcome.intended_recipient.lower()
    return {
        m: {
            str(k): any(prediction.buckets.get(c, "").lower() == intended for c in order[:k])
            for k in K_GRID
        }
        for m, order in prediction.orders.items()
    }


def score(
    case: bc.BenchmarkCase,
    prediction: Prediction,
    outcome: bc.Outcome | None,
    fixture: Any,
) -> dict[str, Any]:
    """T1-T5 for one case and its single failure class (protocol 12.8 sections 8-9)."""
    out: dict[str, Any] = {
        "case_id": case.case_id,
        "population": case.population,
        "cluster_id": case.cluster_id,
        "candidates": len(prediction.candidates),
        "burden": prediction.burden,
        "fidelity": prediction.fidelity,
        "abstain": prediction.abstain,
    }
    if outcome is None or not outcome.verified or not outcome.paid_address:
        return out | {"failure": "outcome_not_verified", "eligible": False}
    synthetic = case.population == "synthetic"
    problems = [
        p for lab in outcome.labels for p in bc.label_problems(lab, synthetic_case=synthetic)
    ]
    if problems or bc.label_conflicts(outcome.labels):
        return out | {"failure": "label_uncertain", "eligible": False, "label_problems": problems}
    paid = outcome.paid_address.lower()
    mechanism = _labelled(outcome, "mechanism")
    elig = bc.mechanism_eligibility(prediction.coverage)
    relevant = (
        [mechanism] if mechanism in bc.MECHANISM_REQUIREMENTS else list(bc.MECHANISM_REQUIREMENTS)
    )
    states = [elig[m]["state"] for m in relevant]
    observed = any(
        o.counterparty == paid and (o.block, o.tx_index) < case.cutoff
        for o in cd.observations(fixture)
    )
    generated = paid in prediction.candidates
    ranks = {
        m: (order.index(paid) + 1 if paid in order else None)
        for m, order in prediction.orders.items()
    }
    mechanism_eligible = all(s == "complete" for s in states)
    out |= {
        "eligible": True,
        "mechanism_label": mechanism,
        "mechanism_eligible": mechanism_eligible,
        "T1_observed": observed,
        "T1_assessable": observed or mechanism_eligible,
        "T2_generated": generated,
        "T3_rank": ranks,
        "T4_exposed": {
            m: {str(k): r is not None and r <= k for k in K_GRID} for m, r in ranks.items()
        },
        "T5g_reference_group_exposed": reference_group_exposure(prediction, outcome),
    }
    if generated and mechanism in bc.MECHANISM_REQUIREMENTS:
        out["T5_mechanism_identified"] = mechanism_identified(
            mechanism, prediction.mechanisms[paid], prediction.kinds[paid]
        )
    else:
        out["T5_mechanism_identified"] = None
    if not observed:
        if "unsupported" in states:
            failure = "observation_unsupported"
        elif not mechanism_eligible:
            failure = "observation_partial"
        else:
            failure = "not_observed_in_complete_stream"
    elif not generated:
        failure = "candidate_not_generated"
    elif (
        outcome.intended_recipient
        and outcome.intended_recipient.lower() not in prediction.references.get(paid, ())
    ):
        failure = "incorrect_reference_matching"
    elif not out["T4_exposed"][PRIMARY_METHOD][str(PRIMARY_K)]:
        failure = "ranked_below_k"
    else:
        failure = "exposed"
    return out | {"failure": failure}


def run_case(
    case: bc.BenchmarkCase, fixture: Any, vault: OutcomeVault, ledger: Ledger
) -> dict[str, Any]:
    """Predict, seal, unblind, score, record: the only sanctioned path to a scored case."""
    prediction = predict(case, fixture)
    vault.seal(prediction)
    outcome = vault.open(prediction)
    return ledger.record(prediction, score(case, prediction, outcome, fixture))


# --- metrics --------------------------------------------------------------------------------


def _ratio(num: int, den: int) -> dict[str, Any]:
    return {"value": round(num / den, 4) if den else None, "numerator": num, "denominator": den}


def aggregate(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Benchmark metrics with their denominators (protocol 12.8 section 8)."""
    verified = [r for r in results if r.get("eligible")]
    mech_ok = [r for r in verified if r["mechanism_eligible"]]
    generated = [r for r in verified if r["T2_generated"]]
    assessable = [r for r in verified if r["T1_assessable"]]
    out: dict[str, Any] = {
        "cases": len(results),
        "verified_outcome": len(verified),
        "mechanism_eligible": len(mech_ok),
        "clusters": len({r["cluster_id"] for r in verified}),
        "failures": _count(r["failure"] for r in results),
        "observation_coverage": _ratio(sum(r["T1_observed"] for r in assessable), len(assessable)),
        "observation_coverage_all_verified": _ratio(
            sum(r["T1_observed"] for r in verified), len(verified)
        ),
        "candidate_recall": _ratio(sum(r["T2_generated"] for r in mech_ok), len(mech_ok)),
        "candidate_recall_all_verified": _ratio(len(generated), len(verified)),
        "conditional_topk": {},
        "end_to_end_topk": {},
        "end_to_end_topk_all_verified": {},
        "mrr_on_generated": {},
    }
    for m in ORDERS:
        out["conditional_topk"][m] = {
            k: _ratio(sum(r["T4_exposed"][m][str(k)] for r in generated), len(generated))
            for k in K_GRID
        }
        out["end_to_end_topk"][m] = {
            k: _ratio(sum(r["T4_exposed"][m][str(k)] for r in mech_ok), len(mech_ok))
            for k in K_GRID
        }
        out["end_to_end_topk_all_verified"][m] = {
            k: _ratio(sum(r["T4_exposed"][m][str(k)] for r in verified), len(verified))
            for k in K_GRID
        }
        rr = [1 / r["T3_rank"][m] for r in generated]
        out["mrr_on_generated"][m] = {
            "value": round(sum(rr) / len(rr), 4) if rr else None,
            "denominator": len(rr),
        }
    grouped = [r for r in mech_ok if r.get("T5g_reference_group_exposed") is not None]
    out["reference_group_exposure"] = {
        m: {
            k: _ratio(
                sum(r["T5g_reference_group_exposed"][m][str(k)] for r in grouped), len(grouped)
            )
            for k in K_GRID
        }
        for m in ORDERS
    }
    out["reference_group_not_assessable"] = len(mech_ok) - len(grouped)
    labelled = [r for r in generated if r["T5_mechanism_identified"] is not None]
    out["mechanism_identification"] = _ratio(
        sum(r["T5_mechanism_identified"] for r in labelled), len(labelled)
    )
    rec = sum(r["fidelity"]["records"] for r in results)
    out["evidence_fidelity"] = _ratio(
        sum(r["fidelity"]["resolved_pre_cutoff"] for r in results), rec
    )
    out["burden"] = burden(results)
    return out


def burden(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    n = len(results)
    if not n:
        return {"windows": 0}
    cands = [r["burden"]["candidates"] for r in results]
    days = sum(r["burden"]["wallet_days"] for r in results)
    return {
        "windows": n,
        "candidates_per_window_mean": round(sum(cands) / n, 3),
        "candidates_per_window_max": max(cands),
        "candidates_per_wallet_day": round(sum(cands) / days, 4) if days else None,
        "evidence_records": sum(r["burden"]["evidence_records"] for r in results),
        "summary_bytes_max": max(r["burden"]["summary_bytes"] for r in results),
    }


def _count(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def false_positive_rate(labels: Sequence[bc.Label], flagged: Sequence[str]) -> dict[str, Any]:
    """FPR over verified-legitimate subjects only. Unknown, unreviewed and ambiguous subjects
    are never negatives; without verified negatives the metric is refused."""
    negatives = {
        lab.subject.lower()
        for lab in labels
        if lab.dimension == "legitimacy"
        and lab.value == "confirmed_legitimate"
        and not bc.label_problems(lab, synthetic_case=True)
    }
    if not negatives:
        return {"status": "blocked", "reason": "no verified-legitimate labels", "value": None}
    fp = len(negatives & {f.lower() for f in flagged})
    return {"status": "ok", **_ratio(fp, len(negatives))}


# --- group-aware splits and leakage ---------------------------------------------------------


def groups(
    cases: Sequence[bc.BenchmarkCase],
    outcomes: Mapping[str, bc.Outcome] | None = None,
    extra: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, int]:
    """Connected components over victim, attack cluster, paid address and any extra keys
    (planting signers, lookalikes): related cases can never sit on both sides of a split."""
    parent = list(range(len(cases)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[str, int] = {}
    for i, c in enumerate(cases):
        keys = [f"v:{c.victim.lower()}", f"c:{c.cluster_id}"]
        o = (outcomes or {}).get(c.case_id)
        if o is not None and o.paid_address:
            keys.append(f"a:{o.paid_address.lower()}")
        keys += [f"x:{k.lower()}" for k in (extra or {}).get(c.case_id, ())]
        for key in keys:
            if key in seen:
                a, b = find(i), find(seen[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                seen[key] = i
    roots = [find(i) for i in range(len(cases))]
    names = {r: n for n, r in enumerate(sorted(set(roots)))}
    return {c.case_id: names[r] for c, r in zip(cases, roots, strict=True)}


def chronological_split(
    cases: Sequence[bc.BenchmarkCase], grp: Mapping[str, int], test_share: float = 0.4
) -> dict[str, str]:
    """Groups ordered by their earliest cutoff; the latest groups form the test side."""
    start: dict[int, int] = {}
    size: dict[int, int] = {}
    for c in cases:
        g = grp[c.case_id]
        start[g] = min(start.get(g, c.cutoff[0]), c.cutoff[0])
        size[g] = size.get(g, 0) + 1
    test: set[int] = set()
    n = 0
    for g in sorted(start, key=lambda g: (start[g], g), reverse=True):
        if n >= test_share * len(cases):
            break
        test.add(g)
        n += size[g]
    return {c.case_id: "test" if grp[c.case_id] in test else "dev" for c in cases}


def leave_one_group_out(grp: Mapping[str, int]) -> list[dict[str, str]]:
    return [
        {cid: "test" if g == held else "dev" for cid, g in grp.items()}
        for held in sorted(set(grp.values()))
    ]


def split_leakage(assignment: Mapping[str, str], grp: Mapping[str, int]) -> list[str]:
    """Groups that appear on more than one side of a split."""
    sides: dict[int, set[str]] = {}
    for cid, side in assignment.items():
        sides.setdefault(grp[cid], set()).add(side)
    return [f"group {g} on {sorted(s)}" for g, s in sorted(sides.items()) if len(s) > 1]


def split_feasibility(n_groups: int) -> dict[str, Any]:
    return {
        "independent_groups": n_groups,
        "chronological_holdout": n_groups >= 10,
        "leave_one_group_out": n_groups >= 3,
        "note": "below 3 groups no split is meaningful; below 10 a holdout has < 4 test groups",
    }


SPENT_POPULATIONS = (
    "archive lookalike-prioritization test split (used in Phase 12.1)",
    "archive lookalike-prioritization development split (12.1, 12.5, 12.7, 12.8)",
    "Level I incidents usdt-counterfeit-39890 and scamsniffer-763k (12.3-12.7.1)",
    "recorded replay and background windows (development; 3 background protected)",
    "12.7 and 12.7.1 synthetic grids",
)


def leakage_audit(
    case: bc.BenchmarkCase,
    fixture: Any,
    prediction: Prediction,
    request: bc.CollectorRequest,
    *,
    protected: bool,
    dev_reasons: Sequence[str],
) -> dict[str, Any]:
    """Automated checks; any failure blocks a confirmatory claim for this case."""
    pre = {o.identity for o in cd.observations(fixture) if (o.block, o.tx_index) < case.cutoff}
    result = ce.build(fixture, cutoff=case.cutoff)
    post = sum(
        1
        for g in result.groups
        for r in g.evidence
        if (r.identity.split(":")[1], r.log_index) not in pre
    )
    allowed = {"chain_id", "wallet", "from_block", "to_block", "observation", "max_requests"}
    checks = {
        "no_post_cutoff_evidence": post == 0,
        "collector_request_has_no_outcome_field": set(request.model_dump()) == allowed,
        "prediction_matches_recording": prediction.observation_sha256 == observation_sha(fixture),
        "no_protected_overlap": not protected,
        "not_a_spent_population": not dev_reasons,
    }
    return {
        "checks": checks,
        "confirmatory_allowed": all(checks.values()),
        "exceptions": list(dev_reasons),
    }


def prediction_json(p: Prediction) -> str:
    return json.dumps(asdict(p), sort_keys=True, default=list)

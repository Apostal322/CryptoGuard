"""Independent incident benchmark (``incident-benchmark/1``), as pre-registered in
docs/ml/protocol-12.3.md. Offline only: it never fetches chain data.

- ``verify``: a provenance, identifier, tier and overlap audit of every discovered case.
- ``run``: tier A operational replay of the cases with a complete recorded wallet stream.
  The unchanged detector sees only records at or before the cutoff and is never told the
  outcome address. Then come the production order (OP0), the frozen recency order (OP1),
  lead times, alert burden and controlled perturbations.
- ``report``: the per-case table.

Evidence levels are never pooled. Nothing here estimates precision, recall or a
false-positive rate.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

BENCHMARK_VERSION = "incident-benchmark/1"
PROTOCOL = "protocol-12.3/1"
FROZEN_AT = "b3f66ae"
MANIFEST = Path("docs/ml/incident-benchmark/candidates.json")
ARCHIVE_BLOCKS = (15_053_226, 20_208_032)
ARCHIVE_LAST_DATE = "2024-06-30"  # the archive's last block (~20.2M) is late June 2024
RECORDING_RPC = (503, 1_361)  # requests per 21,600-block window, measured on the 4 fixtures
DAY = 7_200
_ADDR = re.compile(r"^0x[0-9a-f]{40}$")
_TX = re.compile(r"^0x[0-9a-f]{64}$")


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")

    publisher: str
    url: str
    date: str


class Candidate(BaseModel):
    """One discovered incident. There is deliberately no field for a candidate list: a
    replay must find its candidates itself, never take them from the outcome side."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    source: Source
    chain_id: int | None
    mechanism: str
    identifiers: dict[str, str | None]
    identifier_status: str
    fixture_case_id: str | None
    synthetic: bool


class CandidateManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    protocol: str
    discovery: dict[str, Any]
    candidates: list[Candidate]
    not_usable_sources: list[dict[str, str]] = []


def load_manifest(path: Path = MANIFEST) -> CandidateManifest:
    m = CandidateManifest.model_validate_json(path.read_text(encoding="utf-8"))
    if m.schema_version != "incident-candidates/1":
        raise ValueError(f"{path}: unexpected schema {m.schema_version}")
    ids = [c.case_id for c in m.candidates]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate case ids")
    return m


# --- verify -------------------------------------------------------------------------------


def _complete(ids: Mapping[str, str | None]) -> bool:
    v, lk, tx = ids.get("victim"), ids.get("lookalike"), ids.get("harm_tx")
    return bool(v and lk and tx and _ADDR.match(v) and _ADDR.match(lk) and _TX.match(tx))


def reference_sets(poisoning_dir: Path) -> dict[str, frozenset[str] | None]:
    """Local development and review identifiers. A set that cannot be read is ``None``
    (unknown), never empty."""
    from cryptoguard.ml import lookalike_ranking as lr

    def read_json(p: Path) -> Any:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    out: dict[str, frozenset[str] | None] = {}
    targets = read_json(poisoning_dir / "archive_targets.json")
    for g in (
        "payoff_victims",
        "payoff_lookalikes",
        "payoff_txs",
        "incident_victims",
        "incident_recipients",
        "incident_txs",
        "ph_victims",
        "ph_lookalikes",
        "ph_txs",
    ):
        out[f"archive:{g}"] = None if targets is None else frozenset(targets["groups"].get(g, ()))
    graph = read_json(poisoning_dir / lr.RESEARCH_DIR / "graph_context_targets.json")
    for g in ("candidate_lookalikes", "planting_txs"):
        out[f"phase12_1:{g}"] = None if graph is None else frozenset(graph["groups"].get(g, ()))
    u = read_json(poisoning_dir / "unconfirmed" / "victim_targets.json")
    out["phase12_2:u_victims"] = None if u is None else frozenset(u["groups"].get("u_victims", ()))
    gt = Path("data/external/poison-hunter/phishing_address_groundtruth.txt")
    out["poison_hunter:groundtruth"] = (
        frozenset(x.strip().lower() for x in gt.read_text().split() if x.startswith("0x"))
        if gt.exists()
        else None
    )
    try:
        addrs, txs = lr.protected_entities(poisoning_dir)
        out["frozen_cohorts:addresses"], out["frozen_cohorts:txs"] = addrs, txs
    except FileNotFoundError:
        out["frozen_cohorts:addresses"] = out["frozen_cohorts:txs"] = None
    return out


def fixture_sets(cases: Sequence[Any], exclude: str | None) -> dict[str, frozenset[str]]:
    others = [c for c in cases if c.manifest.case_id != exclude]
    return {
        "fixtures:victims": frozenset(c.manifest.victim.lower() for c in others),
        "fixtures:recipients": frozenset(c.manifest.harm.recipient.lower() for c in others),
        "fixtures:harm_txs": frozenset(c.manifest.harm.transaction_hash.lower() for c in others),
    }


def overlap(
    ids: Mapping[str, str | None], sets: Mapping[str, frozenset[str] | None]
) -> dict[str, list[str]]:
    """For every identifier: the reference sets it is in, plus ``unknown:<set>`` for sets
    that could not be read. Token contracts are never compared."""
    out: dict[str, list[str]] = {}
    for key, value in ids.items():
        if not value:
            continue
        v = value.lower()
        out[key] = sorted(
            name if s is not None else f"unknown:{name}"
            for name, s in sets.items()
            if s is None or v in s
        )
    return out


def verify(
    manifest: CandidateManifest,
    poisoning_dir: Path,
    cases: Sequence[Any] | None = None,
) -> list[dict[str, Any]]:
    from cryptoguard.replay.models import load_cases

    cases = load_cases() if cases is None else cases
    by_id = {c.manifest.case_id: c for c in cases}
    refs = reference_sets(poisoning_dir)
    out: list[dict[str, Any]] = []
    for cand in manifest.candidates:
        row: dict[str, Any] = {"case_id": cand.case_id, "source": cand.source.url}
        if cand.synthetic:
            out.append(
                row
                | {
                    "level": "IV",
                    "tier": "synthetic",
                    "verified": False,
                    "status": "synthetic: software correctness only",
                }
            )
            continue
        if cand.chain_id != 1:
            out.append(
                row
                | {
                    "level": None,
                    "tier": "excluded",
                    "verified": False,
                    "status": "excluded: chain not Ethereum mainnet or not stated",
                }
            )
            continue
        ids = dict(cand.identifiers)
        fx = by_id.get(cand.fixture_case_id or "")
        if cand.fixture_case_id and fx is None:
            raise ValueError(f"{cand.case_id}: fixture {cand.fixture_case_id} is missing")
        sets = {**refs, **fixture_sets(cases, cand.fixture_case_id)}
        if fx is not None:
            m = fx.manifest
            local = {
                "victim": m.victim.lower(),
                "lookalike": m.harm.recipient.lower(),
                "harm_tx": m.harm.transaction_hash.lower(),
            }
            mismatch = sorted(
                k for k, v in ids.items() if v and k in local and v.lower() != local[k]
            )
            ids = {**local, **{k: v for k, v in ids.items() if v and k not in local}}
            complete = fx.fixture is not None and fx.fixture.transfer_scan_complete
            row |= {
                "level": "III",
                "tier": "A" if complete else "B",
                "verified": not mismatch,
                "status": "existing replay fixture"
                + (
                    "; independent source agrees on every identifier"
                    if cand.identifier_status == "verbatim" and not mismatch
                    else ""
                )
                + (f"; MISMATCH on {mismatch}" if mismatch else ""),
                "history": "complete for the recorded window only" if complete else "incomplete",
            }
        elif not _complete(ids):
            row |= {
                "level": None,
                "tier": "not_evaluable",
                "verified": False,
                "status": f"not evaluable: identifiers incomplete ({cand.identifier_status})",
            }
        elif cand.source.date > ARCHIVE_LAST_DATE:
            lo, hi = RECORDING_RPC
            row |= {
                "level": "I (if overlap stays empty)",
                "tier": "not_evaluable",
                "verified": False,
                "status": "not evaluable offline: after the archive's range and no "
                f"recorded wallet stream; recording needs about {lo}-{hi} RPC requests "
                "per 3-day window (not authorized)",
            }
        else:
            row |= {
                "level": "II",
                "tier": "A_prime_candidate",
                "verified": False,
                "status": "in archive range: needs the targeted offline archive lookup",
            }
        row["overlap"] = overlap(ids, sets)
        flagged = {
            k: [n for n in v if not n.startswith("unknown:")] for k, v in row["overlap"].items()
        }
        row["overlap_found"] = sorted({n for v in flagged.values() for n in v})
        if any(n.startswith("frozen_cohorts") for n in row["overlap_found"]):
            row |= {"tier": "excluded", "status": "excluded: frozen review cohort overlap"}
        out.append(row)
    return out


# --- run (tier A) ---------------------------------------------------------------------------


def expected_rank(scores: Mapping[str, float], target: str) -> float:
    """Rank of ``target`` under random tie-breaking (1 = first)."""
    s = scores[target]
    better = sum(1 for v in scores.values() if v > s)
    tied = sum(1 for v in scores.values() if v == s)
    return better + (tied + 1) / 2


def trim(fixture: Any, cutoff: int) -> Any:
    """The fixture as it stood at ``cutoff``: later records removed."""
    return fixture.model_copy(
        update={
            "transfers": [t for t in fixture.transfers if t.block_number <= cutoff],
            "wallet_transactions": [
                t for t in fixture.wallet_transactions if t.block_number <= cutoff
            ],
        }
    )


def warnings_at(fixture: Any, cutoff: int, visibility: Any) -> tuple[list[Any], list[Any]]:
    """All production cases and the warning-rule cases at ``cutoff``. Takes no outcome."""
    from cryptoguard.detectors.poisoning import PoisoningConfig
    from cryptoguard.replay.engine import WARNING_RULES, detector_outputs

    cases, newest = detector_outputs(fixture, cutoff, visibility, PoisoningConfig())
    if newest > cutoff and newest != -1:  # -1: no input at all
        raise RuntimeError(f"detector saw block {newest} after cutoff {cutoff}")
    return cases, [c for c in cases if c.rule_id in WARNING_RULES]


def ranking(warnings: Sequence[Any], target: str, cutoff: int) -> dict[str, Any]:
    from cryptoguard.ml import lookalike_ranking as lr
    from cryptoguard.ml.recency_validation import _pack
    from cryptoguard.ml.warning_rank import baseline_score, rank_warnings, recency_score

    k = len(warnings)
    sus = [w.suspect.lower() for w in warnings]
    if target not in sus:
        return {"k": k, "target_warned": False}
    s0: dict[str, float] = {w.suspect.lower(): _pack(baseline_score(w)) for w in warnings}
    s1: dict[str, float] = {w.suspect.lower(): _pack(recency_score(w, cutoff)) for w in warnings}
    shown = rank_warnings(list(warnings), cutoff)
    return {
        "k": k,
        "target_warned": True,
        "OP0_expected_rank": expected_rank(s0, target),
        "OP1_expected_rank": expected_rank(s1, target),
        "random_expected_rank": (k + 1) / 2,
        "OP0_top1": round(lr.top1(s0, target, k), 4),
        "OP1_top1": round(lr.top1(s1, target, k), 4),
        "OP1_display_rank": next(r.rank for r in shown if r.suspect.lower() == target),
        "warning_set_preserved": sorted(r.suspect for r in shown)
        == sorted(w.suspect for w in warnings),
    }


def _variants(fixture: Any, c: int) -> dict[str, tuple[Any, int, Any]]:
    from cryptoguard.replay.engine import Visibility

    full = Visibility.ERC20_PLUS_WALLET_TRANSACTIONS
    unsigned = fixture.model_copy(
        update={
            "transfers": [t.model_copy(update={"tx_sender": None}) for t in fixture.transfers],
            "wallet_transactions": [],
        }
    )
    lookback = fixture.model_copy(
        update={"transfers": [t for t in fixture.transfers if t.block_number > c - DAY]}
    )
    doubled = fixture.model_copy(update={"transfers": fixture.transfers + fixture.transfers})
    return {
        "primary": (fixture, c, full),
        "delayed_300_blocks": (fixture, c - 300, full),
        "delayed_1_day": (fixture, c - DAY, full),
        "history_last_day_only": (lookback, c, full),
        "erc20_only": (fixture, c, Visibility.ERC20_ONLY),
        "signers_unknown": (unsigned, c, Visibility.ERC20_ONLY),
        "duplicate_records": (doubled, c, full),
    }


def run_case(case: Any) -> dict[str, Any]:
    from cryptoguard.ml import candidates as cand
    from cryptoguard.ml.warning_rank import PLANTING_SIGNALS
    from cryptoguard.replay.engine import replay

    m, fx = case.manifest, case.fixture
    c = m.harm.block_number - 1
    target = m.harm.recipient.lower()
    t = time.perf_counter()
    gen = cand.generate(trim(fx, c))
    looks = {g.event.lookalike for g in gen}
    rep = replay(m, fx)
    out: dict[str, Any] = {
        "case_id": m.case_id,
        "level": "III",
        "tier": "A",
        "cutoff": c,
        "harm_block": m.harm.block_number,
        "window_blocks": fx.to_block - fx.from_block,
        "history": "complete for the recorded window only",
        "candidates": {
            "generated": len(gen),
            "distinct_lookalikes": len(looks),
            "target_recovered": target in looks,
            "target_methods": sorted(
                {x for g in gen if g.event.lookalike == target for x in g.methods}
            ),
        },
        "visibilities": {
            r.visibility.value: {
                "outcome": r.outcome,
                "first_warning_block": r.first_warning.block_number if r.first_warning else None,
                "lead_time_blocks": r.lead_time_blocks,
                "lead_time_seconds": r.lead_time_seconds,
                "other_addresses_flagged_before_harm": r.other_addresses_flagged_before_harm,
            }
            for r in rep.results
        },
        "leakage_checks_passed": all(ch.passed for ch in rep.leakage_checks),
    }
    variants: dict[str, Any] = {}
    for name, (f, cut, vis) in _variants(fx, c).items():
        if cut < fx.from_block:
            variants[name] = {"k": 0, "target_warned": None, "note": "cutoff before the window"}
            continue
        cases_all, warns = warnings_at(f, cut, vis)
        entry = ranking(warns, target, cut) | {"production_cases": len(cases_all)}
        if name == "primary":
            mine = next((w for w in warns if w.suspect.lower() == target), None)
            plants = (
                [
                    s.block_number
                    for s in mine.signals
                    if s.code in PLANTING_SIGNALS
                    and s.block_number is not None
                    and s.block_number <= cut
                ]
                if mine
                else []
            )
            entry["target_first_planting_signal_lead_blocks"] = (
                m.harm.block_number - min(plants) if plants else None
            )
            entry["target_severity"] = mine.severity.value if mine else None
            days = max(1.0, (cut - fx.from_block) / DAY)
            entry["warnings_per_wallet_day"] = round(len(warns) / days, 3)
        variants[name] = entry
    out["ranking"] = variants
    out["seconds"] = round(time.perf_counter() - t, 3)
    return out


def run(
    verified: Sequence[Mapping[str, Any]],
    blind: tuple[frozenset[str], frozenset[str]],
    cases: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Tier A replay of the cases ``verify`` admitted. A case it excluded, or one whose
    recorded window holds a frozen review item, is never computed."""
    from cryptoguard.ml.recency_validation import background, touches_frozen
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes
    from cryptoguard.replay.models import load_cases

    t = time.perf_counter()
    cases = load_cases() if cases is None else cases
    admitted = {v["case_id"] for v in verified if v["tier"] == "A"}
    by_fixture = {v["case_id"]: v for v in verified}
    skipped: list[dict[str, str]] = []
    tier_a = []
    for c in cases:
        if c.fixture is None or not c.fixture.transfer_scan_complete:
            continue
        cid = c.manifest.case_id
        if cid not in admitted:
            status = by_fixture.get(cid, {}).get("status", "not in the verified manifest")
            skipped.append({"case_id": cid, "reason": status})
        elif touches_frozen(c.fixture, blind):
            skipped.append({"case_id": cid, "reason": "recorded window holds a frozen review item"})
        else:
            tier_a.append(c)
    results = [run_case(c) for c in tier_a]
    rankable = [
        r
        for r in results
        if r["ranking"]["primary"].get("target_warned") and r["ranking"]["primary"]["k"] >= 2
    ]
    paired = {"better": 0, "equal": 0, "worse": 0}
    for r in rankable:
        p = r["ranking"]["primary"]
        d = p["OP0_expected_rank"] - p["OP1_expected_rank"]
        paired["better" if d > 0 else "worse" if d < 0 else "equal"] += 1
    peak = peak_rss_bytes()
    return {
        "benchmark": BENCHMARK_VERSION,
        "protocol": PROTOCOL,
        "methods_frozen_at": FROZEN_AT,
        "evidence_level": (
            "III (existing replay incidents); no Level I or II case is evaluable offline"
        ),
        "cases": results,
        "not_computed": skipped,
        "summary_level_III": {
            "tier_A_cases": len(results),
            "target_recovered_as_candidate": sum(
                r["candidates"]["target_recovered"] for r in results
            ),
            "target_warned_at_cutoff": sum(
                bool(r["ranking"]["primary"].get("target_warned")) for r in results
            ),
            "early_warning_full_visibility": sum(
                r["visibilities"]["erc20_plus_wallet_transactions"]["outcome"] == "early_warning"
                for r in results
            ),
            "rankable_cases": len(rankable),
            "OP1_vs_OP0": paired,
            "OP0_top1_cases": sum(r["ranking"]["primary"]["OP0_top1"] == 1.0 for r in rankable),
            "OP1_top1_cases": sum(r["ranking"]["primary"]["OP1_top1"] == 1.0 for r in rankable),
        },
        "background_alert_burden": background(blind),
        "resources": {
            "seconds": round(time.perf_counter() - t, 2),
            "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
            "rpc_requests": 0,
        },
    }


# --- report ---------------------------------------------------------------------------------


def report(verified: Sequence[Mapping[str, Any]], result: Mapping[str, Any]) -> str:
    """Markdown tables: every candidate's status, then the tier A per-case results."""

    def cell(x: Any) -> str:
        return "—" if x is None else str(x)

    lines = [
        "| Case | Level | Tier | Verified | Overlap found | Status |",
        "|---|---|---|---|---|---|",
    ]
    for v in verified:
        lines.append(
            f"| {v['case_id']} | {cell(v.get('level'))} | {v['tier']} | {v['verified']} | "
            f"{', '.join(v.get('overlap_found', [])) or 'none found'} | {v['status']} |"
        )
    lines += [
        "",
        "| Case | Candidate recovered | Warned at cutoff | Pre-harm warning | Lead blocks | k "
        "| OP0 rank | OP1 rank | Random rank |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in result["cases"]:
        p = r["ranking"]["primary"]
        vis = r["visibilities"]["erc20_plus_wallet_transactions"]
        lines.append(
            f"| {r['case_id']} | {r['candidates']['target_recovered']} | "
            f"{p.get('target_warned')} | "
            f"{vis['outcome'] == 'early_warning'} | {cell(vis['lead_time_blocks'])} | {p['k']} | "
            f"{cell(p.get('OP0_expected_rank'))} | {cell(p.get('OP1_expected_rank'))} | "
            f"{cell(p.get('random_expected_rank'))} |"
        )
    return "\n".join(lines) + "\n"

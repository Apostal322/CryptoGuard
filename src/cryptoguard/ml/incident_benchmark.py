"""Independent incident benchmark (``incident-benchmark/1``), as pre-registered in
docs/ml/protocol-12.3.md. Offline only: it never fetches chain data.

- ``verify``: a provenance, identifier, tier and overlap audit of every discovered case.
- ``prepare``: a pre-registered new case's manifest, built from its located receipts
  (``cryptoguard replay locate``); it refuses identifiers the chain does not confirm.
- ``run``: tier A operational replay of the cases with a complete recorded wallet stream.
  The unchanged detector sees only records at or before the cutoff and is never told the
  outcome address. Then come the production order (OP0), the frozen recency order (OP1),
  lead times, alert burden and controlled perturbations.
- ``report``: the per-case table.
- ``resolve`` (Stage 2, amendment A1): a near-miss case's harmful transaction and lookalike,
  found on chain by a rule frozen below before any request (``RESOLUTION_RULES``) from the
  identifiers its source gave. The rule never scores similarity.

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
# Newly recorded cases (Level I), kept apart from the packaged replay cases.
NEW_CASES = Path("docs/ml/incident-benchmark/cases")
STAGE2 = Path("docs/ml/incident-benchmark/stage2-candidates.json")  # as discovered
RESOLVED = Path("docs/ml/incident-benchmark/stage2-resolved.json")  # written by ``resolve``
AMENDMENT = "amendment-12.3-A1"
WINDOW_BLOCKS = 21_600  # before and including the harmful block, as in the 4 replay cases
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


def load_manifests(paths: Sequence[Path]) -> CandidateManifest:
    """The candidates of every manifest that exists, merged; a case id may appear once."""
    found = [load_manifest(path) for path in paths if path.exists()]
    if not found:
        raise FileNotFoundError(f"none of {[str(p) for p in paths]} exists")
    merged = found[0].model_copy(update={"candidates": [c for m in found for c in m.candidates]})
    ids = [c.case_id for c in merged.candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("a case id appears in more than one manifest")
    return merged


# --- resolve (Stage 2, amendment A1) --------------------------------------------------------

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
# Frozen before any Stage 2 request. ``sender``/``recipient`` name identifier keys of the
# case as discovered; dates are inclusive UTC days around the source's reported date.
RESOLUTION_RULES: dict[str, dict[str, Any]] = {
    "scamsniffer-763k-2025-02-20": {
        "sender": "etherscan_filter_fadd",  # Etherscan's advanced filter: fadd is "from"
        "recipient": "etherscan_filter_tadd",  # and tadd is "to"
        "prefixes": [],
        "token": None,
        "since": "2025-02-19",
        "until": "2025-02-21",
    },
    "webacy-6.88m-usdt-2025-09": {
        "sender": "victim",
        "recipient": None,
        "prefixes": ["0x418e0ddb", "0x4186a058", "0x4186a666", "0x4186b115"],
        "token": USDT,
        "since": "2025-09-14",
        "until": "2025-09-19",
    },
}


def _utc(day: str, end: bool = False) -> int:
    from datetime import UTC, datetime

    return int(datetime.fromisoformat(day).replace(tzinfo=UTC).timestamp()) + (86_399 * end)


def resolution_query(cand: Candidate) -> dict[str, Any]:
    """The exact ``replay find-transfers`` query the frozen rule allows for this case."""
    rule = RESOLUTION_RULES.get(cand.case_id)
    if rule is None:
        raise ValueError(f"{cand.case_id}: no pre-registered resolution rule")
    ids = cand.identifiers

    def key(name: str | None) -> str | None:
        if name is None:
            return None
        value = ids.get(name)
        if not value or not _ADDR.match(value):
            raise ValueError(f"{cand.case_id}: identifier {name} is not a full address")
        return value

    return {
        "sender": key(rule["sender"]),
        "recipient": key(rule["recipient"]),
        "recipient_prefixes": [x.lower() for x in rule["prefixes"]],
        "token": rule["token"],
        "since": _utc(rule["since"]),
        "until": _utc(rule["until"], end=True),
    }


def resolve(cand: Candidate, found: Mapping[str, Any]) -> Candidate:
    """The harmful transaction by the frozen rule: the oldest nonzero Transfer the query
    returned whose transaction succeeded and was signed by the sender. Refuses a query that
    differs from the rule, an incomplete scan, or no such transfer (no second rule is tried)."""
    want = resolution_query(cand)
    if dict(found.get("query") or {}) != want:
        raise ValueError(f"{cand.case_id}: the query differs from the pre-registered rule")
    if not found.get("scan_complete"):
        raise ValueError(f"{cand.case_id}: not evaluable: the resolution scan is incomplete")
    sender = str(want["sender"])
    located = {str(x["transaction_hash"]).lower(): x for x in found.get("located") or []}
    for m in found.get("transfers") or []:
        rec = located.get(str(m["transaction_hash"]).lower())
        if rec is None:
            break  # beyond the located prefix: the rule stops rather than guess
        to = str(m["to"]).lower()
        paid = rec.get("found") and any(
            str(tr["from"]).lower() == sender and str(tr["to"]).lower() == to
            for tr in rec.get("transfers") or []
        )
        if paid and rec.get("succeeded") and str(rec.get("from") or "").lower() == sender:
            rule = RESOLUTION_RULES[cand.case_id]
            return cand.model_copy(
                update={
                    "identifiers": {
                        "victim": sender,
                        "lookalike": to,
                        "intended": cand.identifiers.get("intended"),
                        "planting_tx": None,
                        "harm_tx": str(m["transaction_hash"]).lower(),
                    },
                    "identifier_status": f"resolved on chain ({AMENDMENT}): oldest nonzero "
                    f"Transfer signed by {rule['sender']} "
                    + (f"to {rule['recipient']}" if rule["recipient"] else "to a reported prefix")
                    + f", {rule['since']}..{rule['until']} UTC",
                }
            )
    raise ValueError(
        f"{cand.case_id}: identifiers not confirmed on chain (no nonzero Transfer from the "
        "sender, signed by it, among the located matches)"
    )


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


def load_new_cases(directory: Path = NEW_CASES) -> list[Any]:
    from cryptoguard.replay.models import load_cases

    if not directory.is_dir() or not any(p.is_dir() for p in directory.iterdir()):
        return []
    return load_cases(directory)


def onchain_check(ids: Mapping[str, str | None], case: Any) -> dict[str, Any]:
    """Do the reported identifiers appear in the recorded window? The harmful transfer must
    be in it, from the victim to the lookalike; the planting transaction must be in it with
    the lookalike as a party, unless it falls before the window."""
    m, fx = case.manifest, case.fixture
    victim, look = (ids.get("victim") or "").lower(), (ids.get("lookalike") or "").lower()
    by_tx: dict[str, list[Any]] = {}
    for tr in fx.transfers:
        by_tx.setdefault(tr.transaction_hash.lower(), []).append(tr)
    harm_tx = (ids.get("harm_tx") or "").lower()
    harm = by_tx.get(harm_tx, [])
    same_case = m.victim.lower() == victim and m.harm.transaction_hash.lower() == harm_tx
    harm_ok = same_case and any(
        tr.sender.lower() == victim and tr.recipient.lower() == look
        for tr in harm
        if tr.block_number == m.harm.block_number
    )
    plant_tx = (ids.get("planting_tx") or "").lower()
    plants = by_tx.get(plant_tx, [])
    if not plant_tx:
        planting = "not reported"
    elif any(look in (tr.sender.lower(), tr.recipient.lower()) for tr in plants):
        planting = "confirmed in the window"
    elif not plants:
        planting = "not in the window (earlier, or not a transfer of this wallet)"
    else:
        planting = "MISMATCH: in the window without the lookalike"
    return {
        "harm_transfer_confirmed": harm_ok,
        "planting": planting,
        "verified": harm_ok and not planting.startswith("MISMATCH"),
    }


def verify(
    manifest: CandidateManifest,
    poisoning_dir: Path,
    cases: Sequence[Any] | None = None,
    new_cases: Sequence[Any] | None = None,
) -> list[dict[str, Any]]:
    from cryptoguard.replay.models import load_cases

    if new_cases is None:  # the committed folder, unless the caller supplies its own cases
        new_cases = load_new_cases() if cases is None else []
    cases = load_cases() if cases is None else cases
    by_id = {c.manifest.case_id: c for c in cases}
    new_by_id = {c.manifest.case_id: c for c in new_cases}
    if set(by_id) & set(new_by_id):
        raise ValueError(f"case ids in both case sets: {sorted(set(by_id) & set(new_by_id))}")
    refs = reference_sets(poisoning_dir)
    out: list[dict[str, Any]] = []
    for cand in manifest.candidates:
        row: dict[str, Any] = {
            "case_id": cand.case_id,
            "source": cand.source.url,
            # amendment A1: identifiers found by a frozen on-chain rule, not given verbatim
            "identifier_source": "resolved"
            if cand.identifier_status.startswith("resolved")
            else "verbatim",
        }
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
        new = new_by_id.get(cand.case_id)
        sets = {
            **refs,
            **fixture_sets([*cases, *new_cases], cand.fixture_case_id or (new and cand.case_id)),
        }
        if new is not None and fx is None:
            if new.fixture is None:
                row |= {
                    "level": "I (if overlap stays empty)",
                    "tier": "not_evaluable",
                    "verified": False,
                    "status": "pre-registered; window not recorded",
                }
            else:
                check = onchain_check(ids, new)
                complete = new.fixture.transfer_scan_complete
                row |= {
                    "level": "I",
                    "tier": "A" if complete and check["verified"] else "B",
                    "verified": check["verified"],
                    "onchain": check,
                    "status": "newly recorded window"
                    + ("" if check["verified"] else "; identifiers NOT confirmed on chain")
                    + ("" if complete else "; transfer scan incomplete"),
                    "history": "complete for the recorded window only"
                    if complete
                    else "incomplete",
                }
        elif fx is not None:
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


# --- prepare (new cases) --------------------------------------------------------------------


def prepare(
    cand: Candidate,
    located: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    *,
    title: str,
    first_report: str,
) -> Any:
    """The replay manifest of a pre-registered case, from ``replay locate`` output for its
    harmful (and planting) transaction. The window is fixed by rule, never by inspection.
    Refuses when the chain does not show the reported harmful transfer."""
    from datetime import date

    from cryptoguard.core.address import to_checksum_address
    from cryptoguard.replay.models import (
        EvaluationWindow,
        HarmfulTransaction,
        IncidentManifest,
        SourceRef,
    )

    ids = cand.identifiers
    if cand.synthetic or cand.chain_id != 1 or not _complete(ids):
        raise ValueError(f"{cand.case_id}: not a mainnet case with complete identifiers")
    if isinstance(located, Mapping):  # ``replay find-transfers`` output carries its receipts
        located = list(located.get("located") or [])
    resolved = cand.identifier_status.startswith("resolved")
    by_tx = {str(x["transaction_hash"]).lower(): x for x in located}
    harm = by_tx.get(str(ids["harm_tx"]).lower())
    if harm is None or not harm.get("found"):
        raise ValueError(f"{cand.case_id}: the harmful transaction was not located")
    victim, look = str(ids["victim"]).lower(), str(ids["lookalike"]).lower()
    paid = [
        tr for tr in harm["transfers"] if tr["from"].lower() == victim and tr["to"].lower() == look
    ]
    if not harm.get("succeeded") or str(harm.get("from") or "").lower() != victim or not paid:
        raise ValueError(
            f"{cand.case_id}: identifiers not confirmed on chain (the harmful transaction is "
            "not a successful transfer signed by the victim to the lookalike)"
        )
    block = int(harm["block_number"])
    checks = [
        f"Harmful transaction {ids['harm_tx']}: block {block}, signed by the victim, "
        f"{len(paid)} Transfer log(s) from the victim to the lookalike (replay locate)."
    ]
    plant = by_tx.get(str(ids.get("planting_tx") or "").lower())
    if plant is not None:
        checks.append(
            f"Planting transaction {ids['planting_tx']}: "
            + (f"block {plant['block_number']}" if plant.get("found") else "not found")
            + " (replay locate)."
        )
    intended = ids.get("intended")
    return IncidentManifest(
        case_id=cand.case_id,
        title=title,
        category="address_poisoning",
        chain_id=1,
        summary=f"Pre-registered Phase 12.3 benchmark case ({cand.mechanism}); see "
        f"docs/ml/incident-benchmark/{RESOLVED.name if resolved else 'candidates.json'}.",
        first_public_report=date.fromisoformat(first_report),
        public_sources=[
            SourceRef(
                publisher=cand.source.publisher,
                title=title,
                url=cand.source.url,
                accessed=date.fromisoformat(first_report),
                used_for=(
                    f"the reported addresses and dates; the harmful transaction was resolved "
                    f"on chain by the rule frozen in {AMENDMENT}"
                    if resolved
                    else "victim, lookalike, intended recipient, planting and harmful "
                    "transaction hashes"
                ),
            )
        ],
        victim=to_checksum_address(victim),
        intended_recipient=to_checksum_address(intended) if intended else None,
        harm=HarmfulTransaction(
            transaction_hash=str(ids["harm_tx"]).lower(),
            block_number=block,
            recipient=to_checksum_address(look),
            token=to_checksum_address(paid[0]["token"]),
            value_base_units=str(paid[0]["value_base_units"]),
            description="The victim's transfer to the lookalike, as located on chain.",
        ),
        evaluation=EvaluationWindow(
            from_block=block - WINDOW_BLOCKS,
            to_block=block,
            rationale=f"The {WINDOW_BLOCKS:,} blocks (about 3 days) before and including the "
            "harmful block: the rule pre-registered before any request, the same as the "
            "4 replay cases.",
        ),
        onchain_verification=checks,
        ground_truth_limitations=[
            "One public write-up; the recipient is a lookalike by the source's account and by "
            "the located transfer, not by an independent label.",
            "The recorded window is 3 days; earlier history is not observed.",
        ],
    )


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
    r0, r1 = expected_rank(s0, target), expected_rank(s1, target)
    return {
        "k": k,
        "target_warned": True,
        "OP0_expected_rank": r0,
        "OP1_expected_rank": r1,
        # amendment A1: comparable across k; 0 is first, 1 is last; None when k == 1
        "OP0_normalized_rank": round((r0 - 1) / (k - 1), 4) if k > 1 else None,
        "OP1_normalized_rank": round((r1 - 1) / (k - 1), 4) if k > 1 else None,
        "paired_difference_OP0_minus_OP1": r0 - r1,
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


def run_case(case: Any, level: str = "III") -> dict[str, Any]:
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
        "level": level,
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
    # amendment A1 (scoring side only; the detector never sees these):
    seen = [tr for tr in fx.transfers if tr.block_number <= c and target in _parties(tr)]
    out["cluster_signers"] = sorted(
        {tr.tx_sender.lower() for tr in seen if tr.tx_sender} - {m.victim.lower()}
    )
    first = min((tr.block_number for tr in seen), default=None)
    out["lead_possibly_censored"] = None if first is None else first - fx.from_block < DAY
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


def _parties(tr: Any) -> set[str]:
    return {tr.sender.lower(), tr.recipient.lower()}


def sign_test_p(better: int, worse: int) -> float:
    """Exact one-sided sign test: P(at least ``better`` of ``better + worse`` | p = 1/2)."""
    from math import comb

    n = better + worse
    return sum(comb(n, i) for i in range(better, n + 1)) / (1 << n)


def amended_gate_h(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Gate H under amendment A1: cases linked by a shared planting signer (pre-cutoff,
    from the fixture) form one cluster with one vote; below 6 untied clusters the result is
    DESCRIPTIVE; PASS needs at least 10 rankable clusters, more better than worse, and an
    exact one-sided sign test p < 0.05. A case without a known signer is its own cluster
    and is counted as linkage unknown."""
    rankable = [
        r
        for r in results
        if r["ranking"]["primary"].get("target_warned") and r["ranking"]["primary"]["k"] >= 2
    ]
    parent = list(range(len(rankable)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, r in enumerate(rankable):
        for s in r.get("cluster_signers") or []:
            if s in owner:
                parent[root(i)] = root(owner[s])
            else:
                owner[s] = i
    clusters: dict[int, list[float]] = {}
    for i, r in enumerate(rankable):
        clusters.setdefault(root(i), []).append(
            r["ranking"]["primary"]["OP0_expected_rank"]
            - r["ranking"]["primary"]["OP1_expected_rank"]
        )
    votes = {"better": 0, "equal": 0, "worse": 0}
    for diffs in clusters.values():
        b, w = sum(d > 0 for d in diffs), sum(d < 0 for d in diffs)
        votes["better" if b > w else "worse" if w > b else "equal"] += 1
    untied = votes["better"] + votes["worse"]
    p = sign_test_p(votes["better"], votes["worse"]) if untied >= 6 else None
    if not rankable:
        status = "NOT EVALUATED"
    elif untied < 6:
        status = "DESCRIPTIVE"
    elif votes["worse"] > votes["better"]:
        status = "FAIL"
    elif len(clusters) >= 10 and votes["better"] > votes["worse"] and p is not None and p < 0.05:
        status = "PASS"
    else:
        status = "NOT PASSED"
    return {
        "rule": AMENDMENT,
        "rankable_cases": len(rankable),
        "clusters": len(clusters),
        "linkage_unknown_cases": sum(not r.get("cluster_signers") for r in rankable),
        "cluster_votes": votes,
        "sign_test_p_one_sided": p,
        "status": status,
        "lead_possibly_censored_cases": sum(bool(r.get("lead_possibly_censored")) for r in results),
    }


def _summary(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
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
    return {
        "tier_A_cases": len(results),
        "target_recovered_as_candidate": sum(r["candidates"]["target_recovered"] for r in results),
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
        "gate_H_amended": amended_gate_h(results),
    }


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
    if cases is None:
        cases = [*load_cases(), *load_new_cases()]
    admitted = {v["case_id"] for v in verified if v["tier"] == "A"}
    by_fixture = {v["case_id"]: v for v in verified}
    skipped: list[dict[str, str]] = []
    not_recorded: list[str] = []  # amendment A1: pre-registered, no complete window
    new_ids = {x.manifest.case_id for x in load_new_cases()}
    tier_a = []
    for c in cases:
        if c.fixture is None or not c.fixture.transfer_scan_complete:
            if c.manifest.case_id in new_ids:
                not_recorded.append(c.manifest.case_id)
            continue
        cid = c.manifest.case_id
        if cid not in admitted:
            status = by_fixture.get(cid, {}).get("status", "not in the verified manifest")
            skipped.append({"case_id": cid, "reason": status})
        elif touches_frozen(c.fixture, blind):
            skipped.append({"case_id": cid, "reason": "recorded window holds a frozen review item"})
        else:
            tier_a.append(c)
    results = [
        run_case(c, str(by_fixture[c.manifest.case_id].get("level") or "III"))
        | {"identifier_source": by_fixture[c.manifest.case_id].get("identifier_source")}
        for c in tier_a
    ]
    peak = peak_rss_bytes()
    return {
        "benchmark": BENCHMARK_VERSION,
        "protocol": PROTOCOL,
        "methods_frozen_at": FROZEN_AT,
        "evidence_level": "levels are reported separately and never pooled",
        "cases": results,
        "not_computed": skipped,
        "new_cases_not_recorded": not_recorded,
        "summary_level_I": _summary([r for r in results if r["level"] == "I"]),
        "summary_level_I_verbatim_only": _summary(
            [r for r in results if r["level"] == "I" and r["identifier_source"] == "verbatim"]
        ),
        "summary_level_III": _summary([r for r in results if r["level"] == "III"]),
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
    lines.append("")
    for level in ("I", "III"):
        g = result.get(f"summary_level_{level}", {}).get("gate_H_amended")
        if g:
            lines.append(
                f"Gate H, Level {level} ({g['rule']}): {g['status']}; {g['rankable_cases']} "
                f"rankable cases in {g['clusters']} clusters; cluster votes {g['cluster_votes']}"
            )
    if result.get("new_cases_not_recorded"):
        lines.append(f"Pre-registered, not recorded: {', '.join(result['new_cases_not_recorded'])}")
    return "\n".join(lines) + "\n"

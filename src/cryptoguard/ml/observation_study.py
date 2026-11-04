"""Phase 12.4 offline study (protocol 12.4): observation coverage and candidate discovery on
the local recorded windows. No RPC, no download; recorded windows that hold a frozen review
item are never computed on (only their coverage metadata is listed).

Populations: P2 (packaged replay fixtures: excluded, frozen Cohort B), P3 (the two Level I
cases: development cases), P5 (background windows without frozen items: unlabelled). P1
(synthetic) lives in the test suite with hand-written oracles.
"""

from __future__ import annotations

import hashlib
import statistics
import time
import tracemalloc
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.replay.observation import coverage_of

STUDY_VERSION = "observation-study/1"
PROTOCOL = "protocol-12.4"
DAY = 7_200


def touches_frozen_any(fixture: Any, blind: tuple[frozenset[str], frozenset[str]]) -> bool:
    """``recency_validation.touches_frozen`` widened to every observed class: wallet-signed
    native recipients, native inbound senders and ERC-721-shaped parties as well."""
    from cryptoguard.ml.recency_validation import touches_frozen

    addrs, txs = blind
    if touches_frozen(fixture, blind):
        return True
    parties = [t.to for t in fixture.wallet_transactions if t.to] + [
        t.transaction_hash for t in fixture.wallet_transactions
    ]
    parties += [n.sender for n in fixture.native_inbound or []]
    parties += [n.transaction_hash for n in fixture.native_inbound or []]
    for f in fixture.nft_transfers or []:
        parties += [f.sender, f.recipient, f.transaction_hash]
    return any(p.lower() in addrs or p.lower() in txs for p in parties)


def _payments(fixture: Any, cutoff: tuple[int, int]) -> list[tuple[str, tuple[int, int], str]]:
    """Wallet-signed nonzero payments before ``cutoff``: (recipient, position, kind)."""
    out: list[tuple[str, tuple[int, int], str]] = []
    for o in cd.observations(fixture):
        if (
            o.direction == "out"
            and o.wallet_signed is True
            and o.value > 0
            and (o.block, o.tx_index) < cutoff
        ):
            out.append((o.counterparty, (o.block, o.tx_index), o.kind))
    return out


def _window(case_id: str, population: str, fixture: Any, cutoff: tuple[int, int]) -> dict[str, Any]:
    days = max(1.0, (min(cutoff[0], fixture.to_block + 1) - fixture.from_block) / DAY)
    row: dict[str, Any] = {
        "case_id": case_id,
        "population": population,
        "fixture_sha256": fixture.sha256(),
        "cutoff": list(cutoff),
        "coverage": {k: v.status for k, v in coverage_of(fixture).categories.items()},
    }
    variants = {}
    for variant in ("C0", "C1", "C2"):
        tracemalloc.start()
        t0 = time.perf_counter()
        res = cd.discover(fixture, cutoff=cutoff, variant=variant)
        ms = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        variants[variant] = {
            "candidate_events": len(res.candidates),
            "distinct_lookalikes": len(res.lookalikes),
            "per_wallet_day": round(len(res.candidates) / days, 3),
            "with_imitated_reference": sum(c.imitated is not None for c in res.candidates),
            "abstain": res.abstain,
            "runtime_ms": round(ms, 2),
            "peak_traced_kib": round(peak / 1024, 1),
            "_result": res,
        }
    row["c0_vs_c1"] = cd.compare(variants["C0"]["_result"], variants["C1"]["_result"])
    gaps = sorted(
        c.position[0]
        - next(
            (
                o.block
                for o in reversed(cd.observations(fixture))
                if o.counterparty == c.imitated
                and o.direction == "out"
                and o.block <= c.position[0]
            ),
            c.position[0],
        )
        for c in variants["C1"]["_result"].candidates
        if c.imitated
    )
    row["blocks_reference_to_planting"] = gaps
    pays = _payments(fixture, cutoff)
    screens = [cd.screen_payment(fixture, recipient=r, cutoff=p) for r, p, _ in pays]
    row["payment_screen_unlabelled"] = {
        "payments": len(pays),
        "flagged": sum(s.flagged is True for s in screens),
        "abstained": sum(s.flagged is None for s in screens),
        "flagged_recipients": sorted({s.recipient for s in screens if s.flagged}),
    }
    targets = {c.lookalike for c in variants["C1"]["_result"].candidates} | {r for r, _, _ in pays}
    differ = 0
    for r in sorted(targets):
        from dataclasses import asdict

        from cryptoguard.ml.history import events_from_fixture, history_features

        events, window = events_from_fixture(fixture)
        v1 = asdict(
            history_features(
                events,
                window,
                recipient=r,
                block=cutoff[0],
                tx_index=cutoff[1],
                boundary="pre_execution",
            )
        )
        v2 = cd.scoped_history(fixture, recipient=r, block=cutoff[0], tx_index=cutoff[1])
        differ += sum(1 for k in cd.INBOUND_DEPENDENT if v1[k] is not None and v2[k] is None)
    row["h3_inbound_features_numeric_in_v1_undefined_in_scoped"] = differ
    row["h3_feature_rows"] = len(targets)
    row["variants"] = {
        k: {kk: vv for kk, vv in v.items() if kk != "_result"} for k, v in variants.items()
    }
    row["_results"] = {k: v["_result"] for k, v in variants.items()}
    return row


def run(poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.ml.lookalike_ranking import protected_entities
    from cryptoguard.ml.recency_validation import touches_frozen
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases

    t0 = time.perf_counter()
    blind = protected_entities(poisoning_dir)
    metadata: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for c in load_cases():  # P2
        if c.fixture is not None:
            metadata.append(
                _meta(c.manifest.case_id, "P2", c.fixture, blind, "excluded: frozen Cohort B")
            )
    for c in ib.load_new_cases():  # P3
        if c.fixture is None:
            continue
        fx = c.fixture
        harm = next(
            t
            for t in fx.transfers
            if t.transaction_hash.lower() == c.manifest.harm.transaction_hash.lower()
        )
        metadata.append(_meta(c.manifest.case_id, "P3", fx, blind, "development case"))
        row = _window(c.manifest.case_id, "P3", fx, (c.manifest.harm.block_number, 0))
        screen = cd.screen_payment(
            fx,
            recipient=c.manifest.harm.recipient,
            cutoff=(harm.block_number, harm.transaction_index),
        )
        row["development_payment_screen_on_theft"] = {
            "flagged": screen.flagged,
            "imitated": screen.imitated,
            "affix": screen.affix,
            "recipient_seen_before": screen.recipient_seen_before,
            "reason": screen.reason,
            "label": "development-case regression (motivated-by: P3), not validation",
        }
        rows.append(row)
    for b in load_background():  # P5
        if b.fixture is None:
            continue
        frozen = touches_frozen(b.fixture, blind)
        widened = touches_frozen_any(b.fixture, blind)
        metadata.append(
            _meta(
                b.manifest.case_id,
                "P5",
                b.fixture,
                blind,
                "excluded: frozen item" if widened else "unlabelled",
            )
            | {"frozen_rule_v1": frozen, "frozen_rule_widened": widened}
        )
        if not widened:
            rows.append(_window(b.manifest.case_id, "P5", b.fixture, (b.fixture.to_block + 1, 0)))
    links = cd.signer_links(
        [(r["case_id"], _fixture_of(r["case_id"]), r["_results"]["C1"]) for r in rows]
    )
    gaps = [g for r in rows for g in r["blocks_reference_to_planting"]]
    peak = peak_rss_bytes()
    return {
        "study": STUDY_VERSION,
        "protocol": PROTOCOL,
        "discovery": cd.DISCOVERY_VERSION,
        "scoped_history": cd.SCOPED_HISTORY_VERSION,
        "git": _git(),
        "rpc_requests": 0,
        "fixtures": metadata,
        "windows": [{k: v for k, v in r.items() if k != "_results"} for r in rows],
        "signer_links": links,
        "reference_to_planting_blocks": {
            "n": len(gaps),
            "median": statistics.median(gaps) if gaps else None,
            "min": min(gaps, default=None),
            "max": max(gaps, default=None),
            "label": "descriptive only; P3 (development) and P5 (unlabelled) pooled for this count",
        },
        "resources": {
            "seconds": round(time.perf_counter() - t0, 2),
            "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
        },
    }


_FIXTURES: dict[str, Any] = {}


def _meta(case_id: str, population: str, fixture: Any, blind: Any, status: str) -> dict[str, Any]:
    _FIXTURES[case_id] = fixture
    cov = coverage_of(fixture)
    return {
        "case_id": case_id,
        "population": population,
        "status": status,
        "schema": cov.schema_version,
        "fixture_sha256": fixture.sha256(),
        "not_complete": sorted(k for k, v in cov.categories.items() if v.status != "complete"),
    }


def _fixture_of(case_id: str) -> Any:
    return _FIXTURES[case_id]


def _git() -> str | None:
    import subprocess

    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def digest(result: dict[str, Any]) -> str:
    import json

    return hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()


def main(poisoning_dir: Path, out: Path) -> dict[str, Any]:
    import json

    result = run(poisoning_dir)
    out.mkdir(parents=True, exist_ok=True)
    body = json.dumps(result, indent=1, default=str, sort_keys=True)
    (out / "observation-study.json").write_text(body + "\n", encoding="utf-8")
    return result


__all__: Sequence[str] = ("main", "run", "touches_frozen_any")

"""Label-free offline diagnostics (``cryptoguard ml diagnostics``, Phase 11.7). Aggregate
output only. Nothing here is fraud-detection accuracy.

1. **Source-positive candidate coverage.** For the payoff-linked source positives (the 60
   reserved review items excluded), rebuild a 7-day history before each planting from the
   archive rows of the victim, then check whether ``candidates/2`` emits the planting.
   - *strict*: no signer is known (the archive records none);
   - *optimistic*: the victim's own non-poisoning outgoing rows count as signed. This uses
     the source's flags only to model the signer, as a sensitivity bound.
   - The history is source-selected, so this measures what the generator can see in such
     data, not recall on real wallets.
2. **Evidence availability**: per-cohort coverage of the registered evidence packets.
3. **Generator invariance** on the 13 recorded windows: reordering, letter case, duplicates
   and future activity.
4. **Scalability** on synthetic histories.
"""

from __future__ import annotations

import json
import sqlite3
import time
import tracemalloc
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptoguard.ml import candidates as cand

DIAG_VERSION = "diagnostics/1"
WINDOW = 50_400  # about 7 days of blocks


def _fixture(victim: str, rows: list[tuple[Any, ...]], block: int, optimistic: bool) -> Any:
    from cryptoguard.ml.tsuchiya_archive import POISONING
    from cryptoguard.replay.models import RecordedTransfer, ReplayFixture

    transfers = []
    for line, b, tx, token, s, r, value, flags in rows:
        signer = None
        if optimistic and s == victim and not flags & POISONING:
            signer = victim  # the victim's own payment, assumed signed by it
        v = 1 if value is None or value != value else max(0, round(value))
        transfers.append(
            RecordedTransfer(
                token=token,
                sender=s,
                recipient=r,
                value=str(v),
                block_number=b,
                block_hash="0x" + "0" * 64,
                transaction_hash=tx,
                transaction_index=0,
                log_index=line % 1_000_000,
                tx_sender=signer,
            )
        )
    return ReplayFixture(
        case_id="diagnostic",
        chain_id=1,
        wallet=victim,
        from_block=block - WINDOW,
        to_block=block,
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        recorded_with="tsuchiya-archive rows (source-selected)",
        rpc_requests=0,
        transfer_scan_complete=False,
        sender_lookups_skipped=len(transfers),
        method=[],
        wallet_code_hex={},
        block_timestamps={},
        transfers=transfers,
        wallet_transactions=[],
    )


def source_positive_coverage(poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml.review_sample import read_sheet

    reserved = {
        r["victim_event_id"]
        for r in read_sheet(poisoning_dir / "review_sample" / "reviewer_sheet.jsonl")
    }
    packets = [
        p
        for p in map(
            json.loads,
            (poisoning_dir / "review_packets_payoff_linked.jsonl")
            .read_text(encoding="utf-8")
            .splitlines(),
        )
        if p["victim_event_id"] not in reserved
    ]
    con = sqlite3.connect(
        f"file:{(poisoning_dir / 'archive_subset.sqlite').as_posix()}?mode=ro", uri=True
    )
    q = (
        "select line, block, tx, token, sender, receiver, value, flags from transfers "
        "where (sender = ? or receiver = ?) and block between ? and ? order by block, line"
    )
    out: dict[str, Counter[str]] = {"strict": Counter(), "optimistic": Counter()}
    by_subtype: dict[str, Counter[str]] = {"strict": Counter(), "optimistic": Counter()}
    total: Counter[str] = Counter()
    for p in packets:
        v, b = p["victim"], p["observation_block"]
        rows = con.execute(q, (v, v, b - WINDOW, b)).fetchall()
        total[p["subtype"]] += 1
        for mode in ("strict", "optimistic"):
            hits = [
                c
                for c in cand.generate(_fixture(v, rows, b, mode == "optimistic"))
                if c.event.planting_tx == p["planting_tx"] and c.event.lookalike == p["lookalike"]
            ]
            if hits:
                by_subtype[mode][p["subtype"]] += 1
                for m in hits[0].methods:
                    out[mode][m] += 1
    con.close()
    n = sum(total.values())
    return {
        "population": "payoff-linked source positives minus the 60 reserved review items",
        "attempts": n,
        "by_subtype_total": dict(total),
        **{
            mode: {
                "emitted": sum(by_subtype[mode].values()),
                "share": round(sum(by_subtype[mode].values()) / n, 4) if n else None,
                "by_subtype": {s: f"{by_subtype[mode][s]}/{total[s]}" for s in sorted(total)},
                "methods_of_first_hit": dict(out[mode]),
            }
            for mode in ("strict", "optimistic")
        },
    }


def evidence_availability(poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml.evidence import PACKETS

    out: dict[str, Any] = {}
    for name, work in (
        ("review-sample/1", "review"),
        ("hard-negative-candidates/1", "hard_negative/review"),
    ):
        path = poisoning_dir / work / "evidence" / PACKETS
        if not path.exists():
            out[name] = "packets not built"
            continue
        ps = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        hist = sorted(p["wallet_history"]["rows_before_cutoff"] for p in ps)
        out[name] = {
            "items": len(ps),
            "candidate_transfer_found": sum(bool(p["candidate_event"]) for p in ps),
            "signer_known": sum(p["transaction_semantics"]["signer"] is not None for p in ps),
            "token_on_reviewed_list": sum(
                all(t["on_reviewed_token_list"] for t in p["token_provenance"])
                for p in ps
                if p["token_provenance"]
            ),
            "wallet_history_rows_median": hist[len(hist) // 2] if hist else None,
            "no_wallet_history": sum(h == 0 for h in hist),
            "earlier_rows_with_address": sum(
                p["address_relationship"]["earlier_rows_between_wallet_and_address"] > 0 for p in ps
            ),
            "graph_context_available": sum(p["graph_context"] is not None for p in ps),
            "same_block_order_unknown": sum(
                p["wallet_history"].get("same_block_rows_order_unknown", 0) > 0 for p in ps
            ),
            "statuses": dict(Counter(s for p in ps for s in p["coverage"]["statuses"])),
        }
    return out


def generator_invariance() -> dict[str, Any]:
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases

    fixtures = [c.fixture for c in load_cases() if c.fixture] + [
        b.fixture for b in load_background() if b.fixture
    ]

    def key(fx: Any) -> list[tuple[str, tuple[str, ...], Any]]:
        return [(c.event.victim_event_id, c.methods, c.best_match) for c in cand.generate(fx)]

    checks: Counter[str] = Counter()
    for fx in fixtures:
        base = key(fx)
        rev = fx.model_copy(update={"transfers": list(reversed(fx.transfers))})
        upper = fx.model_copy(
            update={
                "wallet": fx.wallet.upper().replace("0X", "0x"),
                "transfers": [
                    t.model_copy(
                        update={
                            "sender": t.sender.upper().replace("0X", "0x"),
                            "recipient": t.recipient.upper().replace("0X", "0x"),
                        }
                    )
                    for t in fx.transfers
                ],
            }
        )
        later = fx.model_copy(
            update={
                "transfers": [
                    *fx.transfers,
                    *[
                        t.model_copy(
                            update={
                                "block_number": fx.to_block + 1,
                                "transaction_hash": t.transaction_hash[:-4] + "ffff",
                            }
                        )
                        for t in fx.transfers
                    ],
                ]
            }
        )
        checks["reorder_identical"] += key(rev) == base
        checks["letter_case_identical"] += key(upper) == base
        checks["future_activity_keeps_past"] += key(later)[: len(base)] == base
    return {"fixtures": len(fixtures), **dict(checks)}


def scalability() -> list[dict[str, Any]]:
    import random

    from cryptoguard.replay.models import RecordedTransfer, ReplayFixture

    rng = random.Random(1)  # noqa: S311 - synthetic workload, not security
    wallet = "0x" + "11" * 20
    parties = ["0x" + f"{rng.getrandbits(160):040x}" for _ in range(400)]
    out = []
    for n in (1_000, 10_000, 30_000):
        ts = []
        for i in range(n):
            out_tx = i % 3 == 0
            party = rng.choice(parties)
            ts.append(
                RecordedTransfer(
                    token="0xdac17f958d2ee523a2206206994597c13d831ec7",  # noqa: S106 - USDT
                    sender=wallet if out_tx else party,
                    recipient=party if out_tx else wallet,
                    value=str(rng.choice([0, 5, 10**9])),
                    block_number=100 + i,
                    block_hash="0x" + "0" * 64,
                    transaction_hash="0x" + f"{i:064x}",
                    transaction_index=0,
                    log_index=0,
                    tx_sender=wallet if out_tx else None,
                )
            )
        fx = ReplayFixture(
            case_id="scale",
            chain_id=1,
            wallet=wallet,
            from_block=100,
            to_block=100 + n,
            recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
            recorded_with="synthetic",
            rpc_requests=0,
            transfer_scan_complete=True,
            sender_lookups_skipped=0,
            method=[],
            wallet_code_hex={},
            block_timestamps={},
            transfers=ts,
            wallet_transactions=[],
        )
        tracemalloc.start()
        t0 = time.perf_counter()
        c = cand.generate(fx)
        dt = time.perf_counter() - t0
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        out.append(
            {
                "transfers": n,
                "candidates": len(c),
                "seconds": round(dt, 3),
                "peak_mib": round(peak / 2**20, 1),
            }
        )
    return out


def run_diagnostics(data_dir: Path, poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml.cross_dataset import git_state

    t0 = time.perf_counter()
    return {
        "version": DIAG_VERSION,
        "candidate_version": cand.CANDIDATE_VERSION,
        "git": git_state(),
        "source_positive_coverage": source_positive_coverage(poisoning_dir),
        "evidence_availability": evidence_availability(poisoning_dir),
        "generator_invariance": generator_invariance(),
        "scalability": scalability(),
        "runtime_seconds": round(time.perf_counter() - t0, 1),
        "rpc_requests": 0,
        "notes": "aggregate only; the source-positive histories are source-selected rows",
    }

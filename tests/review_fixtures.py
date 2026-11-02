"""Synthetic frozen review samples and reviewer decisions for the Phase 11.4 tests.

Nothing here is a real label: decisions are generated to exercise the software."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cryptoguard.ml import review_sample as rs
from cryptoguard.ml.review import ReviewPacket

B2022, B2023, B2024 = 16_000_000, 17_000_000, 19_000_000


def addr(n: int) -> str:
    return "0x" + f"{n:040x}"


def pkt(
    n: int,
    *,
    subtype: str = "fake_token",
    block: int = B2023,
    victim: int | None = None,
    lookalike: int | None = None,
    rival: bool = False,
) -> ReviewPacket:
    return ReviewPacket(
        victim_event_id=f"{n:016x}",
        victim=addr(victim if victim is not None else 10_000 + n),
        lookalike=addr(lookalike if lookalike is not None else 20_000 + n),
        imitated=addr(30_000 + n),
        planting_tx="0x" + f"{n:064x}",
        observation_block=block + n,
        subtype=subtype,
        evidence_summary=f"Source-labelled poisoning transfer {n}; the victim paid later.",
        coverage_limitations="no wallet history observed",
        source_labels=(f"tsuchiya-archive:{subtype}", "tsuchiya-payoff:confirmed"),
        competing_lookalikes=(addr(40_000 + n),) if rival else (),
        payment_evidence=(f"0x{n + 7_000_000:064x} block {block + n + 50} after_planting",),
    )


def queue() -> list[ReviewPacket]:
    out: list[ReviewPacket] = []
    n = 0
    for subtype, block, rival, count in (
        ("fake_token", B2023, False, 40),
        ("fake_token", B2023, True, 50),
        ("fake_token", B2024, True, 6),
        ("spoofed_transfer_from", B2022, False, 20),
        ("spoofed_transfer_from", B2023, True, 60),
        ("dust", B2023, True, 12),
        ("zero_value", B2023, True, 2),
    ):
        for _ in range(count):
            n += 1
            out.append(pkt(n, subtype=subtype, block=block, rival=rival))
    # Two attempts against one victim: a two-attempt campaign group.
    out.append(pkt(500, victim=10_001, rival=False))
    return out


def write_queue(path: Path, packets: list[ReviewPacket]) -> Path:
    path.write_text("".join(p.model_dump_json() + "\n" for p in packets), encoding="utf-8")
    return path


def frozen(tmp: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, dict[str, Any]]:
    """Freeze a synthetic sample and make its hashes the 'committed' ones for this test."""
    q = write_queue(tmp / "queue.jsonl", queue())
    sample = tmp / "sample"
    manifest, _ = rs.freeze(q, sample)
    for name in (rs.SHEET, rs.KEY, rs.MANIFEST):
        monkeypatch.setitem(rs.FROZEN_V1, name, rs.file_sha256(sample / name))
    monkeypatch.setitem(rs.FROZEN_V1, "selection", manifest["selection_sha256"])
    monkeypatch.setitem(rs.FROZEN_V1, "queue", rs.file_sha256(q))
    return q, sample, manifest


ATTEMPT_FIELDS: dict[str, Any] = {
    "decision": "confirmed_poisoning_attempt",
    "confidence": "high",
    "planting_transfer": "observed",
    "prior_counterparty": "observed",
    "prior_counterparty_address": addr(99),
    "matched_leading": 4,
    "matched_trailing": 4,
    "token": "imitation",
    "value_class": "zero",
    "initiator": "third_party",
    "legitimate_explanation": "not_observed",
    "used_explorer": True,
    "viewed_after_cutoff": "no",
    "saw_external_label": "no",
    "saw_source_or_model_output": False,
    "rationale": "Lookalike of the earlier recipient, imitation token, no relationship found.",
}
INSUFFICIENT_FIELDS: dict[str, Any] = {
    **ATTEMPT_FIELDS,
    "decision": "insufficient_evidence",
    "confidence": "low",
    "prior_counterparty": "not_available",
    "prior_counterparty_address": None,
    "matched_leading": None,
    "matched_trailing": None,
    "legitimate_explanation": "not_loaded",
    "rationale": "History before the block could not be loaded.",
}


def fields(item: int, event_id: str, base: dict[str, Any] = ATTEMPT_FIELDS) -> dict[str, Any]:
    return {**base, "item": item, "victim_event_id": event_id}

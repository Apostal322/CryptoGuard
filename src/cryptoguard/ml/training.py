"""Synthetic reviewer-training cohort (``training/1``, Phase 11.6).

Ten invented cases let reviewers learn the app and the evidence panels before any real
item. Their addresses and transactions are fabricated and marked as such. They share
nothing with the frozen cohorts, and the unblinding gate refuses them: they are not in
``review_sample.COHORTS``. The teaching notes are separate from the sheet; reviewers read
them *after* trying the cases.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptoguard.ml import evidence as ev

TRAINING_VERSION = "training/1"
DESCRIPTION = "TRAINING ITEM (synthetic, not real chain data)"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE_TOKEN = "0x" + "fa" * 20
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
NOTES = "training_notes.md"


def _a(head: str, tail: str, fill: str) -> str:
    return "0x" + head + fill * (40 - len(head) - len(tail)) + tail


WALLET = _a("7e57", "7e57", "1")
FRIEND = _a("d2962", "5d7d5", "2")
LOOKALIKE = _a("d2962", "5d7d5", "9")  # 5 leading + 5 trailing characters shared
WEAK = _a("d29", "d7d5", "4")  # 3 + 4
STRANGER = _a("c0ffee", "c0ffee", "3")


def _tx(n: int) -> str:
    return "0x" + f"{n:064x}"


def _row(
    block: int,
    sender: str,
    receiver: str,
    value: str,
    *,
    token: str = USDT,
    tx: int,
    signer: str | None,
    order: int = 0,
) -> ev.Row:
    return ev.Row(
        block, (order, 0), _tx(tx), token, sender, receiver, value, signer, "recorded_window"
    )


def _history() -> list[ev.Row]:
    return [
        _row(1_000, WALLET, FRIEND, "250000000", tx=1, signer=WALLET),
        _row(1_400, FRIEND, WALLET, "1000000", tx=2, signer=FRIEND),
        _row(1_800, WALLET, FRIEND, "90000000", tx=3, signer=WALLET),
    ]


# (title, candidate rows, source, extra history, note)
CASES: list[tuple[str, list[ev.Row], str | None, list[ev.Row], str]] = [
    (
        "Clear planting",
        [_row(2_000, WALLET, LOOKALIKE, "0", tx=101, signer=STRANGER)],
        "recorded_window",
        [],
        "A zero-value transfer *from* the wallet to an address sharing 5+5 characters with "
        "FRIEND, which the wallet paid twice before. A third party signed it, so the wallet "
        "did not choose this. Typical: confirmed attempt, with the earlier FRIEND payments "
        "cited.",
    ),
    (
        "Ordinary transfer",
        [_row(2_000, FRIEND, WALLET, "5000000", tx=102, signer=FRIEND)],
        "recorded_window",
        [],
        "The sender is FRIEND itself (the exact address seen before), not a look-alike. "
        "Similarity rules do not apply. Typical: confirmed legitimate, citing the earlier "
        "payments.",
    ),
    (
        "Ambiguous similarity",
        [_row(2_000, WEAK, WALLET, "40000000", tx=103, signer=WEAK)],
        "recorded_window",
        [],
        "Only 3+4 characters match FRIEND, the token is genuine and the value ordinary. "
        "Weak similarity alone is not intent. Without more, insufficient evidence or likely "
        "is defensible; confirmed is not.",
    ),
    (
        "Spoofed Transfer log",
        [_row(2_000, WALLET, LOOKALIKE, "1000000000", token=FAKE_TOKEN, tx=104, signer=STRANGER)],
        "recorded_window",
        [],
        "An unreviewed token contract emitted a Transfer 'from' the wallet that the wallet "
        "never signed. Logs can be forged by their emitting contract. Check the contract on "
        "an explorer; an imitation token plus a look-alike recipient supports confirmed.",
    ),
    (
        "Reverted transaction",
        [],
        "recorded_window",
        [],
        "The listed transaction left no Transfer log in the recorded data (for example it "
        "reverted). There is nothing to judge: insufficient evidence.",
    ),
    (
        "Unknown token",
        [_row(2_000, LOOKALIKE, WALLET, "1", token=FAKE_TOKEN, tx=106, signer=LOOKALIKE)],
        "recorded_window",
        [],
        "The token is not on the reviewed list, which means only that it is unknown, not "
        "that it is fake. Look up the contract before calling it an imitation.",
    ),
    (
        "Missing history",
        [_row(2_000, LOOKALIKE, WALLET, "0", tx=107, signer=None)],
        "archive",
        [],
        "No earlier rows of this wallet are available locally. Find the earlier counterparty "
        "on an explorer, up to the cutoff block, or answer insufficient evidence.",
    ),
    (
        "Contract-mediated transfer",
        [_row(2_000, WALLET, STRANGER, "70000000", tx=108, signer=ROUTER)],
        "recorded_window",
        [],
        "Tokens left the wallet in a transaction signed by a public router: usually an "
        "approved swap, not a spoof. No look-alike is involved. Typical: confirmed legitimate "
        "if the approval is visible, otherwise insufficient evidence.",
    ),
    (
        "Competing look-alikes",
        [_row(2_000, LOOKALIKE, WALLET, "0", tx=109, signer=LOOKALIKE)],
        "recorded_window",
        [
            _row(1_900, _a("d2962", "5d7d5", "8"), WALLET, "0", tx=110, signer=None),
            _row(1_950, _a("d2962", "5d7d5", "7"), WALLET, "0", tx=111, signer=None),
        ],
        "Several different look-alikes of FRIEND sent zero-value transfers before the cutoff. "
        "That supports a campaign against this wallet, but each item is judged on its own "
        "evidence. Do not infer that the addresses share an owner from similarity alone.",
    ),
    (
        "Insufficient evidence",
        [],
        None,
        [],
        "No local data at all. Without an explorer check, the only honest answer is "
        "insufficient evidence. Do not answer legitimate merely because nothing bad is "
        "visible.",
    ),
]


@lru_cache(maxsize=1)
def build() -> tuple[bytes, bytes, str]:
    """(sheet bytes, packet bytes, notes markdown), deterministic."""
    sheet, packets, notes = [], [], ["# Training notes (read after trying the items)", ""]
    for n, (title, cand, source, extra, note) in enumerate(CASES, start=1):
        address = next((r.sender if r.receiver == WALLET else r.receiver for r in cand), LOOKALIKE)
        line = {
            "schema_version": "review-sheet/2",
            "item": n,
            "victim_event_id": f"{0xFEED0000 + n:016x}",
            "description": DESCRIPTION,
            "chain_id": 1,
            "wallet": WALLET,
            "address_under_review": address,
            "transaction": cand[0].tx if cand else _tx(100 + n),
            "block": 2_000,
            "coverage_note": "Synthetic case.",
        }
        rows = [*(_history() if source == "recorded_window" else []), *extra, *cand]
        packets.append(
            ev.packet(
                line,
                rows=rows,
                source=source,
                window=(500, 3_000) if source == "recorded_window" else None,
            )
        )
        sheet.append(line)
        notes += [f"## {n}. {title}", "", note, ""]
    return ev.dumps(sheet), ev.dumps(packets), "\n".join(notes)


def sheet_sha256() -> str:
    return hashlib.sha256(build()[0]).hexdigest()


def packets_sha256() -> str:
    return hashlib.sha256(build()[1]).hexdigest()


def make_package(reviewer: str, out: Path) -> Path:
    from cryptoguard.ml.annotation import PROTOCOL, REVIEWER_ID, AnnotationError, atomic_write
    from cryptoguard.ml.review_sample import SHEET

    if not REVIEWER_ID.match(reviewer):
        raise AnnotationError(f"invalid reviewer pseudonym {reviewer!r}")
    if out.exists() and any(out.iterdir()):
        raise AnnotationError(f"{out} is not empty")
    sheet, packets, notes = build()
    out.mkdir(parents=True, exist_ok=True)
    atomic_write(out / SHEET, sheet)
    atomic_write(out / ev.PACKETS, packets)
    atomic_write(out / NOTES, notes.encode())
    info = {
        "reviewer": reviewer,
        "protocol": PROTOCOL,
        "selection_sha256": TRAINING_VERSION,
        "sheet_sha256": sheet_sha256(),
        "training": True,
    }
    atomic_write(out / "reviewer.json", json.dumps(info, indent=1).encode() + b"\n")
    return out


def info() -> dict[str, Any]:
    return {"version": TRAINING_VERSION, "items": len(CASES), "sheet_sha256": sheet_sha256()}

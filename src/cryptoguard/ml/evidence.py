"""Offline, pre-cutoff evidence packets for reviewers (``evidence-packets/1``, Phase 11.6).

For each item of a frozen reviewer sheet, the builder gathers what the *local* recorded
data show strictly before the item's block. The block is the observation cutoff; a
same-block row is included only when the recorded order proves it came first.

The builder reads the reviewer sheet, never the unblinding key. From the archive it reads
only block, transaction, token, sender, receiver and value. It never reads the source's
category flags, its ``intended`` (imitated) address or its payoff markings. It computes no
similarity: reviewers find the imitated counterparty themselves, so their identification
stays independent of the source's matching. No network access.

Sections:
1. candidate event;
2. address relationship;
3. transaction semantics;
4. wallet history;
5. token provenance;
6. historical graph context;
7. coverage and uncertainty.

Unknown values are ``None`` or an explicit status, never 0 or False.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptoguard.ml.payments import TRUSTED_TOKENS

EVIDENCE_VERSION = "evidence-packets/2"  # /2: same-block ambiguity, relationship reading
MAX_HISTORY = 50
PACKETS = "evidence_packets.jsonl"
Status = Literal[
    "complete_for_declared_scope",
    "partial_history",
    "source_selected_rows_only",
    "missing_transaction_details",
    "missing_receipt",
    "unknown_signer",
    "unknown_token_legitimacy",
    "unsupported_contract_execution",
    "insufficient_evidence",
    "same_block_order_unknown",
]
ARCHIVE_COLUMNS = "line, block, tx, token, sender, receiver, value"  # never flags or intended


class EvidenceError(ValueError):
    """The requested cutoff or item disagrees with the recorded data."""


@dataclass(frozen=True)
class Row:
    """One recorded transfer, label-free. ``order`` sorts rows within a block when the
    source records it (fixtures: transaction and log index); the archive leaves it None."""

    block: int
    order: tuple[int, int] | None
    tx: str
    token: str
    sender: str
    receiver: str
    value: str
    signer: str | None
    source: str  # "recorded_window" or "archive"


def _archive_rows(dbs: Sequence[Path], where: str, args: Sequence[Any]) -> list[Row]:
    seen: dict[int, Row] = {}
    for db in dbs:
        if not db.exists():
            continue
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        for line, block, tx, token, s, r, value in con.execute(
            f"select {ARCHIVE_COLUMNS} from transfers where {where}",  # noqa: S608 - fixed text
            args,
        ):
            seen.setdefault(
                line,
                Row(
                    block,
                    None,
                    tx,
                    token.lower(),
                    s.lower(),
                    r.lower(),
                    _num(value),
                    None,
                    "archive",
                ),
            )
        con.close()
    return sorted(seen.values(), key=lambda x: (x.block, x.tx, x.sender, x.receiver))


def _num(v: Any) -> str:
    if v is None or (isinstance(v, float) and v != v):
        return "unknown"
    return format(v, ".10g") if isinstance(v, float) else str(v)


def _fixture_rows(fx: Any) -> list[Row]:
    rows = [
        Row(
            t.block_number,
            (t.transaction_index, t.log_index),
            t.transaction_hash.lower(),
            t.token.lower(),
            t.sender.lower(),
            t.recipient.lower(),
            str(t.value),
            t.tx_sender.lower() if t.tx_sender else None,
            "recorded_window",
        )
        for t in fx.transfers
    ]
    rows += [
        Row(
            t.block_number,
            (t.transaction_index, -1),
            t.transaction_hash.lower(),
            "native-eth",
            fx.wallet.lower(),
            (t.to or "").lower(),
            str(t.value),
            fx.wallet.lower(),
            "recorded_window",
        )
        for t in fx.wallet_transactions
        if t.to
    ]
    return sorted(rows, key=lambda x: (x.block, x.order or (0, 0), x.tx))


def _before(r: Row, cutoff: int, position: tuple[int, int] | None) -> bool:
    if r.block != cutoff:
        return r.block < cutoff
    return position is not None and r.order is not None and r.order < position


def packet(
    item: Mapping[str, Any],
    *,
    rows: Sequence[Row],
    source: str | None,
    window: tuple[int, int] | None,
    max_history: int = MAX_HISTORY,
) -> dict[str, Any]:
    """One item's packet from rows already restricted to its wallet and address."""
    wallet, addr = item["wallet"].lower(), item["address_under_review"].lower()
    tx, cutoff = item["transaction"].lower(), int(item["block"])
    candidate = [r for r in rows if r.tx == tx and {wallet, addr} <= {r.sender, r.receiver}]
    statuses: list[Status] = []
    if candidate:
        blocks = {r.block for r in candidate}
        if blocks != {cutoff}:
            raise EvidenceError(
                f"item {item['item']}: transaction at blocks {sorted(blocks)}, "
                f"sheet cutoff {cutoff}"
            )
        position = candidate[0].order
    else:
        statuses.append("missing_transaction_details")
        position = None
    history = [r for r in rows if wallet in (r.sender, r.receiver) and _before(r, cutoff, position)]
    graph = [
        r
        for r in rows
        if addr in (r.sender, r.receiver)
        and wallet not in (r.sender, r.receiver)
        and _before(r, cutoff, position)
    ]
    prior_pair = [r for r in history if addr in (r.sender, r.receiver)]
    # Same-block rows whose order relative to the candidate is unknown: neither shown as
    # history nor silently dropped.
    ambiguous = [
        r
        for r in rows
        if wallet in (r.sender, r.receiver)
        and r.block == cutoff
        and r.tx != tx
        and (position is None or r.order is None)
    ]
    signers = {r.signer for r in candidate}
    if candidate and None in signers:
        statuses.append("unknown_signer")
    tokens = sorted({r.token for r in candidate})
    if any(t not in TRUSTED_TOKENS for t in tokens):
        statuses.append("unknown_token_legitimacy")
    if source == "archive":
        statuses.append("source_selected_rows_only")
        if not history:
            statuses.append("partial_history")  # no row of this wallet before the cutoff
    elif source == "recorded_window":
        statuses.append("complete_for_declared_scope")
    if source is None:
        statuses.append("insufficient_evidence")
    if ambiguous:
        statuses.append("same_block_order_unknown")

    def view(r: Row) -> dict[str, Any]:
        return {
            "block": r.block,
            "transaction": r.tx,
            "token": r.token,
            "from": r.sender,
            "to": r.receiver,
            "value_base_units": r.value,
        }

    return {
        "schema_version": EVIDENCE_VERSION,
        "item": item["item"],
        "victim_event_id": item["victim_event_id"],
        "cutoff": {
            "block": cutoff,
            "rule": "rows strictly before this block; same-block rows only when the recorded "
            "order proves they came earlier",
        },
        "candidate_event": [
            view(r) | {"direction": "wallet sends" if r.sender == wallet else "wallet receives"}
            for r in candidate
        ],
        "address_relationship": {
            "earlier_rows_between_wallet_and_address": len(prior_pair),
            "interpretation": _relationship(len(prior_pair), source),
            "note": "find the earlier counterparty yourself in the wallet history below; no "
            "similarity is computed here",
        },
        "transaction_semantics": {
            "execution": "succeeded (a Transfer log was recorded)" if candidate else None,
            "signer": (
                None
                if not candidate or None in signers
                else ("the wallet" if signers == {wallet} else sorted(signers))
            ),
            "zero_value": any(r.value == "0" for r in candidate) if candidate else None,
        },
        "token_provenance": [
            {"token": t, "on_reviewed_token_list": True if t in TRUSTED_TOKENS else None}
            for t in tokens
        ],
        "wallet_history": {
            "rows_before_cutoff": len(history),
            "same_block_rows_order_unknown": len(ambiguous),
            "shown": [view(r) for r in history[-max_history:]],
            "window": list(window) if window else None,
        },
        "graph_context": (
            {
                "earlier_rows_of_address_with_other_wallets": len(graph),
                "distinct_other_wallets": len(
                    {r.receiver if r.sender == addr else r.sender for r in graph}
                ),
            }
            if source == "archive"
            else None  # a recorded window holds only this wallet's transfers
        ),
        "coverage": {
            "source": source,
            "statuses": statuses,
            "explanation": _explain(source),
        },
    }


def _relationship(n: int, source: str | None) -> str:
    """What a count of earlier wallet-address rows means under this coverage. Missing
    history is never read as 'unfamiliar'."""
    if source is None:
        return "no wallet history is available locally: familiarity is unknown"
    if source == "recorded_window":
        scope = "in the complete recorded window (history before the window is not recorded)"
    else:
        scope = "among the rows a research dataset kept (ordinary activity is missing)"
    return f"{n} earlier row(s) {scope}" if n else f"none {scope}; this is not proof of novelty"


def _explain(source: str | None) -> str:
    if source == "recorded_window":
        return (
            "Every transfer of this wallet inside the recorded block window, and nothing "
            "before the window."
        )
    if source == "archive":
        return (
            "Only rows the research dataset kept (those involving look-alike addresses): "
            "ordinary activity is missing. Use a block explorer for the full history, up "
            "to the cutoff block."
        )
    return "No local record of this wallet. Use a block explorer, up to the cutoff block."


def build(
    sheet: Iterable[Mapping[str, Any]],
    *,
    archive_dbs: Sequence[Path],
    fixtures: Sequence[Any],
    max_history: int = MAX_HISTORY,
) -> list[dict[str, Any]]:
    """Packets for every sheet item, in item order. Deterministic; reads no key."""
    out = []
    for item in sorted(sheet, key=lambda i: i["item"]):
        wallet, addr = item["wallet"].lower(), item["address_under_review"].lower()
        block = int(item["block"])
        fx = next(
            (
                f
                for f in fixtures
                if f.wallet.lower() == wallet and f.from_block <= block <= f.to_block
            ),
            None,
        )
        if fx is not None:
            rows = [r for r in _fixture_rows(fx) if {wallet, addr} & {r.sender, r.receiver}]
            out.append(
                packet(
                    item,
                    rows=rows,
                    source="recorded_window",
                    window=(fx.from_block, fx.to_block),
                    max_history=max_history,
                )
            )
            continue
        rows = _archive_rows(
            archive_dbs, "sender in (?, ?) or receiver in (?, ?)", (wallet, addr, wallet, addr)
        )
        out.append(
            packet(
                item,
                rows=rows,
                source="archive" if rows else None,
                window=None,
                max_history=max_history,
            )
        )
    return out


def dumps(packets: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(json.dumps(p, sort_keys=True).encode() + b"\n" for p in packets)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_cohort(
    sample_dir: Path, out_dir: Path, *, archive_dbs: Sequence[Path], cohort: str
) -> dict[str, Any]:
    """Build, write and describe the packets of one frozen cohort. The frozen sheet is
    verified first; the output goes to ``out_dir``, never into the frozen directory."""
    from cryptoguard.ml import review_sample as rs
    from cryptoguard.ml.annotation import atomic_write
    from cryptoguard.ml.cross_dataset import git_state
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases

    rs.verify_frozen(sample_dir, cohort=cohort, with_key=False)
    fixtures = [c.fixture for c in load_cases() if c.fixture] + [
        b.fixture for b in load_background() if b.fixture
    ]
    packets = build(
        rs.read_sheet(sample_dir / rs.SHEET), archive_dbs=archive_dbs, fixtures=fixtures
    )
    data = dumps(packets)
    out_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(out_dir / PACKETS, data)
    manifest = {
        "version": EVIDENCE_VERSION,
        "cohort": cohort,
        "sheet_sha256": rs.COHORTS[cohort][rs.SHEET],
        "packets_sha256": sha256(data),
        "inputs": {db.name: rs.file_sha256(db) for db in archive_dbs if db.exists()}
        | {f"fixture:{f.case_id}": f.sha256() for f in fixtures},
        "items": len(packets),
        "git": git_state(),
        "rpc_requests": 0,
    }
    atomic_write(out_dir / "evidence_manifest.json", json.dumps(manifest, indent=1).encode())
    return manifest

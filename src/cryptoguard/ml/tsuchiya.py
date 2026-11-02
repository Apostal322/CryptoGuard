"""Typed parser and offline cross-check for Tsuchiya et al.'s ``payoff_transfers_ethereum.csv``.

Source: Tsuchiya et al., "Blockchain Address Poisoning", USENIX Security 2025. Companion
dataset on KiltHub, DOI 10.1184/R1/29212703.v1, licensed CC BY-NC-ND 4.0. Each row is one
token transfer in which a victim paid a lookalike address (a *payoff*). The file stays local
(``data/`` is git-ignored) because the licence forbids redistributing adaptations, so only
aggregate counts and Poison-Hunter line numbers leave this module.

Columns (checked on all 1,738 rows of the pinned file; see ML_POISONING_DATASET.md):

==========================  ===========================================================
column                      content
==========================  ===========================================================
block_number                payoff block
tx_hash                     payoff transaction (one row per transaction)
addr                        token contract (USDT, USDC or DAI in all but 5 rows)
topics_from_addr            payer: the victim
topics_to_addr              recipient: the lookalike
value                       amount in base units, float-encoded (some rows use
                            scientific notation, so values above 2**53 are rounded)
value_usd                   amount in USD, as computed by the source
is_sender_victim            ``True`` in every row
num_first_matched_digits    leading hex characters shared with ``intended_addr``
num_last_matched_digits     trailing hex characters shared with ``intended_addr``
intended_addr               the address the victim presumably meant to pay
==========================  ===========================================================

The file has no native-ETH payoffs, and the study selected lookalikes sharing at least 3
leading and 4 trailing hex characters. Absence of a victim from this file is therefore not
evidence that no payment happened: ETH payments, other tokens, lookalikes outside that
definition and payments after the study period are not in it.
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from cryptoguard.detectors.poisoning import PoisoningConfig, affix_match, is_lookalike
from cryptoguard.ml.candidates import MIN_AFFIX, MIN_SUFFIX
from cryptoguard.ml.poison_hunter import PoisonHunterRecord, SchemaMismatchError

PARSER_VERSION = "tsuchiya-payoff/1"
SOURCE_DOI = "10.1184/R1/29212703.v1"
SOURCE_LICENSE = "CC BY-NC-ND 4.0"
SOURCE_FILE = "payoff_transfers_ethereum.csv"
# Not in ml/sources.py: `fetch-sources` downloads every listed source unasked, and this
# file needs an explicit download decision. Fetched once on 2026-11-02 (482,397 bytes).
SOURCE_URL = "https://ndownloader.figshare.com/files/55053137"
SOURCE_MD5 = "a42bda4339981d31a7e31b66c2d92297"  # published by KiltHub for version 1
SOURCE_SHA256 = "7851f9f9edcf04189137894e16dd228a544d13f4a0799548ece79c69762f2f78"
EXPECTED_HEADER = [
    "block_number",
    "tx_hash",
    "addr",
    "topics_from_addr",
    "topics_to_addr",
    "value",
    "value_usd",
    "is_sender_victim",
    "num_first_matched_digits",
    "num_last_matched_digits",
    "intended_addr",
]
TOKENS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
}
WINDOW_BLOCKS = 50_400  # the pilot's 7-day payment window
_EXACT_FLOAT = 2**53

_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")

Status = Literal["valid", "quarantined"]


class PayoffTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_line: int  # 1-based line in the CSV (header = line 1)
    status: Status
    issues: tuple[str, ...]
    block_number: int | None
    tx_hash: str
    token: str
    payer: str
    lookalike: str
    intended: str
    value_usd: float | None
    value_exact: bool  # False when the float encoding cannot hold the base-unit amount
    prefix_match: int
    suffix_match: int


class PayoffParse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parser_version: str
    source_sha256: str
    source_md5: str
    records: list[PayoffTransfer]

    @property
    def valid(self) -> list[PayoffTransfer]:
        return [r for r in self.records if r.status == "valid"]


def _int(text: str) -> int | None:
    try:
        return int(text)
    except ValueError:
        return None


def _float(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _exact(text: str) -> bool:
    try:
        value = Decimal(text)
    except InvalidOperation:
        return False
    return value == value.to_integral_value() and abs(value) < _EXACT_FLOAT


def _parse_row(line: int, r: dict[str, str]) -> PayoffTransfer:
    issues: list[str] = []
    addresses = ("addr", "topics_from_addr", "topics_to_addr", "intended_addr")
    for name in addresses:
        if not _ADDR.match(r[name]):
            issues.append(f"{name} is not an address")
    if not _HASH.match(r["tx_hash"]):
        issues.append("tx_hash is not a 32-byte hash")
    block = _int(r["block_number"])
    if block is None:
        issues.append("block_number is not an integer")
    if r["is_sender_victim"] != "True":
        issues.append(f"is_sender_victim is {r['is_sender_victim']!r}")
    usd = _float(r["value_usd"])
    if usd is None or usd < 0:
        issues.append("value_usd is not a non-negative number")
    valid_pair = all(_ADDR.match(r[n]) for n in ("topics_to_addr", "intended_addr"))
    prefix, suffix = affix_match(r["topics_to_addr"], r["intended_addr"]) if valid_pair else (0, 0)
    declared = (_int(r["num_first_matched_digits"]), _int(r["num_last_matched_digits"]))
    if valid_pair and declared != (prefix, suffix):
        issues.append(f"declared affix {declared} differs from the addresses ({prefix}, {suffix})")
    return PayoffTransfer(
        source_line=line,
        status="quarantined" if issues else "valid",
        issues=tuple(issues),
        block_number=block,
        tx_hash=r["tx_hash"].lower(),
        token=r["addr"].lower(),
        payer=r["topics_from_addr"].lower(),
        lookalike=r["topics_to_addr"].lower(),
        intended=r["intended_addr"].lower(),
        value_usd=usd,
        value_exact=_exact(r["value"]),
        prefix_match=prefix,
        suffix_match=suffix,
    )


def parse_payoffs(path: Path) -> PayoffParse:
    """Parse every row; rows failing a check are quarantined with reasons, never dropped."""
    raw = path.read_bytes()
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != EXPECTED_HEADER:
            raise SchemaMismatchError(f"{path}: header differs from the identified layout")
        rows = list(reader)
    if any(None in r or None in r.values() for r in rows):
        raise SchemaMismatchError(f"{path}: a row's width differs from the header")
    return PayoffParse(
        parser_version=PARSER_VERSION,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_md5=hashlib.md5(raw, usedforsecurity=False).hexdigest(),
        records=[_parse_row(i + 2, r) for i, r in enumerate(rows)],
    )


def block_range(payoffs: list[PayoffTransfer]) -> tuple[int, int] | None:
    blocks = [p.block_number for p in payoffs if p.block_number is not None]
    return (min(blocks), max(blocks)) if blocks else None


def profile(result: PayoffParse, config: PoisoningConfig | None = None) -> dict[str, Any]:
    """Aggregate validation report (no addresses)."""
    config = config or PoisoningConfig()
    valid = result.valid
    usd = sorted(p.value_usd for p in valid if p.value_usd is not None)
    return {
        "parser_version": result.parser_version,
        "source_sha256": result.source_sha256,
        "source_md5_matches_published": result.source_md5 == SOURCE_MD5,
        "source_sha256_matches_pinned": result.source_sha256 == SOURCE_SHA256,
        "rows": len(result.records),
        "valid": len(valid),
        "quarantined": [
            {"line": r.source_line, "issues": list(r.issues)}
            for r in result.records
            if r.status == "quarantined"
        ],
        "block_range": block_range(valid),
        "tokens": dict(Counter(TOKENS.get(p.token, "other") for p in valid).most_common()),
        "distinct_txs": len({p.tx_hash for p in valid}),
        "distinct_payers": len({p.payer for p in valid}),
        "distinct_lookalikes": len({p.lookalike for p in valid}),
        "inexact_values": sum(1 for p in valid if not p.value_exact),
        "usd_total": round(sum(usd)),
        "usd_median": round(usd[len(usd) // 2], 2) if usd else None,
        # The study's 3+4 selection implies both predicates, so these are consistency
        # checks of the shared affix arithmetic, not recall measurements.
        "detector_predicate_accepts": sum(
            1 for p in valid if is_lookalike(p.lookalike, p.intended, config)
        ),
        "candidate_rule_accepts": sum(
            1
            for p in valid
            if p.prefix_match + p.suffix_match >= MIN_AFFIX and p.suffix_match >= MIN_SUFFIX
        ),
    }


def _bucket() -> dict[str, int]:
    return dict.fromkeys(
        (
            "rows",
            "in_period",
            "in_definition",
            "victim_paid_this_lookalike",
            "victim_paid_this_lookalike_in_window",
            "victim_paid_other_lookalike_of_same_address",
            "victim_paid_any_lookalike",
            "lookalike_paid_by_another_victim",
        ),
        0,
    )


def _finding(r: PoisonHunterRecord, outcome: str, p: PayoffTransfer, kind: str) -> dict[str, Any]:
    return {
        "line": r.source_line,
        "outcome": outcome,
        "paid": kind,
        "blocks_after_planting": (
            p.block_number - r.block_number
            if p.block_number is not None and r.block_number is not None
            else None
        ),
        "value_usd": round(p.value_usd) if p.value_usd is not None else None,
        "same_intended_address": p.intended == r.imitated,
        "paid_affix": [p.prefix_match, p.suffix_match],
        "row_affix": [r.prefix_match, r.suffix_match],
    }


def cross_check(
    payoffs: list[PayoffTransfer],
    rows: list[PoisonHunterRecord],
    outcomes: Sequence[str] | None,
    incidents: list[dict[str, Any]],
    window_blocks: int = WINDOW_BLOCKS,
) -> dict[str, Any]:
    """Match payoffs against Poison-Hunter rows (with their pilot outcomes) and incidents.

    ``outcomes`` is aligned with ``rows``; ``incidents`` items carry ``case``, ``victim``,
    ``block``, ``tx`` and ``token``. A payoff counts *in window* when it lands in blocks
    (planting, planting + window]. Rows are reported by Poison-Hunter line, never address."""
    if outcomes is not None and len(outcomes) != len(rows):
        raise ValueError(f"{len(outcomes)} outcomes for {len(rows)} rows")
    span = block_range(payoffs)
    by_payer: dict[str, list[PayoffTransfer]] = {}
    by_lookalike: dict[str, list[PayoffTransfer]] = {}
    for p in payoffs:
        by_payer.setdefault(p.payer, []).append(p)
        by_lookalike.setdefault(p.lookalike, []).append(p)

    buckets: dict[str, dict[str, int]] = {}
    findings: list[dict[str, Any]] = []
    contradictions: list[int] = []
    for i, r in enumerate(rows):
        outcome = outcomes[i] if outcomes is not None else "no_pilot_record"
        b = buckets.setdefault(outcome, _bucket())
        b["rows"] += 1
        planted = r.block_number
        in_period = span is not None and planted is not None and span[0] <= planted <= span[1]
        b["in_period"] += in_period
        b["in_definition"] += in_period and r.tsuchiya_lookalike
        paid = by_payer.get(r.victim, [])
        same = [p for p in paid if p.lookalike == r.lookalike]
        in_window = [
            p
            for p in same
            if planted is not None
            and p.block_number is not None
            and 0 < p.block_number - planted <= window_blocks
        ]
        other = [p for p in paid if p.lookalike != r.lookalike and p.intended == r.imitated]
        b["victim_paid_this_lookalike"] += bool(same)
        b["victim_paid_this_lookalike_in_window"] += bool(in_window)
        b["victim_paid_other_lookalike_of_same_address"] += bool(other)
        b["victim_paid_any_lookalike"] += bool(paid)
        b["lookalike_paid_by_another_victim"] += any(
            p.payer != r.victim for p in by_lookalike.get(r.lookalike, [])
        )
        if in_window and outcome == "no_direct_payment_observed_with_complete_declared_coverage":
            contradictions.append(r.source_line)
        for p in paid:
            if p.lookalike == r.lookalike:
                kind = "this lookalike"
            elif p.intended == r.imitated:
                kind = "another lookalike of the same address"
            else:
                kind = "a lookalike of another address"
            findings.append(_finding(r, outcome, p, kind))
        findings += [
            _finding(r, outcome, p, "this lookalike, by another victim")
            for p in by_lookalike.get(r.lookalike, [])
            if p.payer != r.victim
        ]

    tokens = {p.token for p in payoffs}
    txs = {p.tx_hash for p in payoffs}
    incident_rows = [
        {
            "case": inc["case"],
            "in_period": span is not None and span[0] <= inc["block"] <= span[1],
            "token_in_file": inc["token"].lower() in tokens,
            "harm_tx_listed": inc["tx"].lower() in txs,
            "victim_listed": inc["victim"].lower() in by_payer,
        }
        for inc in incidents
    ]
    return {
        "window_blocks": window_blocks,
        "payoff_block_range": span,
        "by_outcome": dict(sorted(buckets.items())),
        "contradicted_complete_rows": contradictions,
        "findings": sorted(findings, key=lambda f: (f["line"], f["paid"])),
        "incidents": incident_rows,
    }

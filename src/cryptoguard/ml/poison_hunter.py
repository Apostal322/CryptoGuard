"""Typed parser for Poison-Hunter's ``phishing_transfers_sample.csv`` (150 planting transfers).

The file has a 15-name header and 17 fields per row. Field identification (checked on all
150 rows of the pinned revision; see ML_POISONING_DATASET.md):

====  ==========================  ====================================================
idx   header name                 observed content
====  ==========================  ====================================================
0     attacker                    lowercase address: the lookalike that sent the planting
1     victim                      lowercase address: the wallet the planting targeted
2     similar_norm                lowercase address: the address the lookalike imitates
3     tx_hash                     planting transaction hash (shared by batched rows)
4     symbol                      ``usdc`` or ``usdt``: the token imitated
5     phishing_type               ``dust`` / ``zero`` / ``fake``
6     fake_token_address          token contract emitting the planting log: the genuine
                                  USDC/USDT for ``dust``/``zero``, a fake token for ``fake``
7     fake_token_deployer         deployer of the fake token (empty unless ``fake``)
8     tx_from                     planting transaction signer (= attacker for ``dust``; a
                                  batch operator for ``zero``/``fake``)
9     tx_to                       transaction target (the token for ``dust``, a batch
                                  contract otherwise)
10    tx_fee                      fee in ETH
11    is_batching                 batch size (a count, not a flag; 1 for ``dust``)
12    batch_contract_deployer     batch contract deployer (empty for ``dust``)
13    block_number                planting block
14    block_distance              blocks since the victim's imitated transfer (inferred)
15    (unnamed)                   ``from``/``to``: direction of the imitated transfer
16    (unnamed)                   small integer, close to the matched hex-character count
====  ==========================  ====================================================

The header is aligned for fields 0-14; fields 15-16 are unnamed and their meaning is
inferred, not documented by the source. Two names do not describe their content (6, 11).

Labels from this file are **weak**: they come from the source's pipeline (Etherscan/Forta
ground truth plus their detector), not from independent review. Structural validity is not
proof that a planting was malicious. The source has no license: the raw file stays local.
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cryptoguard.detectors.poisoning import PoisoningConfig, affix_match, is_lookalike

PARSER_VERSION = "poison-hunter-sample/1"
SOURCE_REPOSITORY = "DS2L/Poison-Hunter"
SOURCE_FILE = "phishing_transfers_sample.csv"
EXPECTED_HEADER = [
    "attacker",
    "victim",
    "similar_norm",
    "tx_hash",
    "symbol",
    "phishing_type",
    "fake_token_address",
    "fake_token_deployer",
    "tx_from",
    "tx_to",
    "tx_fee",
    "is_batching",
    "batch_contract_deployer",
    "block_number",
    "block_distance",
]
FIELDS = 17
STUDY_BLOCKS = (15_000_000, 19_500_000)  # Nov 2022 - Feb 2024 per the source, with margin
MIN_AFFIX_TOTAL = 5  # below any published lookalike definition (CryptoGuard, Tsuchiya 3+4)

_ADDR = re.compile(r"^0x[0-9a-f]{40}$")
_ADDR_ANY_CASE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH = re.compile(r"^0x[0-9a-f]{64}$")

Subtype = Literal["dust", "zero", "fake"]
Status = Literal["valid", "quarantined"]


class PoisonHunterRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_line: int  # 1-based line in the CSV (header = line 1)
    status: Status
    issues: tuple[str, ...]
    lookalike: str
    victim: str
    imitated: str
    planting_tx: str
    token_symbol: str
    subtype: str
    log_contract: str  # contract that emitted the planting Transfer log
    fake_token_deployer: str | None
    tx_signer: str
    tx_target: str
    batch_size: int | None
    block_number: int | None
    block_distance: int | None
    imitated_direction: str | None
    source_similarity: int | None
    prefix_match: int
    suffix_match: int
    cryptoguard_lookalike: bool  # CryptoGuard's detector predicate (for comparison only)
    tsuchiya_lookalike: bool  # >= 3 leading and >= 4 trailing hex characters


class ParseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parser_version: str
    source_sha256: str
    header: list[str]
    records: list[PoisonHunterRecord]

    @property
    def valid(self) -> list[PoisonHunterRecord]:
        return [r for r in self.records if r.status == "valid"]

    @property
    def quarantined(self) -> list[PoisonHunterRecord]:
        return [r for r in self.records if r.status == "quarantined"]


class SchemaMismatchError(ValueError):
    """The file's header or row width differs from the identified layout: refuse to guess."""


def _int(text: str) -> int | None:
    try:
        return int(float(text)) if text.strip() else None
    except ValueError:
        return None


def _parse_row(line: int, r: list[str], config: PoisoningConfig) -> PoisonHunterRecord:
    issues: list[str] = []
    lookalike, victim, imitated = (r[0].lower(), r[1].lower(), r[2].lower())
    for name, value in (("attacker", r[0]), ("victim", r[1]), ("similar_norm", r[2])):
        if not _ADDR.match(value):
            issues.append(f"{name} is not a lowercase address")
    for name, value in (("tx_from", r[8]), ("tx_to", r[9]), ("token", r[6])):
        if not _ADDR_ANY_CASE.match(value):
            issues.append(f"{name} is not an address")
    if not _HASH.match(r[3]):
        issues.append("tx_hash is not a 32-byte hash")
    if r[5] not in ("dust", "zero", "fake"):
        issues.append(f"unknown phishing_type {r[5]!r}")
    block = _int(r[13])
    if block is None or not STUDY_BLOCKS[0] <= block <= STUDY_BLOCKS[1]:
        issues.append("block_number missing or outside the source's study period")
    if victim in (imitated, lookalike):
        issues.append("victim equals the imitated or lookalike address")
    if r[5] == "dust" and r[8].lower() != lookalike:
        issues.append("dust planting not signed by the lookalike")
    if r[5] == "fake" and not r[7]:
        issues.append("fake planting without a fake-token deployer")
    if r[15] not in ("from", "to"):
        issues.append(f"unknown direction field {r[15]!r}")
    elif r[15] == "to":
        issues.append("only direction 'to' row: imitation mapping for this direction unverified")
    valid_addresses = bool(_ADDR_ANY_CASE.match(r[0]) and _ADDR_ANY_CASE.match(r[2]))
    prefix, suffix = affix_match(lookalike, imitated) if valid_addresses else (0, 0)
    if valid_addresses and prefix + suffix < MIN_AFFIX_TOTAL:
        issues.append(
            f"lookalike shares {prefix}+{suffix} hex characters with the imitated address, "
            "below any published lookalike definition"
        )
    return PoisonHunterRecord(
        source_line=line,
        status="quarantined" if issues else "valid",
        issues=tuple(issues),
        lookalike=lookalike,
        victim=victim,
        imitated=imitated,
        planting_tx=r[3].lower(),
        token_symbol=r[4],
        subtype=r[5],
        log_contract=r[6].lower(),
        fake_token_deployer=r[7].lower() or None,
        tx_signer=r[8].lower(),
        tx_target=r[9].lower(),
        batch_size=_int(r[11]),
        block_number=block,
        block_distance=_int(r[14]),
        imitated_direction=r[15] or None,
        source_similarity=_int(r[16]),
        prefix_match=prefix,
        suffix_match=suffix,
        cryptoguard_lookalike=bool(valid_addresses and is_lookalike(lookalike, imitated, config)),
        tsuchiya_lookalike=prefix >= 3 and suffix >= 4,
    )


def parse_sample(path: Path, config: PoisoningConfig | None = None) -> ParseResult:
    """Parse every row; rows failing a check are quarantined with reasons, never dropped."""
    config = config or PoisoningConfig()
    raw = path.read_bytes()
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    if not rows or rows[0] != EXPECTED_HEADER:
        raise SchemaMismatchError(f"{path}: header differs from the identified layout")
    widths = Counter(len(r) for r in rows[1:])
    if set(widths) != {FIELDS}:
        raise SchemaMismatchError(f"{path}: expected {FIELDS} fields per row, got {dict(widths)}")
    records = [_parse_row(i + 2, r, config) for i, r in enumerate(rows[1:])]
    return ParseResult(
        parser_version=PARSER_VERSION,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        header=rows[0],
        records=records,
    )


def profile(result: ParseResult) -> dict[str, object]:
    """Aggregate validation report (no addresses): counts, reuse, duplicates, similarity."""
    rs = result.records
    valid = result.valid
    pairs = Counter((r.planting_tx, r.victim, r.lookalike) for r in rs)
    return {
        "parser_version": result.parser_version,
        "source_sha256": result.source_sha256,
        "rows": len(rs),
        "valid": len(valid),
        "quarantined": [
            {"line": r.source_line, "issues": list(r.issues)} for r in result.quarantined
        ],
        "subtypes": dict(Counter(r.subtype for r in rs)),
        "distinct_victims": len({r.victim for r in valid}),
        "distinct_lookalikes": len({r.lookalike for r in valid}),
        "distinct_planting_txs": len({r.planting_tx for r in valid}),
        "planting_txs_with_several_rows": sum(
            1 for c in Counter(r.planting_tx for r in valid).values() if c > 1
        ),
        "duplicate_victim_events": sum(c - 1 for c in pairs.values() if c > 1),
        "victims_in_several_rows": sum(
            1 for c in Counter(r.victim for r in valid).values() if c > 1
        ),
        "lookalikes_in_several_rows": sum(
            1 for c in Counter(r.lookalike for r in valid).values() if c > 1
        ),
        "block_range": [
            min(r.block_number for r in valid if r.block_number),
            max(r.block_number for r in valid if r.block_number),
        ]
        if valid
        else None,
        "cryptoguard_lookalike": sum(r.cryptoguard_lookalike for r in valid),
        "tsuchiya_lookalike": sum(r.tsuchiya_lookalike for r in valid),
        "source_similarity_equals_prefix_plus_suffix": sum(
            1 for r in valid if r.source_similarity == r.prefix_match + r.suffix_match
        ),
    }

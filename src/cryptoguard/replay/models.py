"""Incident manifests (ground truth) and recorded fixtures (detector inputs).

The separation is the core leakage control: the replay engine feeds detectors only from the
fixture. The manifest — what is known *after* the incident (victim, harmful transaction,
attacker address) — is used only to score the detector's output.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.blockchain.erc20 import TransferEvent
from cryptoguard.detectors.poisoning import NativeSend

CASES_PACKAGE = "cryptoguard.replay.cases"


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    publisher: str
    title: str
    url: str
    accessed: date
    used_for: str


class HarmfulTransaction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_hash: str
    block_number: int
    recipient: str
    token: str
    value_base_units: str
    description: str


class EvaluationWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_block: int
    to_block: int = Field(description="The harmful transaction's block.")
    rationale: str


class IncidentManifest(BaseModel):
    """Publicly sourced ground truth. Never used as a detector input."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    title: str
    category: Literal["address_poisoning"]
    chain_id: int
    summary: str
    first_public_report: date
    public_sources: list[SourceRef]
    victim: str
    intended_recipient: str | None
    harm: HarmfulTransaction
    evaluation: EvaluationWindow
    onchain_verification: list[str]
    ground_truth_limitations: list[str]


class RecordedTransaction(BaseModel):
    """A transaction signed by the watched wallet inside the window."""

    model_config = ConfigDict(extra="forbid")

    transaction_hash: str
    block_number: int
    transaction_index: int
    nonce: int
    to: str | None
    value: str
    # Receipt status (ETH-carrying transactions): False = reverted, None = not recorded.
    succeeded: bool | None = None

    def as_native_send(self) -> NativeSend | None:
        if self.to is None or int(self.value) == 0:
            return None
        return NativeSend(
            to=self.to,
            value=int(self.value),
            block_number=self.block_number,
            transaction_hash=self.transaction_hash,
            transaction_index=self.transaction_index,
            succeeded=self.succeeded,
        )


class RecordedTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    sender: str
    recipient: str
    value: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int
    tx_sender: str | None

    def as_event(self) -> TransferEvent:
        return TransferEvent(
            token=self.token,
            sender=self.sender,
            recipient=self.recipient,
            value=int(self.value),
            block_number=self.block_number,
            block_hash=self.block_hash,
            transaction_hash=self.transaction_hash,
            transaction_index=self.transaction_index,
            log_index=self.log_index,
            tx_sender=self.tx_sender,
        )

    @classmethod
    def from_event(cls, event: TransferEvent) -> RecordedTransfer:
        return cls(
            token=event.token,
            sender=event.sender,
            recipient=event.recipient,
            value=str(event.value),
            block_number=event.block_number,
            block_hash=event.block_hash,
            transaction_hash=event.transaction_hash,
            transaction_index=event.transaction_index,
            log_index=event.log_index,
            tx_sender=event.tx_sender,
        )


class ReplayFixture(BaseModel):
    """Chain data recorded once from an RPC provider; the only input replay detectors see."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    chain_id: int
    wallet: str
    from_block: int
    to_block: int
    recorded_at: datetime
    recorded_with: str
    rpc_requests: int
    transfer_scan_complete: bool
    sender_lookups_skipped: int
    method: list[str]
    wallet_code_hex: dict[str, str] = Field(description="eth_getCode(wallet) by block number.")
    block_timestamps: dict[str, int]
    transfers: list[RecordedTransfer]
    wallet_transactions: list[RecordedTransaction]

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, indent=1).encode()

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ReplayCase(BaseModel):
    manifest: IncidentManifest
    fixture: ReplayFixture | None
    fixture_sha256: str | None


def _case_dirs() -> list[Path]:
    root = resources.files(CASES_PACKAGE)
    return sorted(
        Path(str(entry))
        for entry in root.iterdir()
        if entry.is_dir() and (Path(str(entry)) / "manifest.json").exists()
    )


def load_cases(directory: Path | None = None) -> list[ReplayCase]:
    """Load every case (manifest, plus fixture when recorded) from the packaged case folders."""
    dirs = sorted(p for p in directory.iterdir() if p.is_dir()) if directory else _case_dirs()
    cases: list[ReplayCase] = []
    for case_dir in dirs:
        manifest = IncidentManifest.model_validate_json((case_dir / "manifest.json").read_text())
        fixture_path = case_dir / "fixture.json"
        fixture = (
            ReplayFixture.model_validate_json(fixture_path.read_text())
            if fixture_path.exists()
            else None
        )
        if fixture is not None and fixture.case_id != manifest.case_id:
            raise ValueError(f"fixture in {case_dir} belongs to case {fixture.case_id}")
        cases.append(
            ReplayCase(
                manifest=manifest,
                fixture=fixture,
                fixture_sha256=fixture.sha256() if fixture else None,
            )
        )
    return cases


def case_directory(case_id: str) -> Path:
    for case_dir in _case_dirs():
        if case_dir.name == case_id:
            return case_dir
    raise KeyError(case_id)

"""ORM models.

Timestamps are stored as naive UTC (SQLite has no time zones) and returned as aware UTC.
Block time (``block_timestamp``) and CryptoGuard's own observation time (``observed_at``) are
kept as separate columns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not accepted; use UTC-aware values")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class AddressObservation(Base):
    """One observation of an address's state at a specific block.

    The identity (chain, address, block hash, type, source) makes writes idempotent: repeating
    an inspection at the same block does not create a duplicate row. Keying on the block hash
    rather than the number keeps observations from different forks distinct.
    """

    __tablename__ = "address_observations"
    __table_args__ = (
        UniqueConstraint(
            "chain_id",
            "address",
            "block_hash",
            "observation_type",
            "data_source",
            name="uq_address_observation_identity",
        ),
        Index("ix_address_observation_wallet_block", "chain_id", "address", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    address: Mapped[str] = mapped_column(String(42))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    block_timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    observation_type: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(64))
    data_source: Mapped[str] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime())
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ApprovalEventRecord(Base):
    """A decoded ERC-20 ``Approval`` log.

    A log is identified by (chain, block hash, log index): the same transaction re-included in
    a different block after a reorg is a distinct record, and re-scanning a range is idempotent.
    ``value`` is a decimal string because uint256 exceeds every SQL integer type.
    """

    __tablename__ = "approval_events"
    __table_args__ = (
        UniqueConstraint("chain_id", "block_hash", "log_index", name="uq_approval_event_log"),
        Index("ix_approval_event_owner_block", "chain_id", "owner", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    token: Mapped[str] = mapped_column(String(42))
    owner: Mapped[str] = mapped_column(String(42))
    spender: Mapped[str] = mapped_column(String(42))
    value: Mapped[str] = mapped_column(String(78))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    transaction_hash: Mapped[str] = mapped_column(String(66))
    transaction_index: Mapped[int] = mapped_column(BigInteger)
    log_index: Mapped[int] = mapped_column(BigInteger)
    data_source: Mapped[str] = mapped_column(String(32))
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime())


class WalletSnapshotRecord(Base):
    """A wallet's security state at one block, plus the delta from the previous snapshot.

    ``orphaned`` marks snapshots whose block was later reorganized out of the canonical chain;
    they stay for audit but are never used as a comparison base.
    """

    __tablename__ = "wallet_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "address", "block_hash", "data_source", name="uq_wallet_snapshot_block"
        ),
        Index("ix_wallet_snapshot_wallet_block", "chain_id", "address", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    address: Mapped[str] = mapped_column(String(42))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    block_timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    head_block_number: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    data_source: Mapped[str] = mapped_column(String(32))
    schema_version: Mapped[str] = mapped_column(String(64))
    ruleset_version: Mapped[str] = mapped_column(String(32))
    previous_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("wallet_snapshots.id"), nullable=True
    )
    is_baseline: Mapped[bool] = mapped_column(Boolean)
    orphaned: Mapped[bool] = mapped_column(Boolean, default=False)
    token_scope: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON)
    state: Mapped[dict[str, Any]] = mapped_column(JSON)
    state_hash: Mapped[str] = mapped_column(String(66))
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSON)


class FindingRecord(Base):
    """A security finding, identified by its deterministic fingerprint per wallet."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("chain_id", "address", "fingerprint", name="uq_finding_fingerprint"),
        Index("ix_finding_wallet_status", "chain_id", "address", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    address: Mapped[str] = mapped_column(String(42))
    fingerprint: Mapped[str] = mapped_column(String(66))
    rule_id: Mapped[str] = mapped_column(String(32))
    ruleset_version: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16))
    subject: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(300))
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    data_source: Mapped[str] = mapped_column(String(32))
    first_seen_snapshot_id: Mapped[int] = mapped_column(ForeignKey("wallet_snapshots.id"))
    first_seen_block: Mapped[int] = mapped_column(BigInteger)
    last_seen_snapshot_id: Mapped[int] = mapped_column(ForeignKey("wallet_snapshots.id"))
    last_seen_block: Mapped[int] = mapped_column(BigInteger)
    resolved_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())


class FindingTransitionRecord(Base):
    """Audit trail of every finding status change, with the snapshot that caused it (if any)."""

    __tablename__ = "finding_transitions"
    __table_args__ = (Index("ix_finding_transition_snapshot", "snapshot_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("wallet_snapshots.id"), nullable=True
    )
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(300))
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class TokenTransferRecord(Base):
    """An ERC-20 Transfer involving a monitored wallet (either direction).

    Identity is (chain, wallet, block hash, log index), so re-scans are idempotent and a
    reorged-out log is a different row. ``tx_sender`` is the transaction signer when it was
    looked up, otherwise NULL (unknown).
    """

    __tablename__ = "token_transfers"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "wallet", "block_hash", "log_index", name="uq_token_transfer_log"
        ),
        Index("ix_token_transfer_wallet_block", "chain_id", "wallet", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    wallet: Mapped[str] = mapped_column(String(42))
    token: Mapped[str] = mapped_column(String(42))
    sender: Mapped[str] = mapped_column(String(42))
    recipient: Mapped[str] = mapped_column(String(42))
    value: Mapped[str] = mapped_column(String(78))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    transaction_hash: Mapped[str] = mapped_column(String(66))
    transaction_index: Mapped[int] = mapped_column(BigInteger)
    log_index: Mapped[int] = mapped_column(BigInteger)
    tx_sender: Mapped[str | None] = mapped_column(String(42), nullable=True)
    data_source: Mapped[str] = mapped_column(String(32))
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime())


class WalletTransactionRecord(Base):
    """A transaction signed by a monitored wallet (located by nonce bisection).

    Native-ETH payments here are what the poisoning detector uses as references when the
    wallet paid an address in ETH rather than with an ERC-20 token.
    """

    __tablename__ = "wallet_transactions"
    __table_args__ = (
        UniqueConstraint(
            "chain_id", "wallet", "transaction_hash", "block_hash", name="uq_wallet_transaction"
        ),
        Index("ix_wallet_transaction_wallet_block", "chain_id", "wallet", "block_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    wallet: Mapped[str] = mapped_column(String(42))
    transaction_hash: Mapped[str] = mapped_column(String(66))
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[str] = mapped_column(String(66))
    transaction_index: Mapped[int] = mapped_column(BigInteger)
    nonce: Mapped[int] = mapped_column(BigInteger)
    to: Mapped[str | None] = mapped_column(String(42), nullable=True)
    value: Mapped[str] = mapped_column(String(78))
    # Receipt status of an ETH-carrying transaction (None: not read). Added by migration 2.
    succeeded: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    data_source: Mapped[str] = mapped_column(String(32))
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime())


class CampaignRunRecord(Base):
    """One experimental campaign analysis over stored data at a fixed cutoff.

    ``result`` holds the attempts, clusters and evidence exactly as computed (JSON), keyed by
    the input hash, so the same inputs never produce two runs and every run is reproducible.
    Only the newest runs are retained (``CRYPTOGUARD_CAMPAIGN_RUNS_RETAINED``).
    """

    __tablename__ = "campaign_runs"
    __table_args__ = (
        UniqueConstraint("chain_id", "data_source", "input_sha256", name="uq_campaign_run_input"),
        Index("ix_campaign_run_cutoff", "chain_id", "data_source", "cutoff_block"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    data_source: Mapped[str] = mapped_column(String(32))
    cutoff_block: Mapped[int] = mapped_column(BigInteger)
    algorithm_version: Mapped[str] = mapped_column(String(64))
    input_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)
    result: Mapped[dict[str, Any]] = mapped_column(JSON)


class CampaignMembershipRecord(Base):
    """Which wallets (as targets) and addresses appear in which cluster of a run; indexed
    lookup for "related activity" without loading every run."""

    __tablename__ = "campaign_memberships"
    __table_args__ = (
        UniqueConstraint("run_id", "cluster_id", "role", "address", name="uq_campaign_member"),
        Index("ix_campaign_member_address", "address", "role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("campaign_runs.id", ondelete="CASCADE"))
    cluster_id: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(16))  # target | lookalike | signer
    address: Mapped[str] = mapped_column(String(42))


class CampaignExpansionTaskRecord(Base):
    """A completed (or failed) expansion task: the checkpoint that makes expansion resumable
    and prevents refetching data already stored with provenance."""

    __tablename__ = "campaign_expansion_tasks"
    __table_args__ = (
        UniqueConstraint("chain_id", "data_source", "task_id", name="uq_campaign_task"),
        Index("ix_campaign_task_entity", "chain_id", "kind", "entity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain_id: Mapped[int] = mapped_column(BigInteger)
    data_source: Mapped[str] = mapped_column(String(32))
    task_id: Mapped[str] = mapped_column(String(66))
    kind: Mapped[str] = mapped_column(String(32))
    entity: Mapped[str] = mapped_column(String(66))
    seed_block: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime())


class OperationLeaseRecord(Base):
    """Exclusive, expiring ownership of a long operation (one snapshot per wallet, one
    campaign run) across threads, processes and restarts. See ``database/leases.py``."""

    __tablename__ = "operation_leases"

    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    owner: Mapped[str] = mapped_column(String(32))
    generation: Mapped[int] = mapped_column(BigInteger)
    acquired_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())


class SchemaVersionRecord(Base):
    """Applied schema migrations (see ``database/migrations.py``)."""

    __tablename__ = "schema_versions"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    description: Mapped[str] = mapped_column(String(200))
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime())

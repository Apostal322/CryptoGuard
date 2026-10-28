"""Database-backed operation leases: single-flight across threads, processes and restarts.

A lease is one row per operation key. Acquisition is atomic in the database, never
check-then-insert in Python:

- **free key**: ``INSERT`` succeeds; a concurrent second ``INSERT`` fails on the primary key;
- **held, expired key** (its owner crashed or overran): a conditional ``UPDATE ... WHERE
  expires_at < now`` takes it over; databases apply it to one writer only (SQLite serializes
  writers; PostgreSQL re-checks the condition after the row lock), so two contenders cannot
  both succeed. Each takeover increments ``generation``.

The owner token plus generation is a fencing token. A worker whose lease expired and was
taken over must not commit results: ``check`` runs inside the result-writing transaction
and aborts it if the lease is no longer this worker's. ``release`` deletes only the
caller's own lease, so a stale worker cannot free a newer owner's lease.

Leases expire; they are not renewed while work runs. ``ttl`` must therefore exceed the
longest expected run (the default is 15 minutes, settable with
``CRYPTOGUARD_OPERATION_LEASE_SECONDS``). A run that overruns loses its lease and its write
is refused rather than racing a newer run.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cryptoguard.core.errors import CryptoGuardError
from cryptoguard.database.models import OperationLeaseRecord
from cryptoguard.database.repository import ObservationRepository


class LeaseLostError(CryptoGuardError):
    """The worker's lease expired and was taken over; its results must not be written."""

    code = "operation_lease_lost"
    http_status = 409
    retryable = True


@dataclass(frozen=True)
class Lease:
    key: str
    owner: str
    generation: int
    expires_at: datetime


class LeaseStore:
    def __init__(self, repository: ObservationRepository) -> None:
        self._sessions = repository._sessions

    def acquire(self, key: str, ttl_seconds: float, *, now: datetime | None = None) -> Lease | None:
        """Take the lease for ``key``, or return None if another live owner holds it."""
        now = now or datetime.now(UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        token = uuid.uuid4().hex
        with self._sessions() as session:
            try:
                with session.begin():
                    session.add(
                        OperationLeaseRecord(
                            key=key, owner=token, generation=1, acquired_at=now, expires_at=expires
                        )
                    )
                return Lease(key, token, 1, expires)
            except IntegrityError:
                pass  # held (or just taken): fall through to the expiry takeover
            with session.begin():
                result = session.execute(
                    update(OperationLeaseRecord)
                    .where(
                        (OperationLeaseRecord.key == key) & (OperationLeaseRecord.expires_at < now)
                    )
                    .values(
                        owner=token,
                        generation=OperationLeaseRecord.generation + 1,
                        acquired_at=now,
                        expires_at=expires,
                    )
                )
                if int(getattr(result, "rowcount", 0) or 0) != 1:
                    return None
                generation = session.scalar(
                    select(OperationLeaseRecord.generation).where(
                        (OperationLeaseRecord.key == key) & (OperationLeaseRecord.owner == token)
                    )
                )
            return Lease(key, token, int(generation or 0), expires)

    @staticmethod
    def check(session: Session, lease: Lease, *, now: datetime | None = None) -> None:
        """Fencing check, to run inside the transaction that writes the lease's results."""
        now = now or datetime.now(UTC)
        row = session.get(OperationLeaseRecord, lease.key)
        if (
            row is None
            or row.owner != lease.owner
            or row.generation != lease.generation
            or row.expires_at <= now
        ):
            raise LeaseLostError(
                "This operation ran longer than its lease or was superseded; its results were "
                "not saved. Retry it."
            )

    def release(self, lease: Lease) -> bool:
        """Delete the lease if (and only if) it is still this owner's."""
        with self._sessions() as session, session.begin():
            result = session.execute(
                delete(OperationLeaseRecord).where(
                    (OperationLeaseRecord.key == lease.key)
                    & (OperationLeaseRecord.owner == lease.owner)
                    & (OperationLeaseRecord.generation == lease.generation)
                )
            )
            return int(getattr(result, "rowcount", 0) or 0) == 1

    def holder(self, key: str) -> Lease | None:
        with self._sessions() as session:
            row = session.get(OperationLeaseRecord, key)
            if row is None:
                return None
            return Lease(row.key, row.owner, row.generation, row.expires_at)

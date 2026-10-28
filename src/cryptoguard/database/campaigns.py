"""Storage for experimental campaign runs and expansion checkpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select

from cryptoguard.database.models import (
    CampaignExpansionTaskRecord,
    CampaignMembershipRecord,
    CampaignRunRecord,
    WalletSnapshotRecord,
)
from cryptoguard.database.repository import ObservationRepository


class CampaignStore:
    def __init__(self, repository: ObservationRepository) -> None:
        self._sessions = repository._sessions

    def monitored_wallets(self, chain_id: int, data_source: str) -> list[str]:
        with self._sessions() as session:
            rows = session.scalars(
                select(WalletSnapshotRecord.address)
                .where(
                    (WalletSnapshotRecord.chain_id == chain_id)
                    & (WalletSnapshotRecord.data_source == data_source)
                    & WalletSnapshotRecord.orphaned.is_(False)
                )
                .distinct()
                .order_by(WalletSnapshotRecord.address)
            ).all()
        return list(rows)

    def save_run(
        self,
        *,
        chain_id: int,
        data_source: str,
        cutoff_block: int,
        algorithm_version: str,
        input_sha256: str,
        summary: dict[str, Any],
        result: dict[str, Any],
        memberships: list[tuple[str, str, str]],  # (cluster id, role, address)
        retained: int,
    ) -> tuple[int, bool]:
        """Store a run unless the same inputs were already analysed; returns (id, created).
        Keeps only the newest ``retained`` runs."""
        with self._sessions() as session, session.begin():
            existing = session.scalar(
                select(CampaignRunRecord.id).where(
                    (CampaignRunRecord.chain_id == chain_id)
                    & (CampaignRunRecord.data_source == data_source)
                    & (CampaignRunRecord.input_sha256 == input_sha256)
                )
            )
            if existing is not None:
                return int(existing), False
            run = CampaignRunRecord(
                chain_id=chain_id,
                data_source=data_source,
                cutoff_block=cutoff_block,
                algorithm_version=algorithm_version,
                input_sha256=input_sha256,
                created_at=datetime.now(UTC),
                summary=summary,
                result=result,
            )
            session.add(run)
            session.flush()
            session.add_all(
                CampaignMembershipRecord(run_id=run.id, cluster_id=c, role=r, address=a)
                for c, r, a in sorted(set(memberships))
            )
            old = session.scalars(
                select(CampaignRunRecord.id)
                .where(
                    (CampaignRunRecord.chain_id == chain_id)
                    & (CampaignRunRecord.data_source == data_source)
                )
                .order_by(CampaignRunRecord.id.desc())
                .offset(retained)
            ).all()
            if old:
                session.execute(
                    delete(CampaignMembershipRecord).where(CampaignMembershipRecord.run_id.in_(old))
                )
                session.execute(delete(CampaignRunRecord).where(CampaignRunRecord.id.in_(old)))
            return int(run.id), True

    def latest_run(self, chain_id: int, data_source: str) -> CampaignRunRecord | None:
        with self._sessions() as session:
            return session.scalars(
                select(CampaignRunRecord)
                .where(
                    (CampaignRunRecord.chain_id == chain_id)
                    & (CampaignRunRecord.data_source == data_source)
                )
                .order_by(CampaignRunRecord.id.desc())
                .limit(1)
            ).first()

    def save_task(
        self,
        *,
        chain_id: int,
        data_source: str,
        task_id: str,
        kind: str,
        entity: str,
        seed_block: int,
        status: str,
        payload: dict[str, Any],
    ) -> None:
        with self._sessions() as session, session.begin():
            row = session.scalar(
                select(CampaignExpansionTaskRecord).where(
                    (CampaignExpansionTaskRecord.chain_id == chain_id)
                    & (CampaignExpansionTaskRecord.data_source == data_source)
                    & (CampaignExpansionTaskRecord.task_id == task_id)
                )
            )
            if row is None:
                session.add(
                    CampaignExpansionTaskRecord(
                        chain_id=chain_id,
                        data_source=data_source,
                        task_id=task_id,
                        kind=kind,
                        entity=entity,
                        seed_block=seed_block,
                        status=status,
                        payload=payload,
                        recorded_at=datetime.now(UTC),
                    )
                )
            elif row.status != "complete":  # a complete task is never overwritten
                row.status, row.payload, row.recorded_at = status, payload, datetime.now(UTC)

    def load_tasks(self, chain_id: int, data_source: str) -> list[dict[str, Any]]:
        with self._sessions() as session:
            rows = session.scalars(
                select(CampaignExpansionTaskRecord)
                .where(
                    (CampaignExpansionTaskRecord.chain_id == chain_id)
                    & (CampaignExpansionTaskRecord.data_source == data_source)
                )
                .order_by(CampaignExpansionTaskRecord.id)
            ).all()
            return [dict(r.payload) for r in rows]

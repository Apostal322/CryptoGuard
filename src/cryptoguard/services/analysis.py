"""Experimental wallet analysis from stored data (no chain reads), in shadow mode only.

Each section is computed only when its setting is ``shadow``. Results are context for a
human reviewer: they are never turned into findings, never change a severity and never
resolve or supersede anything. A section with nothing to report says whether that is
because nothing unusual was observed or because the data was insufficient — and neither
statement means the wallet is safe.
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel

from cryptoguard.analytics import ANALYTICS_VERSION
from cryptoguard.blockchain.provider import DataSource
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import NoSnapshotError
from cryptoguard.database.history import HistoryRepository
from cryptoguard.replay.engine import WARNING_RULES
from cryptoguard.risk.lifecycle import OPEN_STATUSES

log = logging.getLogger(__name__)

SectionStatus = Literal["disabled", "unavailable", "insufficient_data", "ok", "skipped"]
NOT_SAFE = (
    "No unusual pattern in the observed data is not evidence that the wallet is safe: "
    "CryptoGuard sees only the activity listed under coverage."
)


class PathStepView(BaseModel):
    source: str
    target: str
    relation: str
    events: int
    example_transaction: str | None
    example_block: int | None


class RelatedAddressView(BaseModel):
    address: str
    roles: list[str]
    hops: int
    linked_to: str
    path: list[PathStepView]
    score: float


class NetworkSection(BaseModel):
    status: SectionStatus
    statement: str | None = None
    flagged_addresses: list[str] = []
    related: list[RelatedAddressView] = []
    parameters: dict[str, object] = {}
    notes: list[str] = []


class ActivityAnomalyView(BaseModel):
    statement: str
    series: str
    from_block: int
    to_block: int
    observed: int
    expected: float
    score: float
    history_bins: int
    transactions: list[str]


class ActivitySection(BaseModel):
    status: SectionStatus
    statement: str | None = None
    anomalies: list[ActivityAnomalyView] = []
    bins: dict[str, int] = {}
    parameters: dict[str, object] = {}
    notes: list[str] = []


class StructureSection(BaseModel):
    status: SectionStatus
    features: dict[str, float | int | str | None] = {}
    notes: list[str] = []


class WalletAnalysis(BaseModel):
    analytics_version: str
    wallet: str
    chain_id: int
    simulated: bool
    cutoff_block: int
    experimental: bool = True
    coverage: list[str]
    network: NetworkSection
    activity: ActivitySection
    structure: StructureSection
    notes: list[str]


def _available() -> bool:
    try:
        import numpy  # noqa: F401
        import scipy  # noqa: F401
    except ImportError:
        return False
    return True


UNAVAILABLE = "The optional analytics dependencies (numpy, scipy) are not installed."


def wallet_analysis(
    repo: HistoryRepository,
    address: str,
    *,
    chain_id: int,
    data_source: DataSource,
    settings: Settings,
    history_limit: int,
) -> WalletAnalysis:
    from cryptoguard.analytics.observations import BlockRange, ObservationSet

    wallet = to_checksum_address(address)
    latest = repo.recent_snapshots(chain_id, wallet, data_source, limit=1)
    if not latest:
        raise NoSnapshotError("No snapshot exists for this wallet yet. Take a snapshot first.")
    snap = latest[0]
    cov = snap.coverage

    def ranges(key: str) -> list[BlockRange]:
        return [BlockRange(int(r["from_block"]), int(r["to_block"])) for r in cov.get(key, [])]

    observations = ObservationSet.build(
        chain_id=chain_id,
        wallet=wallet,
        cutoff_block=snap.block_number,
        transfers=repo.load_transfers(chain_id, wallet, data_source, history_limit),
        native_sends=[
            s
            for t in repo.load_wallet_transactions(chain_id, wallet, data_source, history_limit)
            if (s := t.as_native_send()) is not None
        ],
        transfer_ranges=ranges("transfers_scanned"),
        wallet_tx_ranges=ranges("wallet_txs_scanned"),
        wallet_transactions_unlocated=int(cov.get("wallet_txs_unlocated", 0)),
    )
    available = _available()
    flagged = [
        (
            f.subject.split(":", 1)[1],
            f"{f.rule_id} first seen at block {f.first_seen_block}",
            f.first_seen_block,
        )
        for f in repo.list_findings(chain_id, wallet, [s.value for s in OPEN_STATUSES])
        if f.data_source == data_source
        and f.rule_id in WARNING_RULES
        and f.subject.startswith("poisoning:")
        and f.first_seen_block <= snap.block_number
    ]
    return WalletAnalysis(
        analytics_version=ANALYTICS_VERSION,
        wallet=wallet,
        chain_id=chain_id,
        simulated=data_source == "demo_fixture",
        cutoff_block=snap.block_number,
        coverage=observations.coverage.describe(),
        network=_network(observations, flagged, settings, available),
        activity=_activity(observations, settings, available),
        structure=_structure(observations, settings, available),
        notes=[NOT_SAFE],
    )


def _network(
    observations: object, flagged: list[tuple[str, str, int]], settings: Settings, available: bool
) -> NetworkSection:
    if settings.analysis_graph == "off":
        return NetworkSection(status="disabled")
    if not available:
        return NetworkSection(status="unavailable", notes=[UNAVAILABLE])
    from cryptoguard.analytics.diffusion import Seed, propagate
    from cryptoguard.analytics.graph import GraphScope, build_graph
    from cryptoguard.analytics.observations import ObservationSet

    assert isinstance(observations, ObservationSet)
    if not flagged:
        return NetworkSection(
            status="insufficient_data",
            notes=["No open address-poisoning warning to start from; nothing to relate."],
        )
    graph = build_graph(observations, GraphScope(max_nodes=settings.analysis_max_nodes))
    result = propagate(
        graph, [Seed(a, src, b) for a, src, b in flagged], max_nodes=settings.analysis_max_nodes
    )
    notes = list(result.notes)
    if graph.truncated_nodes:
        notes.append(f"{graph.truncated_nodes} least recently active nodes were left out.")
    if result.status != "ok":
        return NetworkSection(
            status="skipped" if result.status == "skipped" else "insufficient_data",
            flagged_addresses=[a for a, _, _ in flagged],
            parameters=dict(result.parameters),
            notes=notes,
        )
    related = [
        RelatedAddressView(
            address=r.address,
            roles=list(r.roles),
            hops=r.hops,
            linked_to=r.nearest_seed,
            path=[
                PathStepView(
                    source=s.source,
                    target=s.target,
                    relation=s.kind,
                    events=s.events,
                    example_transaction=s.example_transaction,
                    example_block=s.example_block,
                )
                for s in r.path
            ],
            score=round(r.scores["heat_tau_1"], 6),
        )
        for r in result.related
    ]
    return NetworkSection(
        status="ok",
        statement="Indirect links to a previously flagged address were identified."
        if related
        else None,
        flagged_addresses=[a for a, _, _ in flagged],
        related=related,
        parameters=dict(result.parameters),
        notes=notes,
    )


def _activity(observations: object, settings: Settings, available: bool) -> ActivitySection:
    if settings.analysis_temporal == "off":
        return ActivitySection(status="disabled")
    from cryptoguard.analytics.observations import ObservationSet
    from cryptoguard.analytics.temporal import detect_bursts

    assert isinstance(observations, ObservationSet)
    params = {"bin_blocks": 300, "threshold": 4.0, "min_count": 3, "min_history_bins": 12}
    found, bins = detect_bursts(observations, last_bins=24)  # the last ~day
    if bins["scored"] == 0:
        return ActivitySection(
            status="insufficient_data",
            bins=bins,
            parameters=params,
            notes=[
                "Not enough fully observed history (12 bins of 300 blocks) to establish a "
                "baseline; no statement is made."
            ],
        )
    return ActivitySection(
        status="ok",
        statement=(
            "Recent transaction behavior differs substantially from the observed historical "
            "baseline."
            if found
            else "No unusual activity rate in the observed data."
        ),
        anomalies=[
            ActivityAnomalyView(
                statement=a.statement,
                series=a.series,
                from_block=a.from_block,
                to_block=a.to_block,
                observed=a.observed,
                expected=a.expected,
                score=round(a.score, 2),
                history_bins=a.history_bins,
                transactions=list(a.transactions),
            )
            for a in found
        ],
        bins=bins,
        parameters=params,
        notes=[
            "Scores are robust z-statistics against the wallet's own earlier bins, not "
            "probabilities. Bins outside the scanned ranges are missing, not zero."
        ],
    )


def _structure(observations: object, settings: Settings, available: bool) -> StructureSection:
    if settings.analysis_spectral == "off":
        return StructureSection(status="disabled")
    if not available:
        return StructureSection(status="unavailable", notes=[UNAVAILABLE])
    from cryptoguard.analytics.graph import build_graph
    from cryptoguard.analytics.observations import ObservationSet
    from cryptoguard.analytics.spectral import structural_features

    assert isinstance(observations, ObservationSet)
    f = structural_features(build_graph(observations))
    return StructureSection(
        status="ok" if f.spectral_status == "ok" else "skipped",
        features={
            "nodes": f.nodes,
            "edges": f.edges,
            "counterparties": f.counterparties,
            "events": f.events,
            "max_degree": f.max_degree,
            "components": f.components,
            "algebraic_connectivity": f.algebraic_connectivity,
            "lambda_max": f.lambda_max,
            "spectral_status": f.spectral_status,
        },
        notes=[
            "Engineering diagnostics only: structural change was not validated as a threat "
            "signal (see EVALUATION.md)."
        ],
    )


def shadow_log(analysis: WalletAnalysis) -> None:
    """One structured log line per snapshot; nothing is stored or alerted."""
    log.info(
        "shadow analysis",
        extra={
            "wallet": analysis.wallet,
            "cutoff_block": analysis.cutoff_block,
            "network_status": analysis.network.status,
            "related_addresses": len(analysis.network.related),
            "activity_status": analysis.activity.status,
            "activity_anomalies": len(analysis.activity.anomalies),
            "structure_status": analysis.structure.status,
        },
    )

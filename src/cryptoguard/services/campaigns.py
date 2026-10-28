"""Experimental cross-wallet campaign analysis over stored data (shadow mode only).

A run collects the poisoning attempts of every monitored wallet (their stored transfers
and wallet-signed transactions, cut at each wallet's latest snapshot), adds verified
attempts and deployers from stored expansion tasks, clusters them and stores the result.
Runs read no chain data. They never create findings, change severities or label any
address as malicious: the output is "potentially related poisoning activity" with its
evidence and limits.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
from typing import Any, Literal

from pydantic import BaseModel

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.provider import DataSource
from cryptoguard.campaigns.attempts import ATTEMPT_MODEL_VERSION, PoisoningAttempt, extract_attempts
from cryptoguard.campaigns.cluster import (
    CLUSTER_ALGORITHM_VERSION,
    CampaignAnalysis,
    cluster_attempts,
)
from cryptoguard.campaigns.expansion import (
    EXPANSION_VERSION,
    ExpansionBudget,
    ExpansionResult,
    outcome_from_dict,
)
from cryptoguard.campaigns.graph import build_campaign_graph
from cryptoguard.campaigns.relations import RELATION_LABEL
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import (
    CampaignNotFoundError,
    FeatureDisabledError,
    NoCampaignRunError,
)
from cryptoguard.database.campaigns import CampaignStore
from cryptoguard.database.history import HistoryRepository

DISABLED = (
    "Campaign analysis is disabled. Set CRYPTOGUARD_CAMPAIGN_ANALYSIS=shadow to compute "
    "experimental, read-only context; it never changes findings."
)
LIMITATIONS = [
    "A cluster means the attempts share planting infrastructure as shown. It is not proof "
    "that one person or group controls all of it.",
    "Only wallets monitored here (plus bounded expansion around their attempts, if run) are "
    "seen. Absence of a link is not evidence that attempts are unrelated.",
    "Transfer logs can be forged by token contracts; no asset movement is implied.",
    "Funding sources of planting accounts and contracts created by other contracts are not "
    "visible over standard JSON-RPC.",
]


def require_enabled(settings: Settings) -> None:
    if settings.campaign_analysis == "off":
        raise FeatureDisabledError(DISABLED)


# --- views -----------------------------------------------------------------------------------


class EvidenceView(BaseModel):
    kind: str
    key: str
    statement: str
    strength: str
    attempts: int
    wallets: int
    lookalikes: int
    reason: str
    merges: bool


class CampaignSummary(BaseModel):
    campaign_id: str
    attempts: int
    targeted_wallets: int
    lookalikes: int
    signers: int
    first_block: int
    last_block: int
    structure: str
    confidence: str
    explanation: str


class AttemptView(BaseModel):
    attempt_id: str
    victim: str
    lookalike: str
    imitated: str | None
    event_type: str
    transaction_hash: str
    block_number: int
    log_index: int
    contract: str
    log_from: str
    log_to: str
    value: str
    signer: str | None
    source: str
    rule_id: str


class CampaignDetail(CampaignSummary):
    evidence: list[EvidenceView]
    articulation_entities: list[str]
    articulation_attempts: list[str]
    members: list[AttemptView]
    members_total: int


class RunInfo(BaseModel):
    run_id: int
    created: bool
    chain_id: int
    cutoff_block: int
    algorithm_version: str
    attempt_model_version: str
    input_sha256: str
    attempts: int
    clusters: int
    unclustered: int
    wallets_analysed: int
    expansion_tasks_used: int
    coverage: list[str]
    limitations: list[str]
    experimental: bool = True


class CampaignPage(BaseModel):
    run: RunInfo
    items: list[CampaignSummary]
    total: int
    limit: int
    offset: int


class RelatedActivity(BaseModel):
    run: RunInfo
    wallet: str
    status: Literal["related_activity", "attempts_without_links", "no_attempts"]
    attempts_on_wallet: int
    campaigns: list[CampaignSummary]
    statement: str


class GraphNodeView(BaseModel):
    id: str
    kind: str


class GraphEdgeView(BaseModel):
    source: str
    target: str
    kind: str
    block_number: int | None
    transaction_hash: str | None


class CampaignGraphView(BaseModel):
    campaign_id: str
    nodes: list[GraphNodeView]
    edges: list[GraphEdgeView]
    truncated: bool
    max_attempts: int


# --- runs ------------------------------------------------------------------------------------


def _expansion(
    store: CampaignStore, chain_id: int, data_source: str, cutoff: int
) -> ExpansionResult:
    outcomes = [outcome_from_dict(p) for p in store.load_tasks(chain_id, data_source)]
    return ExpansionResult(
        EXPANSION_VERSION, chain_id, cutoff, ExpansionBudget(), outcomes, 0, 0.0, None
    )


def collect_attempts(
    repo: HistoryRepository, *, chain_id: int, data_source: DataSource, history_limit: int
) -> tuple[list[PoisoningAttempt], int, list[str], int]:
    """Attempts of every monitored wallet, each cut at its latest snapshot. Returns the
    attempts, the run cutoff (newest snapshot), coverage notes and the wallet count."""
    from cryptoguard.analytics.observations import BlockRange, ObservationSet

    store = CampaignStore(repo)
    attempts: list[PoisoningAttempt] = []
    notes: list[str] = []
    cutoffs: list[int] = []
    wallets = store.monitored_wallets(chain_id, data_source)
    for wallet in wallets:
        latest = repo.recent_snapshots(chain_id, wallet, data_source, limit=1)
        if not latest:
            continue
        snap = latest[0]
        cov = snap.coverage

        def ranges(key: str, cov: dict[str, Any] = cov) -> list[BlockRange]:
            return [BlockRange(int(r["from_block"]), int(r["to_block"])) for r in cov.get(key, [])]

        o = ObservationSet.build(
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
        )
        attempts += extract_attempts(
            o, wallet_is_plain_eoa=snap.state.account.code_kind is CodeKind.NO_CODE
        )
        cutoffs.append(snap.block_number)
        ranges_text = ", ".join(f"{r.from_block}-{r.to_block}" for r in o.coverage.transfers)
        notes.append(f"{wallet}: transfers observed in {ranges_text or 'no range'}.")
    cutoff = max(cutoffs, default=0)
    if cutoffs and min(cutoffs) < cutoff:
        notes.append(
            "Wallets were last snapshotted at different blocks; activity after a wallet's own "
            "latest snapshot is not seen."
        )
    return attempts, cutoff, notes, len(cutoffs)


def run_analysis(
    repo: HistoryRepository, *, chain_id: int, data_source: DataSource, settings: Settings
) -> RunInfo:
    require_enabled(settings)
    attempts, cutoff, notes, wallets = collect_attempts(
        repo,
        chain_id=chain_id,
        data_source=data_source,
        history_limit=settings.transfer_history_limit,
    )
    store = CampaignStore(repo)
    expansion = _expansion(store, chain_id, data_source, cutoff)
    extra, deployers = expansion.usable_at(cutoff)
    attempts = [*attempts, *extra]
    if len(attempts) > settings.campaign_max_attempts:
        notes.append(
            f"{len(attempts)} attempts exceed the limit of {settings.campaign_max_attempts}; "
            "the most recent ones were analysed."
        )
        attempts = sorted(attempts)[-settings.campaign_max_attempts :]
    analysis = cluster_attempts(
        attempts, chain_id=chain_id, cutoff_block=cutoff, deployers=deployers
    )
    memberships = [
        (c.cluster_id, role, address)
        for c in analysis.clusters
        for role, addresses in (
            ("target", c.victims),
            ("lookalike", c.lookalikes),
            ("signer", c.signers),
        )
        for address in addresses
    ]
    used = sum(1 for o in expansion.outcomes if o.task.seed_block <= cutoff)
    summary = {
        "attempts": len(analysis.attempts),
        "clusters": len(analysis.clusters),
        "unclustered": len(analysis.unclustered),
        "wallets": wallets,
        "expansion_tasks_used": used,
        "coverage": notes,
    }
    run_id, created = store.save_run(
        chain_id=chain_id,
        data_source=data_source,
        cutoff_block=cutoff,
        algorithm_version=CLUSTER_ALGORITHM_VERSION,
        input_sha256=analysis.input_sha256,
        summary=summary,
        result=analysis_to_dict(analysis),
        memberships=memberships,
        retained=settings.campaign_runs_retained,
    )
    return _run_info(run_id, created, chain_id, cutoff, analysis.input_sha256, summary)


def analysis_to_dict(analysis: CampaignAnalysis) -> dict[str, Any]:
    return asdict(analysis)


def _run_info(
    run_id: int, created: bool, chain_id: int, cutoff: int, input_sha: str, summary: dict[str, Any]
) -> RunInfo:
    return RunInfo(
        run_id=run_id,
        created=created,
        chain_id=chain_id,
        cutoff_block=cutoff,
        algorithm_version=CLUSTER_ALGORITHM_VERSION,
        attempt_model_version=ATTEMPT_MODEL_VERSION,
        input_sha256=input_sha,
        attempts=int(summary["attempts"]),
        clusters=int(summary["clusters"]),
        unclustered=int(summary["unclustered"]),
        wallets_analysed=int(summary["wallets"]),
        expansion_tasks_used=int(summary["expansion_tasks_used"]),
        coverage=list(summary["coverage"]),
        limitations=LIMITATIONS,
    )


def _latest(
    repo: HistoryRepository, chain_id: int, data_source: str
) -> tuple[RunInfo, dict[str, Any]]:
    run = CampaignStore(repo).latest_run(chain_id, data_source)
    if run is None:
        raise NoCampaignRunError("No campaign analysis has been run yet.")
    info = _run_info(run.id, False, run.chain_id, run.cutoff_block, run.input_sha256, run.summary)
    return info, run.result


def _summary(c: dict[str, Any]) -> CampaignSummary:
    return CampaignSummary(
        campaign_id=c["cluster_id"],
        attempts=len(c["attempts"]),
        targeted_wallets=len(c["victims"]),
        lookalikes=len(c["lookalikes"]),
        signers=len(c["signers"]),
        first_block=c["first_block"],
        last_block=c["last_block"],
        structure=c["structure"],
        confidence=c["confidence"],
        explanation=c["explanation"],
    )


def list_campaigns(
    repo: HistoryRepository,
    *,
    chain_id: int,
    data_source: str,
    settings: Settings,
    limit: int,
    offset: int,
) -> CampaignPage:
    require_enabled(settings)
    info, result = _latest(repo, chain_id, data_source)
    clusters = result["clusters"]
    return CampaignPage(
        run=info,
        items=[_summary(c) for c in clusters[offset : offset + limit]],
        total=len(clusters),
        limit=limit,
        offset=offset,
    )


def _find(result: dict[str, Any], campaign_id: str) -> dict[str, Any]:
    for c in result["clusters"]:
        if c["cluster_id"] == campaign_id:
            return dict(c)
    raise CampaignNotFoundError(
        "No campaign with this id in the latest run. IDs change whenever membership changes."
    )


def _evidence(e: dict[str, Any], merges: bool) -> EvidenceView:
    kind = e["entity"]["kind"]
    return EvidenceView(
        kind=kind,
        key=e["entity"]["key"],
        statement=f"These attempts {RELATION_LABEL[kind]}.",
        strength=e["strength"],
        attempts=len(e["attempts"]),
        wallets=e["victims"],
        lookalikes=e["lookalikes"],
        reason=e["reason"],
        merges=merges,
    )


def campaign_detail(
    repo: HistoryRepository,
    campaign_id: str,
    *,
    chain_id: int,
    data_source: str,
    settings: Settings,
    limit: int = 100,
) -> CampaignDetail:
    require_enabled(settings)
    _, result = _latest(repo, chain_id, data_source)
    c = _find(result, campaign_id)
    by_id = {a["attempt_id"]: a for a in result["attempts"]}
    members = [by_id[m] for m in c["attempts"]]
    return CampaignDetail(
        **_summary(c).model_dump(),
        evidence=[_evidence(e, True) for e in c["merging_evidence"]]
        + [_evidence(e, False) for e in c["context_evidence"]],
        articulation_entities=[f"{e['kind']}:{e['key']}" for e in c["articulation_entities"]],
        articulation_attempts=list(c["articulation_attempts"]),
        members=[
            AttemptView(
                **{k: a[k] for k in AttemptView.model_fields if k != "value"}, value=str(a["value"])
            )
            for a in members[:limit]
        ],
        members_total=len(members),
    )


def campaign_graph(
    repo: HistoryRepository,
    campaign_id: str,
    *,
    chain_id: int,
    data_source: str,
    settings: Settings,
    max_attempts: int,
) -> CampaignGraphView:
    require_enabled(settings)
    _, result = _latest(repo, chain_id, data_source)
    c = _find(result, campaign_id)
    by_id = {a["attempt_id"]: a for a in result["attempts"]}
    attempts = [PoisoningAttempt(**by_id[m]) for m in c["attempts"]]
    g = build_campaign_graph(attempts, max_attempts=max_attempts)
    return CampaignGraphView(
        campaign_id=campaign_id,
        nodes=[GraphNodeView(id=n, kind=k) for n, k in g.nodes.items()],
        edges=[GraphEdgeView(**asdict(e)) for e in g.edges],
        truncated=g.truncated,
        max_attempts=max_attempts,
    )


def related_activity(
    repo: HistoryRepository, address: str, *, chain_id: int, data_source: str, settings: Settings
) -> RelatedActivity:
    require_enabled(settings)
    wallet = to_checksum_address(address)
    info, result = _latest(repo, chain_id, data_source)
    own = [a for a in result["attempts"] if a["victim"] == wallet]
    clusters = [c for c in result["clusters"] if wallet in c["victims"]]
    others = [c for c in clusters if len(c["victims"]) > 1]
    if not own:
        status: Literal["related_activity", "attempts_without_links", "no_attempts"] = "no_attempts"
        statement = "No poisoning attempts on this wallet were observed in the analysed data."
    elif not others:
        status = "attempts_without_links"
        statement = (
            "Poisoning attempts on this wallet were observed, but none shares planting "
            "infrastructure with attempts on other analysed wallets."
        )
    else:
        status = "related_activity"
        statement = (
            "Potentially related poisoning activity: attempts on this wallet share planting "
            f"infrastructure with attempts on {len({v for c in others for v in c['victims']}) - 1} "
            "other wallet(s)."
        )
    return RelatedActivity(
        run=info,
        wallet=wallet,
        status=status,
        attempts_on_wallet=len(own),
        campaigns=[_summary(c) for c in clusters],
        statement=statement,
    )


def expansion_summary(outcomes: Sequence[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    return counts

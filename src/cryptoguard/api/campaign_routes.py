"""Experimental campaign endpoints (``CRYPTOGUARD_CAMPAIGN_ANALYSIS=shadow``).

All reads come from the latest stored run; ``POST /campaigns/runs`` computes a new run from
stored data only (no RPC calls), bounded by ``CRYPTOGUARD_CAMPAIGN_MAX_ATTEMPTS``. With the
setting ``off`` (default) every endpoint answers 409 ``feature_disabled``.
"""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Query, Request

from cryptoguard.api.state import get_state
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import CampaignNotFoundError
from cryptoguard.services.campaigns import (
    CampaignDetail,
    CampaignGraphView,
    CampaignPage,
    RelatedActivity,
    RunInfo,
    campaign_detail,
    campaign_graph,
    list_campaigns,
    related_activity,
    run_analysis,
)

router = APIRouter(prefix="/api/v1")
CAMPAIGN_ID = r"^cmp-[0-9a-f]{24}$"


def _source(request: Request) -> str:
    return "demo_fixture" if get_state(request).settings.mode == "demo" else "rpc"


def _run(request: Request) -> RunInfo:
    # Single-flight is enforced by run_analysis with a database lease (all processes).
    state = get_state(request)
    return run_analysis(
        state.repository,
        chain_id=state.chain.chain_id,
        data_source="demo_fixture" if state.settings.mode == "demo" else "rpc",
        settings=state.settings,
    )


@router.post("/campaigns/runs", response_model=RunInfo)
async def create_run(request: Request) -> RunInfo:
    """Cluster the stored poisoning attempts of all monitored wallets (experimental)."""
    return await asyncio.to_thread(_run, request)


@router.get("/campaigns", response_model=CampaignPage)
async def campaigns(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> CampaignPage:
    state = get_state(request)
    return await asyncio.to_thread(
        list_campaigns,
        state.repository,
        chain_id=state.chain.chain_id,
        data_source=_source(request),
        settings=state.settings,
        limit=limit,
        offset=offset,
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetail)
async def campaign(
    request: Request,
    campaign_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> CampaignDetail:
    state = get_state(request)
    return await asyncio.to_thread(
        campaign_detail,
        state.repository,
        _validated(campaign_id),
        chain_id=state.chain.chain_id,
        data_source=_source(request),
        settings=state.settings,
        limit=limit,
    )


@router.get("/campaigns/{campaign_id}/graph", response_model=CampaignGraphView)
async def campaign_graph_route(
    request: Request,
    campaign_id: str,
    max_attempts: int = Query(default=100, ge=1, le=500),
) -> CampaignGraphView:
    state = get_state(request)
    return await asyncio.to_thread(
        campaign_graph,
        state.repository,
        _validated(campaign_id),
        chain_id=state.chain.chain_id,
        data_source=_source(request),
        settings=state.settings,
        max_attempts=max_attempts,
    )


@router.get("/wallets/{address}/related-activity", response_model=RelatedActivity)
async def wallet_related_activity(request: Request, address: str) -> RelatedActivity:
    state = get_state(request)
    return await asyncio.to_thread(
        related_activity,
        state.repository,
        to_checksum_address(address),
        chain_id=state.chain.chain_id,
        data_source=_source(request),
        settings=state.settings,
    )


def _validated(campaign_id: str) -> str:
    if not re.fullmatch(CAMPAIGN_ID, campaign_id):
        raise CampaignNotFoundError("Malformed campaign id.")
    return campaign_id

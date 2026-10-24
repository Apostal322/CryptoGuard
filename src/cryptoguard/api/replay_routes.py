"""Historical incident replay routes. Replays run offline on packaged fixtures (no RPC)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from cryptoguard.core.errors import CryptoGuardError
from cryptoguard.replay.engine import ReplayResult, replay
from cryptoguard.replay.models import IncidentManifest, ReplayCase, load_cases

router = APIRouter(prefix="/api/v1/replay")


class UnknownCaseError(CryptoGuardError):
    code = "unknown_replay_case"
    http_status = 404


class CaseNotRecordedError(CryptoGuardError):
    code = "replay_case_not_recorded"
    http_status = 409


class ReplayCaseView(BaseModel):
    manifest: IncidentManifest
    recorded: bool
    fixture_sha256: str | None
    recorded_with: str | None
    recorded_at: str | None
    transfers_in_fixture: int | None


class ReplayCaseList(BaseModel):
    items: list[ReplayCaseView]


class ReplayRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(max_length=100)


def _view(case: ReplayCase) -> ReplayCaseView:
    fixture = case.fixture
    return ReplayCaseView(
        manifest=case.manifest,
        recorded=fixture is not None,
        fixture_sha256=case.fixture_sha256,
        recorded_with=fixture.recorded_with if fixture else None,
        recorded_at=fixture.recorded_at.isoformat() if fixture else None,
        transfers_in_fixture=len(fixture.transfers) if fixture else None,
    )


@router.get("/cases", response_model=ReplayCaseList)
async def replay_cases() -> ReplayCaseList:
    cases = await asyncio.to_thread(load_cases)
    return ReplayCaseList(items=[_view(c) for c in cases])


@router.post("/runs", response_model=ReplayResult)
async def replay_run(body: ReplayRunRequest) -> ReplayResult:
    """Replay one case deterministically. Results are recomputed, not stored."""
    cases = await asyncio.to_thread(load_cases)
    case = next((c for c in cases if c.manifest.case_id == body.case_id), None)
    if case is None:
        raise UnknownCaseError(f"No replay case named {body.case_id!r}.")
    if case.fixture is None:
        raise CaseNotRecordedError(
            "This case has no recorded fixture yet. Record it with `cryptoguard replay record`."
        )
    return await asyncio.to_thread(replay, case.manifest, case.fixture)

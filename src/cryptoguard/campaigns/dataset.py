"""Campaign evaluation dataset: attempts from the recorded replay fixtures plus a recorded,
checkpointed expansion around them (``replay/campaign_cases/expansion.json``).

Incident fixtures are cut one block before their harmful transaction, so a theft's own
transfer never becomes campaign input. Manifests (ground truth) are not read here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from cryptoguard.analytics.observations import ObservationSet
from cryptoguard.campaigns.attempts import PoisoningAttempt, extract_attempts
from cryptoguard.campaigns.expansion import (
    ExpansionBudget,
    ExpansionResult,
    outcome_from_dict,
    outcome_to_dict,
)
from cryptoguard.replay.analytics_eval import observations_of
from cryptoguard.replay.background import load_background
from cryptoguard.replay.models import ReplayFixture, load_cases

CAMPAIGN_PACKAGE = "cryptoguard.replay.campaign_cases"


@dataclass(frozen=True)
class SubjectAttempts:
    subject_id: str
    kind: str  # "incident" | "background"
    wallet: str
    cutoff_block: int
    fixture_sha256: str
    attempts: tuple[PoisoningAttempt, ...]  # as known at ``cutoff_block``
    observations: ObservationSet = field(repr=False, compare=False)
    fixture: ReplayFixture = field(repr=False, compare=False)

    def attempts_at(self, block: int) -> list[PoisoningAttempt]:
        """Attempts as the detector would have reported them at ``block``.

        Not the same as filtering ``attempts`` by block: whether a planting event qualifies
        can depend on later data (e.g. the victim paying the imitated address afterwards),
        so the detector is re-run on the observations cut at ``block``.
        """
        cut = min(block, self.cutoff_block)
        if cut >= self.cutoff_block:
            return list(self.attempts)
        if cut < self.fixture.from_block:
            return []
        return extract_attempts(
            self.observations.at(cut), wallet_is_plain_eoa=_plain(self.fixture, cut)
        )


def _plain(fixture: ReplayFixture, cutoff: int) -> bool | None:
    known = {int(b): c for b, c in fixture.wallet_code_hex.items() if int(b) <= cutoff}
    return known[max(known)] == "0x" if known else None


def _subject(subject_id: str, kind: str, fixture: ReplayFixture, cutoff: int) -> SubjectAttempts:
    o = observations_of(fixture).at(cutoff)
    return SubjectAttempts(
        subject_id=subject_id,
        kind=kind,
        wallet=o.wallet,
        cutoff_block=cutoff,
        fixture_sha256=fixture.sha256(),
        attempts=tuple(extract_attempts(o, wallet_is_plain_eoa=_plain(fixture, cutoff))),
        observations=o,
        fixture=fixture,
    )


def fixture_attempts() -> list[SubjectAttempts]:
    out: list[SubjectAttempts] = []
    for case in load_cases():
        if case.fixture is not None:  # the harmful block is never input
            out.append(
                _subject(
                    case.manifest.case_id,
                    "incident",
                    case.fixture,
                    case.manifest.harm.block_number - 1,
                )
            )
    for bg in load_background():
        if bg.fixture is not None:
            out.append(_subject(bg.manifest.case_id, "background", bg.fixture, bg.fixture.to_block))
    return out


def attempts_at(subjects: list[SubjectAttempts], block: int) -> list[PoisoningAttempt]:
    return [a for s in subjects for a in s.attempts_at(block)]


def campaign_root() -> Path:
    return Path(str(resources.files(CAMPAIGN_PACKAGE)))


def expansion_path() -> Path:
    return campaign_root() / "expansion.json"


def save_expansion(path: Path, result: ExpansionResult, meta: dict[str, Any]) -> None:
    payload = {
        **meta,
        "version": result.version,
        "chain_id": result.chain_id,
        "cutoff_block": result.cutoff_block,
        "budget": asdict(result.budget),
        "requests": result.requests,
        "seconds": round(result.seconds, 1),
        "stopped": result.stopped,
        "outcomes": [outcome_to_dict(o) for o in result.outcomes],
    }
    path.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def load_expansion(path: Path | None = None) -> tuple[ExpansionResult, dict[str, Any]] | None:
    path = path or expansion_path()
    if not path.exists():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    result = ExpansionResult(
        version=raw["version"],
        chain_id=raw["chain_id"],
        cutoff_block=raw["cutoff_block"],
        budget=ExpansionBudget(**raw["budget"]),
        outcomes=[outcome_from_dict(o) for o in raw["outcomes"]],
        requests=raw["requests"],
        seconds=raw["seconds"],
        stopped=raw["stopped"],
    )
    return result, raw


def canonical_sha256(raw: dict[str, Any]) -> str:
    """Hash of the parsed content (line endings and key order do not matter)."""
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

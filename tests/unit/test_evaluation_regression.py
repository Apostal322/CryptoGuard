"""Pins the headline results of EVALUATION.md and CAMPAIGN_EVALUATION.md.

If a change moves one of these numbers, regenerate the reports and update this file in the
same commit, saying why in the message. A silent change here means the reports went stale.
"""

from __future__ import annotations

import pytest

from cryptoguard.campaigns.cluster import cluster_attempts
from cryptoguard.campaigns.dataset import fixture_attempts, load_expansion
from cryptoguard.campaigns.evaluate import _incident_checks, _prior_context
from cryptoguard.replay.engine import Visibility, replay
from cryptoguard.replay.models import load_cases

REPLAY = {  # case -> (erc20_only outcome, lead with wallet transactions)
    "wbtc-1155-poisoning-2024-05-03": ("not_detected", 367),
    "eth-140-poisoning-2025-08-14": ("not_detected", 42),
    "usdt-50m-poisoning-2025-12-19": ("early_warning", 113),
    "eth-4556-poisoning-2026-01-30": ("early_warning", 13_057),
}


@pytest.mark.parametrize("case_id", sorted(REPLAY))
def test_replay_headlines(case_id: str) -> None:
    case = next(c for c in load_cases() if c.manifest.case_id == case_id)
    assert case.fixture is not None
    result = replay(case.manifest, case.fixture)
    by = {v.visibility: v for v in result.results}
    assert by[Visibility.ERC20_ONLY].outcome == REPLAY[case_id][0]
    assert by[Visibility.ERC20_PLUS_WALLET_TRANSACTIONS].lead_time_blocks == REPLAY[case_id][1]
    assert all(c.passed for c in result.leakage_checks)


def test_campaign_headlines() -> None:
    subjects = fixture_attempts()
    loaded = load_expansion()
    assert loaded is not None
    expansion = loaded[0]
    cutoff = max(s.cutoff_block for s in subjects)
    attempts = [a for s in subjects for a in s.attempts]
    monitored = cluster_attempts(attempts, chain_id=1, cutoff_block=cutoff)
    assert len(attempts) == 54
    assert sum(len(c.victims) > 1 for c in monitored.clusters) == 4

    extra, deployers = expansion.usable_at(cutoff)
    assert len(extra) == 140
    expanded = cluster_attempts(
        [*attempts, *extra], chain_id=1, cutoff_block=cutoff, deployers=deployers
    )
    assert sum(len(c.victims) > 1 for c in expanded.clusters) == 9

    prior = _prior_context(subjects, expansion)
    assert prior["signer_already_seen_on_other_wallets"] == 23

    for check in _incident_checks(subjects, expansion):
        assert check.inputs_after_cutoff == 0
        if check.lead_blocks is not None:  # never earlier than the existing detector
            assert check.existing_detector_lead_blocks is not None
            assert check.lead_blocks <= check.existing_detector_lead_blocks

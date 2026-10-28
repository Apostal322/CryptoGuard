"""Experimental analyses in shadow mode: off by default, read-only, never change findings."""

from __future__ import annotations

import pytest

pytest.importorskip("scipy")

from cryptoguard.blockchain.provider import RpcEthereumProvider
from cryptoguard.core.config import Settings
from cryptoguard.services.analysis import wallet_analysis
from cryptoguard.services.snapshots import take_snapshot
from tests.fakenode import FakeNode
from tests.integration.test_api import WALLET as API_WALLET
from tests.integration.test_api import node as api_node  # noqa: F401
from tests.integration.test_api import rpc_client_for
from tests.integration.test_snapshots import repository
from tests.integration.test_wallet_transactions import LIMITS, MAINNET
from tests.unit.test_poisoning import ATTACKER_SIGNER, FAKE, REAL, TOKEN, WALLET

SHADOW = {"analysis_graph": "shadow", "analysis_spectral": "shadow", "analysis_temporal": "shadow"}


def settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


async def _poisoned_history(node: FakeNode, provider: RpcEthereumProvider):  # type: ignore[no-untyped-def]
    node.add_token(TOKEN)
    node.head = 1_000
    repo = repository()
    node.send_native(WALLET, REAL, 5 * 10**16, block=900)
    await take_snapshot(
        provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0, block=950
    )
    node.head = 1_100
    node.add_transfer_log(TOKEN, WALLET, FAKE, 50_000, block=1_010, signer=ATTACKER_SIGNER)
    await take_snapshot(
        provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0, block=1_050
    )
    return repo


def analyse(repo, **flags: object):  # type: ignore[no-untyped-def]
    return wallet_analysis(
        repo,
        WALLET,
        chain_id=1,
        data_source="rpc",
        settings=settings(**flags),
        history_limit=20_000,
    )


async def test_all_sections_disabled_by_default(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    result = analyse(await _poisoned_history(node, provider))
    assert result.network.status == "disabled"
    assert result.activity.status == "disabled"
    assert result.structure.status == "disabled"
    assert result.experimental
    assert any("not evidence that the wallet is safe" in n for n in result.notes)


async def test_shadow_network_links_the_poisoner_to_the_flagged_lookalike(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    result = analyse(await _poisoned_history(node, provider), **SHADOW)
    assert result.cutoff_block == 1_050
    assert result.network.status == "ok"
    assert result.network.flagged_addresses == [FAKE]
    signer = next(r for r in result.network.related if r.address == ATTACKER_SIGNER)
    assert signer.hops == 1
    assert signer.path[0].relation == "caused"
    assert signer.path[0].example_block == 1_010
    assert result.network.statement == (
        "Indirect links to a previously flagged address were identified."
    )
    # A short history cannot support an activity baseline; that is said, not hidden.
    assert result.activity.status in {"ok", "insufficient_data"}
    assert result.structure.status == "ok"
    assert any("Not visible" in c for c in result.coverage)


async def test_no_flagged_address_means_no_network_claim(
    node: FakeNode, provider: RpcEthereumProvider
) -> None:
    node.head = 1_000
    repo = repository()
    node.send_native(WALLET, REAL, 5 * 10**16, block=900)
    await take_snapshot(
        provider, repo, WALLET, chain=MAINNET, limits=LIMITS, confirmations=0, block=950
    )
    result = analyse(repo, **SHADOW)
    assert result.network.status == "insufficient_data"
    assert result.network.related == []


def _snapshot_findings(node: FakeNode, **flags: object) -> tuple[list[tuple[str, str]], dict]:  # type: ignore[type-arg]
    with rpc_client_for(node, **flags) as client:
        response = client.post(f"/api/v1/wallets/{API_WALLET}/snapshots", json={})
        assert response.status_code == 200, response.text
        events = sorted((e["rule_id"], e["to_status"]) for e in response.json()["finding_events"])
        analysis = client.get(f"/api/v1/wallets/{API_WALLET}/analysis")
        assert analysis.status_code == 200, analysis.text
        return events, analysis.json()


def test_shadow_mode_does_not_change_snapshot_findings(api_node: FakeNode) -> None:  # noqa: F811
    off_events, off_analysis = _snapshot_findings(api_node)
    shadow_events, shadow_analysis = _snapshot_findings(api_node, **SHADOW)
    assert off_events == shadow_events
    assert off_events  # the delegated test wallet does produce findings
    assert off_analysis["network"]["status"] == "disabled"
    assert shadow_analysis["network"]["status"] != "disabled"


def test_analysis_requires_a_snapshot(api_node: FakeNode) -> None:  # noqa: F811
    with rpc_client_for(api_node, **SHADOW) as client:
        response = client.get(f"/api/v1/wallets/{API_WALLET}/analysis")
    assert response.status_code == 404


def test_warm_up_loads_the_libraries_only_when_an_analysis_is_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    from cryptoguard.services import analysis

    assert analysis.warm_up(settings()) is False  # default: nothing to load
    assert analysis.warm_up(settings(analysis_temporal="shadow")) is True
    assert {"scipy.sparse.linalg", "scipy.stats"} <= set(sys.modules)
    monkeypatch.setattr(analysis, "_available", lambda: False)
    assert analysis.warm_up(settings(**SHADOW)) is False  # extra missing: no error

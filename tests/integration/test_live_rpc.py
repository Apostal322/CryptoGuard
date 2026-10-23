"""Live checks against a real Ethereum endpoint. Opt-in:

$env:CRYPTOGUARD_LIVE_RPC_URL = "https://..."; uv run pytest -m live
"""

from __future__ import annotations

import os

import pytest

from cryptoguard.blockchain.abi import (
    APPROVAL_TOPIC,
    SEL_ALLOWANCE,
    TRANSFER_TOPIC,
    decode_uint256,
    encode_call,
)
from cryptoguard.blockchain.eip7702 import CodeKind, classify_code
from cryptoguard.blockchain.erc20 import classify_approval_log, classify_transfer_log
from cryptoguard.blockchain.provider import build_rpc_provider
from cryptoguard.core.chains import get_chain
from cryptoguard.core.config import Settings
from cryptoguard.core.known_contracts import KNOWN_CONTRACTS
from cryptoguard.services.approvals import ScanLimits, scan_approvals
from cryptoguard.services.inspection import inspect_address
from cryptoguard.services.poisoning import scan_poisoning
from cryptoguard.services.snapshots import DetectionOptions

pytestmark = pytest.mark.live

LIVE_URL = os.environ.get("CRYPTOGUARD_LIVE_RPC_URL")
# WETH9 on mainnet: a long-lived contract whose presence is easy to verify independently.
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


@pytest.fixture
def live_settings() -> Settings:
    if not LIVE_URL:
        pytest.skip("CRYPTOGUARD_LIVE_RPC_URL is not set")
    return Settings(_env_file=None, rpc_url=LIVE_URL, chain_id=1)  # type: ignore[call-arg]


async def test_live_known_contracts_have_code(live_settings: Settings) -> None:
    provider = build_rpc_provider(live_settings)
    try:
        for address in KNOWN_CONTRACTS[1]:
            code = await provider.get_code(address, "latest")
            assert classify_code(code).kind is CodeKind.CONTRACT, address
    finally:
        await provider.aclose()


async def test_live_scoped_approval_scan_matches_raw_allowance(live_settings: Settings) -> None:
    """Take an owner from a recent real USDC Approval log, scan it, and cross-check the
    reported allowance with an independent eth_call at the same block."""
    provider = build_rpc_provider(live_settings)
    try:
        head = await provider.block_number()
        logs = await provider.get_logs(
            from_block=head - 20, to_block=head, address=USDC, topics=[APPROVAL_TOPIC]
        )
        events = [e for _, e in map(classify_approval_log, logs) if e is not None]
        if not events:
            pytest.skip("no USDC approvals in the last 20 blocks")
        owner = events[-1].owner
        report = (
            await scan_approvals(
                provider,
                owner,
                chain=get_chain(1),
                limits=ScanLimits.from_settings(live_settings),
                lookback_blocks=200,
                tokens=[USDC],
            )
        ).report
        assert report.pairs_discovered >= 1
        entry = report.approvals[0]
        assert entry.token.symbol == "USDC"
        assert entry.token.decimals == 6
        raw = await provider.call(
            USDC,
            encode_call(SEL_ALLOWANCE, owner, entry.spender.address),
            report.block_number,
        )
        assert entry.current_allowance.raw == str(decode_uint256(raw))
    finally:
        await provider.aclose()


async def test_live_poisoning_scan_on_a_zero_value_recipient(live_settings: Settings) -> None:
    """Scan a wallet that just appeared as the 'from' of a zero-value USDC transfer (the
    classic poisoning fingerprint). Real outcomes vary, so this checks soundness, not counts."""
    provider = build_rpc_provider(live_settings)
    try:
        head = await provider.block_number()
        logs = await provider.get_logs(
            from_block=head - 10, to_block=head, address=USDC, topics=[TRANSFER_TOPIC]
        )
        zero = [e for _, e in map(classify_transfer_log, logs) if e is not None and e.value == 0]
        if not zero:
            pytest.skip("no zero-value USDC transfers in the last 10 blocks")
        report = await scan_poisoning(
            provider,
            zero[-1].sender,
            chain=get_chain(1),
            limits=ScanLimits.from_settings(live_settings),
            options=DetectionOptions.from_settings(live_settings),
            lookback_blocks=1000,
            tokens=[USDC],
        )
        assert report.transfers_analyzed >= 1
        for case in report.cases:
            assert case.suspect != case.reference
            assert case.prefix_match + case.suffix_match >= 7
            assert case.signals
    finally:
        await provider.aclose()


async def test_live_mainnet_inspection(live_settings: Settings) -> None:
    provider = build_rpc_provider(live_settings)
    try:
        inspection = await inspect_address(provider, WETH, chain=get_chain(1))
    finally:
        await provider.aclose()
    assert inspection.chain_verified
    assert inspection.block.number > 20_000_000
    assert inspection.account_code.kind is CodeKind.CONTRACT
    assert int(inspection.native_balance.wei) > 0

"""Live checks against a real Ethereum endpoint. Opt-in:

$env:CRYPTOGUARD_LIVE_RPC_URL = "https://..."; uv run pytest -m live
"""

from __future__ import annotations

import os

import pytest

from cryptoguard.blockchain.eip7702 import CodeKind
from cryptoguard.blockchain.provider import build_rpc_provider
from cryptoguard.core.chains import get_chain
from cryptoguard.core.config import Settings
from cryptoguard.services.inspection import inspect_address

pytestmark = pytest.mark.live

LIVE_URL = os.environ.get("CRYPTOGUARD_LIVE_RPC_URL")
# WETH9 on mainnet: a long-lived contract whose presence is easy to verify independently.
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


@pytest.fixture
def live_settings() -> Settings:
    if not LIVE_URL:
        pytest.skip("CRYPTOGUARD_LIVE_RPC_URL is not set")
    return Settings(_env_file=None, rpc_url=LIVE_URL, chain_id=1)  # type: ignore[call-arg]


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

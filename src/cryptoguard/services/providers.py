"""Select the provider for the configured mode. Real mode never falls back to demo data."""

from __future__ import annotations

from cryptoguard.blockchain.provider import EthereumProvider, build_rpc_provider
from cryptoguard.core.config import Settings
from cryptoguard.core.errors import RpcNotConfiguredError
from cryptoguard.services.demo import DemoProvider

RPC_NOT_CONFIGURED_MESSAGE = (
    "No Ethereum RPC endpoint is configured. Set CRYPTOGUARD_RPC_URL for real data, or start "
    "explicitly in demo mode with CRYPTOGUARD_MODE=demo (simulated fixtures)."
)


def build_provider(settings: Settings) -> EthereumProvider | None:
    """Return the provider, or ``None`` in real mode without an RPC endpoint."""
    if settings.mode == "demo":
        return DemoProvider(settings.chain_id)
    if settings.rpc_url is None:
        return None
    return build_rpc_provider(settings)


def require_provider(provider: EthereumProvider | None) -> EthereumProvider:
    if provider is None:
        raise RpcNotConfiguredError(RPC_NOT_CONFIGURED_MESSAGE)
    return provider

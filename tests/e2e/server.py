"""Browser E2E backend: the real CryptoGuard API over real HTTP (uvicorn), with the real RPC
client, chain verification, snapshot pipeline and database, pointed at a deterministic
fake Ethereum node seeded with known scenarios. Test harness only; never shipped.

Profiles:

- ``default``  every experimental feature off (the shipped defaults);
- ``shadow``   experimental analyses and campaign analysis in shadow mode;
- ``degraded`` a provider without historical state, NumPy/SciPy made unavailable, and a
  switch to make the RPC provider fail.

All data is fictional and labelled as test fixtures; nothing contacts a real network. The
database lives in a temporary directory that is removed on exit.
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--profile", choices=("default", "shadow", "degraded"), required=True)
ARGS = parser.parse_args()
if ARGS.profile == "degraded":  # before anything can import them
    sys.modules["numpy"] = None  # type: ignore[assignment]
    sys.modules["scipy"] = None  # type: ignore[assignment]

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from fastapi import APIRouter, Request  # noqa: E402
from pydantic import SecretStr  # noqa: E402

from cryptoguard.api.app import create_app  # noqa: E402
from cryptoguard.blockchain.provider import EthereumProvider, build_rpc_provider  # noqa: E402
from cryptoguard.core.address import to_checksum_address  # noqa: E402
from cryptoguard.core.chains import get_chain  # noqa: E402
from cryptoguard.core.config import Settings  # noqa: E402
from cryptoguard.database.leases import LeaseStore  # noqa: E402
from cryptoguard.database.repository import open_repository  # noqa: E402
from cryptoguard.services.approvals import ScanLimits  # noqa: E402
from cryptoguard.services.campaigns import run_analysis  # noqa: E402
from cryptoguard.services.snapshots import DetectionOptions, take_snapshot  # noqa: E402
from tests.fakenode import FakeNode, FakeToken, abi_string  # noqa: E402


def cs(hex40: str) -> str:
    return to_checksum_address("0x" + hex40)


# --- deterministic scenario addresses ------------------------------------------------------
UNISWAP_ROUTER = to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
EOA_SPENDER = cs("e0a5" * 10)
TOKEN_USD = cs("70" * 20)
TOKEN_EVIL = cs("e7" * 20)
TOKEN_BROKEN = cs("b7" * 20)
FAKE_TOKEN = cs("f" * 39 + "1")
EVIL_SYMBOL = '<img src=x onerror="window.__xss=1">' + "вЂ®Щ‡" * 3

W_APPROVALS = cs("a0" * 20)
W_POISON = cs("a1" * 20)
REAL_PAYEE = cs("abcd" + "1" * 32 + "ef12")
LOOKALIKE = cs("abcd" + "9" * 32 + "ef12")
ATTACKER_SIGNER = cs("5a" * 20)
W_C1, W_C2, W_C3 = cs("c1" * 20), cs("c2" * 20), cs("c3" * 20)
CAMPAIGN_SIGNER, OTHER_SIGNER = cs("55" * 20), cs("66" * 20)
C_PAYEES = [
    cs(p + c * 32 + s)
    for p, c, s in (("bcde", "2", "fa21"), ("cdef", "3", "ab34"), ("def0", "4", "bc45"))
]
C_LOOKS = [
    cs(p + c * 32 + s)
    for p, c, s in (("bcde", "8", "fa21"), ("cdef", "7", "ab34"), ("def0", "6", "bc45"))
]
W_QUIET = cs("90" * 20)
W_NEVER = cs("91" * 20)  # never snapshotted
SECRET_RPC = "https://rpc.e2e.invalid/v2/E2E-PLACEHOLDER-SECRET-123"


class E2ENode(FakeNode):
    down = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503, text="service unavailable")
        return super().handle(request)


def seed_node(profile: str) -> E2ENode:
    node = E2ENode(head=900)
    usd = node.add_token(TOKEN_USD, FakeToken(decimals=6, symbol=abi_string(b"USDT")))
    evil = node.add_token(TOKEN_EVIL, FakeToken(symbol=abi_string(EVIL_SYMBOL.encode())))
    broken = node.add_token(TOKEN_BROKEN)
    from cryptoguard.blockchain.abi import SEL_ALLOWANCE, SEL_DECIMALS, SEL_SYMBOL

    broken.reverts |= {SEL_ALLOWANCE, SEL_DECIMALS, SEL_SYMBOL}
    node.add_token(FAKE_TOKEN)
    node.set_account(UNISWAP_ROUTER, code=bytes.fromhex("6080604052"))
    for wallet in (W_APPROVALS, W_POISON, W_C1, W_C2, W_C3, W_QUIET, W_NEVER):
        node.set_account(wallet, balance=2 * 10**18)
    unlimited = 2**256 - 1
    usd.balances[W_APPROVALS] = 5_000_000_000
    usd.allowances[(W_APPROVALS, UNISWAP_ROUTER)] = unlimited
    evil.allowances[(W_APPROVALS, EOA_SPENDER)] = 1_000
    node.add_approval_log(TOKEN_USD, W_APPROVALS, UNISWAP_ROUTER, unlimited, block=800, log_index=1)
    node.add_approval_log(TOKEN_EVIL, W_APPROVALS, EOA_SPENDER, 1_000, block=801, log_index=2)
    node.add_approval_log(TOKEN_BROKEN, W_APPROVALS, EOA_SPENDER, 5, block=802, log_index=3)
    for i, (wallet, payee) in enumerate(zip((W_C1, W_C2, W_C3), C_PAYEES, strict=True)):
        node.send_native(wallet, payee, 10**16, block=850 + i)
    node.send_native(W_POISON, REAL_PAYEE, 5 * 10**16, block=860)
    if profile == "degraded":
        node.state_history = 40  # only the last 40 blocks of state are served
    return node


def settings_for(profile: str, db_url: str) -> Settings:
    shadow = "shadow" if profile in ("shadow", "degraded") else "off"
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        rpc_url=SecretStr(SECRET_RPC),
        database_url=db_url,
        snapshot_confirmations=0,
        rate_limit_per_minute=10_000,
        rpc_max_retries=1,
        rpc_backoff_base_seconds=0.1,
        log_level="ERROR",  # the deliberately broken token logs expected call failures
        analysis_graph=shadow,
        analysis_spectral=shadow,
        analysis_temporal=shadow,
        campaign_analysis="shadow" if profile == "shadow" else "off",
    )


async def seed_history(node: E2ENode, settings: Settings, repo: Any, factory: Any) -> None:
    provider: EthereumProvider = factory(settings)
    chain = get_chain(1)
    limits = ScanLimits.from_settings(settings)
    options = DetectionOptions.from_settings(settings)

    async def snap(wallet: str, block: int) -> None:
        await take_snapshot(
            provider,
            repo,
            wallet,
            chain=chain,
            limits=limits,
            confirmations=0,
            block=block,
            lookback_blocks=1_000,
            options=options,
        )

    try:
        if node.state_history is None:
            await snap(W_APPROVALS, 900)
            await snap(W_POISON, 900)  # baseline: paid the real payee, nothing suspicious yet
            node.head = 1_000
            node.add_transfer_log(
                FAKE_TOKEN,
                W_POISON,
                LOOKALIKE,
                50_000,
                block=950,
                signer=ATTACKER_SIGNER,
                log_index=7,
            )
            await snap(W_POISON, 1_000)  # CG-POI-001: lookalike planted
            node.head = 1_100
            node.send_native(W_POISON, LOOKALIKE, 10**18, block=1_050)
            await snap(W_POISON, 1_100)  # CG-POI-003: the wallet paid the lookalike
            node.head = 1_200
            for i, (wallet, look) in enumerate(zip((W_C1, W_C2, W_C3), C_LOOKS, strict=True)):
                signer = CAMPAIGN_SIGNER if i < 2 else OTHER_SIGNER
                node.add_transfer_log(
                    FAKE_TOKEN, wallet, look, 0, block=1_110 + i, signer=signer, log_index=20 + i
                )
                await snap(wallet, 1_200)
            await snap(W_QUIET, 1_200)
        else:
            node.head = 1_200
            await snap(W_QUIET, 1_200)
    finally:
        await provider.aclose()
    node.head = 1_300


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="cryptoguard-e2e-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    db_url = f"sqlite:///{(tmp / 'e2e.db').as_posix()}"
    node = seed_node(ARGS.profile)
    settings = settings_for(ARGS.profile, db_url)
    rng = random.Random(0)

    def factory(s: Settings) -> EthereumProvider:
        return build_rpc_provider(s, transport=node.transport(), rng=rng)

    repo = open_repository(db_url)
    asyncio.run(seed_history(node, settings, repo, factory))
    if ARGS.profile == "shadow":
        run_analysis(repo, chain_id=1, data_source="rpc", settings=settings)

    app = create_app(settings, provider_factory=factory, repository=repo)
    harness = APIRouter(prefix="/__e2e__")

    @harness.get("/scenarios")
    async def scenarios() -> dict[str, object]:
        return {
            "profile": ARGS.profile,
            "approvals": W_APPROVALS,
            "poison": W_POISON,
            "lookalike": LOOKALIKE,
            "real_payee": REAL_PAYEE,
            "attacker_signer": ATTACKER_SIGNER,
            "campaign": [W_C1, W_C2, W_C3],
            "campaign_signer": CAMPAIGN_SIGNER,
            "quiet": W_QUIET,
            "never": W_NEVER,
            "evil_symbol": EVIL_SYMBOL,
            "uniswap_router": UNISWAP_ROUTER,
            "eoa_spender": EOA_SPENDER,
            "token_usd": TOKEN_USD,
            "token_evil": TOKEN_EVIL,
            "token_broken": TOKEN_BROKEN,
            "secret_fragment": "E2E-PLACEHOLDER-SECRET-123",
        }

    @harness.post("/rpc")
    async def rpc(request: Request) -> dict[str, bool]:
        node.down = bool((await request.json())["down"])
        return {"down": node.down}

    @harness.post("/hold-snapshot-lease")
    async def hold(request: Request) -> dict[str, bool]:
        body = await request.json()
        key = f"snapshot:1:rpc:{to_checksum_address(body['wallet'])}"
        store = LeaseStore(repo)
        if body.get("release"):
            held = store.holder(key)
            return {"released": bool(held and store.release(held))}
        return {"held": store.acquire(key, 300) is not None}

    app.include_router(harness)
    uvicorn.run(app, host="127.0.0.1", port=ARGS.port, log_level="warning")


if __name__ == "__main__":
    main()

"""Background wallets: randomly sampled, *unlabelled* wallets for false-alarm measurements.

Selection (seeded, reproducible, recorded in ``background_cases/SELECTION-<seed>.json``):

1. draw a block uniformly from a fixed range, then one transaction uniformly from it;
2. take its signer (``tx.from``);
3. keep it only if it is a plain EOA at that block (no code) and signed at most
   ``max_nonce_delta`` transactions in the window (bounds the recording cost);
4. record the ``window_blocks`` blocks ending at the sampled block.

Biases, stated rather than hidden: sampling by transaction favours active wallets; step 3
excludes contracts, smart accounts and very busy wallets (exchanges, bots). The wallets are
**not** known to be benign: address poisoning is common, so an alert on a background wallet
may be correct. Alert rates on them are upper bounds on false-alarm rates, not estimates.
"""

from __future__ import annotations

import json
import random
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cryptoguard.blockchain.provider import EthereumProvider
from cryptoguard.core.address import to_checksum_address
from cryptoguard.core.errors import InvalidAddressError
from cryptoguard.replay.models import ReplayFixture

BACKGROUND_PACKAGE = "cryptoguard.replay.background_cases"


class BackgroundSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seed: int
    draw: int
    sampled_block: int
    sampled_transaction: str
    rule: str


class BackgroundManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    chain_id: int
    label: Literal["unlabelled_background"] = "unlabelled_background"
    wallet: str
    from_block: int
    to_block: int
    selection: BackgroundSelection


class Exclusion(BaseModel):
    draw: int
    block: int
    reason: str
    wallet: str | None = None


class SelectionLog(BaseModel):
    seed: int
    block_range: tuple[int, int]
    window_blocks: int
    max_nonce_delta: int
    created_at: datetime
    selected: list[str]
    excluded: list[Exclusion]


class BackgroundCase(BaseModel):
    manifest: BackgroundManifest
    fixture: ReplayFixture | None


def background_root() -> Path:
    return Path(str(resources.files(BACKGROUND_PACKAGE)))


async def sample_background(
    provider: EthereumProvider,
    *,
    seed: int,
    count: int,
    block_range: tuple[int, int],
    window_blocks: int,
    max_nonce_delta: int = 100,
    max_draws: int | None = None,
    created_at: datetime,
) -> tuple[list[BackgroundManifest], SelectionLog]:
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling, not cryptography
    rule = (
        f"uniform block in {block_range[0]}..{block_range[1]}, uniform transaction in it, its "
        f"signer if a plain EOA with <= {max_nonce_delta} signed transactions in the "
        f"{window_blocks}-block window ending there"
    )
    chosen: list[BackgroundManifest] = []
    excluded: list[Exclusion] = []
    wallets: set[str] = set()
    draw = 0
    while len(chosen) < count and draw < (max_draws or count * 8):
        draw += 1
        block = rng.randint(*block_range)
        txs = await provider.get_block_transactions(block)
        if not txs:
            excluded.append(Exclusion(draw=draw, block=block, reason="empty block"))
            continue
        tx = txs[rng.randrange(len(txs))]
        try:
            wallet = to_checksum_address(tx.get("from"))
        except InvalidAddressError:
            excluded.append(Exclusion(draw=draw, block=block, reason="malformed signer"))
            continue
        if wallet in wallets:
            excluded.append(Exclusion(draw=draw, block=block, reason="duplicate", wallet=wallet))
            continue
        if await provider.get_code(wallet, block):
            excluded.append(
                Exclusion(
                    draw=draw, block=block, reason="not a plain EOA (has code)", wallet=wallet
                )
            )
            continue
        start = block - window_blocks + 1
        delta = await provider.get_transaction_count(wallet, block) - (
            await provider.get_transaction_count(wallet, start - 1)
        )
        if delta > max_nonce_delta:
            excluded.append(
                Exclusion(
                    draw=draw, block=block, reason=f"too active ({delta} signed txs)", wallet=wallet
                )
            )
            continue
        wallets.add(wallet)
        chosen.append(
            BackgroundManifest(
                case_id=f"bg-{seed}-{draw:03d}",
                chain_id=await provider.chain_id(),
                wallet=wallet,
                from_block=start,
                to_block=block,
                selection=BackgroundSelection(
                    seed=seed,
                    draw=draw,
                    sampled_block=block,
                    sampled_transaction=str(tx.get("hash")),
                    rule=rule,
                ),
            )
        )
    log = SelectionLog(
        seed=seed,
        block_range=block_range,
        window_blocks=window_blocks,
        max_nonce_delta=max_nonce_delta,
        created_at=created_at,
        selected=[m.case_id for m in chosen],
        excluded=excluded,
    )
    return chosen, log


def load_background(directory: Path | None = None) -> list[BackgroundCase]:
    root = directory or background_root()
    out: list[BackgroundCase] = []
    for case_dir in sorted(p for p in root.iterdir() if (p / "manifest.json").exists()):
        manifest = BackgroundManifest.model_validate_json((case_dir / "manifest.json").read_text())
        path = case_dir / "fixture.json"
        fixture = ReplayFixture.model_validate_json(path.read_text()) if path.exists() else None
        if fixture is not None and fixture.case_id != manifest.case_id:
            raise ValueError(f"fixture in {case_dir} belongs to {fixture.case_id}")
        out.append(BackgroundCase(manifest=manifest, fixture=fixture))
    return out


def write_manifest(manifest: BackgroundManifest, root: Path | None = None) -> Path:
    case_dir = (root or background_root()) / manifest.case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_dir / "manifest.json"
    path.write_text(json.dumps(manifest.model_dump(mode="json"), indent=1) + "\n")
    return path

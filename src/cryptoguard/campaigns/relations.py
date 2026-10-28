"""Relationship evidence between attempts: which shared entity, how strong, and why.

Two attempts are related only through a **planting-side entity** they share. The victim is
never such an entity: many unrelated attackers target the same wallet, and anyone can send
an innocent wallet tokens, so linking through victims would let an attacker pull innocent
wallets into a "campaign". Recipients the victim paid (the imitated addresses) are not
entities either, for the same reason.

| Shared entity | Strength | Merges clusters | Why |
|---|---|---|---|
| planting transaction | directly observed | yes | one transaction planted both |
| lookalike address | strongly supported | yes | planting only benefits its controller |
| verified planting signer | strongly supported | yes | the same key paid for both plantings |
| emitting contract (narrow) | tentative | no | a fake token can be reused or copied; context only |
| contract deployer | tentative | no | deployers can be shared tooling; context only |
| emitting contract (common) | insufficient | no | popular tokens are used by everyone |
| block proximity | insufficient | no | unrelated bots react to the same public transaction |

"Strongly supported" means strong evidence of shared infrastructure, **not** of a single
operator: a planting key or lookalike could be part of a shared service. No strength is a
probability.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from cryptoguard.campaigns.attempts import PoisoningAttempt
from cryptoguard.core.address import to_checksum_address

EntityKind = Literal["transaction", "lookalike", "signer", "contract", "deployer"]
Strength = Literal["directly_observed", "strongly_supported", "tentative", "insufficient"]
STRENGTH_ORDER: tuple[Strength, ...] = (
    "directly_observed",
    "strongly_supported",
    "tentative",
    "insufficient",
)
RELATION_LABEL: dict[EntityKind, str] = {
    "transaction": "share a planting transaction",
    "lookalike": "plant the same lookalike address",
    "signer": "share a verified planting signer",
    "contract": "use the same token contract",
    "deployer": "use token contracts created by the same deployer",
}

# Token contracts used by very many unrelated parties. Poisoners call transferFrom(victim,
# lookalike, 0) on them precisely because they are popular, so sharing one says nothing.
# Addresses from the issuers' published deployments (checked on Etherscan, 2026-10-28).
COMMON_CONTRACTS: Mapping[int, frozenset[str]] = {
    1: frozenset(
        to_checksum_address(a)
        for a in (
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT (Tether)
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC (Circle)
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI (MakerDAO)
            "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",  # WBTC
        )
    )
}


@dataclass(frozen=True, order=True)
class Entity:
    kind: EntityKind
    key: str

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.key}"


@dataclass(frozen=True)
class EntityEvidence:
    entity: Entity
    strength: Strength
    attempts: tuple[str, ...]  # attempt ids, sorted
    victims: int
    lookalikes: int
    reason: str


@dataclass(frozen=True)
class RelationConfig:
    """Which shared entities may merge attempts into one cluster, and the hub guard."""

    merge_kinds: frozenset[EntityKind] = frozenset({"transaction", "lookalike", "signer"})
    merge_strengths: frozenset[Strength] = frozenset({"directly_observed", "strongly_supported"})
    # An entity linking more distinct lookalikes than this is treated as shared
    # infrastructure (a service, not one operation): reported, never used to merge.
    max_lookalikes_per_entity: int = 25
    # A narrow contract is one used by at most this many distinct victims in the data and
    # not on the common-contract list.
    narrow_contract_max_victims: int = 10
    use_common_contract_list: bool = True


def entities_of(
    attempt: PoisoningAttempt, deployers: Mapping[str, str] | None = None
) -> list[Entity]:
    out = [
        Entity("transaction", attempt.transaction_hash.lower()),
        Entity("lookalike", attempt.lookalike),
    ]
    # A signer equal to the lookalike is already represented by the lookalike entity.
    if attempt.signer is not None and attempt.signer not in (attempt.victim, attempt.lookalike):
        out.append(Entity("signer", attempt.signer))
    out.append(Entity("contract", attempt.contract))
    if deployers and attempt.contract in deployers:
        out.append(Entity("deployer", deployers[attempt.contract]))
    return out


def shared_entities(
    attempts: Sequence[PoisoningAttempt],
    *,
    chain_id: int,
    deployers: Mapping[str, str] | None = None,
    config: RelationConfig | None = None,
) -> list[EntityEvidence]:
    """Every entity shared by at least two attempts, with its strength and the reason."""
    config = config or RelationConfig()
    members: dict[Entity, list[PoisoningAttempt]] = defaultdict(list)
    for a in attempts:
        for e in entities_of(a, deployers):
            members[e].append(a)
    common = (
        COMMON_CONTRACTS.get(chain_id, frozenset())
        if config.use_common_contract_list
        else frozenset()
    )
    out: list[EntityEvidence] = []
    for entity in sorted(members):
        group = members[entity]
        if len(group) < 2:
            continue
        victims = len({a.victim for a in group})
        lookalikes = len({a.lookalike for a in group})
        strength, reason = _strength(entity, victims, lookalikes, common, config)
        out.append(
            EntityEvidence(
                entity=entity,
                strength=strength,
                attempts=tuple(sorted(a.attempt_id for a in group)),
                victims=victims,
                lookalikes=lookalikes,
                reason=reason,
            )
        )
    return out


def _strength(
    entity: Entity,
    victims: int,
    lookalikes: int,
    common: frozenset[str],
    config: RelationConfig,
) -> tuple[Strength, str]:
    if entity.kind == "transaction":
        return "directly_observed", "Both events were emitted in the same planting transaction."
    if entity.kind == "lookalike":
        return "strongly_supported", "The same lookalike address was planted each time."
    if entity.kind == "signer":
        if lookalikes > config.max_lookalikes_per_entity:
            return (
                "insufficient",
                f"This signer planted {lookalikes} different lookalikes, more than the "
                f"{config.max_lookalikes_per_entity} allowed for one operation; treated as "
                "shared infrastructure.",
            )
        return "strongly_supported", "The same verified key signed each planting transaction."
    if entity.kind == "contract":
        if entity.key in common:
            return "insufficient", "A widely used token contract; sharing it says nothing."
        if victims > config.narrow_contract_max_victims:
            return (
                "insufficient",
                f"Used against {victims} victims in the data; too common to be distinctive.",
            )
        return "tentative", "The same (not widely used) token contract emitted each event."
    return "tentative", "The emitting contracts were created by the same deployer."


def merging(evidence: Iterable[EntityEvidence], config: RelationConfig) -> list[EntityEvidence]:
    return [
        e
        for e in evidence
        if e.entity.kind in config.merge_kinds and e.strength in config.merge_strengths
    ]


def temporal_pairs(
    attempts: Sequence[PoisoningAttempt], *, window_blocks: int
) -> list[tuple[str, str]]:
    """Weak feature only: attempts on *different* victims within ``window_blocks`` blocks.
    Never used to merge; reported to measure how often coincidence alone would link."""
    ordered = sorted(attempts)
    pairs: list[tuple[str, str]] = []
    start = 0
    for i, a in enumerate(ordered):
        while ordered[start].block_number < a.block_number - window_blocks:
            start += 1
        for b in ordered[start:i]:
            if b.victim != a.victim:
                pairs.append(tuple(sorted((a.attempt_id, b.attempt_id))))  # type: ignore[arg-type]
    return sorted(set(pairs))

"""Typed entity relationships for campaign isolation (Phase 11.5).

Every relationship between two events has a type. Only some types are evidence of one
campaign.

Isolating (they link events into one group):
- ``shared_planting_tx``: one transaction plants every victim it touches;
- ``shared_lookalike``: the lookalike is the attacker's address;
- ``shared_planting_signer``: unless the signer is public infrastructure (a relayer or
  router signs for everyone);
- ``shared_victim``: one wallet's events must not straddle a split;
- ``shared_imitated``: unless public infrastructure (an exchange hot wallet is imitated by
  unrelated attackers);
- ``shared_counterfeit_token``: a counterfeit token contract is attack infrastructure,
  whatever its degree;
- ``shared_verified_infra``: caller-supplied, independently verified attack addresses.

Not isolating:
- ``shared_token_contract``: USDT, USDC, DAI; everyone uses them;
- ``shared_recipient``: an ordinary or public counterparty says nothing about an attacker.

High degree alone never exempts an address. Exemption needs membership of the reviewed
public-infrastructure list (``dataset.PUBLIC_INFRASTRUCTURE``) or the trusted-token list.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptoguard.ml.dataset import PUBLIC_INFRASTRUCTURE
from cryptoguard.ml.events import PoisoningEvent, _UnionFind
from cryptoguard.ml.payments import TRUSTED_TOKENS

GROUPING_VERSION = "typed-groups/1"
ISOLATING = frozenset(
    {
        "shared_planting_tx",
        "shared_lookalike",
        "shared_planting_signer",
        "shared_victim",
        "shared_imitated",
        "shared_counterfeit_token",
        "shared_verified_infra",
    }
)
NON_ISOLATING = frozenset({"shared_token_contract", "shared_recipient"})


@dataclass(frozen=True)
class GroupingPolicy:
    public: frozenset[str] = field(default_factory=lambda: frozenset(PUBLIC_INFRASTRUCTURE))
    trusted_tokens: frozenset[str] = field(default_factory=lambda: frozenset(TRUSTED_TOKENS))
    verified_infra: frozenset[str] = frozenset()  # independently verified attack addresses
    # Edge types not used for this grouping (e.g. ``shared_victim`` when sampling within one
    # wallet's candidates, where the wallet is already its own stratum).
    exclude: frozenset[str] = frozenset()


def _lower(v: str | None) -> str | None:
    return v.lower() if v else None


def edge_keys(e: PoisoningEvent, policy: GroupingPolicy) -> list[tuple[str, str]]:
    """``(edge type, entity)`` pairs of one event, isolating or not."""
    public = {a.lower() for a in policy.public}
    verified = {v.lower() for v in policy.verified_infra}
    trusted_tokens = {t.lower() for t in policy.trusted_tokens}
    keys: list[tuple[str, str]] = [
        ("shared_planting_tx", e.planting_tx_id),
        ("shared_lookalike", e.lookalike.lower()),
        ("shared_victim", e.victim.lower()),
    ]
    signer = _lower(e.tx_signer)
    if signer and signer != e.victim.lower():
        keys.append(("shared_recipient" if signer in public else "shared_planting_signer", signer))
    imitated = _lower(e.imitated)
    if imitated:
        keys.append(("shared_recipient" if imitated in public else "shared_imitated", imitated))
    token = _lower(e.log_contract)
    if token:
        trusted = token in trusted_tokens or token in public
        keys.append(("shared_token_contract" if trusted else "shared_counterfeit_token", token))
    for addr in (signer, e.lookalike.lower(), token):
        if addr and addr in verified:
            keys.append(("shared_verified_infra", addr))
    return keys


@dataclass(frozen=True)
class Grouping:
    group: dict[str, str]  # victim_event_id -> group id
    edges_used: dict[str, int]  # isolating edge type -> events carrying it
    edges_ignored: dict[str, int]  # non-isolating edge type -> events carrying it
    linking: dict[str, int]  # isolating edge type -> entities shared by 2+ events


def typed_groups(
    events: Sequence[PoisoningEvent], policy: GroupingPolicy | None = None
) -> Grouping:
    policy = policy or GroupingPolicy()
    uf = _UnionFind()
    used: Counter[str] = Counter()
    ignored: Counter[str] = Counter()
    members: dict[tuple[str, str], set[str]] = defaultdict(set)
    for e in events:
        node = "e:" + e.victim_event_id
        uf.find(node)
        for kind, key in edge_keys(e, policy):
            if kind in ISOLATING and kind not in policy.exclude:
                used[kind] += 1
                members[(kind, key)].add(e.victim_event_id)
                uf.union(node, f"{kind}:{key}")
            else:
                ignored[kind] += 1
    roots = {e.victim_event_id: uf.find("e:" + e.victim_event_id) for e in events}
    names = {r: f"t{i:05d}" for i, r in enumerate(sorted(set(roots.values())))}
    linking: Counter[str] = Counter(k for (k, _), ids in members.items() if len(ids) > 1)
    return Grouping(
        {e: names[r] for e, r in roots.items()}, dict(used), dict(ignored), dict(linking)
    )


def overlapping(a: Iterable[PoisoningEvent], b: Iterable[PoisoningEvent]) -> set[str]:
    """Isolating entities shared between two event sets (for split-leakage checks)."""
    policy = GroupingPolicy()
    left = {k for e in a for k in edge_keys(e, policy) if k[0] in ISOLATING}
    return {f"{k}:{v}" for k, v in left & {k for e in b for k in edge_keys(e, policy)}}

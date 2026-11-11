"""Phase 12.5 archive research (protocol 12.5 §4 and §5), offline.

- ``cache_episodes`` / ``load_cache``: the eligible Phase 12.1 payoff episodes (protected
  wallets and every episode sharing an entity or linkage group with a frozen review item
  removed), with 12.1's group ids and temporal dev/test split, cached once locally. The
  source is CC BY-NC-ND: the cache stays in the git-ignored research folder.
- **RQ8, the primary ML test** (``proxy_task``): predict the mechanism class of a victim's
  next planting from plantings in strictly earlier blocks. A self-supervised event-pattern
  proxy on source-flagged rows, **not** poisoning detection. Baselines: global frequency,
  victim-prefix frequency, first-order Markov. Model: a fixed multinomial logistic
  regression. Metric: test log loss with a group-bootstrap CI of the paired difference.
- **RQ2, exploratory** (``semantic_channel``): rank candidates by the semantic channel of
  their latest planting (``spoofed_out`` first) with recency breaking ties, against recency
  alone, on the development split only.
- **H3a** (``mad_recency_equivalence``): a median/MAD-normalized recency ranks exactly as
  recency within an episode.
"""

from __future__ import annotations

import json
import math
import random
import statistics
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROXY_TASK = "planting-mechanism-next/1"
PROXY_FEATURES = "proxy-features/1"
CLASSES = ("spoofed_out", "counterfeit_in", "tiny_in", "zero_in", "other")
SEED = 20261109
STABLECOINS = frozenset(
    {
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "0x6b175474e89094c44da98b954eedeac495271d0f",
    }
)


@dataclass(frozen=True)
class Planting:
    block: int
    line: int
    token: str
    sender: str
    receiver: str
    flags: int


@dataclass(frozen=True)
class CachedEpisode:
    victim: str
    payoff_block: int
    paid: str
    group: int
    split: str  # "dev" or "test" (12.1's temporal group split)
    plantings: tuple[Planting, ...]

    def lookalike(self, p: Planting) -> str:
        return p.receiver if p.sender == self.victim else p.sender

    @property
    def candidates(self) -> tuple[str, ...]:
        return tuple(sorted({self.lookalike(p) for p in self.plantings}))


def mechanism(p: Planting, victim: str) -> str:
    """The protocol's class of one planting (source flags; a proxy, not a verdict)."""
    from cryptoguard.ml.tsuchiya_archive import COUNTERFEIT, TINY, ZERO

    if p.sender == victim:
        return "spoofed_out"
    if p.flags & COUNTERFEIT:
        return "counterfeit_in"
    if p.flags & TINY:
        return "tiny_in"
    if p.flags & ZERO:
        return "zero_in"
    return "other"


# --- cache ----------------------------------------------------------------------------------


def cache_episodes(poisoning_dir: Path, out: Path) -> dict[str, Any]:
    """Build the episode cache from the local archive subset (about 5 minutes on an HDD)."""
    from cryptoguard.ml import lookalike_ranking as lr

    episodes, excluded = lr.load_episodes(poisoning_dir)
    addrs, txs = lr.protected_entities(poisoning_dir)
    overlap = lr.protected_overlap(episodes, addrs, txs)
    kept = [e for e, o in zip(episodes, overlap, strict=True) if not o]
    grp, mode = lr.protocol_groups(kept)
    split = lr.temporal_split(kept, grp)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for e, g, s in zip(kept, grp, split, strict=True):
            fh.write(
                json.dumps(
                    {
                        "victim": e.victim,
                        "payoff_block": e.payoff_block,
                        "paid": e.paid,
                        "group": g,
                        "split": s,
                        "plantings": [
                            [r.block, r.line, r.token, r.sender, r.receiver, r.flags]
                            for r in e.plantings
                        ],
                    }
                )
                + "\n"
            )
    return {
        "eligible_episodes": len(episodes),
        "excluded_before": excluded,
        "excluded_protected_overlap": sum(overlap),
        "kept": len(kept),
        "group_mode": mode,
        "groups": len(set(grp)),
        "dev": split.count("dev"),
        "test": split.count("test"),
    }


def load_cache(path: Path) -> list[CachedEpisode]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        out.append(
            CachedEpisode(
                d["victim"],
                d["payoff_block"],
                d["paid"],
                d["group"],
                d["split"],
                tuple(Planting(*p) for p in d["plantings"]),
            )
        )
    return out


# --- RQ8: next-planting mechanism (self-supervised proxy) -----------------------------------


@dataclass(frozen=True)
class ProxyRow:
    group: int
    split: str
    victim: str
    target: str
    prefix: tuple[str, ...]  # classes of plantings in strictly earlier blocks, in order
    features: tuple[float, ...]


FEATURE_NAMES = (
    *(f"count_{c}" for c in CLASSES),
    *(f"share_{c}" for c in CLASSES),
    *(f"last_{c}" for c in CLASSES),
    "log_prefix_len",
    "log_blocks_since_last",
    "distinct_lookalikes",
    "last_token_stablecoin",
    "last_two_equal",
)


def proxy_rows(episodes: Sequence[CachedEpisode]) -> list[ProxyRow]:
    """One row per planting that has at least one planting in a strictly earlier block.
    Same-block predecessors are never inputs (their order is unknown)."""
    rows = []
    for e in episodes:
        ordered = sorted(e.plantings, key=lambda p: (p.block, p.line))
        for i, p in enumerate(ordered):
            prior = [q for q in ordered[:i] if q.block < p.block]
            if not prior:
                continue
            classes = tuple(mechanism(q, e.victim) for q in prior)
            counts = Counter(classes)
            n = len(prior)
            last = prior[-1]
            feats = (
                *(float(counts[c]) for c in CLASSES),
                *(counts[c] / n for c in CLASSES),
                *(float(classes[-1] == c) for c in CLASSES),
                math.log1p(n),
                math.log1p(p.block - last.block),
                float(len({e.lookalike(q) for q in prior})),
                float(last.token.lower() in STABLECOINS),
                float(n >= 2 and classes[-1] == classes[-2]),
            )
            rows.append(
                ProxyRow(e.group, e.split, e.victim, mechanism(p, e.victim), classes, feats)
            )
    return rows


def _global(train: Sequence[ProxyRow]) -> dict[str, float]:
    c = Counter(r.target for r in train)
    k = len(CLASSES)
    return {cls: (c[cls] + 1) / (len(train) + k) for cls in CLASSES}


def baseline_probs(
    train: Sequence[ProxyRow], rows: Sequence[ProxyRow]
) -> dict[str, list[dict[str, float]]]:
    """Probabilities from the three baselines (fit on ``train`` only)."""
    g = _global(train)
    trans: dict[str, Counter[str]] = {c: Counter() for c in CLASSES}
    for r in train:
        trans[r.prefix[-1]][r.target] += 1
    k = len(CLASSES)
    out: dict[str, list[dict[str, float]]] = {"global": [], "victim_prefix": [], "markov": []}
    for r in rows:
        out["global"].append(g)
        pc = Counter(r.prefix)
        n = len(r.prefix)
        out["victim_prefix"].append({c: (pc[c] + g[c]) / (n + 1) for c in CLASSES})
        t = trans[r.prefix[-1]]
        tot = sum(t.values())
        out["markov"].append({c: (t[c] + 1) / (tot + k) for c in CLASSES})
    return out


def logistic_probs(train: Sequence[ProxyRow], rows: Sequence[ProxyRow]) -> list[dict[str, float]]:
    """The protocol's fixed model: standardized features, multinomial L2 logistic regression,
    C = 1, lbfgs, seed fixed. No search."""
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    labels = sorted({r.target for r in train})
    if len(labels) < 2:
        raise ValueError("single-class training data: the proxy task is undefined")
    x = np.array([r.features for r in train], dtype=float)
    y = np.array([r.target for r in train])
    model = make_pipeline(
        StandardScaler(), LogisticRegression(C=1.0, max_iter=2000, random_state=SEED)
    )
    model.fit(x, y)
    proba = model.predict_proba(np.array([r.features for r in rows], dtype=float))
    classes = list(model.classes_)
    eps = 1e-6  # a class absent from training keeps a small floor, then renormalize
    out = []
    for p in proba:
        d = {c: eps for c in CLASSES}
        for c, v in zip(classes, p, strict=True):
            d[c] = float(v) + eps
        s = sum(d.values())
        out.append({c: v / s for c, v in d.items()})
    return out


def log_losses(probs: Sequence[Mapping[str, float]], rows: Sequence[ProxyRow]) -> list[float]:
    return [-math.log(max(p[r.target], 1e-12)) for p, r in zip(probs, rows, strict=True)]


def macro_f1(probs: Sequence[Mapping[str, float]], rows: Sequence[ProxyRow]) -> dict[str, Any]:
    pred = [max(CLASSES, key=lambda c: (p[c], -CLASSES.index(c))) for p in probs]
    true = [r.target for r in rows]
    per: dict[str, dict[str, float | int]] = {}
    f1s = []
    for c in CLASSES:
        tp = sum(1 for a, b in zip(pred, true, strict=True) if a == c and b == c)
        fp = sum(1 for a, b in zip(pred, true, strict=True) if a == c and b != c)
        fn = sum(1 for a, b in zip(pred, true, strict=True) if a != c and b == c)
        support = tp + fn
        if support == 0:
            continue  # macro-F1 over classes present in the evaluation set
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / support
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[c] = {"support": support, "recall": round(rec, 4), "f1": round(f1, 4)}
        f1s.append(f1)
    return {"macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None, "per_class": per}


def group_bootstrap_diff(
    a: Sequence[float], b: Sequence[float], groups: Sequence[int], *, draws: int = 2000
) -> dict[str, float]:
    """Mean of a - b (per row), and a 95% percentile CI from resampling groups."""
    by: dict[int, list[float]] = {}
    for x, y, g in zip(a, b, groups, strict=True):
        by.setdefault(g, []).append(x - y)
    keys = sorted(by)
    sums = {g: sum(v) for g, v in by.items()}
    lens = {g: len(v) for g, v in by.items()}
    rng = random.Random(SEED)  # noqa: S311 - resampling, not cryptography
    stats = []
    for _ in range(draws):
        pick = [keys[rng.randrange(len(keys))] for _ in keys]
        stats.append(sum(sums[g] for g in pick) / sum(lens[g] for g in pick))
    stats.sort()
    point = sum(sums.values()) / sum(lens.values())
    return {
        "mean_diff": round(point, 5),
        "ci_low": round(stats[int(0.025 * draws)], 5),
        "ci_high": round(stats[int(0.975 * draws) - 1], 5),
        "groups": len(keys),
    }


def proxy_task(episodes: Sequence[CachedEpisode]) -> dict[str, Any]:
    rows = proxy_rows(episodes)
    train = [r for r in rows if r.split == "dev"]
    test = [r for r in rows if r.split == "test"]
    if not train or not test:
        raise ValueError("the proxy task needs both development and test rows")
    probs = baseline_probs(train, test)
    probs["logistic"] = logistic_probs(train, test)
    losses = {k: log_losses(v, test) for k, v in probs.items()}
    mean = {k: round(statistics.fmean(v), 5) for k, v in losses.items()}
    best = min(("global", "victim_prefix", "markov"), key=lambda k: mean[k])
    diff = group_bootstrap_diff(losses["logistic"], losses[best], [r.group for r in test])
    supported = (
        all(mean["logistic"] < mean[k] for k in ("global", "victim_prefix", "markov"))
        and diff["ci_high"] < 0
    )
    return {
        "task": PROXY_TASK,
        "features": PROXY_FEATURES,
        "feature_names": list(FEATURE_NAMES),
        "rows": {"train": len(train), "test": len(test)},
        "groups": {
            "train": len({r.group for r in train}),
            "test": len({r.group for r in test}),
        },
        "class_counts": {
            "train": dict(Counter(r.target for r in train)),
            "test": dict(Counter(r.target for r in test)),
        },
        "test_log_loss": mean,
        "test_macro_f1": {k: macro_f1(v, test) for k, v in probs.items()},
        "best_baseline": best,
        "logistic_minus_best_baseline": diff,
        "h8_supported": supported,
        "label": "self-supervised proxy on source-flagged plantings; not poisoning detection",
    }


# --- RQ2 exploratory and H3a ---------------------------------------------------------------


def _latest(e: CachedEpisode) -> dict[str, Planting]:
    latest: dict[str, Planting] = {}
    for p in sorted(e.plantings, key=lambda p: (p.block, p.line)):
        latest[e.lookalike(p)] = p
    return latest


def top1(scores: Mapping[str, tuple[float, ...]], paid: str) -> float:
    best = max(scores.values())
    top = [c for c, s in scores.items() if s == best]
    return 1.0 / len(top) if paid in top else 0.0


def semantic_channel(episodes: Sequence[CachedEpisode]) -> dict[str, Any]:
    """B5 (spoofed-out latest planting first, recency second) against T0 (recency), on the
    development split only. Tie-averaged top-1."""
    dev = [e for e in episodes if e.split == "dev"]
    t0s, b5s, grp = [], [], []
    paid_spoofed = rival_spoofed = rivals = 0
    for e in dev:
        latest = _latest(e)
        t0 = {c: (float(p.block),) for c, p in latest.items()}
        b5 = {
            c: (float(mechanism(p, e.victim) == "spoofed_out"), float(p.block))
            for c, p in latest.items()
        }
        t0s.append(top1(t0, e.paid))
        b5s.append(top1(b5, e.paid))
        grp.append(e.group)
        for c, p in latest.items():
            spoofed = mechanism(p, e.victim) == "spoofed_out"
            if c == e.paid:
                paid_spoofed += spoofed
            else:
                rivals += 1
                rival_spoofed += spoofed
    return {
        "split": "dev",
        "episodes": len(dev),
        "groups": len(set(grp)),
        "T0_top1": round(statistics.fmean(t0s), 4),
        "B5_top1": round(statistics.fmean(b5s), 4),
        "B5_minus_T0": group_bootstrap_diff(b5s, t0s, grp),
        "latest_planting_spoofed_share": {
            "paid": round(paid_spoofed / len(dev), 4),
            "rivals": round(rival_spoofed / rivals, 4) if rivals else None,
        },
        "label": "exploratory (12.1 development split; test split not used)",
    }


def mad_recency_equivalence(episodes: Sequence[CachedEpisode]) -> dict[str, Any]:
    """H3a: z = (latest block - median) / MAD of the episode's planting blocks is a strictly
    increasing transform of the latest block, so it must rank candidates exactly as T0."""
    same = differ = undefined = 0
    for e in episodes:
        latest = _latest(e)
        blocks = [p.block for p in e.plantings]
        med = statistics.median(blocks)
        mad = statistics.median(abs(b - med) for b in blocks)
        if mad == 0:
            undefined += 1
            continue
        t0 = sorted(latest, key=lambda c: (latest[c].block, c))
        z = sorted(latest, key=lambda c: ((latest[c].block - med) / mad, c))
        if t0 == z:
            same += 1
        else:
            differ += 1
    return {"episodes_same_order": same, "differ": differ, "mad_zero_undefined": undefined}


def inventory(poisoning_dir: Path) -> dict[str, Any]:
    """Exact counts of the local research sources (no network)."""
    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import load_cases
    from cryptoguard.replay.observation import coverage_of

    def window(fx: Any) -> dict[str, Any]:
        cov = coverage_of(fx)
        return {
            "schema": cov.schema_version,
            "blocks": fx.to_block - fx.from_block + 1,
            "transfers": len(fx.transfers),
            "wallet_transactions": len(fx.wallet_transactions),
            "native_inbound": None if fx.native_inbound is None else len(fx.native_inbound),
            "not_complete": sorted(k for k, v in cov.categories.items() if v.status != "complete"),
        }

    out: dict[str, Any] = {"replay_cases": {}, "level_i": {}, "background": {}}
    for c in load_cases():
        if c.fixture:
            out["replay_cases"][c.manifest.case_id] = window(c.fixture)
    for c in ib.load_new_cases():
        if c.fixture:
            out["level_i"][c.manifest.case_id] = window(c.fixture)
    blind = Path("data/ml/research/phase12.4/blind-v2/fixture.json")
    if blind.exists():
        from cryptoguard.replay.models import ReplayFixture

        out["level_i"]["scamsniffer-blind-v2"] = window(
            ReplayFixture.model_validate_json(blind.read_text(encoding="utf-8"))
        )
    for b in load_background():
        if b.fixture:
            out["background"][b.manifest.case_id] = window(b.fixture)
    sub = poisoning_dir / "archive_subset.sqlite"
    out["archive_subset_bytes"] = sub.stat().st_size if sub.exists() else None
    return out


# --- wallet-centric experiments (protocol 12.5 §6) -----------------------------------------

STABLECOIN_USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
TRANSFORMS = (
    "no_native",
    "signer_unknown",
    "last_day_only",
    "no_reference_history",
    "receipts_unknown",
)


def _window_variants(fixture: Any, cutoff: tuple[int, int]) -> dict[str, Any]:
    import time
    import tracemalloc

    from cryptoguard.ml import candidate_discovery as cd

    days = max(1.0, (min(cutoff[0], fixture.to_block + 1) - fixture.from_block) / 7_200)
    out: dict[str, Any] = {}
    for v in ("C0", "C1", "C2"):
        tracemalloc.start()
        t0 = time.perf_counter()
        res = cd.discover(fixture, cutoff=cutoff, variant=v)
        ms = (time.perf_counter() - t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        by_method: Counter[str] = Counter(m for c in res.candidates for m in c.methods)
        out[v] = {
            "events": len(res.candidates),
            "distinct": len(res.lookalikes),
            "per_wallet_day": round(len(res.candidates) / days, 3),
            "by_method": dict(sorted(by_method.items())),
            "abstain": res.abstain,
            "runtime_ms": round(ms, 2),
            "peak_kib": round(peak / 1024, 1),
        }
    out["duplicates_suppressed_by_C2"] = out["C1"]["events"] - out["C2"]["events"]
    return out


def _drop(fixture: Any, transform: str, cutoff: tuple[int, int]) -> Any:
    """Controlled information loss. It never adds anything the source did not observe."""
    from cryptoguard.replay.observation import CategoryCoverage

    if transform == "no_native":
        cov = fixture.observation
        cats = dict(cov.categories) if cov else {}
        cats["native_inbound_external"] = CategoryCoverage(status="not_collected")
        return fixture.model_copy(
            update={
                "native_inbound": None,
                "observation": cov.model_copy(update={"categories": cats}) if cov else None,
            }
        )
    if transform == "signer_unknown":
        return fixture.model_copy(
            update={
                "transfers": [t.model_copy(update={"tx_sender": None}) for t in fixture.transfers]
            }
        )
    if transform == "last_day_only":
        lo = cutoff[0] - 7_200
        return fixture.model_copy(
            update={
                "from_block": max(fixture.from_block, lo),
                "transfers": [t for t in fixture.transfers if t.block_number >= lo],
                "wallet_transactions": [
                    t for t in fixture.wallet_transactions if t.block_number >= lo
                ],
                "native_inbound": None
                if fixture.native_inbound is None
                else [n for n in fixture.native_inbound if n.block_number >= lo],
            }
        )
    if transform == "no_reference_history":
        w = fixture.wallet.lower()
        return fixture.model_copy(
            update={
                "transfers": [
                    t
                    for t in fixture.transfers
                    if not (t.sender.lower() == w and (t.tx_sender or "").lower() == w)
                ],
                "wallet_transactions": [],
            }
        )
    if transform == "receipts_unknown":
        if fixture.native_inbound is None:
            return fixture
        return fixture.model_copy(
            update={
                "native_inbound": [
                    n.model_copy(update={"succeeded": None}) for n in fixture.native_inbound
                ]
            }
        )
    raise ValueError(transform)


def robustness(fixture: Any, cutoff: tuple[int, int]) -> dict[str, Any]:
    from cryptoguard.ml import candidate_discovery as cd

    base = cd.discover(fixture, cutoff=cutoff, variant="C2")
    out: dict[str, Any] = {"base": sorted(base.lookalikes)}
    for t in TRANSFORMS:
        res = cd.discover(_drop(fixture, t, cutoff), cutoff=cutoff, variant="C2")
        diff = cd.compare(base, res)
        out[t] = {
            "kept": len(diff["kept"]),
            "removed": len(diff["removed"]),
            "added": len(diff["added"]),
            "abstain": res.abstain,
            "not_complete": sorted(k for k, s in res.coverage.items() if s != "complete"),
        }
    return out


def development_ranks(fixture: Any, cutoff: tuple[int, int], paid: str) -> dict[str, Any]:
    """Where each ordering puts the later-paid address among C2 candidates (descriptive)."""
    from cryptoguard.ml import candidate_features as cf

    ranked = cf.rank(fixture, cutoff)
    hit = next((r for r in ranked if r.lookalike == paid.lower()), None)
    return {
        "candidates": len(ranked),
        "paid_present": hit is not None,
        "paid_ranks": None if hit is None else hit.baseline_ranks,
        "label": "development case (outcome known); never used for selection",
    }


def flood_fixture(n_zero: int, n_lookalikes: int) -> Any:
    """Synthetic: a wallet flooded with zero-value native transfers from strangers and
    1-wei transfers from many lookalikes of one reference."""
    from datetime import UTC, datetime

    from cryptoguard.replay.models import RecordedNativeInbound, RecordedTransfer, ReplayFixture
    from cryptoguard.replay.observation import (
        OBSERVATION_V2,
        CategoryCoverage,
        ObservationCoverage,
    )

    wallet = "0x" + "c" * 40
    ref = "0xabcde" + "1" * 30 + "54321"
    counter = iter(range(1, 10**7))

    def h() -> str:
        return "0x" + f"{next(counter):064x}"

    native = [
        RecordedNativeInbound(
            transaction_hash=h(),
            block_number=2_000 + i % 5_000,
            transaction_index=0,
            sender="0x" + f"{i + 1:040x}",
            value="0",
            succeeded=None,
        )
        for i in range(n_zero)
    ]
    native += [
        RecordedNativeInbound(
            transaction_hash=h(),
            block_number=2_000 + i % 5_000,
            transaction_index=1,
            sender="0xabcde" + f"{i:030x}" + "54321",
            value="1",
            succeeded=True,
        )
        for i in range(n_lookalikes)
    ]
    cats = {
        k: CategoryCoverage(status="complete")
        for k in (
            "erc20_transfer_logs",
            "erc20_outgoing_signers",
            "erc721_transfer_logs",
            "wallet_signed_transactions",
            "native_inbound_external",
        )
    }
    return ReplayFixture(
        case_id="synthetic-flood",
        chain_id=1,
        wallet=wallet,
        from_block=1_000,
        to_block=8_000,
        recorded_at=datetime(2026, 11, 9, tzinfo=UTC),
        recorded_with="synthetic",
        rpc_requests=0,
        transfer_scan_complete=True,
        sender_lookups_skipped=0,
        method=["synthetic"],
        wallet_code_hex={"1000": "0x"},
        block_timestamps={},
        transfers=[
            RecordedTransfer(
                token=STABLECOIN_USDT,
                sender=wallet,
                recipient=ref,
                value="5",
                block_number=1_500,
                block_hash=h(),
                transaction_hash=h(),
                transaction_index=0,
                log_index=0,
                tx_sender=wallet,
            )
        ],
        wallet_transactions=[],
        observation=ObservationCoverage(schema_version=OBSERVATION_V2, categories=cats),
        native_inbound=native,
        unattributed_inbound=[],
        nft_transfers=[],
    )


def flood_cost(n_zero: int = 10_000, n_lookalikes: int = 1_000) -> dict[str, Any]:
    import time
    import tracemalloc

    from cryptoguard.ml import candidate_discovery as cd
    from cryptoguard.ml import candidate_features as cf

    fx = flood_fixture(n_zero, n_lookalikes)
    cut = (8_001, 0)
    out: dict[str, Any] = {
        "label": "synthetic",
        "zero_value_strangers": n_zero,
        "lookalikes": n_lookalikes,
    }
    runs: dict[str, Callable[[], Sequence[Any]]] = {
        "C1": lambda: cd.discover(fx, cutoff=cut, variant="C1").candidates,
        "C2": lambda: cd.discover(fx, cutoff=cut, variant="C2").candidates,
        "ranking": lambda: cf.rank(fx, cut),
    }
    for name, fn in runs.items():
        tracemalloc.start()
        t0 = time.perf_counter()
        n = len(fn())
        sec = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        out[name] = {"items": n, "seconds": round(sec, 2), "peak_mib": round(peak / 2**20, 1)}
    return out


def wallet_experiments(poisoning_dir: Path) -> dict[str, Any]:
    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.ml.lookalike_ranking import protected_entities
    from cryptoguard.ml.observation_study import touches_frozen_any
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import ReplayFixture

    blind = protected_entities(poisoning_dir)
    windows: dict[str, Any] = {}
    dev: dict[str, Any] = {}
    robust: dict[str, Any] = {}
    for c in ib.load_new_cases():
        if c.fixture is None:
            continue
        cut = (c.manifest.harm.block_number, 0)
        windows[c.manifest.case_id] = {"population": "P3", **_window_variants(c.fixture, cut)}
        dev[c.manifest.case_id] = development_ranks(c.fixture, cut, c.manifest.harm.recipient)
        robust[c.manifest.case_id] = robustness(c.fixture, cut)
    path = Path("data/ml/research/phase12.4/blind-v2/fixture.json")
    if path.exists():
        fx = ReplayFixture.model_validate_json(path.read_text(encoding="utf-8"))
        cut = (21_890_897, 0)
        paid = "0x804051b0cbc20443943c4f363573ef9bb7793375"
        windows["scamsniffer-blind-v2"] = {"population": "P3", **_window_variants(fx, cut)}
        dev["scamsniffer-blind-v2"] = development_ranks(fx, cut, paid)
        robust["scamsniffer-blind-v2"] = robustness(fx, cut)
    for b in load_background():
        if b.fixture is None or touches_frozen_any(b.fixture, blind):
            continue
        cut = (b.fixture.to_block + 1, 0)
        windows[b.manifest.case_id] = {"population": "P5", **_window_variants(b.fixture, cut)}
    return {
        "windows": windows,
        "development_ranks": dev,
        "robustness": robust,
        "flood": flood_cost(),
    }


# --- entry point ----------------------------------------------------------------------------


def _git() -> str | None:
    import subprocess

    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def main(poisoning_dir: Path, out: Path, rebuild_cache: bool = False) -> dict[str, Any]:
    """Run every Phase 12.5 experiment from local artifacts; write one JSON."""
    import hashlib
    import time

    from cryptoguard.ml import candidate_features as cf
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    t0 = time.perf_counter()
    cache = out / "episodes.jsonl"
    cache_info = None
    if rebuild_cache or not cache.exists():
        cache_info = cache_episodes(poisoning_dir, cache)
    episodes = load_cache(cache)
    timings: dict[str, float] = {}

    def timed(name: str, fn: Callable[[], Any]) -> Any:
        s = time.perf_counter()
        value = fn()
        timings[name] = round(time.perf_counter() - s, 2)
        return value

    proxy = timed("proxy_task", lambda: proxy_task(episodes))
    semantic = timed("semantic_channel", lambda: semantic_channel(episodes))
    mad = timed("mad_recency", lambda: mad_recency_equivalence(episodes))
    wallet = timed("wallet_experiments", lambda: wallet_experiments(poisoning_dir))
    inv = timed("inventory", lambda: inventory(poisoning_dir))
    peak = peak_rss_bytes()
    result: dict[str, Any] = {
        "protocol": "protocol-12.5",
        "git": _git(),
        "versions": {
            "proxy_task": PROXY_TASK,
            "proxy_features": PROXY_FEATURES,
            "candidate_features": cf.FEATURE_VERSION,
            "ranking": cf.RANKING_VERSION,
        },
        "seed": SEED,
        "inputs": {
            "episode_cache_sha256": hashlib.sha256(cache.read_bytes()).hexdigest(),
            "episodes": len(episodes),
            "cache_built_now": cache_info,
        },
        "rpc_requests": 0,
        "proxy_task": proxy,
        "semantic_channel": semantic,
        "mad_recency_equivalence": mad,
        "wallet": wallet,
        "inventory": inv,
        "resources": {
            "seconds": round(time.perf_counter() - t0, 2),
            "steps": timings,
            "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
        },
    }
    result["summary"] = {
        "proxy_test_log_loss": proxy["test_log_loss"],
        "h8_supported": proxy["h8_supported"],
        "logistic_minus_best": proxy["logistic_minus_best_baseline"],
        "semantic_B5_minus_T0_dev": semantic["B5_minus_T0"],
        "mad_equivalence": mad,
        "resources": result["resources"],
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "candidate-research.json").write_text(
        json.dumps(result, indent=1, default=str, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result

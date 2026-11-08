"""Phase 12.6 offline study (protocol 12.6): signer provenance, evidence groups, bounded
summaries, spam resilience, robust proxy features and cost. No RPC; frozen-overlap windows
are never computed on; the 12.5 proxy test split is never used.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from cryptoguard.ml import candidate_discovery as cd
from cryptoguard.ml import candidate_evidence as ce

STUDY_VERSION = "reliability-study/1"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
FAKE = "0x" + "f" * 40
WALLET = "0x" + "c" * 40
REF = "0xabcde" + "1" * 30 + "54321"


def lookalike(i: int, *, prefix: int = 3, suffix: int = 3, ref: str = REF) -> str:
    """A deterministic lookalike of ``ref`` sharing exactly ``prefix`` and ``suffix`` hex."""
    body = ref[2:]
    mid_len = 40 - prefix - suffix
    # the first and last differing characters are fixed (so the shared affix is exact) and
    # the index fills the middle (so different indexes give different addresses)
    first = "f" if body[prefix] != "f" else "e"
    last = "f" if body[39 - suffix] != "f" else "e"
    middle = f"{i:0{mid_len - 2}x}"
    if len(middle) > mid_len - 2:
        raise ValueError("index too large for this affix")
    return "0x" + body[:prefix] + first + middle + last + body[40 - suffix :]


def wallet_fixture(
    *,
    transfers: Sequence[tuple[str, str, int, int, str | None, str, int]] = (),
    native: Sequence[tuple[str, int, int, bool | None]] = (),
    wallet_txs: Sequence[tuple[str, int, int]] = (),
    ref_block: int = 1_100,
    refs_complete: bool = True,
    code: str = "0x",
) -> Any:
    """Synthetic window. The wallet pays REF (wallet-signed, in its signed set) at
    ``ref_block``. ``transfers``: (sender, recipient, value, block, signer, token, tx_index);
    ``native``: (sender, value, block, succeeded); ``wallet_txs``: (to, value, block)."""
    import hashlib

    from cryptoguard.replay.models import (
        RecordedNativeInbound,
        RecordedTransaction,
        RecordedTransfer,
        ReplayFixture,
    )
    from cryptoguard.replay.observation import (
        OBSERVATION_V2,
        CategoryCoverage,
        ObservationCoverage,
    )

    def h(*parts: object) -> str:
        """A content-derived hash: the same record gets the same hash in any fixture."""
        return "0x" + hashlib.sha256(repr(parts).encode()).hexdigest()

    ref_tx = h("ref", ref_block)
    rows = [
        RecordedTransfer(
            token=USDT,
            sender=WALLET,
            recipient=REF,
            value="1000000",
            block_number=ref_block,
            block_hash=h("block", ref_block),
            transaction_hash=ref_tx,
            transaction_index=0,
            log_index=0,
            tx_sender=WALLET,
        )
    ]
    for i, (s, r, v, b, signer, token, idx) in enumerate(transfers):
        rows.append(
            RecordedTransfer(
                token=token,
                sender=s,
                recipient=r,
                value=str(v),
                block_number=b,
                block_hash=h("block", b),
                transaction_hash=h("transfer", s, r, v, b, signer, token, idx),
                transaction_index=idx,
                log_index=i + 1,
                tx_sender=signer,
            )
        )
    txs = [
        RecordedTransaction(
            transaction_hash=ref_tx,
            block_number=ref_block,
            transaction_index=0,
            nonce=0,
            to=USDT,
            value="0",
        )
    ]
    for n, (to, v, b) in enumerate(wallet_txs, start=1):
        txs.append(
            RecordedTransaction(
                transaction_hash=h("wallet-tx", to, v, b, n),
                block_number=b,
                transaction_index=0,
                nonce=n,
                to=to,
                value=str(v),
                succeeded=True,
            )
        )
    nat = [
        RecordedNativeInbound(
            transaction_hash=h("native", s, v, b, ok),
            block_number=b,
            transaction_index=1,
            sender=s,
            value=str(v),
            succeeded=ok,
        )
        for s, v, b, ok in native
    ]
    status = "complete" if refs_complete else "partial"
    cats = {
        k: CategoryCoverage(status="complete")
        for k in (
            "erc20_transfer_logs",
            "erc20_outgoing_signers",
            "erc721_transfer_logs",
            "native_inbound_external",
            "malformed_transfer_logs",
        )
    }
    cats["wallet_signed_transactions"] = CategoryCoverage(status=status)
    return ReplayFixture(
        case_id="synthetic",
        chain_id=1,
        wallet=WALLET,
        from_block=1_000,
        to_block=9_000,
        recorded_at=datetime(2026, 11, 9, tzinfo=UTC),
        recorded_with="synthetic",
        rpc_requests=0,
        transfer_scan_complete=True,
        sender_lookups_skipped=0,
        method=["synthetic"],
        wallet_code_hex={"1000": code},
        block_timestamps={},
        transfers=rows,
        wallet_transactions=txs,
        observation=ObservationCoverage(schema_version=OBSERVATION_V2, categories=cats),
        native_inbound=nat,
        unattributed_inbound=[],
        nft_transfers=[],
    )


END = (9_001, 0)


# --- adversarial scenarios (protocol 12.6 H3) ----------------------------------------------


def scenarios() -> dict[str, tuple[Any, str | None]]:
    """name -> (fixture, the designated high-evidence lookalike or None)."""
    strong = lookalike(0, prefix=5, suffix=5)
    weak = [lookalike(i + 1) for i in range(1_000)]
    refs = [lookalike(i, prefix=0, suffix=0, ref="0x" + f"{i + 7:040x}") for i in range(50)]
    out: dict[str, tuple[Any, str | None]] = {
        "1_zero_value_strangers": (
            wallet_fixture(
                native=[("0x" + f"{i + 1:040x}", 0, 2_000 + i, None) for i in range(1_000)]
            ),
            None,
        ),
        "2_distinct_lookalikes": (
            wallet_fixture(native=[(w, 1, 2_000 + i, True) for i, w in enumerate(weak)]),
            None,
        ),
        "3_repeated_dust_one_lookalike": (
            wallet_fixture(native=[(weak[0], 1, 2_000 + i, True) for i in range(500)]),
            weak[0],
        ),
        "4_many_lookalikes_one_reference_with_one_strong": (
            wallet_fixture(
                native=[(w, 1, 3_000 + i, True) for i, w in enumerate(weak)]
                + [(strong, 1, 2_000, True)]
            ),
            strong,
        ),
        "5_multiple_references": (
            wallet_fixture(
                wallet_txs=[(r, 10**15, 1_200 + i) for i, r in enumerate(refs)],
                native=[(lookalike(i, ref=r), 1, 3_000 + i, True) for i, r in enumerate(refs)],
            ),
            None,
        ),
        "6_fake_token_spam": (
            wallet_fixture(
                transfers=[
                    (w, WALLET, 10**18, 2_000 + i, None, FAKE, 0) for i, w in enumerate(weak)
                ]
            ),
            None,
        ),
        "7_same_block_repeats": (
            wallet_fixture(native=[(w, 1, 2_000, True) for w in weak[:100]]),
            None,
        ),
        "8_unknown_signer_with_complete_signed_set": (
            wallet_fixture(transfers=[(WALLET, strong, 0, 2_000, None, USDT, 0)]),
            strong,
        ),
        "9_missing_receipt": (wallet_fixture(native=[(strong, 1, 2_000, None)]), strong),
        "10_partial_history": (
            wallet_fixture(
                transfers=[(WALLET, strong, 0, 2_000, None, USDT, 0)], refs_complete=False
            ),
            None,
        ),
        "11_one_strong_among_weak": (
            wallet_fixture(
                transfers=[(WALLET, strong, 0, 2_000, "0x" + "a1" * 20, USDT, 0)]
                + [
                    ("0x" + f"{i + 1:040x}", WALLET, 5, 3_000 + i, None, USDT, 0)
                    for i in range(1_000)
                ],
                native=[(w, 1, 4_000 + i, None) for i, w in enumerate(weak)],
            ),
            strong,
        ),
        "12_public_token_reuse": (
            wallet_fixture(
                transfers=[
                    (w, WALLET, 0, 2_000 + i, None, USDT, 0) for i, w in enumerate(weak[:200])
                ]
            ),
            None,
        ),
    }
    return out


def _measure(fn: Callable[[], Any]) -> tuple[Any, float, float]:
    tracemalloc.start()
    t0 = time.perf_counter()
    value = fn()
    sec = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return value, round(sec, 3), round(peak / 2**20, 2)


def run_scenarios(k: int = 10) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, (fx, strong) in scenarios().items():
        res, sec, mib = _measure(partial(ce.build, fx, cutoff=END))
        summary = ce.summarize(res, k)
        again = ce.summarize(ce.build(fx, cutoff=END), k)
        c1 = cd.discover(fx, cutoff=END, variant="C1")
        top = [t["identity"].split(":")[-1] for t in summary["top"]]
        out[name] = {
            "raw_events": res.raw_events,
            "c1_events": len(c1.candidates),
            "groups": len(res.groups),
            "evidence_records": res.evidence_records,
            "summary_shown": summary["shown"],
            "truncated": summary["truncated"],
            "hidden": len(summary["hidden_identities"]),
            "by_level": summary["by_level"],
            "strong_rank": None
            if strong is None
            else next((i + 1 for i, g in enumerate(res.groups) if g.lookalike == strong), None),
            "strong_in_top_k": None if strong is None else strong in top,
            "abstain": res.abstain,
            "deterministic": summary == again,
            "seconds": sec,
            "peak_mib": mib,
            "summary_bytes": len(json.dumps(summary)),
        }
    return out


# --- signer-provenance and masking experiments (H1, H4) -------------------------------------


def rsig_consistency(fixtures: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    agree = disagree = foreign = 0
    for _, f in fixtures:
        w = f.wallet.lower()
        signed = {t.transaction_hash.lower() for t in f.wallet_transactions}
        for t in f.transfers:
            if t.sender.lower() != w or t.tx_sender is None:
                continue
            truth = t.tx_sender.lower() == w
            agree += truth == (t.transaction_hash.lower() in signed)
            disagree += truth != (t.transaction_hash.lower() in signed)
            foreign += not truth
    return {
        "outgoing_with_known_signer": agree + disagree,
        "agree": agree,
        "disagree": disagree,
        "foreign": foreign,
        "windows": len(fixtures),
    }


def _c1_unsafe(
    obs: Sequence[cd.Observation], fixture: Any, cutoff: tuple[int, int], masked: str
) -> int:
    """Claims C1's rules make that need the masked information."""
    n = 0
    chosen: dict[str, dict[str, int]] = {}
    for o in obs:
        if (o.block, o.tx_index) >= cutoff:
            continue
        match = cd._match(o.counterparty, chosen) if o.direction == "in" else None
        methods = cd._methods(o, match[1] if match else None)
        if masked == "token" and "untrusted_token_in" in methods and o.emitter is None:
            n += 1
        if o.direction == "out" and o.wallet_signed is True:
            chosen.setdefault(o.counterparty[-3:], {})[o.counterparty] = o.block
    del fixture
    return n


def masking(fixture: Any, cutoff: tuple[int, int]) -> dict[str, Any]:
    """S0 complete; S1 signer; S2 event sender (outgoing events unattributable);
    S3 receipt; S4 token identity; S5 partial history (signed set incomplete, early half
    of the window lost)."""
    base_obs = cd.observations(fixture)
    s0 = ce.build(fixture, cutoff=cutoff)
    base = {g.lookalike: g.level for g in s0.groups}
    conditions: dict[str, Any] = {
        "S1_signer": (ce.mask(base_obs, "signer"), None, None),
        "S2_event_sender": ([o for o in base_obs if o.direction != "out"], None, None),
        "S3_receipt": (ce.mask(base_obs, "receipt"), None, None),
        "S4_token": (ce.mask(base_obs, "token"), None, None),
    }
    mid = (fixture.from_block + cutoff[0]) // 2
    conditions["S5_partial_history"] = ([o for o in base_obs if o.block >= mid], None, False)
    out: dict[str, Any] = {"S0": {"groups": len(base), "levels": _levels(s0)}}
    for name, (obs, signed, complete) in conditions.items():
        res = ce.build(
            fixture, cutoff=cutoff, observations=obs, signed=signed, wallet_tx_complete=complete
        )
        now = {g.lookalike: g.level for g in res.groups}
        out[name] = {
            "kept": len(base.keys() & now.keys()),
            "lost": len(base.keys() - now.keys()),
            "added": len(now.keys() - base.keys()),
            "level_lowered": sum(
                1
                for k in base.keys() & now.keys()
                if ce.LEVELS.index(now[k]) > ce.LEVELS.index(base[k])
            ),
            "level_raised": sum(
                1
                for k in base.keys() & now.keys()
                if ce.LEVELS.index(now[k]) < ce.LEVELS.index(base[k])
            ),
            "signers_recovered": res.signers_recovered,
            "abstain": res.abstain is not None,
            "unattributable_events": len(base_obs) - len(obs) if name == "S2_event_sender" else 0,
            "c1_unsafe_inferences": _c1_unsafe(obs, fixture, cutoff, name.split("_")[1]),
            "evidence_unsafe_inferences": _evidence_unsafe(res, name),
            "c1_candidates": len(
                {
                    o.counterparty
                    for o in obs
                    if (o.block, o.tx_index) < cutoff and cd._methods(o, None)
                }
            ),
        }
    return out


def _levels(res: ce.EvidenceResult) -> dict[str, int]:
    c: dict[str, int] = {}
    for g in res.groups:
        c[g.level] = c.get(g.level, 0) + 1
    return c


def _evidence_unsafe(res: ce.EvidenceResult, condition: str) -> int:
    """A claim the evidence model makes although its required information was masked."""
    n = 0
    for g in res.groups:
        for r in g.evidence:
            if (
                condition == "S4_token"
                and "untrusted_token_in" in r.mechanisms
                and r.emitter is None
            ):
                n += 1
            if "spoofed_out" in r.mechanisms and r.signer_status == "unknown":
                n += 1
            if r.level == "directly_verified" and r.kind == "native" and r.receipt == "unknown":
                n += 1
    return n


# --- spam stability of orderings (H5) -------------------------------------------------------


def spam_stability(
    fixture: Any, cutoff: tuple[int, int], *, n: int = 1_000, k: int = 10
) -> dict[str, Any]:
    """Inject ``n`` cheap native-dust lookalikes (affix 3+3, latest in the window) into a
    copy of a real window (in memory) and check which orderings keep the real candidates
    in the top-k."""
    from cryptoguard.replay.models import RecordedNativeInbound

    base = ce.build(fixture, cutoff=cutoff)
    real = [g.lookalike for g in base.groups if g.references]
    if not real:
        return {"real_candidates": 0}
    ref = base.groups[0].references[0][0] if base.groups[0].references else real[0]
    last = cutoff[0] - 1
    spam = [
        RecordedNativeInbound(
            transaction_hash="0x" + f"{0xEE00000000 + i:064x}",
            block_number=last - (i % 50),
            transaction_index=0,
            sender=lookalike(i + 1, ref=ref),
            value="1",
            succeeded=True,
        )
        for i in range(n)
    ]
    spammed = fixture.model_copy(
        update={"native_inbound": list(fixture.native_inbound or []) + spam}
    )
    res = ce.build(spammed, cutoff=cutoff)
    groups = list(res.groups)
    orders = {
        "evidence_aware": [g.lookalike for g in groups],
        "recency_only": [
            g.lookalike
            for g in sorted(groups, key=lambda g: (tuple(-x for x in g.last_position), g.lookalike))
        ],
        "similarity_only": [
            g.lookalike for g in sorted(groups, key=lambda g: (-(g.affix or 0), g.lookalike))
        ],
    }
    before = [g.lookalike for g in base.groups if g.lookalike in real]
    out: dict[str, Any] = {"real_candidates": len(real), "spam": n, "k": k}
    for name, order in orders.items():
        kept = [x for x in order[:k] if x in real]
        rel = [x for x in order if x in real]
        out[name] = {"real_in_top_k": len(kept), "kendall_tau_vs_unspammed": _tau(before, rel)}
    return out


def _tau(a: Sequence[str], b: Sequence[str]) -> float | None:
    pos = {x: i for i, x in enumerate(b)}
    items = [x for x in a if x in pos]
    if len(items) < 2:
        return None
    conc = disc = 0
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            same = (pos[items[i]] - pos[items[j]]) * (i - j)
            conc += same > 0
            disc += same < 0
    return round((conc - disc) / (conc + disc), 4) if conc + disc else None


# --- robust proxy features (H6, exploratory, development split only) ------------------------


def robust_proxy_dev(cache: Path) -> dict[str, Any]:
    import math

    from cryptoguard.ml import candidate_research as cr

    episodes = [e for e in cr.load_cache(cache) if e.split == "dev"]  # never the test split
    start: dict[int, int] = {}
    for e in episodes:
        start[e.group] = min(start.get(e.group, e.payoff_block), e.payoff_block)
    ordered = sorted(start, key=lambda g: (start[g], g))
    cut = int(0.7 * len(ordered))
    inner_train = set(ordered[:cut])
    rows = cr.proxy_rows(episodes)
    train = [replace(r, split="dev") for r in rows if r.group in inner_train]
    val = [replace(r, split="test") for r in rows if r.group not in inner_train]
    names = cr.FEATURE_NAMES

    def robust(r: cr.ProxyRow) -> cr.ProxyRow:
        f = list(r.features)
        for i, name in enumerate(names):
            if name.startswith("count_") or name == "distinct_lookalikes":
                f[i] = math.log1p(f[i])
        return replace(r, features=tuple(f))

    probs = cr.baseline_probs(train, val)
    probs["logistic_raw"] = cr.logistic_probs(train, val)
    probs["logistic_robust"] = cr.logistic_probs(
        [robust(r) for r in train], [robust(r) for r in val]
    )
    losses = {k: cr.log_losses(v, val) for k, v in probs.items()}

    def quant(xs: list[int]) -> list[int]:
        s = sorted(xs)
        return [s[int(q * (len(s) - 1))] for q in (0.5, 0.9, 0.99)]

    return {
        "label": "exploratory: 12.1 development split only, internal temporal sub-split",
        "rows": {"inner_train": len(train), "inner_validation": len(val)},
        "groups": {"inner_train": len(inner_train), "inner_validation": len(ordered) - cut},
        "prefix_len_p50_p90_p99": {
            "inner_train": quant([len(r.prefix) for r in train]),
            "inner_validation": quant([len(r.prefix) for r in val]),
        },
        "log_loss": {k: round(sum(v) / len(v), 5) for k, v in losses.items()},
        "macro_f1": {k: cr.macro_f1(v, val)["macro_f1"] for k, v in probs.items()},
        "top_class_ece": {k: _ece(v, val) for k, v in probs.items()},
        "robust_minus_raw": cr.group_bootstrap_diff(
            losses["logistic_robust"], losses["logistic_raw"], [r.group for r in val]
        ),
    }


def _ece(probs: Sequence[dict[str, float]], rows: Sequence[Any], bins: int = 10) -> float:
    b: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for p, r in zip(probs, rows, strict=True):
        c = max(p, key=lambda x: p[x])
        conf = p[c]
        b[min(bins - 1, int(conf * bins))].append((conf, c == r.target))
    n = len(rows)
    return round(
        sum(
            abs(sum(x for x, _ in xs) / len(xs) - sum(y for _, y in xs) / len(xs)) * len(xs) / n
            for xs in b
            if xs
        ),
        5,
    )


# --- cost (H7) ------------------------------------------------------------------------------


def scaling(sizes: Sequence[int] = (10, 100, 1_000, 10_000)) -> list[dict[str, Any]]:
    out = []
    for n in sizes:
        fx = wallet_fixture(
            native=[(lookalike(i + 1), 1, 2_000 + i % 6_000, True) for i in range(n)]
        )
        res, sec, mib = _measure(partial(ce.build, fx, cutoff=END))
        summary, s_sec, _ = _measure(partial(ce.summarize, res, 10))
        out.append(
            {
                "candidates": n,
                "groups": len(res.groups),
                "evidence_records": res.evidence_records,
                "build_seconds": sec,
                "summary_seconds": s_sec,
                "peak_mib": mib,
                "summary_bytes": len(json.dumps(summary)),
                "full_result_bytes": len(ce.to_json(res)),
                "groups_per_second": round(len(res.groups) / sec) if sec else None,
            }
        )
    return out


# --- entry point ----------------------------------------------------------------------------


def eligible_windows(poisoning_dir: Path) -> list[tuple[str, Any, tuple[int, int]]]:
    from cryptoguard.ml import incident_benchmark as ib
    from cryptoguard.ml.lookalike_ranking import protected_entities
    from cryptoguard.ml.observation_study import touches_frozen_any
    from cryptoguard.replay.background import load_background
    from cryptoguard.replay.models import ReplayFixture

    blind = protected_entities(poisoning_dir)
    out = [
        (c.manifest.case_id, c.fixture, (c.manifest.harm.block_number, 0))
        for c in ib.load_new_cases()
        if c.fixture is not None
    ]
    path = Path("data/ml/research/phase12.4/blind-v2/fixture.json")
    if path.exists():
        out.append(
            (
                "scamsniffer-blind-v2",
                ReplayFixture.model_validate_json(path.read_text(encoding="utf-8")),
                (21_890_897, 0),
            )
        )
    for b in load_background():
        if b.fixture is not None and not touches_frozen_any(b.fixture, blind):
            out.append((b.manifest.case_id, b.fixture, (b.fixture.to_block + 1, 0)))
    return out


def main(poisoning_dir: Path, out: Path, cache: Path) -> dict[str, Any]:
    import subprocess

    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    t0 = time.perf_counter()
    windows = eligible_windows(poisoning_dir)
    dedup = {}
    masks = {}
    for name, fx, cut in windows:
        res = ce.build(fx, cutoff=cut)
        dedup[name] = {
            "raw_events": res.raw_events,
            "c1_events": len(cd.discover(fx, cutoff=cut, variant="C1").candidates),
            "c2_candidates": len(cd.discover(fx, cutoff=cut, variant="C2").candidates),
            "groups": len(res.groups),
            "evidence_records": res.evidence_records,
            "levels": _levels(res),
            "abstain": res.abstain,
        }
        if res.groups:
            masks[name] = masking(fx, cut)
    spam = {
        n: spam_stability(fx, cut)
        for n, fx, cut in windows
        if n.startswith(("usdt", "scamsniffer-blind"))
    }
    try:
        git = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        git = None
    result: dict[str, Any] = {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.6",
        "evidence_version": ce.EVIDENCE_VERSION,
        "git": git,
        "rpc_requests": 0,
        "rsig_consistency": rsig_consistency([(n, fx) for n, fx, _ in windows]),
        "deduplication": dedup,
        "masking": masks,
        "scenarios": run_scenarios(),
        "spam_stability": spam,
        "robust_proxy_dev": robust_proxy_dev(cache) if cache.exists() else "episode cache missing",
        "scaling": scaling(),
    }
    peak = peak_rss_bytes()
    result["resources"] = {
        "seconds": round(time.perf_counter() - t0, 2),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "reliability-study.json").write_text(
        json.dumps(result, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result

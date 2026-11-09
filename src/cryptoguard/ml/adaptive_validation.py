"""Phase 12.7.1: debiased synthetic validation of the frozen 12.7 selectors and a bounded
adaptive attacker (protocol 12.7.1). Research only; no RPC; nothing reaches the detector.

The generator is independent of the 12.7 benchmark. It builds candidate groups directly
(the same ``CandidateGroup`` records ``candidate_evidence.build`` produces; a fidelity check
rebuilds a sample through real fixtures) from uniformly random addresses with a designed
affix to a designated victim reference, assigns each candidate's reference with the
pipeline's own ``_match`` rule, and shuffles the population. The oracle target is drawn
by the family's rule and kept outside the groups: no selector can see it, and nothing about
its address, position in the list, age, mechanism or reference is systematically special
unless a family varies that factor on purpose, in which case the factor is balanced.

Categories are kept apart in the output: ``E2`` (the sealed primary benchmark), ``E3``
(adaptive attacker and counterexamples, exploratory), ``E4`` (the two known incidents,
regression only). ``E1`` (the 12.7 grid) is not rerun here.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
import tracemalloc
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from typing import Any

from cryptoguard.ml import adversarial_ranking as ar
from cryptoguard.ml import candidate_evidence as ce

STUDY_VERSION = "adaptive-ranking-validation/1"
MASTER = "cg-12.7.1"  # seed namespace, fixed in the protocol
WALLET = "0x" + "c" * 40

# The frozen algorithms (protocol 12.7.1 section 3): the evaluation refuses to run if the
# selector module or a configuration differs from these.
FROZEN_SOURCE = "src/cryptoguard/ml/adversarial_ranking.py"
FROZEN_SOURCE_SHA256 = "2c0e65aec71c9b20c422594452e3e338fc6986ba05c8ba3f5bc1302a8892ff1a"
FROZEN_REVISION = "0968ff8"
PUBLIC_SEED = 0
FROZEN_SELECTORS: dict[str, ar.Selector] = {
    "B0": ar.Selector("B0"),
    "B1": ar.Selector("B1"),
    "B2_oldest": ar.Selector("revrec"),
    "B3": ar.Selector("B3"),
    "B4": ar.Selector("B4"),
    "B6": ar.Selector("B6", seed=PUBLIC_SEED),
    "B7_P1": ar.Selector("P1", seed=PUBLIC_SEED),
    "B8_P1b": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True),
    # ablations of P1b
    "A_lam_inf": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True, lam=math.inf),
    "A_lam2": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True, lam=2.0),
    "A_lam8": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True, lam=8.0),
    "A_nosim": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True, nosim=True),
    "A_recency_ties": ar.Selector("P1", seed=PUBLIC_SEED, bucket_tie=True, tie="recency"),
    "NC_group_rotation": ar.Selector(
        "P1", seed=PUBLIC_SEED, bucket_tie=True, lam=math.inf, nosim=True
    ),
}
FROZEN_CONFIG_HASHES = {
    "B0": "7ecd8843cf738bec",
    "B1": "944418279feaaeb2",
    "B4": "2bf989929000f1e6",
    "B6": "93cdbe0b57c2958b",
    "B7_P1": "66b77df10d259828",
    "B8_P1b": "8b3795e363aad678",
}

MECHS = ("native_dust", "fake_token_in", "zero_value_in", "spoofed_out")
_MECH = {
    "native_dust": (("lookalike_in",), "native", "directly_verified"),
    "fake_token_in": (("lookalike_in", "untrusted_token_in"), "erc20", "supported"),
    "zero_value_in": (("lookalike_in", "zero_value_in"), "erc20", "supported"),
    "spoofed_out": (("spoofed_out",), "erc20", "directly_verified"),
}
AGE_RELATIONS = (
    "target_oldest",
    "target_newest",
    "target_intermediate",
    "target_random",
    "same_block",
    "decoys_precede",
    "decoys_follow",
    "overlap",
)
MECH_RELATIONS = ("same", "different", "mixed_independent", "target_unique", "majority_same")
FAMILIES = (
    "F1_target_stronger",
    "F2_equal_other_groups",
    "F3_equal_own_group",
    "F4_equal_uniform",
    "F5_target_weaker",
    "F6_exchangeable_null",
    "F7_same_total_split",
    "F8_reference_overlap",
    "F9_several_relevant",
    "F10_equal_leaders",
)
CONTROL_FAMILIES = ("F6_exchangeable_null",)
PRIMARY_FAMILIES = tuple(f for f in FAMILIES if f not in CONTROL_FAMILIES)
G_GRID = (1, 2, 5, 10, 25)
M_GRID = (0, 10, 100, 1_000, 10_000)
K_GRID = (1, 3, 5, 10, 20, 50)
SEEDS_PER_M = {0: 40, 10: 40, 100: 40, 1_000: 16, 10_000: 8}
N_BACKGROUND = 5
N_UNREFERENCED = 2
LO, HI = 2_000, 8_999  # planting blocks; the cutoff is (9_001, 0)


# --- frozen-algorithm verification ----------------------------------------------------------


def verify_frozen(root: Path = Path()) -> dict[str, Any]:
    """Refuse to evaluate anything but the frozen selector module and configurations."""
    src = (root / FROZEN_SOURCE).read_bytes().replace(b"\r\n", b"\n")
    digest = hashlib.sha256(src).hexdigest()
    hashes = {k: ar.config_hash(FROZEN_SELECTORS[k]) for k in FROZEN_CONFIG_HASHES}
    ok = digest == FROZEN_SOURCE_SHA256 and hashes == FROZEN_CONFIG_HASHES
    if not ok:
        raise RuntimeError(f"frozen selectors changed: {digest} {hashes}")
    return {"source_sha256": digest, "config_hashes": hashes, "revision": FROZEN_REVISION}


# --- scenario generation --------------------------------------------------------------------


@dataclass(frozen=True)
class Spec:
    family: str
    groups: int  # G: number of genuine victim references
    m: int  # attacker decoys
    rep: int  # replicate index within the template
    age: str
    mech: str

    @property
    def template(self) -> tuple[str, int, int]:
        return (self.family, self.groups, self.m)

    @property
    def key(self) -> str:
        return f"{self.family}|{self.groups}|{self.m}|{self.rep}"


@dataclass
class Scenario:
    spec: Spec
    groups: list[ce.CandidateGroup]  # shuffled; carries no target information
    relevant: tuple[str, ...]  # oracle (lookalike addresses), never given to a selector
    attacker: frozenset[str]  # decoy addresses (for displacement), never given to a selector
    references: tuple[str, ...]
    meta: dict[str, Any] = field(default_factory=dict)


def specs() -> list[Spec]:
    """The sealed design: every family x G x m, with the replicate count fixed per m. Age
    and mechanism relations rotate across replicates so each template is balanced."""
    out = []
    for fam in FAMILIES:
        for gi, g in enumerate(G_GRID):
            for mi, m in enumerate(M_GRID):
                for r in range(SEEDS_PER_M[m]):
                    age = AGE_RELATIONS[(r + gi + mi) % len(AGE_RELATIONS)]
                    mech = MECH_RELATIONS[(r // len(AGE_RELATIONS) + r + gi) % len(MECH_RELATIONS)]
                    out.append(Spec(fam, g, m, r, age, mech))
    return out


def _rng(*parts: object) -> random.Random:
    seed = int(hashlib.sha256("|".join(map(str, (MASTER, *parts))).encode()).hexdigest()[:16], 16)
    return random.Random(seed)  # noqa: S311 - reproducible simulation, not security


def _hex(rng: random.Random, n: int) -> str:
    return f"{rng.getrandbits(4 * n):0{n}x}" if n else ""


def _other(rng: random.Random, c: str) -> str:
    x = c
    while x == c:
        x = "0123456789abcdef"[rng.randrange(16)]
    return x


def lookalike_of(rng: random.Random, ref: str, p: int, s: int) -> str:
    """A uniformly random address sharing exactly ``p`` leading and ``s`` trailing hex
    characters with ``ref``."""
    body = ref[2:]
    mid = 40 - p - s - 2
    return (
        "0x"
        + body[:p]
        + _other(rng, body[p])
        + _hex(rng, mid)
        + _other(rng, body[39 - s])
        + body[40 - s :]
    )


def split(rng: random.Random, total: int, avoid: tuple[int, int] | None = None) -> tuple[int, int]:
    """A (prefix, suffix) with prefix + suffix = total and suffix >= 3 (the pipeline's rule),
    uniformly over the allowed splits, avoiding ``avoid`` when another split exists."""
    options = [(total - s, s) for s in range(3, total + 1)]
    if avoid in options and len(options) > 1:
        options.remove(avoid)
    return options[rng.randrange(len(options))]


def _references(rng: random.Random, g: int, overlap: bool) -> list[str]:
    refs = ["0x" + _hex(rng, 40) for _ in range(g)]
    if overlap:  # pairs share exactly a 3-character prefix and suffix
        for i in range(1, g, 2):
            a = refs[i - 1][2:]
            refs[i] = "0x" + a[:3] + _other(rng, a[3]) + _hex(rng, 32) + _other(rng, a[36]) + a[37:]
    return refs


def _tier_iid(rng: random.Random) -> int:
    return rng.choices((6, 7, 8, 9), weights=(4, 3, 2, 1))[0]


@dataclass
class _Cand:
    address: str
    designed_ref: str | None
    mech: str
    block: int
    tx: int
    role: str  # "target" | "decoy" | "background" | "unreferenced" (generator only)


def _times(
    rng: random.Random, age: str, n_dec: int, n_other: int
) -> tuple[list[int], list[int], list[int]]:
    """(target blocks, decoy blocks, background blocks) for one relation."""

    def u(a: int, b: int, k: int) -> list[int]:
        return [rng.randint(a, b) for _ in range(k)]

    if age == "target_oldest":
        return [LO], u(LO + 1, HI, n_dec), u(LO + 1, HI, n_other)
    if age == "target_newest":
        return [HI], u(LO, HI - 1, n_dec), u(LO, HI - 1, n_other)
    if age == "target_intermediate":
        dec, oth = u(LO, HI, n_dec), u(LO, HI, n_other)
        allb = sorted(dec + oth)
        mid = allb[len(allb) // 2] if allb else (LO + HI) // 2
        return [mid], dec, oth
    if age == "target_random":
        return u(LO, HI, 1), u(LO, HI, n_dec), u(LO, HI, n_other)
    if age == "same_block":
        b = (LO + HI) // 2
        return [b], [b] * n_dec, [b] * n_other
    if age == "decoys_precede":
        t = rng.randint(6_000, HI)
        return [t], u(LO, t - 1, n_dec), u(LO, HI, n_other)
    if age == "decoys_follow":
        t = rng.randint(LO, 5_000)
        return [t], u(t + 1, HI, n_dec), u(LO, HI, n_other)
    if age == "overlap":
        t = rng.randint(4_000, 7_000)
        return [t], u(t - 1_000, t + 1_000, n_dec), u(LO, HI, n_other)
    raise ValueError(age)


def _mechs(
    rng: random.Random, rel: str, target: str, n_dec: int, n_bg: int
) -> tuple[list[str], list[str]]:
    others = [x for x in MECHS if x != target]
    if rel == "same":
        dec = [target] * n_dec
    elif rel == "different":
        d = others[rng.randrange(3)]
        dec = [d] * n_dec
    elif rel == "mixed_independent":
        dec = [MECHS[rng.randrange(4)] for _ in range(n_dec)]
    elif rel == "target_unique":
        dec = [others[rng.randrange(3)] for _ in range(n_dec)]
    elif rel == "majority_same":
        dec = [target if rng.random() < 0.8 else others[rng.randrange(3)] for _ in range(n_dec)]
    else:
        raise ValueError(rel)
    pool = others if rel == "target_unique" else list(MECHS)
    bg = [pool[rng.randrange(len(pool))] for _ in range(n_bg)]
    return dec, bg


def generate(spec: Spec) -> Scenario:
    rng = _rng("scenario", spec.key)
    fam, g, m = spec.family, spec.groups, spec.m
    refs = _references(rng, g, overlap=fam == "F8_reference_overlap")
    t_idx = rng.randrange(g)
    t_ref = refs[t_idx]
    others = [r for i, r in enumerate(refs) if i != t_idx] or [t_ref]
    # F8: the reference sharing a 3+3 affix with the target's (its overlap partner)
    p_idx = t_idx + 1 if t_idx % 2 == 0 else t_idx - 1
    partner = refs[p_idx] if 0 <= p_idx < g else others[0]
    cands: list[_Cand] = []
    meta_rel: dict[str, Any]
    if fam == "F6_exchangeable_null":
        # every candidate i.i.d.; the target is a uniformly drawn member (a null family)
        n = m + 1
        blocks = [rng.randint(LO, HI) for _ in range(n)]
        for i in range(n):
            ref = refs[rng.randrange(g)]
            p, s = split(rng, _tier_iid(rng))
            cands.append(
                _Cand(
                    lookalike_of(rng, ref, p, s),
                    ref,
                    MECHS[rng.randrange(4)],
                    blocks[i],
                    rng.randrange(200),
                    "decoy",
                )
            )
        pick = rng.randrange(n)
        cands[pick].role = "target"
        meta_rel = {"age": "exchangeable", "mech": "exchangeable"}
    else:
        n_targets = 3 if fam == "F9_several_relevant" else 1
        if fam in ("F1_target_stronger", "F10_equal_leaders"):
            t_tier = rng.choice((7, 8, 9))
        else:
            t_tier = rng.choice((6, 7, 8))
        t_mech = MECHS[rng.randrange(4)]
        n_leaders = (g - 1) if fam == "F10_equal_leaders" else 0
        dec_mechs, bg_mechs = _mechs(rng, spec.mech, t_mech, m + n_leaders, N_BACKGROUND)
        t_blocks, d_blocks, o_blocks = _times(
            rng, spec.age, m + n_leaders, N_BACKGROUND + N_UNREFERENCED
        )
        # target(s)
        t_refs = [t_ref]
        if n_targets == 3:
            t_refs += rng.sample(others, 2) if g >= 3 else [t_ref, t_ref]
        t_split = split(rng, t_tier)
        for j, r in enumerate(t_refs):
            ps = t_split if j == 0 else split(rng, t_tier)
            blk = (
                t_blocks[0]
                if j == 0
                else (t_blocks[0] if spec.age == "same_block" else rng.randint(LO, HI))
            )
            cands.append(
                _Cand(lookalike_of(rng, r, *ps), r, t_mech, blk, rng.randrange(200), "target")
            )
        # decoys (and F10's equal-strength leaders, attacker-placed one per other reference)
        for i in range(m + n_leaders):
            if fam == "F10_equal_leaders" and i < n_leaders:
                ref, tier, ps_avoid = others[i], t_tier, None
            else:
                if fam == "F8_reference_overlap":
                    ref = partner
                elif fam == "F2_equal_other_groups":
                    ref = others[rng.randrange(len(others))]
                elif fam == "F3_equal_own_group":
                    ref = t_ref
                else:
                    ref = refs[rng.randrange(g)]
                if fam == "F1_target_stronger":
                    tier = rng.randint(6, t_tier - 1)
                elif fam == "F5_target_weaker":
                    tier = rng.randint(t_tier + 1, t_tier + 2)
                elif fam == "F10_equal_leaders":
                    tier = t_tier - 1
                else:
                    tier = t_tier
                ps_avoid = t_split if fam == "F7_same_total_split" else None
            ps = split(rng, tier, ps_avoid)
            cands.append(
                _Cand(
                    lookalike_of(rng, ref, *ps),
                    ref,
                    dec_mechs[i],
                    d_blocks[i],
                    rng.randrange(200),
                    "decoy",
                )
            )
        meta_rel = {
            "age": spec.age,
            "mech": spec.mech,
            "target_tier": t_tier,
            "target_mech": t_mech,
        }
        # background: other campaigns' lookalikes (i.i.d.) and unreferenced strangers
        for i in range(N_BACKGROUND):
            ref = refs[rng.randrange(g)]
            ps = split(rng, _tier_iid(rng))
            cands.append(
                _Cand(
                    lookalike_of(rng, ref, *ps),
                    ref,
                    bg_mechs[i],
                    o_blocks[i],
                    rng.randrange(200),
                    "background",
                )
            )
        for i in range(N_UNREFERENCED):
            cands.append(
                _Cand(
                    "0x" + _hex(rng, 40),
                    None,
                    "zero_value_in",
                    o_blocks[N_BACKGROUND + i],
                    rng.randrange(200),
                    "unreferenced",
                )
            )
    groups, relevant, attacker = _groups(cands, refs)
    rng.shuffle(groups)
    meta = {**meta_rel, "target_ref_index": t_idx, "references": g}
    return Scenario(spec, groups, relevant, attacker, tuple(refs), meta)


def _groups(
    cands: list[_Cand], refs: Sequence[str]
) -> tuple[list[ce.CandidateGroup], tuple[str, ...], frozenset[str]]:
    chosen: dict[str, dict[str, int]] = {}
    for r in refs:
        chosen.setdefault(r[-3:], {})[r] = 0
    seen: set[str] = {r.lower() for r in refs}
    out: list[ce.CandidateGroup] = []
    relevant: list[str] = []
    attacker: set[str] = set()
    for i, c in enumerate(cands):
        a = c.address.lower()
        if a in seen:
            continue
        seen.add(a)
        match = ce._match(a, chosen)
        out.append(make_group(a, match, c.mech, (c.block, c.tx, i)))
        if c.role == "target":
            relevant.append(a)
        elif c.role == "decoy":
            attacker.add(a)
    return out, tuple(relevant), frozenset(attacker)


def make_group(
    address: str, match: tuple[str, tuple[int, int]] | None, mech: str, pos: tuple[int, int, int]
) -> ce.CandidateGroup:
    """One single-record candidate group, exactly as ``build`` would form it."""
    mechanisms, kind, level = _MECH[mech]
    if match is None:  # no reference: only a zero-value event is evidence without one
        mechanisms, kind, level = ("zero_value_in",), "erc20", "partially_supported"
    refs = ((match[0], match[1][0], match[1][1]),) if match else ()
    rec = ce.EvidenceRecord(
        identity=f"tx:0x{hashlib.sha256(f'{address}:{pos}'.encode()).hexdigest()}:{pos[2]}",
        kind=kind,
        direction="out" if mech == "spoofed_out" else "in",
        block=pos[0],
        tx_index=pos[1],
        log_index=pos[2],
        mechanisms=mechanisms,
        level=level,
        signer_status="foreign_known" if mech == "spoofed_out" else "lookalike_itself",
        signer=None,
        authorization="not_required" if mech == "spoofed_out" else "not_applicable",
        event_sender=WALLET if mech == "spoofed_out" else address,
        event_recipient=address if mech == "spoofed_out" else WALLET,
        emitter=None,
        receipt="implied_by_log" if kind == "erc20" else "succeeded",
        value_zero=mech in ("spoofed_out", "zero_value_in"),
        missing=(),
    )
    return ce.CandidateGroup(
        identity=f"1:{WALLET}:{address}",
        chain_id=1,
        victim=WALLET,
        lookalike=address,
        references=refs,
        mechanisms=tuple(sorted(mechanisms)),
        kinds=(kind,),
        level=level,
        affix=(match[1][0] + match[1][1]) if match else None,
        first_position=pos,
        last_position=pos,
        evidence=(rec,),
        missing=(),
    )


def scenario_hash(sc: Scenario) -> str:
    rows = sorted(
        (g.lookalike, list(g.references), list(g.mechanisms), list(g.last_position))
        for g in sc.groups
    )
    payload = {
        "spec": sc.spec.key,
        "age": sc.spec.age,
        "mech": sc.spec.mech,
        "rows": rows,
        "relevant": sorted(sc.relevant),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def manifest(spec_list: Sequence[Spec] | None = None) -> dict[str, Any]:
    """The sealed manifest: per-family and overall hashes of every generated scenario."""
    spec_list = list(spec_list or specs())
    per_family: dict[str, hashlib._Hash] = {}
    overall = hashlib.sha256()
    counts: dict[str, int] = {}
    candidates = 0
    for sp in spec_list:
        sc = generate(sp)
        h = scenario_hash(sc)
        overall.update(h.encode())
        per_family.setdefault(sp.family, hashlib.sha256()).update(h.encode())
        counts[sp.family] = counts.get(sp.family, 0) + 1
        candidates += len(sc.groups)
    return {
        "scenarios": len(spec_list),
        "candidates": candidates,
        "per_family_count": counts,
        "per_family_sha256": {k: v.hexdigest() for k, v in per_family.items()},
        "sha256": overall.hexdigest(),
    }


# --- methods --------------------------------------------------------------------------------

Order = Callable[[Sequence[ce.CandidateGroup], Spec], list[ce.CandidateGroup]]


def _frozen(name: str) -> Order:
    sel = FROZEN_SELECTORS[name]
    return lambda gs, _sp: ar.order(gs, sel)


def _local(key: Callable[[ce.CandidateGroup, Spec], Any]) -> Order:
    def run(gs: Sequence[ce.CandidateGroup], sp: Spec) -> list[ce.CandidateGroup]:
        return sorted(gs, key=lambda g: key(g, sp))

    return run


def _b9(gs: Sequence[ce.CandidateGroup], sp: Spec) -> list[ce.CandidateGroup]:
    rng = _rng("B9", sp.key)  # a fixed, per-scenario randomized tie-break, declared seed
    noise = {g.lookalike: rng.random() for g in sorted(gs, key=lambda g: g.lookalike)}
    return sorted(gs, key=lambda g: (-ar.bits(g), noise[g.lookalike]))


def _random(gs: Sequence[ce.CandidateGroup], sp: Spec) -> list[ce.CandidateGroup]:
    out = sorted(gs, key=lambda g: g.lookalike)
    _rng("NC_random", sp.key).shuffle(out)
    return out


def _pure_similarity_key(g: ce.CandidateGroup, _sp: Spec) -> tuple[int, str]:
    return (-ar.bits(g), g.lookalike)


def _newest_key(g: ce.CandidateGroup, _sp: Spec) -> tuple[tuple[int, int, int], str]:
    return ((-g.last_position[0], -g.last_position[1], -g.last_position[2]), g.lookalike)


def _hash_key(g: ce.CandidateGroup, _sp: Spec) -> tuple[int, str]:
    return (ar.keyed(PUBLIC_SEED, g.lookalike), g.lookalike)


METHODS: dict[str, Order] = {
    **{n: _frozen(n) for n in FROZEN_SELECTORS},
    "B5_pure_similarity": _local(_pure_similarity_key),
    "B9_random_ties": _b9,
    "NC_newest": _local(_newest_key),
    "NC_random": _random,
    "NC_hash_order": _local(_hash_key),
}
SIMPLE_BASELINES = ("B4", "B5_pure_similarity", "B6", "B9_random_ties")


# --- evaluation -----------------------------------------------------------------------------


def _ranks(
    ordered: Sequence[ce.CandidateGroup], targets: Sequence[str]
) -> tuple[list[int], list[int]]:
    pos = {g.lookalike: i + 1 for i, g in enumerate(ordered)}
    bucket_first: dict[str, int] = {}
    for i, g in enumerate(ordered):
        bucket_first.setdefault(ce.bucket_of(g), i + 1)
    by_look = {g.lookalike: g for g in ordered}
    return [pos[t] for t in targets], [bucket_first[ce.bucket_of(by_look[t])] for t in targets]


def evaluate(sc: Scenario) -> dict[str, Any]:
    """Ranks of each relevant candidate and of its reference bucket, for every method; plus
    a pseudo-target (a random non-relevant referenced candidate) and the clean ranks."""
    out: dict[str, Any] = {"methods": {}}
    pick_rng = _rng("pseudo", sc.spec.key)
    pool = sorted(g.lookalike for g in sc.groups if g.references and g.lookalike not in sc.relevant)
    pseudo = pool[pick_rng.randrange(len(pool))] if pool else None
    clean = [g for g in sc.groups if g.lookalike not in sc.attacker]
    for name, run in METHODS.items():
        ordered = run(sc.groups, sc.spec)
        if len(ordered) != len(sc.groups):
            raise AssertionError("not a permutation")
        ranks, bfirst = _ranks(ordered, sc.relevant)
        row: dict[str, Any] = {"r": ranks, "b": bfirst}
        if pseudo is not None and name in ("B0", "B8_P1b", "NC_random"):
            row["pseudo"] = _ranks(ordered, [pseudo])[0][0]
        if name in ("B0", "B8_P1b") and sc.spec.m:
            row["clean"] = _ranks(run(clean, sc.spec), sc.relevant)[0]
        out["methods"][name] = row
    return out


def _exposure(ranks: Sequence[int], k: int) -> float:
    return sum(1 for r in ranks if r <= k) / len(ranks)


def score(row: dict[str, Any], what: str = "r") -> float:
    """Mean over the K grid of mean Exposure@K over the relevant candidates."""
    return sum(_exposure(row[what], k) for k in K_GRID) / len(K_GRID)


def diagnostics(sc: Scenario) -> dict[str, Any]:
    """Generator neutrality diagnostics for the first relevant candidate (no method)."""
    t = sc.relevant[0]
    gs = sc.groups
    by = {g.lookalike: g for g in gs}
    tg = by[t]
    order_time = sorted(gs, key=lambda g: (g.last_position, g.lookalike))
    n = len(gs)
    age_pct = order_time.index(tg) / (n - 1) if n > 1 else 0.5
    addr_pct = sorted(g.lookalike for g in gs).index(t) / (n - 1) if n > 1 else 0.5
    list_pct = [g.lookalike for g in gs].index(t) / (n - 1) if n > 1 else 0.5
    sizes: dict[str, int] = {}
    for g in gs:
        sizes[ce.bucket_of(g)] = sizes.get(ce.bucket_of(g), 0) + 1
    tb = ce.bucket_of(tg)
    ref_buckets = sorted(b for b in sizes if not b.startswith("mech:"))
    mech_counts: dict[tuple[str, ...], int] = {}
    for g in gs:
        mech_counts[g.mechanisms] = mech_counts.get(g.mechanisms, 0) + 1
    return {
        "age_pct": age_pct,
        "oldest": order_time[0].lookalike == t,
        "newest": order_time[-1].lookalike == t,
        "address_pct": addr_pct,
        "list_pct": list_pct,
        "ref_sorted_pct": ref_buckets.index(tb) / (len(ref_buckets) - 1)
        if len(ref_buckets) > 1 and tb in ref_buckets
        else None,
        "largest_group": len(ref_buckets) > 1 and sizes[tb] == max(sizes[b] for b in ref_buckets),
        "smallest_group": len(ref_buckets) > 1 and sizes[tb] == min(sizes[b] for b in ref_buckets),
        "mech_unique": mech_counts[tg.mechanisms] == 1,
        "bits": ar.bits(tg),
        "bits_pct_strict_above": sum(1 for g in gs if ar.bits(g) > ar.bits(tg)) / n,
    }


def iterate(spec_list: Sequence[Spec]) -> Iterator[tuple[Spec, Scenario, dict[str, Any]]]:
    for sp in spec_list:
        sc = generate(sp)
        yield sp, sc, evaluate(sc)


# --- aggregation and uncertainty ------------------------------------------------------------


def aggregate(
    rows: Sequence[dict[str, Any]],
    method: str,
    what: str = "r",
    subset: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Equal weight by template within a family, equal weight by family across families."""
    fam_t: dict[str, dict[tuple[int, int], list[float]]] = {}
    for row in rows:
        if subset is not None and not subset(row):
            continue
        fam_t.setdefault(row["family"], {}).setdefault((row["G"], row["m"]), []).append(
            score(row["methods"][method], what)
        )
    fam = {f: sum(sum(v) / len(v) for v in t.values()) / len(t) for f, t in fam_t.items()}
    prim = [fam[f] for f in PRIMARY_FAMILIES if f in fam]
    return {
        "family": {k: round(v, 4) for k, v in fam.items()},
        "primary_mean": round(sum(prim) / len(prim), 4) if prim else None,
    }


def paired(
    rows: Sequence[dict[str, Any]],
    a: str,
    b: str,
    *,
    what: str = "r",
    subset: Callable[[dict[str, Any]], bool] | None = None,
    n_boot: int = 2_000,
) -> dict[str, Any]:
    """Mean paired difference a - b (equal family, equal template), with a stratified
    template-cluster bootstrap: templates are resampled within each family."""
    import numpy as np

    fam_t: dict[str, dict[tuple[int, int], list[float]]] = {}
    for row in rows:
        if row["family"] not in PRIMARY_FAMILIES or (subset is not None and not subset(row)):
            continue
        d = score(row["methods"][a], what) - score(row["methods"][b], what)
        fam_t.setdefault(row["family"], {}).setdefault((row["G"], row["m"]), []).append(d)
    fams = sorted(fam_t)
    tmeans = {f: np.array([sum(v) / len(v) for v in fam_t[f].values()]) for f in fams}
    fam_mean = {f: float(tmeans[f].mean()) for f in fams}
    est = float(np.mean([fam_mean[f] for f in fams])) if fams else float("nan")
    rng = np.random.default_rng(20261109)
    boots = np.empty(n_boot)
    for i in range(n_boot):
        boots[i] = np.mean(
            [tmeans[f][rng.integers(0, len(tmeans[f]), len(tmeans[f]))].mean() for f in fams]
        )
    lo, hi = np.percentile(boots, [2.5, 97.5]) if fams else (float("nan"), float("nan"))
    per_m: dict[int, list[float]] = {}
    for f in fams:
        for (_g, m), v in fam_t[f].items():
            per_m.setdefault(m, []).append(sum(v) / len(v))
    return {
        "mean": round(est, 4),
        "ci95": [round(float(lo), 4), round(float(hi), 4)],
        "per_family": {f: round(v, 4) for f, v in fam_mean.items()},
        "worst_family": min(fam_mean.items(), key=lambda kv: kv[1]) if fams else None,
        "per_budget": {m: round(sum(v) / len(v), 4) for m, v in sorted(per_m.items())},
        "templates": sum(len(fam_t[f]) for f in fams),
        "scenarios": sum(len(v) for f in fams for v in fam_t[f].values()),
    }


def h1_decision(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The pre-registered classification (protocol 12.7.1 section 8)."""
    main = paired(rows, "B8_P1b", "B0")
    indep = paired(rows, "B8_P1b", "B0", subset=independent)
    p1b = aggregate(rows, "B8_P1b")["primary_mean"]
    simple = {s: aggregate(rows, s)["primary_mean"] for s in SIMPLE_BASELINES}
    beaten_by = [
        s for s, v in simple.items() if v is not None and p1b is not None and v >= p1b + 0.02
    ]
    effect = main["mean"] >= 0.05 and main["ci95"][0] > 0
    worst_ok = main["worst_family"] is not None and main["worst_family"][1] >= -0.05
    indep_ok = indep["mean"] >= 0.05
    if beaten_by:
        verdict = "inferior to a simpler baseline"
    elif effect and worst_ok and indep_ok:
        verdict = "supported under the declared synthetic threat model"
    elif effect:
        verdict = "supported with significant limitations"
    else:
        verdict = "not supported after debiasing"
    return {
        "paired_P1b_minus_B0": main,
        "paired_independent_subset": indep,
        "P1b_primary_mean": p1b,
        "simple_baselines_primary_mean": simple,
        "beaten_by_simpler": beaten_by,
        "criteria": {
            "effect": effect,
            "worst_family_ok": worst_ok,
            "independent_subset_ok": indep_ok,
        },
        "verdict": verdict,
    }


def independent(row: dict[str, Any]) -> bool:
    """Scenarios where neither age nor mechanism relates to the target by construction."""
    return (
        row["age"] in ("target_random", "overlap", "same_block")
        and row["mech"] == "mixed_independent"
    )


# --- sealed primary run ---------------------------------------------------------------------


def primary(spec_list: Sequence[Spec] | None = None) -> dict[str, Any]:
    spec_list = list(spec_list or specs())
    rows: list[dict[str, Any]] = []
    diags: list[dict[str, Any]] = []
    overall = hashlib.sha256()
    t0 = time.perf_counter()
    for sp, sc, ev in iterate(spec_list):
        overall.update(scenario_hash(sc).encode())
        rows.append(
            {
                "family": sp.family,
                "G": sp.groups,
                "m": sp.m,
                "rep": sp.rep,
                "age": sp.age,
                "mech": sp.mech,
                "n": len(sc.groups),
                **ev,
            }
        )
        diags.append(
            {"family": sp.family, "age": sp.age, "mech": sp.mech, "m": sp.m, **diagnostics(sc)}
        )
    return {
        "rows": rows,
        "diagnostics": diags,
        "manifest_sha256": overall.hexdigest(),
        "seconds": round(time.perf_counter() - t0, 1),
    }


def summarize_primary(res: dict[str, Any]) -> dict[str, Any]:
    rows = res["rows"]
    methods = list(METHODS)
    out: dict[str, Any] = {
        "scenarios": len(rows),
        "templates": len({(r["family"], r["G"], r["m"]) for r in rows}),
        "manifest_sha256": res["manifest_sha256"],
        "exposure": {m: aggregate(rows, m) for m in methods},
        "group_exposure": {m: aggregate(rows, m, "b") for m in methods},
        "H1": h1_decision(rows),
        "group_paired_P1b_minus_B0": paired(rows, "B8_P1b", "B0", what="b"),
        "P1b_minus_B4": paired(rows, "B8_P1b", "B4"),
        "P1b_minus_P1": paired(rows, "B8_P1b", "B7_P1"),
        "worst_budget": {
            m: paired(rows, m, "B0", subset=lambda r: r["m"] == 10_000)["mean"]
            for m in ("B8_P1b", "B7_P1", "B4", "B6")
        },
        "by_age": {
            a: {
                m: aggregate(rows, m, subset=partial(_field_is, "age", a))["primary_mean"]
                for m in ("B0", "B8_P1b", "B2_oldest", "NC_newest", "B1")
            }
            for a in AGE_RELATIONS
        },
        "by_mech": {
            x: {
                m: aggregate(rows, m, subset=partial(_field_is, "mech", x))["primary_mean"]
                for m in ("B0", "B8_P1b", "B3")
            }
            for x in MECH_RELATIONS
        },
        "by_k": {
            m: {k: round(_mean_k(rows, m, k), 4) for k in K_GRID}
            for m in ("B0", "B1", "B4", "B6", "B7_P1", "B8_P1b", "NC_random")
        },
        "pseudo_target": _pseudo(rows),
        "displacement": _displacement(rows),
        "diagnostics": _diag_summary(res["diagnostics"]),
        "tie_neutrality": tie_neutrality(rows),
    }
    return out


def _field_is(key: str, value: object, row: dict[str, Any]) -> bool:
    return bool(row[key] == value)


def _mean_k(rows: Sequence[dict[str, Any]], m: str, k: int) -> float:
    fam: dict[str, dict[tuple[int, int], list[float]]] = {}
    for r in rows:
        if r["family"] in PRIMARY_FAMILIES:
            fam.setdefault(r["family"], {}).setdefault((r["G"], r["m"]), []).append(
                _exposure(r["methods"][m]["r"], k)
            )
    vals = [sum(sum(v) / len(v) for v in t.values()) / len(t) for t in fam.values()]
    return sum(vals) / len(vals)


def _pseudo(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, dict[str, float]] = {}
    for meth in ("B0", "B8_P1b", "NC_random"):
        acc: dict[str, list[float]] = {}
        for r in rows:
            p = r["methods"][meth].get("pseudo")
            if p is not None:
                acc.setdefault(r["family"], []).append(
                    sum(1 for k in K_GRID if p <= k) / len(K_GRID)
                )
        out[meth] = {f: round(sum(v) / len(v), 4) for f, v in acc.items()}
    return out


def _displacement(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for meth in ("B0", "B8_P1b"):
        per_m: dict[int, list[float]] = {}
        for r in rows:
            row = r["methods"][meth]
            if "clean" in row and r["family"] in PRIMARY_FAMILIES:
                per_m.setdefault(r["m"], []).append(row["r"][0] - row["clean"][0])
        out[meth] = {
            m: {"median": sorted(v)[len(v) // 2], "mean": round(sum(v) / len(v), 1)}
            for m, v in sorted(per_m.items())
        }
    return out


def _diag_summary(diags: Sequence[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fam in FAMILIES:
        ds = [d for d in diags if d["family"] == fam and d["m"] > 0]
        if not ds:
            continue

        def mean(key: str, ds: list[dict[str, Any]] = ds) -> float | None:
            vals = [float(d[key]) for d in ds if d[key] is not None]
            return round(sum(vals) / len(vals), 4) if vals else None

        out[fam] = {
            k: mean(k)
            for k in (
                "age_pct",
                "oldest",
                "newest",
                "address_pct",
                "list_pct",
                "ref_sorted_pct",
                "largest_group",
                "smallest_group",
                "mech_unique",
                "bits_pct_strict_above",
            )
        }
    return out


def tie_neutrality(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """H5: in F10 (equal leaders), the target leader's bucket position against the target
    group's size (top vs bottom half of the scenario's bucket sizes is not stored, so the
    proxy is m: decoys inflate other buckets). Neutral selectors keep the mean bucket
    position near (G + 1) / 2 at every m."""
    out: dict[str, Any] = {}
    for meth in ("B7_P1", "B8_P1b", "B4"):
        acc: dict[tuple[int, int], list[float]] = {}
        for r in rows:
            if r["family"] == "F10_equal_leaders" and r["G"] > 1:
                acc.setdefault((r["G"], r["m"]), []).append(
                    (r["methods"][meth]["b"][0] - 1) / (r["G"] - 1)
                )
        out[meth] = {f"G{g}_m{m}": round(sum(v) / len(v), 3) for (g, m), v in sorted(acc.items())}
    return out


# --- E3: adaptive attacker (exploratory) ----------------------------------------------------

ATTACK_METHODS = ("B0", "B1", "B4", "B5_pure_similarity", "B6", "B7_P1", "B8_P1b")
ATTACK_BUDGETS = (10, 100, 1_000)  # target-tier address equivalents
ATTACK_CAP = 2_000  # largest decoy population evaluated (disclosed limit)


@dataclass(frozen=True)
class Attack:
    delta: int  # decoy tier relative to the target (+1 costs 16x, -1 costs 1/16 per address)
    alloc: str  # "own" | "others" | "uniform" | "tie_winners"
    timing: str  # "older" | "newer"
    grind: bool  # keep only decoys whose public keyed hash beats the target's


ATTACKS = tuple(
    Attack(d, a, t, gr)
    for d in (-1, 0, 1)
    for a in ("own", "others", "uniform", "tie_winners")
    for t in ("older", "newer")
    for gr in (False, True)
)


def victim(i: int) -> tuple[list[ce.CandidateGroup], str, list[str], int]:
    """An attack-free victim population: references, a 'spoofed_out' target, background."""
    g = (2, 5, 10, 25)[i % 4]
    tier = (6, 7, 8)[i // 4 % 3]
    rng = _rng("victim", i)
    refs = _references(rng, g, overlap=False)
    t_ref = refs[rng.randrange(g)]
    cands = [
        _Cand(
            lookalike_of(rng, t_ref, *split(rng, tier)), t_ref, "spoofed_out", 5_000, 100, "target"
        )
    ]
    for _ in range(N_BACKGROUND):
        ref = refs[rng.randrange(g)]
        cands.append(
            _Cand(
                lookalike_of(rng, ref, *split(rng, _tier_iid(rng))),
                ref,
                MECHS[rng.randrange(4)],
                rng.randint(LO, HI),
                rng.randrange(200),
                "background",
            )
        )
    groups, relevant, _ = _groups(cands, refs)
    return groups, relevant[0], refs, tier


def attack_population(
    base: list[ce.CandidateGroup],
    target: str,
    refs: Sequence[str],
    tier: int,
    att: Attack,
    budget: int,
    seed_rng: random.Random,
) -> tuple[list[ce.CandidateGroup], dict[str, Any]]:
    """Legal attacker additions only: new lookalike addresses with chosen tier, reference,
    timing; existing records and the victim's references are never touched."""
    t_group = next(g for g in base if g.lookalike == target)
    t_ref = ce.bucket_of(t_group)
    t_hash = ar.keyed(PUBLIC_SEED, target)
    d_tier = tier + att.delta
    if d_tier < 6:
        return base, {"decoys": 0, "generated": 0, "illegal": "tier below the similarity rule"}
    n = min(ATTACK_CAP, int(budget * 16.0 ** (-att.delta)))
    others = [r for r in refs if r != t_ref] or [t_ref]
    t_bucket_hash = ar.keyed(PUBLIC_SEED, "bucket:" + t_ref)
    winners = [r for r in others if ar.keyed(PUBLIC_SEED, "bucket:" + r) < t_bucket_hash] or others
    pool = {"own": [t_ref], "others": others, "uniform": list(refs), "tie_winners": winners}[
        att.alloc
    ]
    chosen: dict[str, dict[str, int]] = {}
    for r in refs:
        chosen.setdefault(r[-3:], {})[r] = 0
    block = t_group.last_position[0]
    out = list(base)
    generated = kept = 0
    while generated < n:
        ref = pool[generated % len(pool)]
        addr = lookalike_of(seed_rng, ref, *split(seed_rng, d_tier))
        generated += 1
        if att.grind and ar.keyed(PUBLIC_SEED, addr) >= t_hash:
            continue  # ground away: the attacker keeps only hash winners (public seed)
        b = (
            seed_rng.randint(LO, block - 1)
            if att.timing == "older"
            else seed_rng.randint(block + 1, HI)
        )
        out.append(
            make_group(
                addr,
                ce._match(addr, chosen),
                "spoofed_out",
                (b, seed_rng.randrange(200), 10_000 + kept),
            )
        )
        kept += 1
    return out, {"decoys": kept, "generated": generated}


def adaptive(victims: int = 12) -> dict[str, Any]:
    """For each victim, budget and method/knowledge model: the attack (from the bounded
    grid ATTACKS) that pushes the target lowest. Each attack population is generated once
    and scored by every method. K1: the attacker knows the algorithm and its public seed.
    K2: the selector uses a seed the attacker does not know (the attacker still uses the
    public seed for grinding and tie-winner choice, and so guesses wrong)."""
    runs = [(m, "K1_public_seed", PUBLIC_SEED) for m in ATTACK_METHODS] + [
        (m, "K2_secret_seed", 987_654_321)
        for m in ATTACK_METHODS
        if FROZEN_SELECTORS.get(m, ar.Selector("B0")).method in ("B6", "P1")
    ]
    worst: dict[tuple[str, str, int, int], tuple[int, Attack | None]] = {}
    for v in range(victims):
        base, target, refs, tier = victim(v)
        for budget in ATTACK_BUDGETS:
            for att in ATTACKS:
                pop, info = attack_population(
                    base, target, refs, tier, att, budget, _rng("attack", v, budget, att)
                )
                if not info.get("decoys"):
                    continue
                for meth, know, seed in runs:
                    rank = _method_rank(pop, target, meth, seed)
                    key = (meth, know, budget, v)
                    if rank > worst.get(key, (0, None))[0]:
                        worst[key] = (rank, att)
    out: dict[str, Any] = {}
    for meth, know, _seed in runs:
        cell: dict[str, Any] = {}
        for budget in ATTACK_BUDGETS:
            ranks = [worst.get((meth, know, budget, v), (1, None))[0] for v in range(victims)]
            best: dict[str, int] = {}
            for v in range(victims):
                won = worst.get((meth, know, budget, v), (1, None))[1]
                if won is not None:
                    k = f"d{won.delta}/{won.alloc}/{won.timing}/grind={won.grind}"
                    best[k] = best.get(k, 0) + 1
            cell[str(budget)] = {
                "worst_rank_median": sorted(ranks)[len(ranks) // 2],
                "worst_rank_min": min(ranks),
                "displaced_beyond": {
                    k: round(sum(1 for r in ranks if r > k) / len(ranks), 3) for k in (1, 5, 10)
                },
                "best_attacks": dict(sorted(best.items(), key=lambda kv: -kv[1])[:3]),
            }
        out[f"{meth}/{know}"] = cell
    return out


def _method_rank(pop: Sequence[ce.CandidateGroup], target: str, meth: str, seed: int) -> int:
    if meth == "B5_pure_similarity":
        ordered = sorted(pop, key=lambda g: (-ar.bits(g), g.lookalike))
    else:
        ordered = ar.order(
            pop,
            replace(FROZEN_SELECTORS[meth], seed=seed)
            if FROZEN_SELECTORS[meth].method in ("B6", "P1")
            else FROZEN_SELECTORS[meth],
        )
    return next(i + 1 for i, g in enumerate(ordered) if g.lookalike == target)


def attack_cost_curve(adaptive_out: dict[str, Any], k: int) -> dict[str, int | None]:
    """The smallest budget at which the best attack displaces the median victim's target."""
    out: dict[str, int | None] = {}
    for key, cell in adaptive_out.items():
        hit = None
        for b in ATTACK_BUDGETS:
            if cell[str(b)]["worst_rank_median"] > k:
                hit = b
                break
        out[key] = hit
    return out


# --- E3: counterexamples --------------------------------------------------------------------


def counterexamples(trials: int = 20_000) -> dict[str, Any]:
    """Bounded random search over tiny populations for each named failure type, with
    greedy shrinking (drop candidates while the property still holds)."""
    found: dict[str, Any] = {}
    p1b, b0, rot = (
        FROZEN_SELECTORS["B8_P1b"],
        FROZEN_SELECTORS["B0"],
        FROZEN_SELECTORS["NC_group_rotation"],
    )
    # the 12.7 theorem concerns a bucket's *first* member: weaker candidates can never move
    # it down. A non-leading target can be passed by a weaker leader of another bucket (the
    # group discount at work): that is recorded as a counterexample type, not a break.
    invariant_breaks = {"bound": 0, "weaker_decoy_moves_bucket_leader": 0}
    for i in range(trials):
        rng = _rng("cx", i)
        g = rng.choice((1, 2, 3))
        refs = _references(rng, g, overlap=rng.random() < 0.3)
        k = rng.choice((1, 2, 3))
        cands = []
        for j in range(rng.randint(2, 6)):
            ref = refs[rng.randrange(g)]
            cands.append(
                _Cand(
                    lookalike_of(rng, ref, *split(rng, rng.choice((6, 7, 8)))),
                    ref,
                    MECHS[rng.randrange(4)],
                    rng.randint(LO, HI),
                    rng.randrange(5),
                    "target" if j == 0 else "decoy",
                )
            )
        groups, rel, _ = _groups(cands, refs)
        if not rel:
            continue
        t = rel[0]
        checks = _checks(t, k, p1b, b0, rot)
        for name, prop in checks.items():
            if name not in found and prop(groups):
                found[name] = _shrink(groups, t, prop) | {"K": k}
        tg = next(x for x in groups if x.lookalike == t)
        bound = ar.displacement_bound(groups, ce.bucket_of(tg), 4.0)
        if bound is not None and _bk(groups, t, p1b) > bound:
            invariant_breaks["bound"] += 1
        weaker = [x for x in groups if x.lookalike != t and ar.bits(x) < ar.bits(tg)]
        if weaker:
            w = weaker[0]
            without = [x for x in groups if x is not w]
            if _bk(groups, t, p1b) > _bk(without, t, p1b):
                invariant_breaks["weaker_decoy_moves_bucket_leader"] += 1
            name = "weaker_decoy_displaces_non_leading_target"
            if name not in found and _rk(groups, t, p1b) > _rk(without, t, p1b):

                def worse_with_w(
                    gs: list[ce.CandidateGroup], w: ce.CandidateGroup = w, t: str = t
                ) -> bool:
                    return w in gs and _rk(gs, t, p1b) > _rk([x for x in gs if x is not w], t, p1b)

                found[name] = _shrink(groups, t, worse_with_w) | {"weaker_decoy": w.lookalike}
    # multi-reference assignment: a candidate equally similar to two references
    found["multi_reference_assignment"] = _multi_ref_example()
    return {"trials": trials, "found": found, "invariant_breaks": invariant_breaks}


Prop = Callable[[list[ce.CandidateGroup]], bool]


def _checks(t: str, k: int, p1b: ar.Selector, b0: ar.Selector, rot: ar.Selector) -> dict[str, Prop]:
    def loses_b0(gs: list[ce.CandidateGroup]) -> bool:
        return _rk(gs, t, p1b) > k >= _rk(gs, t, b0)

    def loses_rotation(gs: list[ce.CandidateGroup]) -> bool:
        return _rk(gs, t, p1b) > k >= _rk(gs, t, rot)

    def group_hidden(gs: list[ce.CandidateGroup]) -> bool:
        return _bk(gs, t, p1b) > k

    def tie_lost(gs: list[ce.CandidateGroup]) -> bool:
        return _leader_tie_lost(gs, t)

    return {
        "P1b_loses_to_B0": loses_b0,
        "P1b_loses_to_group_rotation": loses_rotation,
        "P1b_group_not_exposed": group_hidden,
        "equal_leader_tie_favours_other_group": tie_lost,
    }


def _rk(gs: Sequence[ce.CandidateGroup], t: str, sel: ar.Selector) -> int:
    return next(i + 1 for i, g in enumerate(ar.order(gs, sel)) if g.lookalike == t)


def _bk(gs: Sequence[ce.CandidateGroup], t: str, sel: ar.Selector) -> int:
    tb = ce.bucket_of(next(g for g in gs if g.lookalike == t))
    return next(i + 1 for i, g in enumerate(ar.order(gs, sel)) if ce.bucket_of(g) == tb)


def _leader_tie_lost(gs: Sequence[ce.CandidateGroup], t: str) -> bool:
    tg = next(g for g in gs if g.lookalike == t)
    tb = ce.bucket_of(tg)
    leaders: dict[str, ce.CandidateGroup] = {}
    for g in gs:
        b = ce.bucket_of(g)
        if b.startswith("mech:"):
            continue
        if b not in leaders or ar.bits(g) > ar.bits(leaders[b]):
            leaders[b] = g
    if leaders.get(tb) is not tg:
        return False
    rivals = [g for b, g in leaders.items() if b != tb and ar.bits(g) == ar.bits(tg)]
    return bool(rivals) and _rk(gs, rivals[0].lookalike, FROZEN_SELECTORS["B8_P1b"]) < _rk(
        gs, t, FROZEN_SELECTORS["B8_P1b"]
    )


def _shrink(
    gs: list[ce.CandidateGroup], t: str, prop: Callable[[list[ce.CandidateGroup]], bool]
) -> dict[str, Any]:
    cur = list(gs)
    changed = True
    while changed:
        changed = False
        for x in list(cur):
            if x.lookalike == t:
                continue
            trial = [y for y in cur if y is not x]
            if prop(trial):
                cur, changed = trial, True
                break
    return {
        "target": t,
        "candidates": [
            {
                "lookalike": g.lookalike,
                "bucket": ce.bucket_of(g),
                "bits": ar.bits(g),
                "last_position": list(g.last_position),
                "mechanisms": list(g.mechanisms),
                "is_target": g.lookalike == t,
            }
            for g in sorted(cur, key=lambda g: g.lookalike)
        ],
        "order_B0": [g.lookalike for g in ar.order(cur, FROZEN_SELECTORS["B0"])],
        "order_P1b": [g.lookalike for g in ar.order(cur, FROZEN_SELECTORS["B8_P1b"])],
        "order_rotation": [
            g.lookalike for g in ar.order(cur, FROZEN_SELECTORS["NC_group_rotation"])
        ],
    }


def _multi_ref_example() -> dict[str, Any]:
    from cryptoguard.ml.candidates import similar

    rng = _rng("multiref")
    a = "0x" + _hex(rng, 40)
    b = "0x" + a[2:5] + _other(rng, a[5]) + _hex(rng, 32) + _other(rng, a[-4]) + a[-3:]
    cand = "0x" + a[2:5] + _other(rng, a[5]) + _hex(rng, 32) + _other(rng, a[-4]) + a[-3:]
    chosen = {a[-3:]: {a: 0, b: 0}}
    m = ce._match(cand, chosen)
    return {
        "references": [a, b],
        "candidate": cand,
        "similar_to": {"a": list(similar(cand, a) or ()), "b": list(similar(cand, b) or ())},
        "assigned": m[0] if m else None,
        "rule": (
            "equal sum and suffix: the lexicographically larger reference "
            "(candidate_evidence._match); label-independent"
        ),
    }


# --- fidelity, regression, performance ------------------------------------------------------


def fidelity(n: int = 30) -> dict[str, Any]:
    """Rebuild a sample of generated scenarios through real fixtures and ``build``: the
    groups' references, affixes and mechanisms, and P1b's order, must match."""
    from cryptoguard.ml import reliability_study as rs

    usdt, fake = rs.USDT, rs.FAKE
    checked = mismatched = 0
    sample = [sp for sp in specs() if sp.m <= 100][
        :: max(1, len([sp for sp in specs() if sp.m <= 100]) // n)
    ][:n]
    for sp in sample:
        sc = generate(sp)
        transfers: list[tuple[Any, ...]] = []
        native: list[tuple[Any, ...]] = []
        for g in sc.groups:
            mech = (
                "native_dust"
                if g.kinds == ("native",)
                else (
                    "spoofed_out"
                    if "spoofed_out" in g.mechanisms
                    else "fake_token_in"
                    if "untrusted_token_in" in g.mechanisms
                    else "zero_value_in"
                )
            )
            blk = g.last_position[0]
            if mech == "native_dust":
                native.append((g.lookalike, 1, blk, True))
            elif mech == "spoofed_out":
                transfers.append(
                    (rs.WALLET, g.lookalike, 0, blk, rs.ATTACKER, usdt, g.last_position[1])
                )
            elif mech == "fake_token_in":
                transfers.append(
                    (g.lookalike, rs.WALLET, 10**18, blk, None, fake, g.last_position[1])
                )
            else:
                transfers.append((g.lookalike, rs.WALLET, 0, blk, None, usdt, g.last_position[1]))
        groups = [
            replace(g, victim=rs.WALLET.lower(), identity=f"1:{rs.WALLET.lower()}:{g.lookalike}")
            for g in sc.groups
        ]
        fx = rs.wallet_fixture(
            transfers=transfers,
            native=native,
            wallet_txs=[(r, 10**15, 1_101 + i) for i, r in enumerate(sc.references)],
        )
        built = ce.build(fx, cutoff=(9_001, 0))
        a = {g.lookalike: (ce.bucket_of(g), g.affix, g.mechanisms) for g in groups if g.references}
        b = {
            g.lookalike: (ce.bucket_of(g), g.affix, g.mechanisms)
            for g in built.groups
            if g.references
        }
        sel = FROZEN_SELECTORS["B8_P1b"]
        oa = [g.lookalike for g in ar.order([g for g in groups if g.references], sel)]
        ob = [g.lookalike for g in ar.order([g for g in built.groups if g.references], sel)]
        checked += 1
        mismatched += int(a != b or oa != ob)
    return {"scenarios": checked, "mismatched": mismatched}


def regression(poisoning_dir: Path) -> dict[str, Any]:
    """E4: the two known incidents (development cases, not validation)."""
    from cryptoguard.ml import adversarial_benchmark as ab
    from cryptoguard.ml import reliability_study as rs

    out = ab.development_cases(poisoning_dir)
    for row in out.values():
        row["label"] = "known development case - not independent validation"

    pages = {}
    for name, fx, cut in rs.eligible_windows(poisoning_dir):
        if name not in out:
            continue
        res = ar.select(ce.build(fx, cutoff=cut), FROZEN_SELECTORS["B8_P1b"])
        s = ce.summarize(res, 1)
        seen, off = [i["identity"] for i in s["top"]], s["next_offset"]
        while off is not None:
            pg = ce.page(res, offset=off, limit=1, expect_digest=s["result_digest"])
            seen += [i["identity"] for i in pg["items"]]
            off = pg["next_offset"]
        pages[name] = {
            "all_groups_reachable": seen == [g.identity for g in res.groups],
            "groups": len(res.groups),
        }
    return {"cases": out, "pagination": pages}


def performance(sizes: Sequence[int] = (100, 1_000, 10_000, 100_000)) -> list[dict[str, Any]]:
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    out = []
    for n in sizes:
        rng = _rng("perf", n)
        refs = _references(rng, 10, overlap=False)
        cands = [
            _Cand(
                lookalike_of(rng, refs[i % 10], *split(rng, _tier_iid(rng))),
                refs[i % 10],
                MECHS[i % 4],
                rng.randint(LO, HI),
                rng.randrange(200),
                "decoy",
            )
            for i in range(n)
        ]
        groups, _, _ = _groups(cands, refs)
        row: dict[str, Any] = {"candidates": n}
        for meth in ("B0", "B8_P1b"):
            tracemalloc.start()
            t0 = time.perf_counter()
            ar.order(groups, FROZEN_SELECTORS[meth])
            sec = time.perf_counter() - t0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            row[meth] = {"seconds": round(sec, 3), "peak_traced_mib": round(peak / 2**20, 2)}
        rss = peak_rss_bytes()
        row["process_peak_rss_mib"] = None if rss is None else round(rss / 2**20, 1)
        out.append(row)
        del groups, cands
    return out


# --- entry point ----------------------------------------------------------------------------


def main(
    poisoning_dir: Path, out: Path, *, manifest_only: bool = False, adaptive_victims: int = 12
) -> dict[str, Any]:
    import subprocess

    from cryptoguard.ml.adversarial_benchmark import free_ram_bytes
    from cryptoguard.ml.tsuchiya_archive import peak_rss_bytes

    frozen = verify_frozen()
    out.mkdir(parents=True, exist_ok=True)
    if manifest_only:
        man = manifest()
        (out / "manifest.json").write_text(
            json.dumps(man, indent=1, sort_keys=True) + "\n", encoding="utf-8"
        )
        return {"frozen": frozen, "manifest": man}
    t0 = time.perf_counter()
    free = free_ram_bytes()
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
    prim = primary()
    summary = summarize_primary(prim)
    result: dict[str, Any] = {
        "study": STUDY_VERSION,
        "protocol": "protocol-12.7.1",
        "git": git,
        "rpc_requests": 0,
        "preflight_free_ram_mib": None if free is None else round(free / 2**20),
        "frozen": frozen,
        "categories": {
            "E2": "sealed debiased synthetic benchmark (primary)",
            "E3": "adaptive attacker and counterexamples (exploratory)",
            "E4": "known incidents (regression; not validation)",
        },
        "E2": summary,
        "E2_seconds": prim["seconds"],
    }
    del prim
    t_a = time.perf_counter()
    adapt = adaptive(adaptive_victims)
    result["E3_adaptive"] = {
        "victims": adaptive_victims,
        "attack_grid": len(ATTACKS),
        "budgets": list(ATTACK_BUDGETS),
        "cap": ATTACK_CAP,
        "cells": adapt,
        "cost_to_displace_K5": attack_cost_curve(adapt, 5),
        "cost_to_displace_K10": attack_cost_curve(adapt, 10),
        "seconds": round(time.perf_counter() - t_a, 1),
    }
    result["E3_counterexamples"] = counterexamples()
    result["fidelity"] = fidelity()
    result["E4"] = regression(poisoning_dir)
    result["performance"] = performance()
    peak = peak_rss_bytes()
    result["resources"] = {
        "seconds": round(time.perf_counter() - t0, 1),
        "peak_rss_mib": None if peak is None else round(peak / 2**20, 1),
    }
    (out / "adaptive-validation.json").write_text(
        json.dumps(result, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )
    return result

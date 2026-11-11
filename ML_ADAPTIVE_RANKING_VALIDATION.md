# Adaptive-adversary validation of P1b (Phase 12.7.1)

| Item | Value |
|---|---|
| Protocol (frozen before any selector ran on the sealed scenarios) | [`docs/ml/protocol-12.7.1.md`](docs/ml/protocol-12.7.1.md), `d98a636` |
| Frozen algorithms | `adversarial_ranking.py` from `0968ff8` (SHA-256 `2c0e65ae…`); P1b config `8b3795e363aad678`; checked at run time by `verify_frozen` |
| Sealed manifest | 7,200 scenarios, 5,079,472 candidates, SHA-256 `2e294aeb…` (reproduced by the primary run) |
| Primary run | once, on `d98a636`: 1,379 s, 310 MiB peak RSS (`cryptoguard ml adaptive-validation`) |
| Output (git-ignored) | `data/ml/research/phase12.7.1/adaptive-validation.json`, `manifest.json` |
| RPC requests / downloads | **0** / none |

**Labels used throughout:**
- **[E2]:** sealed debiased synthetic benchmark (primary).
- **[E3]:** adaptive attacker and counterexamples (exploratory).
- **[E4]:** the two known incidents (regression only).
- **[POST-HOC]:** computed after the primary results were seen.

None of them are pooled.

## 1. Executive summary

**Verdict:** on a benchmark without the 12.7 shortcuts, **P1b is not supported**
(pre-registered classification: *not supported after debiasing*).
- **P1b − B0 = −0.018** mean Exposure@K, 95 % CI [−0.031, −0.004], over 225 templates and
  6,480 scenarios. The 12.7 gain (+0.29 on the old grid) does not survive.
- **P1b's 12.7 advantage came from the benchmark.** Its targets were always older than their
  decoys, so B0's recency tie-break always worked against them. Under balanced timing, B0's
  recency tie-break exposes the target whenever the target happens to be newest. That makes
  B0 bimodal: 0.70–0.73 when the target is newest or the decoys came first, and 0.31–0.39
  otherwise. P1b reads no time and stays flat at 0.42–0.44.

**Where P1b genuinely helps [E2]:**
- **Floods of *other* references:** +0.142 (F2) and +0.097 (F8) in address exposure, and
  +0.119 / +0.116 in reference-group exposure. Overall group exposure is +0.032 [0.024, 0.041].
- **The shortcut-free subset** (random timing, independent mechanisms): +0.054 [0.034, 0.074].

**Where it hurts [E2]:** whenever the target's own group is flooded with equal-strength
lookalikes. F3 is −0.121 and F4 −0.108. Its hash tie-break gives about K/(m+1), while B0's
recency gets lucky half the time.

**Simpler baselines:**
- **B4** (reference round-robin, recency within) beats P1b: −0.018 [−0.028, −0.010]. That is
  just under the pre-registered 0.02 "inferior" threshold.
- **B0** also edges P1b.
- **Mechanism round-robin (B3)** scores highest overall (0.534), but only through the
  designed mechanism-shortcut conditions: 0.70–0.73 there, against 0.38–0.47 elsewhere.

**Adaptive attacker [E3]:**
- An attacker who knows the algorithm displaces the target past K = 5 for the median victim
  with **10** equal-tier lookalikes of the target's own reference, under **every** method,
  P1b included (it also grinds for hashes against P1b's public seed).
- P1b requires no larger budget than B0 (H2 not supported).
- The reference *group* stays exposed: it holds the attacker's own lookalikes.

**What stands:**
- the 12.7 theorem (a group's *first* member cannot be displaced by weaker candidates): 0
  breaks in 20,000 random trials;
- time-invariance;
- exact reproducibility;
- the bounded summary and pagination.

**Independent real-world validation: BLOCKED BY DATA.**

## 2. Phase 12.7 original findings (E1, development)

| Method | 12.7 grid mean Exposure@K |
|---|---|
| Recency-first | 0.304 |
| B0 | 0.525 |
| P1 | 0.773 |
| P1b (post hoc) | 0.813 |

Its negative controls already flagged that oldest-first scored 0.986 and mechanism
round-robin 0.839.

## 3. Identified benchmark biases (12.7)

1. **Age:** the target was always older than its decoys. That penalizes B0 and recency, and
   rewards oldest-first.
2. **Mechanism:** the target usually differed from its decoys, which rewarded mechanism
   round-robin.
3. **Reference position:** the target was always on R1, which sorts 3rd of 5, so B4's
   address tie-break was not neutral.
4. **Address order:** the target's address always sorted first among equals, which rewarded
   address tie-breaks.
5. **No null family.**

The 12.7 post-hoc checks varied one factor at a time. E2 removes them all by design.

## 4. Frozen P1b implementation

**Definition:** group candidates by the victim reference they best imitate (bucket); member j
of a bucket gets priority `4·affix − 4·j`; order globally by priority ↓, then bucket best ↓,
then keyed hash of the bucket, then keyed hash of the member.

| Item | Value |
|---|---|
| Source | `0968ff8`, SHA-256 `2c0e65ae…` |
| Config hash | `8b3795e363aad678` |
| Public seed | 0 |

`verify_frozen()` refuses to run if the module or any of six config hashes differs. Nothing
changed after the protocol commit.

## 5. Research hypotheses

H1–H9 as in protocol §8 (decisions: §16, §18, §20, §22).

## 6. Threat model

**The attacker controls:**
- lookalike addresses and their tier (subject to the pipeline's rule: prefix + suffix ≥ 6,
  suffix ≥ 3);
- which genuine reference each one imitates;
- planting time;
- mechanism and repetition;
- how many addresses to use.

**The attacker does not control:** the victim's references or signatures, finalized order,
provenance, or the scoring target.

**Knowledge:**
- **K1:** the algorithm and its public seed.
- **K2:** a seed the attacker does not know. This is a diagnostic only; a seed kept in
  public configuration is not secret.

**Costs:**
- **Address generation:** 2^(4(p+s)) key trials for one specific reference.
- **Planting:** gas per event.
- **Repetition:** gas only.

Budgets are counted in target-tier address equivalents: one tier stronger costs ×16, one tier
weaker ÷16. No vanity search is run.

## 7. Synthetic generator design [E2]

**A new module,** `ml/adaptive_validation.py`. It does not copy the 12.7 scenarios.

**Per scenario,** a seeded RNG from `sha256(MASTER | family | G | m | replicate)` generates:
- G uniformly random references;
- the target(s) and m decoys per the family;
- 5 i.i.d. background lookalikes;
- 2 unreferenced strangers.

**How candidates are built:**
- Addresses are random apart from the designed affix.
- References are assigned by the pipeline's own `_match`.
- Groups are `CandidateGroup` records.
- The population is shuffled.
- The oracle is stored outside the groups.

**Fidelity:** 30 of 30 scenarios rebuilt through real fixtures and `build` matched in
references, affixes, mechanisms and P1b order (0 mismatches).

## 8. Target assignment

- **Targets are generated** like any candidate of the family's declared tier, with a
  uniform reference index, a uniform mechanism and a time from the age relation.
- **F6 (exchangeable null):** the target is a uniformly drawn member of an i.i.d.
  population.
- **Diagnostics, mean over m > 0 scenarios:** the target's address percentile is 0.47–0.53,
  its list-position percentile 0.49–0.51, and its sorted-reference percentile 0.48–0.52.
  None is a shortcut.

## 9. Age balancing

- **Eight relations,** rotated so every template sees all eight: target oldest, newest,
  intermediate, random, one block, decoys precede, decoys follow, overlap.
- **Target age percentile:** 0.49–0.51 in every family.
- **Oldest vs newest:** the target is oldest in 0.16–0.19 of scenarios and newest in
  0.15–0.18. In F6 both are 0.03, i.e. at chance.

## 10. Mechanism balancing

- **Five relations:** same, different, mixed independent, target unique (a deliberate
  shortcut condition), majority same.
- **Target mechanism:** uniform.
- **Target's mechanism unique among candidates:** 0.23–0.26 of scenarios per family (0.00 in
  F9, 0.02 in F6).

## 11. Reference-group balancing

- **G:** {1, 2, 5, 10, 25}.
- **Target in the largest group:** F2 0.02, F3 0.79 (by design), F4/F7 0.24–0.26.
- **Target in the smallest group:** F2 0.72 (by design), F3 0.00.
- **Target reference's sorted position:** about 0.5.
- **Overlapping references and multi-reference matches** are handled by the pipeline's tie
  rule (§24.6).

## 12. Similarity balancing

| Family | Share of candidates strictly stronger than the target |
|---|---|
| F1 (target stronger) | 0.014 |
| F2–F4, F7, F8 (equal) | 0.04 (background only) |
| F5 (target weaker) | 0.84 (intrinsically ambiguous) |
| F6 | 0.34 |

## 13. Primary evaluation protocol

- **Templates:** 10 families × 5 G × 5 m. Replicates per template: 40 at m ≤ 100, 16 at
  m = 1,000, 8 at m = 10,000.
- **K:** {1, 3, 5, 10, 20, 50}.
- **Aggregation:** equal weight by template within a family, and equal weight by family over
  the 9 primary families. F6 is a control.
- **Uncertainty:** stratified template-cluster bootstrap, 2,000 resamples.
- **Run once.**

## 14. Adaptive adversary [E3]

**Setup:**
- **Victims:** 12 (G ∈ {2, 5, 10, 25} × tier {6, 7, 8}).
- **Budgets:** W ∈ {10, 100, 1,000}, capped at 2,000 decoys.
- **Attacks:** an exhaustive grid of 48:
  - tier offset −1, 0 or +1;
  - allocation: own group, other groups, uniform, or public-hash tie winners;
  - timing: older or newer;
  - grinding on or off.
- **Methods:** B0, B1, B4, B5, B6, P1 and P1b under K1, plus K2 for the seeded ones.
- **Rules:** additions only; references, records and receipts are untouched; illegal tiers
  are rejected (tested).
- **Runtime:** 45 s.

## 15. Baselines

| Id | Definition |
|---|---|
| B0 | similarity → recency |
| B1 | recency → similarity |
| B2 | oldest first |
| B3 | mechanism round-robin |
| B4 | reference round-robin, recency within |
| B5 | similarity, address ties |
| B6 | similarity, keyed-hash ties |
| B7 | P1 |
| B8 | P1b |
| B9 | similarity, seeded random ties |

Controls: newest first, random, hash order, pure group rotation.

## 16. Primary Exposure@K results [E2]

**Equal-family means over the 9 primary families (F6 control alongside):**

| Method | Exposure@K | GroupExposure@K | F6 null |
|---|---|---|---|
| B3 mechanism RR (control) | 0.534 | 0.808 | 0.361 |
| A: P1b with recency ties [ablation] | 0.468 | 0.819 | 0.356 |
| B4 reference RR | 0.448 | 0.822 | 0.354 |
| **B0** | **0.447** | 0.787 | 0.357 |
| P1b λ=2 [ablation] | 0.430 | 0.818 | 0.360 |
| **P1b** | **0.429** | **0.819** | 0.360 |
| P1b λ=8 [ablation] | 0.426 | 0.822 | 0.359 |
| P1 | 0.424 | 0.817 | 0.362 |
| P1b λ=∞ [ablation] | 0.412 | 0.823 | 0.359 |
| B1 / newest first | 0.388 | 0.752 | 0.356 |
| B2 oldest first | 0.387 | 0.747 | 0.357 |
| B5 pure similarity | 0.386 | 0.742 | 0.359 |
| B6 / B9 | 0.382 | 0.763 / 0.767 | 0.362 / 0.357 |
| Pure group rotation / P1b no similarity | 0.303 | 0.751 | 0.356 |
| Random | 0.265 | 0.705 | 0.365 |
| Hash order | 0.264 | 0.704 | 0.361 |

**H1 (pre-registered), paired P1b − B0:**

| Measure | Value |
|---|---|
| Mean | **−0.0177** |
| 95 % CI | [−0.0313, −0.0044] |
| Shortcut-free subset (486 scenarios) | +0.054 [0.034, 0.074] |
| Worst family | F3, −0.121 |
| Simpler baseline ≥ P1b + 0.02 | none; B4 is +0.018 |

**Classification: NOT SUPPORTED AFTER DEBIASING.** The effect criterion fails.

**Per family (mean Exposure@K):**

| Family | B0 | P1b | P1b − B0 | B4 | P1 |
|---|---|---|---|---|---|
| F1 target stronger | 0.881 | 0.879 | −0.002 | 0.831 | 0.875 |
| F2 equal, other groups | 0.391 | 0.533 | **+0.142** | 0.548 | 0.494 |
| F3 equal, own group | 0.389 | 0.268 | **−0.121** | 0.351 | 0.269 |
| F4 equal, uniform | 0.393 | 0.285 | −0.108 | 0.347 | 0.285 |
| F5 target weaker | 0.215 | 0.216 | +0.001 | 0.211 | 0.217 |
| F7 same total, other split | 0.387 | 0.287 | −0.101 | 0.340 | 0.290 |
| F8 reference overlap | 0.358 | 0.455 | **+0.097** | 0.458 | 0.446 |
| F9 several relevant | 0.319 | 0.261 | −0.058 | 0.290 | 0.259 |
| F10 equal leaders | 0.690 | 0.681 | −0.010 | 0.654 | 0.682 |
| F6 null (control) | 0.357 | 0.360 | — | 0.354 | 0.362 |

**Mean Exposure@K by K:**

| K | B0 | P1b | B4 | P1 |
|---|---|---|---|---|
| 1 | 0.119 | 0.091 | 0.101 | 0.085 |
| 3 | 0.314 | 0.270 | 0.258 | 0.263 |
| 5 | 0.442 | 0.399 | 0.388 | 0.393 |
| 10 | 0.534 | 0.524 | 0.563 | 0.522 |
| 20 | 0.624 | 0.623 | 0.669 | 0.614 |
| 50 | 0.650 | 0.670 | 0.707 | 0.670 |

## 17. GroupExposure@K [E2]

Reported separately: exposing the right reference is not exposing the right address.
- **P1b − B0:** +0.032 [0.024, 0.041].
- **Gains:** F2 +0.119, F8 +0.116, F5 +0.040, F9 +0.026.
- **Losses:** F3 −0.017, F10 −0.003.
- **Ranking:** B4 0.822 and P1b 0.819 are at the top, against 0.787 for B0.

## 18. Attack-budget curves

**[E2] by decoy count, P1b − B0:**

| m | 0 | 10 | 100 | 1,000 | 10,000 |
|---|---|---|---|---|---|
| P1b − B0 | −0.003 | +0.009 | +0.003 | −0.037 | **−0.061** |

At m = 10,000 the worst-budget differences against B0 are: P1 −0.066, B6 −0.117, B4 +0.004.

**[E2] median rank displacement (rank with decoys minus without):**

| m | B0 | P1b |
|---|---|---|
| 10 | 5 | 3 |
| 100 | 48 | 24 |
| 1,000 | 497 | 240 |
| 10,000 | 4,988 | 2,264 |

**[E3] adaptive, median victim's worst-case rank by budget W, with the share displaced
beyond K = 10:**

| Method / knowledge | W=10 | W=100 | W=1,000 | Budget displacing past K=5 / K=10 |
|---|---|---|---|---|
| B0 / K1 | 13 (1.00) | 103 (1.00) | 1,003 (1.00) | 10 / 10 |
| B1 / K1 | 163 (1.00) | 1,603 | 2,003 | 10 / 10 |
| B4 / K1 | 16 (1.00) | 106 | 1,006 | 10 / 10 |
| B5 / K1 | 12 (0.75) | 86 | 775 | 10 / 10 |
| B6 / K1 | 12 (0.58) | 65 | 555 | 10 / 10 |
| B6 / K2 | 10 (0.33) | 56 | 451 | 10 / **100** |
| P1 / K1 | 13 (0.75) | 62 | 679 | 10 / 10 |
| P1 / K2 | 12 (0.83) | 52 | 441 | 10 / 10 |
| **P1b / K1** | 13 (0.75) | 62 | 680 | **10 / 10** |
| P1b / K2 | 12 (0.83) | 52 | 442 | 10 / 10 |

**Most frequent best attacks:**
- **against B0 and B4:** equal tier, own group, newer;
- **against P1/P1b under K1:** equal tier, own group, newer, with grinding;
- **under K2:** equal tier, own group, older or newer.

**H2: not supported.** P1b needs the same budget as B0, 10 target-tier addresses
(≈ 2^(4t+3.3) trials).

## 19. Worst-case results

| View | Result |
|---|---|
| Worst family | F3 (equal, own group): −0.121 vs B0 |
| Worst budget | m = 10,000: −0.061 vs B0 |
| Worst timing for B0 | target oldest: B0 0.313, P1b 0.428 |
| Worst timing for P1b | none: 0.421–0.442 across all 8 relations |

So **P1b wins the minimax over timing, and B0 wins the mean over balanced timing.** An
attacker who controls timing picks B0's worst case. A non-adaptive or benign distribution
favours B0.

## 20. Negative controls

| Control | Result |
|---|---|
| **F6 exchangeable null** | every method 0.354–0.365 (random 0.365): **no leakage** |
| **Pseudo-target** (random non-relevant referenced candidate) | B0 0.29–0.41, P1b 0.29–0.39, random 0.31–0.39 per family: no method singles out non-targets |
| **Oldest first** | 0.94 when the target is oldest, 0.17 when newest |
| **Newest first** | the mirror image |
| **Mean over balanced age** | both 0.387: **no residual age shortcut** |
| **Mechanism round-robin** | 0.699 / 0.727 in "different" / "target unique" (shortcut conditions), 0.385 / 0.386 / 0.472 in "majority same" / "mixed" / "same": **driven by the designed shortcut** |
| **Hash order / random** | 0.26 |
| **Shuffled timestamps / mechanisms** | P1b is invariant by construction (12.7 tests) |

**H6/H7, P1b by mechanism relation:** 0.424–0.438, flat. **By age relation:** 0.421–0.442,
flat. Both supported. B0 ranges 0.31–0.73 over age.

## 21. Feature-leakage audit

**Selectors receive only `CandidateGroup` records.** No field carries the target, the
relevant set or generator metadata (tested).
- **Addresses:** uniformly random apart from the affix.
- **List order:** shuffled. The target's list percentile is about 0.5.
- **Scenario identifiers:** never passed to a selector.
- **References:** assigned by the pipeline's label-independent `_match`.
- **Time:** no future information exists in the synthetic window; P1b reads no time at all.
- **E4:** uses pre-cutoff fixtures only.
- **F6 at chance** for every method (§20) is the end-to-end leakage check.

## 22. Ablations [E2]

| Variant | Mean | Δ vs P1b |
|---|---|---|
| P1b (λ = 4, bucket-hash ties) | 0.429 | — |
| Recency ties within a bucket | **0.468** | +0.039 |
| λ = 2 | 0.430 | +0.001 |
| λ = 8 | 0.426 | −0.004 |
| P1 (member-hash ties) | 0.424 | −0.005 [−0.008, −0.002] |
| λ = ∞ | 0.412 | −0.017 |
| No reference grouping / no discount (= B6) | 0.382 | −0.047 |
| No similarity (pure rotation) | 0.303 | −0.126 |

- **What contributes:** similarity, then grouping.
- **The bucket-hash fix** helps slightly over P1.
- **Hash ties within a bucket** cost against balanced timing. The recency-tie variant is the
  best P1b variant, but it re-imports B0's timing exposure, and an adaptive attacker defeats
  it the same way.
- **Not a replacement:** these are ablations on E2. No P1c is substituted.

## 23. Theoretical properties

1. **Complexity:** O(n log n), with one SHA-256 per candidate per hash use. No pairwise
   structure.
2. **Determinism:** fixed input and seed give a fixed order, independent of input order
   (tested).
3. **Duplicates:** a repeated event does not create a candidate. Grouping is by address.
4. **Weaker candidates:**
   - **Theorem:** for a bucket T with best bits b, a candidate with bits < b, added anywhere,
     cannot precede T's first member. Its priority is ≤ its bits < b, and it never raises
     another member's priority.
   - **Not claimed:** a weaker leader of *another* bucket *can* precede a **non-leading**
     member of T. That member's priority is b − 4j (counterexample §24.5).
   - **20,000 trials:** 0 breaks of the theorem, 0 breaks of the bound.
5. **Equal-score candidates:** order among equals is decided by the keyed hash. Under a known
   seed this is attacker-controllable by grinding (§25).
6. **Group-level rank bound:** the first member of T sits at a position
   ≤ 1 + Σ_{g ≠ T, best_g ≥ b} min(n_g, ⌊(best_g − b)/λ⌋ + 1). It does not depend on how many
   weaker candidates exist.
7. **Dependence on G:** with equal leaders the bound is about G, so group exposure at K
   needs G ≤ K. G is the victim's reference count, which the attacker cannot change.
8. **Group assignment:**
   - The attacker chooses which reference to imitate, but cannot create references.
   - A candidate that ties two references goes to the lexicographically larger one, a
     label-independent rule (§24.6).
   - The attacker can exploit this only by choosing an affix, which is within capability.
9. **Tie sensitivity:** see §22. Hash ties make the target's position among m equals uniform:
   exposure ≈ K'/(m+1).
10. **Observational equivalence:** if the target and m ≥ K decoys agree on every feature a
    selector reads, no deterministic selector whose tie rule the attacker knows can
    guarantee exposure. The adaptive attacker achieves this with 10 addresses (§18).

## 24. Minimal counterexamples [E3]

**Search:** 20,000 random populations, shrunk greedily. Each counterexample below is feasible
under the threat model, and **none breaks an invariant.**

1. **P1b loses to B0 (K = 1), 2 candidates:** two 32-bit lookalikes of the same reference,
   with the target newer. B0's recency tie-break puts the target first; P1b's hash puts the
   other first.
2. **P1b loses to pure group rotation (K = 1), 2 candidates:** a 24-bit target and a 32-bit
   candidate on the same reference. Rotation ignores similarity, and its hash happens to put
   the target first.
3. **P1b's group not exposed (K = 1), 2 candidates:** a 24-bit target, and a 32-bit leader
   on another reference that rightly comes first.
4. **Equal-leader tie lost, 2 candidates:** two 32-bit leaders of different references. The
   bucket hash decides; under a public seed it is predictable but not attacker-choosable,
   because references belong to the victim.
5. **Weaker decoy displaces a non-leading target, 4 candidates:**
   - the target is the 3rd of three 28-bit members of its bucket (priority 20);
   - a 24-bit leader of another bucket (priority 24) precedes it.
   This is the group discount working as designed.
6. **Multi-reference assignment:** a candidate that matches two references at 3+3 is assigned
   to the lexicographically larger.

## 25. Public versus secret tie-breaking

**Public seed (K1).** An attacker can grind addresses whose member hash beats the target's,
at a cost of about 1/F(h_t) generated addresses per kept decoy.
- Grinding was part of the best attack against P1/P1b at every budget.
- B6 is also defeated at W = 10 for K = 5.

**Secret seed (K2, diagnostic).** It raised the budget needed to displace past K = 10 only for
B6 (10 → 100). For P1/P1b it changed little (displaced share 0.83 vs 0.75 at W = 10), because
own-group equal floods win without grinding.

**Conclusion:** a secret seed does not rescue P1b. Its operational assumption (the seed never
appears in configuration or evidence) is also fragile. No production secrets were introduced.

## 26. Statistical uncertainty

- **Unit:** the template (225 primary). Replicates within a template are not independent
  incidents.
- **Method:** stratified template-cluster bootstrap.
- **Counts:**
  - E2: 7,200 scenarios (6,480 primary);
  - 5,079,472 candidates (never treated as independent observations);
  - target identities: one per scenario (three in F9).
- **The E3 adaptive study** has 12 victims and is exploratory (no CI).

## 27. Existing incident regression [E4] — known development cases, not independent validation

| Window | Paid is a candidate | B0 | B1 | B4 | B6 | P1 | P1b | Pagination |
|---|---|---|---|---|---|---|---|---|
| ScamSniffer `/1` | no (native dust not recorded) | — | — | — | — | — | — | all 2 groups reachable |
| ScamSniffer blind `/2` | yes | 1 | 3 | 1 | 1 | 1 | 1 | all 3 reachable |
| Pilot | yes | 3 | 2 | 3 | 3–5 | 3–5 | 3–5 (seed 0: 5) | all 6 reachable |

These are identical to Phase 12.7. Nothing was tuned on them.

## 28. Performance

**Ordering only, on generated groups:**

| Candidates | B0 | P1b |
|---|---|---|
| 100 | <0.001 s | 0.003 s |
| 1,000 | 0.007 s | 0.045 s |
| 10,000 | 0.116 s | 0.404 s |
| 100,000 | 1.23 s | **4.79 s** |

**Whole run:**
- E2: 1,303 s for 7,200 scenarios × 19 methods;
- E3: 45 s;
- total: 1,379 s.

## 29. Memory

- **Traced peak:** P1b 30.3 MiB and B0 27.4 MiB at 100,000 candidates.
- **Process peak RSS:** 310 MiB for the whole study, in one process with streaming aggregation.
- **Preflight free RAM:** 804 MiB.

## 30. Production isolation

- Research-only modules (`adaptive_validation.py`, CLI `ml adaptive-validation`).
- `adversarial_ranking.py` is unchanged and verified by hash.
- The detector, its warnings and severities are untouched.
- No new dependency. numpy is used only in the bootstrap, imported lazily.
- No evidence is deleted.

## 31. Positive findings

1. P1b's reference grouping helps when *other* references are flooded: +0.14 address,
   +0.12 group exposure (F2).
2. P1b is time- and mechanism-invariant (flat across 8 age and 5 mechanism relations). Its
   worst timing case is 0.42, against B0's 0.31.
3. Reference-group exposure is better than B0's: +0.032 [0.024, 0.041].
4. The 12.7 theorem holds (0 breaks in 20,000 trials). Fidelity 30/30; reproducible.
5. The debiased benchmark works: the null family is at chance, and the controls behave as
   designed.

## 32. Negative findings

1. **H1 is not supported after debiasing.** P1b − B0 = −0.018 [−0.031, −0.004]. The 12.7
   gain was largely a benchmark artifact (the age bias).
2. **H2 is not supported.** An adaptive attacker displaces P1b's target with the same 10
   equal-tier addresses as B0's.
3. **A simpler baseline (B4) beats P1b** by 0.018 (CI excludes 0), just under the
   pre-registered 0.02 line.
4. **Hash ties cost against balanced timing** (recency-tie variant 0.468 vs 0.429).
5. **The worst family regresses:** −0.121 (F3).

## 33. Unresolved limitations

- **Synthetic only.** Real age, mechanism and reference distributions are unknown.
  Phase 12.1's archive found victims usually pay the *most recent* lookalike, which would
  favour B0's recency tie-break in non-adversarial data.
- **Adaptive study scope:** 12 victims and 48 attacks with a 2,000-decoy cap, not a full
  optimizer.
- **Proxies:** H5 used F10 bucket position as a proxy (P1b 0.48–0.58, no drift). It does not
  isolate group-size bias as directly as the 12.7 test did.
- **Similarity model:** exact hex affixes only.

## 34. Independent real-world validation requirements

**Untouched poisoning incidents with:**
- several genuine reference recipients;
- the paid address and its reference (from the harm transaction, used only for scoring);
- an `observation/2` window to H − 1;
- no wallet, campaign or cohort overlap;
- the frozen methods (B0, B4, P1b; seed recorded).

**Measures:**
- address and reference-group exposure separately;
- the age distribution of the paid lookalike relative to its rivals, which decides whether
  recency or hash ties are better in reality.

**Feasibility and cost:**
- 10 incidents is only a feasibility check; about 70 are needed for a powered paired test;
- about 700 to 1,300 RPC requests per window;
- **0 requested here.**

## 35. Final scientific conclusion

**Classification: not supported after debiasing** (pre-registered).

**What happened.** P1b's 12.7 advantage over similarity-first does not survive a benchmark
without the target-age, mechanism, reference-position and address-order shortcuts.
- **Average:** recency tie-breaking (B0) does as well or better than P1b's hash ties whenever
  the attacker does not control timing.
- **Simpler alternatives:** reference round-robin (B4) is slightly better than P1b.
- **Adaptive attacker:** an attacker who controls timing and can afford about 10 equal-tier
  lookalikes of the target's own reference defeats every method, P1b included. That is the
  identifiability limit.

**What survives, under a narrow threat model:**
- grouping by reference keeps a reference visible when *other* references are flooded;
- P1b is insensitive to timing, so it has the better worst case over timing.

**No learned model is justified:** the synthetic task has no real outcome signal, and
Phase 12.7's archive LTR learned only recency.

**Recommendation:**
- **Do not promote P1b.**
- **Treat reference-group exposure, not address exposure, as the defensible target** for
  warnings.
- **Settle the remaining question (recency vs hash ties) with real data, not more
  simulation.**

**Next experiment (not started).** On at least 10 untouched, multi-reference `observation/2`
incidents (about 70 for power):
- **Measure:** whether the paid lookalike's reference group is exposed within the top 5 under
  B4 vs B0, and where the paid lookalike sits in time among its equal-similarity rivals.
- **Labels:** the paid address and its reference.
- **Cost:** about 700 to 1,300 RPC requests per window.
- **Falsification:** reference-group exposure does not differ between B4 and B0 (cluster
  sign test, one-sided α = 0.05, over the discordant incidents), **or** the paid lookalike is
  not more often the newest among its equal rivals than chance. That second outcome would
  remove the reason to keep recency ties.

**Phase 12.8 is not started.**

## Gates

| Gate | Status | Basis |
|---|---|---|
| A Benchmark neutrality | **PASS** | diagnostics ≈ 0.5; null family at chance; age and mechanism controls behave as designed |
| B Historical correctness | **PASS** | selectors read pre-cutoff group features only; fidelity 30/30; no oracle field |
| C P1b improvement | **FAIL** | −0.018 [−0.031, −0.004] |
| D Adaptive robustness | **FAIL** | the same budget (10) displaces P1b and B0 |
| E Worst-family behaviour | **FAIL** | F3 −0.121; m = 10,000 −0.061 |
| F Target-group exposure | **PASS WITH LIMITATIONS** | reported separately: +0.032 [0.024, 0.041]; gains concentrated in other-group floods |
| G Tie-breaking | **PASS WITH LIMITATIONS** | the bucket-hash fix is neutral (no drift in F10; P1b − P1 +0.005); a public seed allows grinding |
| H Identifiability | **PASS** | the limit is stated and demonstrated (F3; adaptive own-group floods) |
| I Evidence preservation | **PASS** | permutations only; E4 pagination reaches every group |
| J Performance | **PASS** | 100,000 candidates in 4.8 s, 30 MiB; study 310 MiB |
| K Reproducibility | **PASS** | sealed manifest reproduced; 100-scenario re-evaluation identical |
| L Independent real-world validation | **BLOCKED BY DATA** | no untouched incidents |

## Validation

| Check | Result |
|---|---|
| `ruff check .` / `ruff format --check .` | clean / 302 files formatted |
| `mypy src` (Windows and `--platform linux`) | clean (156 files) on both |
| Full suite | **1,075 passed, 0 failed**, 4 deselected (15 min 27 s); 24 new tests in `tests/test_ml_adaptive_validation.py` |
| Frozen selectors | `verify_frozen` passed at run time (source and 6 config hashes) |
| Frozen cohorts | sheet and key hashes unchanged (`a0ec4b6e…`, `407b412f…`, `121c112d…`, `f333386d…`) |
| Incident fixtures | untouched (no data file modified) |
| Package and CI | recorded in the PR #1 description |

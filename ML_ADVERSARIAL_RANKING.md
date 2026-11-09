# Adversarial candidate ranking and robust top-K exposure (Phase 12.7)

| Item | Value |
|---|---|
| Protocol (frozen first) | [`docs/ml/protocol-12.7.md`](docs/ml/protocol-12.7.md), `9263dba` |
| Code (committed before the measured run) | `7ac195f` (`adversarial-selection/1`, `adversarial-ranking-study/1`) |
| Post-hoc additions (labelled throughout) | `541c2d2` (design-bias checks), `0968ff8` (P1b tie fix) |
| Measured runs | `7ac195f` (registered), then `0968ff8` (adds P1b and post-hoc checks). The rerun reproduces every registered number exactly. |
| Study output (git-ignored) | `data/ml/research/phase12.7/adversarial-ranking.json`, `posthoc-checks.json` (`cryptoguard ml adversarial-ranking [--posthoc]`) |
| RPC requests / downloads | **0** / none |

**Population labels used in every table:**
- **[SYN]:** synthetic, controlled adversarial robustness. Not real-world recall.
- **[ARCH-DEV]:** the 12.1 archive development split. Source-conditional.
- **[DEV-CASE]:** the two known incidents. Development-case analysis, not independent
  validation.
- **[POST-HOC]:** added after seeing results. Exploratory.

## 1. Executive summary

**The problem.** The 12.6.1 presentation order (B0: similarity, then recency) is cheap to
manipulate whenever decoys match the target's similarity. Recency is free for an attacker to
set, so newer equal-affix decoys bury an older target.

**The proposed selector, P1: work-weighted, group-discounted selection.**
- **Grouping:** candidates are grouped by the victim reference they imitate.
- **Priority:** each one gets `4·affix − 4·j`. The affix term is the key-search work in bits;
  j is the candidate's 0-based rank within its group.
- **Never read:** time, the support level, and the target.
- **Provable bound:** a reference group's first member cannot be displaced by any number of
  weaker decoys, and its worst position is bounded independently of the decoy count.

**Pre-registered result [SYN], H1 supported:**

| | Mean Exposure@K (16 families × 5 decoy counts × 6 K) |
|---|---|
| **P1** | **0.773** |
| B0 | 0.525 |
| Recency first (B1) | 0.304 |

P1 is ≥ B0 in 16 of 16 families and worse in none.

**Pre-registered checks:**
- **H2:** P1 never covers the target's group less often than B0, in 0 of 480 cells. The bound
  held in every cell (0 violations).
- **H3:** recency-first is defeated by m ≥ K newer decoys of any affix, while B0 and P1 keep a
  stronger target at rank 1 for every m up to 10,000.

**What the negative controls caught [POST-HOC].**
- "Oldest first" (0.986) and mechanism round-robin B3 (0.839) scored above P1. Both
  exploited benchmark choices the attacker controls. When an adaptive attacker plants decoys
  older than the target, or gives them the target's mechanism, each falls to 0.111.
- P1 is unaffected by either.
- Debugging also exposed a **P1 design flaw**: its between-group ties favoured flooded
  groups.
- **P1b** breaks those ties with a hash of the group. It reaches **0.813** and is ≥ B0 in
  16 of 16 families, but it is post hoc.

**Limits that no method beats [SYN].**
- Among more than K candidates equal in every feature, nothing guarantees exposure. P1's
  observed exposure matches the theoretical K/(m+1) (200-seed check), so an equal-affix flood
  of the *same* reference still hides the target's address.
- That flood does not hide the reference itself: the group stays visible, with its size.

**Machine learning [ARCH-DEV] does not add robust value (gate G FAIL).**
- A pairwise logistic ranker on the 12.1 development split beats similarity-then-recency by
  +0.289 top-1 [0.207, 0.371].
- It does no better than recency alone (+0.029 [−0.011, 0.070]): it learned recency (weight
  2.42).
- On the adversarial benchmark it reaches 0.356, below B0. The feature real victims follow
  (recency) is the one attackers control.

**Development cases [DEV-CASE]** add no evidence either way.
- **ScamSniffer blind `/2`:** the paid address is rank 1 under B0, P1 and P1b.
- **Pilot:** rank 3 under B0, and 3 to 5 under P1/P1b depending on the seed.
- These cases are not validation.

**Classification:**
- a controlled-robustness improvement with a proven bound;
- a negative ML result;
- an explicit identifiability limit.

**Independent validation: BLOCKED BY DATA.**

## 2. Research questions

| # | Question | Answer here |
|---|---|---|
| 1 | Cheap features | Recency, mechanism, repetition and value: §5–6 |
| 2 | Independent information | Affix work (attacker-costly); the reference bucket (victim-controlled) |
| 3 | When recency fails | Whenever m ≥ K newer decoys exist, at any affix (H3) |
| 4 | When similarity fails | Equal-affix decoys plus a recency tie-break (B0 in F5–F13) |
| 5 | Mechanism diversity | Only while decoys use a different mechanism ([POST-HOC]: 0.833 → 0.111) |
| 6 | Grouping | Reference grouping carries the gain (ablation: −0.196 without it) |
| 7 | Temporal / graph | Temporal is attacker-controlled; no graph context exists for these windows |
| 8 | Robust optimization | The group-discounted priority is the constrained form (§10, §14) |
| 9 | Unavoidable limits | Same-bucket equal floods: exposure ≈ K/(m+1) (§7) |
| 10 | Uncertainty | Bucket size, hidden count and the order label in the summary (§26) |

## 3. Existing ranking limitations

| Order | Weakness | Evidence |
|---|---|---|
| B0 (12.6.1) | recency ties | F7: the target goes from rank 1 to rank m+1 with 10 newer equal decoys |
| B1 | everything newer wins | F1: rank 10,001 with 10,000 weak dust decoys |
| B2 | support first | H5 (12.6); 0.531 here |

## 4. Formal threat model (protocol §2)

**The attacker controls:**
- lookalike addresses, up to a compute budget;
- planting time;
- repetitions, values and mechanisms (native dust, fake-token logs, zero-value
  `transferFrom`);
- how many addresses to use.

**The attacker does not control:**
- the victim's references, and so the number of reference buckets;
- the victim's signatures;
- finalized order and observed provenance.

## 5. Attacker capabilities

| Capability | Cost model |
|---|---|
| Lookalike with affix p+s of one specific reference | 2^(4(p+s)) expected key trials (uniform hex). Matching any of R references divides this by R. Checksum-case or fuzzy similarity are not modelled. |
| Event spam from an existing address | gas only (illustrative: native 21,000; zero-value ERC-20 about 40,000; fake-token log about 45,000) |
| Timing | free (any block before the cutoff) |
| Mechanism | free choice among the above |

## 6. Attacker budgets used [SYN]

| Family | Decoy affix (bits) | Cost of m = 10,000 (log2 trials; gas) |
|---|---|---|
| F1–F3 | 3+3 (24) | 37.3; 210 M / 450 M / 400 M |
| F5, F7, F9–F14 | 4+4 (32) | 45.3; 210 M |
| F4 | one 5+5 address (40), repeated | 40.0; 210 M |
| F6, F8, F16 | 4+4 (32), one reference | 45.3; 210 M |

**Illustrative throughput:** at 10⁹ keys per second, 2^32 trials take about 4 s and 2^40
about 18 min. Any real GPU budget will differ. The 2^40 figure applies only to a 5+5 match
of one reference, so no single work factor is assumed.

## 7. Identifiability limitations

- **L1 (any deterministic tie rule the attacker knows):** m ≥ K equal decoys can occupy every
  slot.
  - B0 in F6: Exposure@K = 0 whenever m ≥ K (H4 rows, all 0).
- **L2 (keyed hash):** expected exposure is min(1, K/(m+1)).
  - **The pre-registered tolerance failed:** P1 was within ±0.10 of theory in 19 of 22 rows
    with 10 seeds. The misses were m=10, K=3 (0.40 vs 0.27), m=10, K=5 (0.60 vs 0.45) and
    m=100, K=50 (0.70 vs 0.50).
  - **[POST-HOC] With 200 seeds** every row is within 1.0 SE. The largest gap is m=100, K=20:
    0.225 vs 0.198, SE 0.028. So the misses were sampling noise at n = 10, but H4 as worded
    is recorded as **not met**.
- **L3:** the target's *bucket* stays visible (§11 property 4), with the bucket size shown.
- **L4:** pagination preserves everything, but preservation is not exposure.

## 8. The candidate-exposure problem

The five stages are separate in the code:

| Stage | Implemented by |
|---|---|
| Generation | `candidate_evidence.build` (unchanged) |
| Scoring and ranking | `adversarial_ranking.order` / `select` |
| Exposure | `summarize`'s top K |
| Preservation | `page`, `group_records` |

`select` returns a labelled permutation: the method label and a config hash. The result
digest covers the order.

## 9. Baseline methods (identical candidate sets)

B0 similarity → recency; B1 recency → similarity; B2 level first; B3 mechanism
round-robin; B4 reference round-robin (λ = ∞, recency within); B5 cover-then-fill;
B6 B0 with keyed-hash ties. B7 (temporal anomaly) is B1, by Phase 12.5's equivalence (MAD ≡
recency on 1,056 of 1,056 episodes). There is no graph context for these windows.

## 10. The new selection algorithm

**P1 (registered).** For each reference bucket (or mechanism bucket, for unreferenced
candidates):
1. sort the members by bits ↓, then the keyed hash;
2. give member j the priority π = bits − λ·j, with λ = 4;
3. order globally by π ↓, then the bucket's best bits ↓, then the member's hash.

λ was fixed a priori: one hex character of key-search work per additional member of the same
bucket. The cost is O(n log n).

**P1b [POST-HOC].** P1 with the cross-bucket tie broken by `hash(seed, bucket)` instead of
the member's hash.
- **Why:** a flooded bucket's leader is the minimum of many member hashes, so P1 handed
  flooded buckets almost every tie. In F7 at m ≥ 100 the lone target was 5th of the 5 tied
  leaders in 10 of 10 seeds.
- **Theory:** the lone target trails all four flooded leaders with probability about 0.92.
  `test_registered_p1_ties_favour_flooded_buckets_and_p1b_does_not` checks it.

## 11. Mathematical properties

**Provable, and tested:**
1. Every selector returns a permutation: nothing added, removed or duplicated (14 selectors).
2. It is deterministic for fixed input and seed, and invariant to input order (NC-serial,
   all 16 families).
3. P1 reads no time, no level, no `missing` and no oracle (NC-time and NC-mech invariance in
   all 16 families; the `replace` test).
4. **Bucket displacement bound:**
   - the first member of bucket T sits at a position ≤ 1 + Σ over other buckets g of
     min(n_g, ⌊(best_g − best_T)/λ⌋ + 1), counting only buckets with best_g ≥ best_T;
   - at λ = ∞, each such bucket contributes at most 1;
   - **the bound does not depend on the number of weaker decoys;**
   - **0 violations** across the grid and in the tests.
5. A duplicate observation does not add a candidate (build deduplication, tested).

**Empirical [SYN]:** §14–21.

**Unsupported:**
- a malicious candidate guaranteed in the top K;
- resistance to unlimited equal-affix addresses;
- any real-world recall, false-positive rate or loss reduction.

## 12. Synthetic benchmark design [SYN]

- **Scenarios:** 16 families × m ∈ {0, 10, 100, 1,000, 10,000} × K ∈ {1, 3, 5, 10, 20, 50},
  with 10 seeds for hash methods.
- **Victim:** 5 genuine references.
- **Targets:** defined by construction and never read by any selector.
- **Definitions:** protocol §5.
- **Design choices the attacker could vary:** decoys newer than targets, decoys using a
  different mechanism, the target always on R1 with a low address. §20 tests these.

## 13. Primary robustness metrics

| Metric | Definition |
|---|---|
| Exposure@K | rank ≤ K, averaged over relevant candidates and seeds |
| TGC@K | the target's best-reference bucket appears in the top K |
| Displacement / attack cost | the smallest m in the grid with median first-relevant rank > K |
| Preservation | the order is a permutation (§11.1) |

Synthetic Exposure@K is not recall. Group coverage is not threat coverage.

## 14. Top-K results [SYN]

**Mean Exposure@K over every family and decoy count:**

| Method | K=1 | K=3 | K=5 | K=10 | K=20 | K=50 | Mean | Mean TGC |
|---|---|---|---|---|---|---|---|---|
| B0 | 0.400 | 0.500 | 0.500 | 0.500 | 0.625 | 0.625 | 0.525 | 0.650 |
| B1 | 0.183 | 0.250 | 0.250 | 0.263 | 0.438 | 0.438 | 0.304 | 0.504 |
| B2 | | | | | | | 0.531 | 0.656 |
| B3 | | | | | | | 0.839 | 0.877 |
| B4 | | | | | | | 0.801 | 0.915 |
| B5 | | | | | | | 0.751 | 0.865 |
| B6 | 0.401 | 0.523 | 0.579 | 0.620 | 0.629 | 0.710 | 0.577 | 0.694 |
| **P1** | 0.401 | 0.583 | 0.898 | 0.907 | 0.915 | 0.932 | **0.773** | 0.875 |
| P1b [POST-HOC] | 0.499 | 0.725 | 0.898 | 0.907 | 0.915 | 0.932 | 0.813 | 0.908 |
| NC-random | | | | | | | 0.387 | 0.581 |
| NC-revrec | | | | | | | 0.986 | 1.000 |

**H1 (registered):**
- P1 − B0 = **+0.248**;
- P1 ≥ B0 in **16 of 16** families;
- worst family difference **0.000**.

**Supported.** Section 20 explains why B3, B4 and NC-revrec above P1 are not robustness.

**Per family (mean over m and K):**

| Family | B0 | B1 | B4 | B5 | B6 | P1 | P1b |
|---|---|---|---|---|---|---|---|
| F1 native dust (3+3) | 1.000 | 0.267 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| F2 fake token (3+3) | 1.000 | 0.267 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| F3 zero value (3+3) | 1.000 | 0.267 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| F4 repetition (one 5+5) | 0.867 | 0.867 | 0.867 | 0.867 | 0.867 | 0.867 | 0.867 |
| F5 equal, all references | 0.267 | 0.267 | 0.267 | 0.267 | 0.357 | 0.333 | 0.337 |
| F6 equal, same reference | 0.267 | 0.267 | 0.267 | 0.267 | 0.360 | 0.360 | 0.360 |
| F7 recent, other references | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F8 reference overlap | 0.267 | 0.267 | 0.867 | 0.867 | 0.363 | 0.870 | 0.947 |
| F9 mixed mechanisms | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F10 unknown signer | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F11 missing receipt | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F12 partial history | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F13 contract-mediated | 0.267 | 0.267 | 0.867 | 0.733 | 0.350 | 0.737 | 0.827 |
| F14 one campaign, 3 relevant | 0.889 | 0.244 | 0.667 | 0.711 | 0.889 | 0.889 | 0.889 |
| F15 one among unrelated | 1.000 | 0.300 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| F16 3 relevant compete | 0.244 | 0.244 | 0.689 | 0.645 | 0.294 | 0.625 | 0.642 |

**Reading the table:**
- **F10–F13:** missing signer, missing receipt, partial history and value-moving pulls give
  results identical to F7. Missing evidence never moves a candidate (gate H).
- **Low m:** 0.267 corresponds to exposure only at m = 0 and at the m < K cells.

## 15. Attack-cost curves [SYN]

The smallest decoy count m in the grid that pushes the (median-seed) first relevant candidate
past K. "—" means it was never displaced up to 10,000.

| Family / method | K=1 | K=3 | K=5 | K=10 | K=20 | K=50 |
|---|---|---|---|---|---|---|
| F7 B0 | 10 | 10 | 10 | 10 | 100 | 100 |
| F7 B1 | 10 | 10 | 10 | 10 | 100 | 100 |
| F7 B6 | 10 | 10 | 100 | 100 | 100 | 1,000 |
| F7 **P1** | 10 | 10 | **—** | **—** | **—** | **—** |
| F6 B0 | 10 | 10 | 10 | 10 | 100 | 100 |
| F6 P1 | 10 | 10 | 100 | 100 | 100 | 1,000 |
| F1 B0 / B6 / P1 | — | — | — | — | — | — |
| F1 B1 | 10 | 10 | 10 | 10 | 100 | 100 |

**Cost in F7:** 10 decoys at 4+4 on other references cost about 2^35.3 key trials and
210,000 gas.
- **Under B0** this is enough at K ≤ 10.
- **Under P1** no budget in the grid (up to 10,000 decoys, about 2^45.3 trials) displaces
  the target past K = 5. The target competes only with the 4 other buckets' leaders.

**F6** is the identifiability family. Every method is displaced at roughly m ≈ K or 2K.

## 16. Temporal robustness [SYN]

- **H3 holds exactly:** in F1–F3, B0 and P1 are rank 1 at every m, while B1 is rank m+1.
- **[POST-HOC] decoys older than the target (F7 variant, mean over m ∈ {10, 100, 1,000}):**

  | Method | Exposure |
  |---|---|
  | B0 | 0.111 → 1.000 |
  | NC-revrec | 1.000 → 0.111 |
  | P1 | 0.695 (unchanged) |
  | P1b | 0.783 (unchanged) |

  B0's result therefore depends entirely on the attacker's choice of timing. P1's does not.
- **Same block:** decoys in one block are handled by the 12.6.1 suite. P1 never reads
  position.

## 17. Similarity robustness [SYN]

| Scenario | Result |
|---|---|
| Weaker affixes (F1–F3, 24 bits vs the target's 32) | never displace the target |
| Equal affixes on other references (F7) | P1 keeps the target within the first 5 (bound 1 + 4) |
| Equal affixes on the same reference (F6) | identifiability limit, ≈ K/(m+1) |
| Overlapping references (F8) | P1 0.870, P1b 0.947 vs B0 0.267. The decoys bucket under R2 (their best match), so R1's candidate keeps its own bucket. |
| One stronger repeated address (F4, 5+5) | collapses to 1 group. Everyone is rank 2 at m > 0. |

## 18. Mechanism diversity

- **B3 (mechanism round-robin)** scored 0.839 in the grid.
- **[POST-HOC]:** when the F7 decoys use the target's own mechanism (zero-value spoofs), B3
  falls to **0.111**. P1 stays at 0.695 and P1b at 0.783.
- **Conclusion:** mechanism is attacker-chosen, so mechanism diversity is not a robust
  exposure rule.
- **P1's mechanism buckets** (for unreferenced candidates) changed nothing: A-nomech is
  identical to P1, 0.7727.

## 19. Historical-recipient grouping

- **Grouping is what carries the gain.** B6 (λ = 0, no grouping) reaches 0.577; P1 reaches
  0.773.
- **Strict round-robin** (B4, or A-λ∞ at 0.762) hurts when one campaign has several strong
  candidates on one reference. In F14 it scores 0.667, against 0.889 for B0, P1 and P1b. The
  finite λ = 4 avoids that loss (H5: no loss).
- **B4's advantage over P1 in F7–F13 is an artifact.** B4 breaks bucket ties by reference
  address, and R1 happens to sort 3rd of 5. [POST-HOC] Averaged over the five possible target
  references:

  | Method | Exposure |
  |---|---|
  | B4 | 0.800 (0.667–1.000 depending on the reference) |
  | P1b | 0.800 |
  | P1 | 0.687 |

- **H2 (P1):** TGC ≥ B0 in every cell (0 of 480 below).
- **P1b [POST-HOC]** is below B0 in 4 cells, all F16 at K = 1. There a single slot goes to
  a tie between the flooded bucket and R2, which holds another relevant candidate. B0 "covers"
  the target's bucket there only because the flood itself sits in it. F16's relevant exposure
  is still 0.642 for P1b vs 0.244 for B0.

## 20. Negative controls

| Control | Result | Interpretation |
|---|---|---|
| NC-random | 0.387 | about K/n |
| NC-revrec (oldest first) | **0.986** | **design bias:** every target is older than its decoys. [POST-HOC] It falls to 0.111 with older decoys. |
| B3 high | 0.839 | design bias (mechanism); falls to 0.111 (§18) |
| Address order | M-LTR-noR scores 1.000 on F6 | the target's address sorts first among equals, and address is its final tie-break. [POST-HOC] With a non-first address, F6 gives B0/B4/B5 0.111 and P1/P1b 0.295. |
| NC-serial | identical order, all methods, all families | |
| NC-time / NC-mech (P1) | identical, all families | |
| NC-signer (1,000 unrelated foreign-signed pulls) | P1 rank 5 → 5, B0 1,001 → 1,001, B1 1,001 → 2,001 | adds 1,000 unreferenced groups |
| NC-public-token (1,000 zero-value strangers) | same as above | same |

**Every control that looked too good was traced to a benchmark choice an adaptive attacker
controls.** P1 and P1b were insensitive to each such choice.

## 21. Ablation study [SYN] (mean Exposure@K)

| Variant | Mean | Δ vs P1 |
|---|---|---|
| P1 | 0.7727 | — |
| A-nosim (no affix) | 0.6272 | −0.146 |
| B6 = A-λ0 (no reference grouping) | 0.5769 | −0.196 |
| A-λ2 | 0.7701 | −0.003 |
| A-λ8 | 0.7672 | −0.006 |
| A-λ∞ | 0.7615 | −0.011 |
| A-rec (recency ties within a bucket) | 0.7597 | −0.013 |
| A-nomech | 0.7727 | 0.000 |
| P1b (bucket ties) [POST-HOC] | 0.8126 | +0.040 |

**What contributes:**
- reference grouping, together with affix work;
- λ is insensitive between 2 and 8;
- mechanism bucketing adds nothing.

**H6:** no simpler variant matched P1 within 0.01 except A-nomech. The simpler equivalent,
one unreferenced bucket, is therefore preferred.

**Not ablated:**
- coverage metadata: never ranked, so identical by construction;
- graph context: NOT EVALUATED, none exists.

## 22. ML feasibility [ARCH-DEV]

**Feasibility rule:** passed.
- 640 evaluable development episodes, 185 validation groups, real payoff labels;
- temporal internal split: 448 fit / 192 validation;
- 1 protected-overlap episode excluded;
- **the 12.1 test split was dropped before feature computation.**

**Weights (standardized):**

| Model | S | S missing | R | N |
|---|---|---|---|---|
| M-LTR | 0.129 | 0 | **2.417** | 0.214 |
| M-LTR-noR | 0.389 | 0 | — | 0.363 |

**Validation:**

| Method | Top-1 | MRR |
|---|---|---|
| Random | 0.211 | 0.423 |
| S (similarity) | 0.340 | 0.540 |
| S then R (= B0) | 0.461 | 0.642 |
| R (recency) | 0.721 | 0.838 |
| **M-LTR** | **0.750** | **0.859** |
| M-LTR-noR | 0.456 | 0.636 |

**Paired comparisons (group bootstrap; group sign-flip p):**
- M-LTR vs B0: **+0.289 [0.207, 0.371], p < 0.001**;
- M-LTR vs R: **+0.029 [−0.011, 0.070], p = 0.25**;
- M-LTR-noR vs B0: −0.005 [−0.073, 0.068].

**Adversarial transfer [SYN], mean Exposure@K:**

| Model | Exposure | vs B0 (0.525) |
|---|---|---|
| M-LTR | 0.356 | **−0.169** |
| M-LTR-noR | 0.661 | — |

M-LTR-noR's figure includes the address-order artifact of §20.

**Gate G: FAIL.**
- Criterion 1 holds: the gain over B0 has a CI that excludes 0.
- Criterion 2 fails: −0.169, against the 0.05 allowed.
- The model learned recency, the feature real victims follow and attackers control. It adds
  nothing over recency alone.

## 23. Source-shift analysis [ARCH-DEV]

| Fit vs validation | Fit | Validation |
|---|---|---|
| Age of last planting (blocks) | q10 5,713 / q50 151,746 / q90 517,934 | 34,712 / 555,903 / 1,033,679 |
| Candidates per episode | 2 / 4 / 15 | 2 / 6 / 29 |
| S (affix) | 7 / 8 / 10 | 7 / 8 / 14 |

**Validation top-1 by candidate count:**

| Candidates | M-LTR | R | B0 |
|---|---|---|---|
| 2 (n = 33) | 0.939 | 0.924 | 0.727 |
| 3–5 (n = 53) | 0.793 | 0.830 | 0.594 |
| 6+ (n = 106) | 0.670 | 0.604 | 0.311 |

The validation period has older plantings and larger candidate pools. Recency still holds
there, so the archive does not reproduce the Phase 12.5 failure mode. It is a
non-adversarial population: attackers were not gaming a ranker.

## 24. Existing incident regressions [DEV-CASE]

Rank of the paid lookalike, at the existing cutoffs:

| Window | Groups | B0 | B1 | B2 | B6 | P1 | P1b | M-LTR | M-LTR-noR | C2 list (own set) |
|---|---|---|---|---|---|---|---|---|---|---|
| ScamSniffer `/1` | 2 | not a candidate | — | — | — | — | — | — | — | not listed |
| ScamSniffer blind `/2` | 3 | 1 | 3 | 1 | 1 | 1 | 1 | 2 | 1 | 1 of 3 |
| Pilot | 6 | 3 | 2 | 2 | 3–5 | 3–5 (seed 0: 5) | 3–5 | 2 | 2 | 5 of 6 |

**Notes:**
- In ScamSniffer `/1` the paid native dust was never recorded (the Phase 12.3/12.4 finding).
- On the pilot, P1 and P1b are seed-dependent. Seed 0 puts the paid address 5th, worse than
  B0's 3rd, because the paid address ties with other lookalikes.
- **No method was tuned on these cases. Development-case analysis, not independent
  validation.**

## 25. Evidence completeness

Selectors never read `level`, `missing` or `receipt`. F10–F13 (missing signer, missing
receipt, partial history, value-moving pulls) behave identically to F7. Unknown evidence stays
listed in each group (tested). **Gate H: PASS.**

## 26. Candidate preservation

**Every selector is a permutation** (tested across 14 selectors). The summary keeps the
12.6.1 contract and adds:
- `order`, the method label (e.g. `P1[lam=4]`);
- `order_config`, a 16-hex config hash;
- each item's `reference_bucket` and `bucket_size`.

**Pages and the digest:**
- pages carry the order;
- the digest covers the order;
- a test pages through a P1-ordered result and reaches every group.

**Display:** an equal-affix flood shows "1 of N candidates imitating R" rather than hiding R.

## 27. Runtime (selection only, on top of evidence groups; run on `0968ff8`)

| Groups | B0 | P1 | P1 groups/s | Summary JSON | Page JSON |
|---|---|---|---|---|---|
| 100 | <0.001 s | 0.002 s | 41,533 | 7.6 KB | 7.1 KB |
| 1,000 | 0.003 s | 0.025 s | 39,277 | 7.7 KB | 7.1 KB |
| 10,000 | 0.055 s | 0.341 s | 29,327 | 7.7 KB | 7.2 KB |
| 100,000 | 0.583 s | 3.83 s | 26,140 | 7.7 KB | 7.2 KB |

- **Why P1 is slower:** it hashes every candidate (SHA-256). It is still O(n log n).
- **Whole study:** 196 s on `0968ff8`, 245 s on `7ac195f`.
- **Learning to rank:** archive load 30 s, total 70 s.

## 28. Memory

- **P1 selection:** 29.3 MiB traced at 100,000 groups (B0: 23.2 MiB).
- **Process peak RSS:** 432 MiB for the whole study.
- **Preflight free RAM:** 1,320 MiB (`7ac195f`) and 1,247 MiB (`0968ff8`).

## 29. Production isolation

- The detector is unchanged (`detector_outputs` is identical before and after selection,
  tested).
- The selectors are reachable only through `cryptoguard ml adversarial-ranking`.
- No new dependency. scikit-learn is used only in the archive LTR, lazily imported.
- No finding is suppressed and no severity is changed. **Gate J: PASS.**

## 30. Statistical limitations

- **[SYN]:** deterministic, with no sampling population. Differences are exact for these
  scenarios and say nothing about real prevalence.
- **Hash methods** use 10 seeds; H4 needed 200 (§7).
- **[ARCH-DEV]:** 192 validation episodes in 185 groups. It is source-conditional (the
  attacks succeeded, so payoff happened) and non-adversarial.
- **[DEV-CASE]:** n = 2 incidents, both seen before.
- **Post hoc:** P1b and the design-bias checks were added after the results. They are
  hypotheses for the next test, not findings.

## 31. Positive results

1. A selector with a proven, decoy-count-independent group displacement bound. It held with
   0 violations.
2. H1 supported: +0.248 Exposure@K over B0, with no family worse.
3. Time-invariance: newer or older decoys change nothing (B0 swings between 0.111 and 1.000).
4. H3 confirmed: B0 and P1 resist floods with weaker affixes at any m.
5. Missing evidence never changes the order.
6. Bounded summaries, now with the order label, config hash and bucket sizes.

## 32. Negative results

1. ML (pairwise LTR) adds no robust value: it learns recency (gate G FAIL).
2. Mechanism diversity (B3) and oldest-first are not robust; each falls to 0.111 against an
   adaptive attacker.
3. H4's pre-registered 10-seed tolerance was not met. 200 seeds confirm the theory.
4. Registered P1 had an attacker-favourable tie rule (P1b fixes it, post hoc).
5. Strict round-robin loses 0.22 when one campaign holds several strong candidates on one
   reference (F14).

## 33. Remaining failure modes

- **Same-reference equal-affix floods** hide the address, though not the reference (L1/L2).
- **K = 1:** five tied bucket leaders compete for a single slot.
- **A public seed** lets an attacker grind addresses against the keyed hash. A deployment
  would need a secret seed.
- **Benchmark scope:** five references, and decoys modelled at 3+3 to 5+5. Similarity
  definitions other than exact hex affixes are not modelled.
- **Real windows:** 0 to 6 groups each, so no real flood has been observed. Robustness under
  floods is measured only on synthetic data.

## 34. Independent benchmark readiness

**Required per incident:**
- verified chain, victim address and harmful transaction;
- planting evidence;
- an `observation/2` window to H − 1 with evidence completeness recorded;
- campaign grouping;
- independent source provenance.

**Controls:**
- no wallet, campaign or protected-cohort overlap with development;
- the selectors frozen at `0968ff8` (B0, P1, P1b with a recorded seed);
- generation and ranking metrics reported separately;
- missingness reported.

**Size:** 10 incidents is a feasibility milestone. To show a paired Exposure@5 difference
with a sign test, about 20 discordant clusters are needed. At an assumed 30 % discordance
that is about 70 incidents.

**RPC:** about 700 to 1,300 requests per window (recorded 12.3/12.4 costs), so 10 incidents
need about 7,000 to 13,000 and 70 need about 50,000 to 90,000. **No requests made.**

**Remaining dependency:** user-sourced incidents with harm-transaction hashes and **more
than one reference recipient**. Single-reference victims cannot separate P1 from B0.

## 35. Next experiment

**Question.** On untouched, multi-reference poisoning victims recorded with `observation/2`,
does P1b expose the paid lookalike's reference bucket within the top 5 more often than B0?
- Frozen at `0968ff8`, with a secret seed.
- B0 and P1b are run on identical groups.

**Data and labels:**
- at least 10 incidents for feasibility, and about 70 for a powered sign test;
- labels: the paid address and its reference, from the harm transaction, used only for
  scoring.

**Cost:** about 700 to 1,300 RPC requests per window. Analysis takes seconds.

**Falsification:** P1b fails if, over the incidents where B0 and P1b disagree on exposing the
paid lookalike's bucket in the top 5, B0 exposes it at least as often (cluster sign test,
one-sided α = 0.05).

**Not started. Phase 12.8 is not started.**

## Gates

| Gate | Status | Basis |
|---|---|---|
| A Historical correctness | **PASS** | pre-cutoff features only; time-invariance; later events change nothing (test); LTR test split never computed |
| B Candidate preservation | **PASS** | permutation for all selectors; pages reach every group |
| C Exposure robustness | **PASS WITH LIMITATIONS** | H1 supported [SYN]; benchmark biases found and characterized |
| D Similarity attacks | **PASS WITH LIMITATIONS** | bounded across references; identifiability limit within a reference |
| E Recency attacks | **PASS** | P1 is time-invariant; H3 confirmed |
| F Diversity trade-offs | **PASS WITH LIMITATIONS** | λ = 4 avoids the F14 loss; P1b loses TGC at K = 1 in F16 |
| G ML contribution | **FAIL** | no gain over recency; −0.169 adversarially |
| H Missingness | **PASS** | levels and `missing` never read; F10–F13 identical to F7 |
| I Runtime and memory | **PASS** | 100,000 groups in 3.8 s, 29 MiB; study 432 MiB |
| J Production isolation | **PASS** | detector unchanged (tested) |
| K Reproducibility | **PASS** | the rerun at `0968ff8` reproduced every registered number |
| L Independent validation | **BLOCKED BY DATA** | no untouched incidents |

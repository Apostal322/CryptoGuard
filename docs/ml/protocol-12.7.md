# Protocol 12.7: adversarial candidate exposure, robust top-K selection, learning-to-rank

**Frozen:** 2026-11-09, in the commit that adds this file. That is before any code for the
proposed selector, the benchmark or the learning-to-rank study exists, and before any result
is computed.

**Base:** `5e37788` (`candidate-evidence/2`).

**RPC budget:** 0.

**Already known before freezing.** These are development facts, and nothing here counts them
as new evidence:
- the Phase 12.6.1 adversarial suite (rank 1 in 8 of 9 scenarios; rank 10,001 under 10,000
  later equal-affix decoys);
- the H5 result (support-first order loses);
- Phase 12.1's finding that recency (`T0`) best predicts which lookalike a victim paid, on its
  test split. That split is never used again here.

## 1. Problem

The current pipeline has five separate stages:

| Stage | What it is | Where it lives |
|---|---|---|
| Generation | evidence groups | `candidate_evidence.build` |
| Scoring | a per-group priority | new |
| Ranking | the full order | new |
| Exposure | the first K of that order | `summarize` |
| Preservation | every group and record reachable | `page`, `group_records` |

Phase 12.7 changes only scoring and ranking, and adds metadata to exposure. Generation and
preservation are unchanged.

## 2. Threat model

**The attacker controls:**
- the lookalike addresses they generate, and their similarity to a victim reference, within
  a compute budget;
- planting time (any block before the cutoff, earlier or later than any other planting);
- repetitions, values and mechanisms: native dust, fake-token logs, zero-value
  `transferFrom` and other foreign-signed transfers;
- how many addresses and transactions they use;
- the distribution of that activity across accounts.

**The attacker does not control:**
- the victim's genuine payments, and so the set of references, whose size G_R is fixed by the
  victim's history;
- the victim's signatures;
- finalized chain order;
- provenance that is already observed.

Unknown information (signer, receipt, token identity, history) stays unknown. It is never
trusted, and it is never ranked.

**Work-factor model (illustrative, not a universal cost).** Take one specific reference R. A
uniformly random address matches its first p and last s hex characters with probability
16^−(p+s). The expected number of key trials is therefore 16^(p+s) = 2^(4(p+s)).
- **Bits of an affix:** `bits = 4(p+s)`.
- **Matching any of R references** costs about 2^(4(p+s)) / R, so the per-reference budget is
  what matters.
- **Other similarity definitions** (case-sensitive checksums, fuzzy or edit distance) have
  other work factors and are not modelled.
- **Event spam** (repeating events from an existing address) costs gas only. Illustrative
  amounts: native transfer 21,000 gas; zero-value `transferFrom` about 40,000; fake-token
  log about 35,000 to 50,000.
- **Reporting:** in key trials and gas units, never in USD.

## 3. Identifiability limits, stated before any experiment

**L1.** Suppose m+1 candidates are equal under every feature an ordering may read, with
m ≥ K. Then for any deterministic ordering whose tie rule is known to the attacker, the
attacker can place the m decoys ahead of the target, so Exposure@K = 0 in the worst case.
- **Recency:** the attacker chooses planting time.
- **Address order:** the attacker grinds addresses.
- **A public-seed hash:** the attacker grinds addresses against it.

**L2.** A keyed hash with a seed the attacker does not know makes the order of equals
uniformly random from the attacker's point of view. The expected exposure of the target
among m+1 equals, with K' slots available to them, is min(1, K'/(m+1)). This tends to 0 as m
grows. It is a probability, not a guarantee. In this study the seed is fixed and public, for
reproducibility, so L2 is measured over 10 seeds as a model of a secret seed.

**L3, group exposure.** Group candidates by the reference they imitate. The number of
reference groups is at most the victim's reference count plus a fixed number of
mechanism buckets for unreferenced candidates, and the attacker cannot increase it. A
selector that reserves exposure per group can therefore bound when the target's *group*
appears, independently of m, while candidate-level exposure inside a flooded group stays
under L1/L2.

**L4. Pagination** always preserves every candidate. It is not exposure.

## 4. Methods (identical candidate sets: the groups of one `build`)

**Features read, all available before the cutoff:**
- `bits` = 4 · affix, or 0 without a reference;
- the best reference, the one with the highest affix, ties going to the lexicographically
  smallest;
- last and first position;
- mechanisms.

Support level, `missing` and receipt status are never read (12.6.1 A3). The oracle target is
never read.

**Bucket:** the best reference. A candidate with no reference goes to the bucket of its
mechanism signature, `mech:<sorted mechanisms>`.

**Keyed hash:** `h = sha256(f"{seed}:{lookalike}")`.

| Id | Order |
|---|---|
| B0 | similarity first: bits ↓, last position ↓ (recency), address (the 12.6.1 presentation order) |
| B1 | recency first: last position ↓, bits ↓, address |
| B2 | evidence level first (negative reference only; H5 failed) |
| B3 | mechanism round-robin: buckets by mechanism signature, ordered by their best B0 member; B0 order within; take one per bucket per round |
| B4 | reference round-robin (λ = ∞): buckets ordered by best bits ↓ then bucket key; B0 order within; one per bucket per round |
| B5 | cover then fill: the B0-best member of every bucket first (in B0 order), then everything else in B0 order |
| B6 | B0 with keyed-hash ties: bits ↓, h, address |
| B7 | temporal anomaly: equivalent to B1 (Phase 12.5 showed MAD ≡ recency on 1,056 of 1,056). Not re-implemented; B1 stands in for it. No graph features exist for these windows. |
| **P1** | **work-weighted, group-discounted selection (WGS)**, below |

**P1 (proposed).**
- **Within each bucket,** order the members by bits ↓, then h, then address. Member j
  (0-based) gets priority `π = bits − λ·j`, with **λ = 4 bits**.
- **Globally,** order by π ↓, then the bucket's best bits ↓, then h, then address.
- **Reading λ = 4:** the j-th lookalike of the same reference must be one hex character
  more similar than a lookalike of another reference to be shown before it.
- **λ is fixed a priori by the work-factor model.** Values 0, 2, 8 and ∞ are sensitivity
  analyses only, and the primary result uses λ = 4.
- **Recency is not read by P1.**
- **Cost:** O(n log n), with no pairwise structure.

**P1's provable properties, each tested:**
1. It is a permutation of the input groups, so nothing is added, removed or duplicated.
2. It is deterministic for fixed input and seed, and invariant to input order.
3. It reads no oracle, no support level and no time.
4. **Bounded group displacement.** Let the target's bucket have best bits b, and let every
   other bucket contain only members with bits ≤ b_A. Then the first member of the target's
   bucket sits at position ≤ 1 + Σ_{other buckets} min(n_g, ⌊(b_A − b)/λ⌋ + 1) when
   b_A ≥ b, and ≤ 1 + (number of other buckets whose best bits are > b, plus ties) when
   b_A < b. Either way the bound does not depend on the number of decoys m. B0's
   displacement grows with the count of decoys with bits ≥ b.

**Ablations of P1:**

| Id | Change |
|---|---|
| A-nosim | bits := 0 (pure bucket rotation in hash order) |
| A-rec | ties within a bucket broken by recency instead of h |
| A-λ0 | λ = 0, which equals B6, i.e. no reference grouping |
| A-λ2, A-λ8 | λ = 2, λ = 8 |
| A-λ∞ | λ = ∞ (round-robin with hash ties) |
| A-nomech | all unreferenced candidates in one bucket |

**Not ablated:**
- **coverage metadata:** reported, never ranked, so the ablation is identical by
  construction;
- **graph context:** none exists for these windows, so NOT EVALUATED.

**Negative controls:**

| Id | Control | Expected |
|---|---|---|
| NC-random | seeded random permutation | Exposure@K ≈ K/n |
| NC-revrec | oldest first | — |
| NC-time | P1 with planting blocks randomly permuted among candidates | identical order (P1 reads no time) |
| NC-mech | P1 with mechanism labels shuffled among referenced candidates | identical |
| NC-serial | every method on shuffled input order | identical |
| NC-signer | add foreign-signed outgoing transfers to non-lookalikes | target rank unchanged |
| NC-public-token | zero-value USDT from many unrelated strangers | at most unreferenced buckets; target exposure unchanged |

## 5. Synthetic benchmark (controlled adversarial robustness; not real-world recall)

**Base window:** the `reliability_study.wallet_fixture` builder, with a victim that has 5
genuine references R1–R5 (wallet-signed payments, blocks 1,100–1,500) and a cutoff of
(9,001, 0). The target(s) are defined by construction (oracle) and never encoded in features.
- **Decoy count m:** {0, 10, 100, 1,000, 10,000}.
- **K:** {1, 3, 5, 10, 20, 50}.
- **Seeds for hash methods:** 0–9.
- **Unless stated:** the target is a zero-value foreign-signed `transferFrom` to a 4+4
  (32-bit) lookalike of R1 at block 2,000, and decoys are newer (blocks ≥ 3,000), assigned to
  references round-robin.

| Family | Target(s) | Decoys (m) |
|---|---|---|
| F1 native dust flood | default | native dust, 3+3, R1–R5 |
| F2 fake-token flood | default | incoming fake-token logs, 3+3, R1–R5 |
| F3 zero-value flood | default | incoming zero-value USDT, 3+3, R1–R5 |
| F4 repetition | default | m native dust repeats from **one** 5+5 lookalike of R2 |
| F5 distinct equal lookalikes | default | native dust, 4+4, R1–R5 |
| F6 equal similarity, same reference | default | native dust, 4+4, **R1 only** (identifiability family) |
| F7 recent decoys, other references | default | native dust, 4+4, R2–R5 |
| F8 reference overlap | default; R2 shares a 3-character prefix and suffix with R1 | native dust, 4+4 of R2 |
| F9 mixed mechanisms | one 4+4 lookalike of R1 with a spoof, native dust and zero-value USDT in (3 records) | 4+4, R2–R5, cycling native / fake token / zero value |
| F10 unknown signer | spoof with an unknown signer (R-SIG) | native dust, 4+4, R2–R5 |
| F11 missing receipt | native dust from a 4+4 lookalike of R1, receipt unknown | verified native dust, 4+4, R2–R5 |
| F12 partial history | spoof with an unknown signer, signed set `partial` (unverified) | native dust, 4+4, R2–R5 |
| F13 contract-mediated | value-moving foreign-signed USDT pull to a 4+4 lookalike of R1 (`foreign_initiated_out`) | native dust, 4+4, R2–R5 |
| F14 one campaign, several relevant | 3 spoofs, 5+5 lookalikes of R1 | native dust, 4+4, R2–R5 |
| F15 one among unrelated | spoof, 3+3 of R1 | m unrelated: half native from non-lookalike strangers, half zero-value USDT from strangers |
| F16 several relevant compete | spoof 4+4 of R1; native 4+4 of R2; zero-value USDT in 3+3 of R3 (blocks 2,000–2,200) | native dust, 4+4, **R1 only** |

## 6. Metrics

- **Exposure@K:** 1 if a relevant candidate's rank ≤ K. Averaged over the relevant candidates
  of a cell, and over seeds for hash methods.
- **Exposure rank and rank displacement:** rank(m) − rank(0).
- **Attack cost to displacement:** the smallest m in the grid with rank > K (∞ if none),
  translated by the cost model into decoy-address work (m · 2^bits_decoy trials, divided by
  the references used) and gas.
- **Target-group coverage@K (TGC@K):** whether any member of the target's best-reference
  bucket is within the top K. Group coverage is not threat coverage.
- **Preservation:** whether the ordering is a permutation of `build`'s groups; checked
  exactly.
- **Determinism:** digest equality on a repeated run.
- **Runtime and memory:** wall time, tracemalloc peak and process peak RSS.

Synthetic Exposure@K is not real-world recall.

## 7. Hypotheses and decision criteria

The benchmark is deterministic: differences are exact, not samples, so no p-values are
computed for it.

- **H1 (primary).** Over all 16 families × 5 m × 6 K, P1's mean Exposure@K exceeds B0's. P1
  is ≥ B0 (family mean over m and K) in at least 12 of 16 families, and no family is worse by
  more than 0.10.
  - **Supported** if all three hold.
  - **Partially supported** if only the first holds.
  - **Failure:** otherwise.
- **H2.** P1's TGC@K ≥ B0's in every cell. The bound of §4 property 4 holds in every cell
  where its premise holds.
- **H3 (recency attacks).** In F1–F3 (decoy bits < target bits), B0 and P1 keep the target at
  rank 1 for every m, while B1's Exposure@K is 0 whenever m ≥ K.
- **H4 (identifiability, F6).** B0's Exposure@K is 0 for m ≥ K, because the target is the
  oldest of its equals. P1 and B6's mean exposure over 10 seeds is within ±0.10 of
  min(1, K/(m+1)) at every m ≥ K. No method guarantees exposure.
- **H5 (diversity cost, F14).** Reported as the trade-off. P1 is not adopted as the research
  default if its F14 mean Exposure@K is below B0's by more than 0.10.
- **H6 (ablations).** Report which component carries any H1 gain. If A-nosim or A-λ∞ alone
  matches P1 within 0.01 overall, the simpler method is preferred.

## 8. Learning to rank

**Feasibility rule.** Train only on a population with at least 100 independent queries, each
with at least 2 candidates and a real outcome label, a temporal split, no protected overlap
and no future features. Otherwise report "not trained".

**Population.** The archive's lookalike-prioritization episodes (`lookalike-prioritization/1`,
real source-confirmed payoffs: which lookalike was paid):
- **12.1 development split only** (640 episodes, 632 groups). The 12.1 test split is not
  used, not even for feature computation.
- **Protected wallets and transactions** are excluded exactly as in 12.1.
- **Features** without the graph, 12.1 definitions: S = `B0` (affix vs. the victim's own
  recipients), R = `T0` (age of the last planting), N = `T1` (distinct planting
  transactions).
- **Internal temporal split:** dev groups ordered by earliest payoff. The earliest 70 % of
  episodes are used to fit, the latest 30 % to evaluate.

**Models:**
- **M-LTR:** a pairwise conditional logit (12.1's `learned` construction: L2 logistic
  regression on standardized paid-minus-rival differences) on (S, R, N).
- **M-LTR-noR:** the same on (S, N), excluding the attacker-cheap feature.

**Baselines on the same episodes, tie-averaged:**
- similarity S;
- recency R;
- lexicographic S-then-R (which is B0);
- random.

**Source-conditional metrics:** top-1 and MRR, with paired group bootstrap and group
sign-flip p-values against B0, as in 12.1.

**Adversarial transfer.** The fitted M-LTR and M-LTR-noR scorers are applied to the synthetic
benchmark, with the same feature definitions computed from evidence groups. Exposure@K is
reported beside B0 and P1.

**Gate G (ML contribution) passes only if both hold:**
1. M-LTR beats B0 on the internal validation split by at least 0.05 top-1, with a CI
   excluding 0;
2. M-LTR's mean benchmark Exposure@K is no more than 0.05 below B0's.

Otherwise ML adds no robust value. The archive is source-conditional: attackers there were
not gaming this ranker, and recency is attacker-controlled.

**Source shift.** Compare the fit and validation feature distributions (quantiles of S, R, N
and candidate counts), and report validation metrics by candidate-count bin and by the
paid planting's mechanism. On the benchmark, report results by family, decoy count and
completeness.

## 9. Development cases (development-case analysis, not independent validation)

The pilot, ScamSniffer `/1` and ScamSniffer blind `/2`, at the existing cutoffs.

**Reported:** the paid lookalike's rank under B0, B1, B2, B6 and P1 (with M-LTR where its
features exist), plus C2's own candidate list order (a different candidate set, labelled as
such), and missingness. No method is tuned on these cases.

## 10. Integration, cost, reproducibility

- `select(result, method, config)` returns the same groups reordered, with the method id and a
  config hash. `summarize` / `page` report both, and each item reports its reference bucket
  size. Nothing else in the summary contract changes.
- **Performance:** P1 on 100, 1,000, 10,000 and 100,000 groups. The study runs in one process
  with a bounded resource preflight.
- **Outputs:** `cryptoguard ml adversarial-ranking` writes
  `data/ml/research/phase12.7/adversarial-ranking.json` (git-ignored), with its git SHA,
  config and seeds.
- **Research-only:** the production detector, its findings and the warning severities are
  unchanged.

## 11. Gates

- **Statuses:** PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA, NOT EVALUATED.
- **Gates:** historical correctness, preservation, exposure (H1), similarity attacks (F5–F8),
  recency attacks (H3), diversity trade-off (H5), ML (gate G), missingness, cost, production
  isolation, reproducibility.
- **Independent validation** is **BLOCKED BY DATA**. Neither synthetic data nor the two known
  incidents can pass it.

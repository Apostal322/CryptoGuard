# Protocol 12.7.1: debiased validation of P1b against an adaptive adversary

**Frozen:** 2026-11-09, in the commit that adds this file. That is after the generator and
evaluation code exist and their integrity tests pass, and **before any selector has been run
on the sealed scenarios**.

**Base:** `073019c`.

**RPC budget:** 0.

**Goal:** to falsify P1b's 12.7 advantage, not to confirm it. P1b was built after the 12.7
outcomes were seen, so it is treated here as an already-developed algorithm that must hold up
on new data.

## 1. Research questions

1. Does P1b beat similarity-first (B0) when the target's age, mechanism, reference group,
   similarity and tie position are not systematically special?
2. Does a simpler baseline match it?
3. What does an adaptive attacker, within the declared capabilities, need to displace the
   target under each method?
4. Where is the task intrinsically ambiguous?

## 2. Evaluation categories (never pooled)

| Id | Data | Status |
|---|---|---|
| E1 | the 12.7 grid | development; not rerun |
| **E2** | the sealed debiased benchmark below | **primary**; synthetic only |
| E3 | the adaptive attacker and the counterexample search | exploratory |
| E4 | the two known incidents | regression only; "known development cases — not independent validation" |

## 3. Frozen algorithms

| Item | Frozen value |
|---|---|
| Module | `src/cryptoguard/ml/adversarial_ranking.py` |
| Last change | `0968ff8` |
| Source SHA-256 (LF) | `2c0e65aec71c9b20c422594452e3e338fc6986ba05c8ba3f5bc1302a8892ff1a` |
| Public seed | 0 |

**Config hashes:**

| Method | Definition | Config hash |
|---|---|---|
| B0 | similarity, then recency, then address | `7ecd8843cf738bec` |
| B1 | recency first | `944418279feaaeb2` |
| B4 | reference round-robin (recency within) | `2bf989929000f1e6` |
| B6 | similarity with keyed-hash ties | `93cdbe0b57c2958b` |
| B7 = P1 | registered | `66b77df10d259828` |
| **B8 = P1b** | bucket-hash ties, λ = 4 | **`8b3795e363aad678`** |

`adaptive_validation.verify_frozen()` refuses to run if the module or any configuration
differs. **No selector changes after this commit.** A defect found later is documented, and
any changed algorithm counts as exploratory on E2 (P1c is never substituted for P1b).

**Baselines and controls** (`adaptive_validation.METHODS`):

| Id | Definition |
|---|---|
| B2 | oldest first |
| B3 | mechanism round-robin |
| B5 | pure similarity, address ties |
| B9 | similarity with per-scenario seeded random ties |
| NC-newest | newest first |
| NC-random | seeded random order |
| NC-hash-order | keyed hash of the address |
| NC-group-rotation | pure group rotation (λ = ∞, no similarity) |

**Ablations of P1b:** λ = ∞, λ = 2, λ = 8, no similarity, recency ties within a bucket, and
member-hash ties (which is P1). Removing reference grouping or the discount both give λ = 0,
which is B6.

## 4. Threat model

**The attacker controls:**
- lookalike addresses and their tier (prefix + suffix ≥ 6, suffix ≥ 3: the pipeline's rule);
- which genuine reference each one imitates;
- planting time;
- mechanism (native dust, fake-token log, zero-value ERC-20 in, spoofed zero-value out);
- repetition;
- how many addresses to use.

**The attacker does not control:**
- the victim's references or signatures;
- finalized order or provenance;
- the scoring target.

**The attacker may know the algorithm and its public seed (K1).** A secret-seed model (K2) is
a diagnostic only: a seed that sits in a public configuration is not secret.

**Costs (illustrative), kept separate:**
- **Address generation:** 2^(4(p+s)) key trials for one specific reference.
- **Planting:** gas per event.
- **Repetition:** gas only, with no new address.

The attacker budget W is counted in **target-tier address equivalents**: a decoy one tier
stronger costs 16, one tier weaker costs 1/16. No vanity search is run; addresses are
simulated.

## 5. Generator (E2), independent of the 12.7 benchmark

**Population.** Each scenario is generated from `sha256(MASTER | family | G | m | replicate)`:
- G uniformly random genuine references; the target's reference index is uniform;
- target(s) and m attacker decoys per the family;
- 5 background lookalikes from other campaigns (tier i.i.d. from {6, 7, 8, 9} with weights
  4:3:2:1, reference uniform, mechanism per the relation, time per the relation);
- 2 unreferenced strangers.

**How candidates are built:**
- Addresses are uniformly random apart from the designed affix.
- Each candidate's reference is assigned by the pipeline's own `candidate_evidence._match`,
  so multi-reference ties follow its label-independent rule.
- Groups are `CandidateGroup` records identical in shape to `build` output. A fidelity check
  rebuilds a sample through real fixtures.
- The population is shuffled.

**The oracle target** is stored outside the groups. No selector receives it, and scenario
identifiers never reach a selector.

**Age relations** (rotated so every template sees all eight): target oldest, newest,
intermediate, random, everyone in one block, decoys precede, decoys follow, overlap.

**Mechanism relations** (rotated): same, different, mixed independent, target unique (a
deliberate shortcut condition), majority same (80 %). The target's mechanism is uniform.

**Families** (target tier t, decoy tier d):

| Family | Definition |
|---|---|
| F1 stronger | t ∈ {7, 8, 9}; d uniform in [6, t−1]; decoys on any reference |
| F2 equal, other groups | d = t; decoys on other references (own if G = 1) |
| F3 equal, own group | d = t; decoys on the target's reference (identifiability) |
| F4 equal, uniform | d = t; decoys on any reference |
| F5 weaker target | d ∈ [t+1, t+2]: intrinsically ambiguous, the target has strictly weaker evidence |
| **F6 exchangeable null (control)** | every candidate i.i.d.; the target is a uniformly drawn member. Excluded from the primary estimate; every method should be at chance. |
| F7 same total, other split | d = t with a different prefix/suffix split |
| F8 reference overlap | references in pairs sharing exactly a 3+3 affix; decoys imitate the target's partner |
| F9 several relevant | 3 targets of tier t on 3 references (when G ≥ 3); decoys d = t anywhere |
| F10 equal leaders | an attacker leader of tier t on every other reference, t ∈ {7, 8, 9}; decoys d = t−1 |

**Grid.** Each family × G ∈ {1, 2, 5, 10, 25} × m ∈ {0, 10, 100, 1,000, 10,000} is a
**template**. Replicates per template: 40 at m ≤ 100, 16 at m = 1,000 and 8 at m = 10,000.
Fewer replicates at the large m are fixed here for compute, not chosen after results.
- 7,200 scenarios and 5,079,472 candidates; 250 templates (225 primary).
- K ∈ {1, 3, 5, 10, 20, 50}.

**Sealed manifest** (`cryptoguard ml adaptive-validation --manifest-only`):
- overall SHA-256 **`2e294aeb7c7558151edd4fb399e950a1d6bf54d32ffc69bf31c984c998882afe`**;
- per-family hashes in `data/ml/research/phase12.7.1/manifest.json`.

The primary run must reproduce the overall hash.

## 6. Metrics

- **Exposure@K:** for each relevant candidate, rank ≤ K. The scenario score is the mean over
  relevant candidates and over the six K values.
- **GroupExposure@K:** the first member of the relevant candidate's reference bucket is
  within K. It is reported separately and never combined with Exposure@K.
- **Rank displacement:** rank minus rank with the attacker's decoys removed (B0, P1b).
- **Worst family:** the lowest family mean paired difference.
- **Worst budget:** the paired difference at m = 10,000.
- **Pseudo-target exposure** (the shuffled-target control): a random non-relevant referenced
  candidate's exposure.
- **Preservation:** every order is a permutation (asserted for every scenario).
- **Runtime and peak RSS.**

## 7. Aggregation and uncertainty

- **Weights:** equal by template within a family (replicates averaged inside a template), and
  equal by family across the **9 primary families**. F6 is reported only as a control.
- **Statistical unit:** the template. Replicates of one template are not independent
  incidents, so millions of candidates are never treated as independent observations.
- **Uncertainty:** a stratified template-cluster bootstrap, resampling templates within each
  family. 2,000 resamples, seed 20261109, percentile 95 % CI.

## 8. Hypotheses and pre-registered decision

**H1 (primary).** Let Δ = the equal-family mean paired difference (P1b − B0) in Exposure@K.

| Classification | Condition |
|---|---|
| **Inferior to a simpler baseline** | any of B4, B5, B6 or B9 reaches an equal-family mean ≥ P1b + 0.02. This takes precedence. |
| **Supported under the declared synthetic threat model** | Δ ≥ 0.05 with CI lower bound > 0; **and** the worst family ≥ −0.05; **and** Δ ≥ 0.05 on the shortcut-free subset (age ∈ {random, overlap, same block} and mechanism = mixed independent) |
| **Supported with significant limitations** | only the first condition holds |
| **Not supported after debiasing** | otherwise |

**Secondary hypotheses (reported, not re-weighted):**
- **H2:** under K1 the best attack needs a larger budget to push the median victim's target
  past K under P1b than under B0.
- **H3:** GroupExposure@K, P1b − B0, under other-group flooding (F2, F10).
- **H4:** in F3, no method keeps the target exposed when m ≫ K.
- **H5:** P1b's bucket position in F10 does not drift with m (neutral to group size). P1's
  can.
- **H6 and H7:** P1b's results by mechanism relation and by age relation do not depend on
  the shortcut conditions. B2, NC-newest and B3 should benefit only in their own designed
  conditions.
- **H8:** P1b runtime and memory at 100 to 100,000 candidates.
- **H9:** report every simpler baseline that matches or beats P1b in any family.

## 9. Adaptive attacker (E3, exploratory)

**Victims:** 12 attack-free victims (G ∈ {2, 5, 10, 25} × target tier {6, 7, 8}), each with a
spoofed-out target and 5 background candidates.

**Budgets:** W ∈ {10, 100, 1,000}. Populations are capped at 2,000 decoys (disclosed).

**Search:** exhaustive over a bounded grid of 48 attacks:
- tier offset −1, 0 or +1 (cost-adjusted counts);
- allocation: own group, other groups, uniform, or tie winners (references whose public
  bucket hash beats the target's);
- timing: older or newer;
- grinding: keep only addresses whose public member hash beats the target's (costs
  generated addresses).

**Legality:** the attacker only adds candidates. It never touches existing records, the
references, or receipts, and tiers below the similarity rule are illegal.

**Methods:** B0, B1, B4, B5, B6, P1 and P1b, under K1, plus K2 for the seeded ones.

**Reported:** the worst-case rank per victim, the share displaced beyond K ∈ {1, 5, 10}, and
the budget at which the median victim is displaced.

**Counterexamples:** 20,000 random populations of up to 6 candidates on up to 3 references,
searched for:
- P1b losing to B0;
- P1b losing to pure group rotation;
- P1b's group not exposed;
- an equal-leader tie lost to another group;
- a weaker decoy displacing a non-leading target.

Each is shrunk greedily. The search also counts **invariant breaks** of the actual 12.7
theorem: the displacement bound, and a weaker decoy moving the target bucket's first member.
**Multi-reference assignment** is shown by an example.

## 10. Other checks

- **E4:** ranks of the paid lookalike in the two known incidents under every frozen method,
  and full pagination of the P1b-ordered result. Excluded from every E2 number.
- **Fidelity:** 30 E2 scenarios rebuilt through fixtures and `build`. References, affixes,
  mechanisms and P1b's order must all match.
- **Performance:** B0 and P1b at 100, 1,000, 10,000 and 100,000 candidates. Peak RSS is
  recorded. Bounded memory, one process.

## 11. Stop conditions

- **Run once.** The primary run executes once on the committed code. A crash may be rerun
  only on unchanged code.
- **Stop with no outcome** if the manifest hash differs or `verify_frozen` fails.
- **After the primary run,** nothing in §3–§8 changes. Later analyses are labelled post hoc.

## 12. Gates

**Statuses:** PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA, NOT EVALUATED.

| Gate | Checks |
|---|---|
| A | neutrality (diagnostics) |
| B | historical correctness |
| C | the H1 classification |
| D | H2 |
| E | worst family |
| F | group vs address exposure kept separate |
| G | tie neutrality (H5) |
| H | identifiability (H4) |
| I | preservation |
| J | performance (H8) |
| K | reproducibility (manifest hash) |
| L | independent real-world validation: **BLOCKED BY DATA**, by construction |

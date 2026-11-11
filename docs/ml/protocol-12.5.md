# Protocol 12.5: ML-driven candidate discovery and evidence-aware ranking

**Frozen:** 2026-11-09, in the commit that adds this file. That is before any outcome of the new tasks below has been computed.

**Already seen at freezing:**
- the Phase 12.1–12.4 results;
- the archive episode counts (1,068 eligible episodes, 32,697 plantings);
- the wallet-centric fixtures used in Phase 12.4.

**RPC:** 0 requests. **Downloads:** none.

## 1. Position

Phase 12.1 (`ML_TEMPORAL_GRAPH_RESEARCH.md`) already ran, on the archive's payoff episodes:
- the temporal, semantic and graph ranking features;
- a learned conditional logit, which did not beat recency (T0);
- ablations, strata and controls.

Its test split has been used. **No archive ranking result in this phase can be confirmatory.** Repeating that study is not a contribution, so archive ranking questions are answered by citing 12.1, plus exploratory analyses on its **development split only**. Wallet-centric data hold 2 known development cases and unlabelled windows, so ranking there is descriptive.

## 2. Research questions and hypotheses

| RQ | Hypothesis | Task | Population | Status |
|---|---|---|---|---|
| RQ1 coverage | `observation/2` plus C1 recovers mechanisms invisible to C0. C2 bounds the volume. | T1, T2 | P1 synthetic; P3 dev (v1 and blind v2); P5 | descriptive and controlled |
| RQ2 semantics | The semantic channel of a candidate's latest planting (spoofed-outgoing vs inbound) carries ranking information beyond recency. | T3 | archive development split | **exploratory** |
| RQ3 temporal | **H3a:** a wallet-normalized temporal anomaly score (median/MAD of interarrival) adds nothing to recency within an episode. Predicted analytically: any per-episode monotone transform of the same recency ranks identically. **H3b:** recency is the strongest available temporal ranking signal. | T3 | archive (cited, 12.1); P3 descriptive | analytic, cited |
| RQ4 graph | Graph features add information. | T3 | — | **not re-run.** 12.1 found G1 at random and G2/G3 below it, and the wallet-centric data have 0 cross-wallet signer links. Recorded as blocked. |
| RQ5 missingness | C2 and the feature schema abstain or mark unknowns, and never invent evidence, under controlled information loss. | T5 | P1, P3 | controlled |
| RQ6 cost | Discovery, features and ranking stay bounded under floods. | T5 | P1 | controlled |
| RQ7 generalization | Which findings survive source, mechanism and time shift? | all | stratified | descriptive |
| **RQ8 proxy (new)** | **H8: the mechanism of a victim's next planting is predictable from its planting prefix, better than frequency and Markov baselines.** | T4, a self-supervised event-pattern task | archive episodes | **primary ML test (§4)** |

## 3. Populations (never pooled)

| ID | Description | Use |
|---|---|---|
| P1 | Synthetic fixtures with hand-written oracles | correctness, coverage, robustness, cost |
| P2 | The 4 packaged replay fixtures | excluded: frozen Cohort B |
| P3 | 2 Level I development cases. One is recorded twice: `observation/1` (frozen) and the blind `observation/2` replay. | development-case description only; never used for selection |
| P4 | Archive payoff episodes (Tsuchiya, CC BY-NC-ND, local only) | RQ2 exploratory; RQ8 primary |
| P5 | 6 background windows without frozen items (`observation/1`) | unlabelled volume. **Never used to estimate native volume.** |

**Protected data.** Episodes of the 60 review wallets are already excluded by `load_episodes`. Episodes that share an entity or a linkage group with any frozen item (`lookalike_ranking.protected_overlap`) are also removed. Cohort files must keep their hashes (§8).

## 4. Primary ML test: RQ8 (next-planting mechanism)

- **Unit.** One planting event of an eligible archive episode, from the second planting on.
- **Input.** Only plantings in **strictly earlier blocks**. Same-block order is unknown, so same-block predecessors are excluded.
- **Target.** The event's mechanism class:

  | Class | Rule |
  |---|---|
  | `spoofed_out` | the victim is the sender |
  | `counterfeit_in` | otherwise, the counterfeit flag |
  | `tiny_in` | otherwise, the tiny flag |
  | `zero_in` | otherwise, the zero flag |
  | `other` | anything else |

  The flags are the source's own heuristics, and the target is a proxy. **It is not poisoning detection.**
- **Prefix features** (`proxy-features/1`):
  - counts and shares of each class in the prefix;
  - the last class (one-hot);
  - log prefix length;
  - log blocks since the previous planting;
  - distinct lookalikes in the prefix;
  - the last planting's token in a reviewed-stablecoin list or not;
  - whether the last two classes are equal.
- **Split.** Phase 12.1's temporal group split (`protocol_groups`, `temporal_split`, test share 0.4):
  - train on development episodes;
  - evaluate once on test episodes.

  Test episodes were inspected for a different target (12.1 ranking), never for this one. That is disclosed.
- **Baselines** (fit on train only):
  1. the global class frequency;
  2. the victim-prefix frequency (Laplace α = 1, backed off to global);
  3. a first-order Markov transition from the last class (Laplace α = 1).
- **Model.** Multinomial logistic regression (scikit-learn, L2, C = 1, `lbfgs`, standardized features, seed 20261109). **No hyperparameter search.**
- **Primary metric:** test log loss (cross-entropy).
- **Secondary metrics:** macro-F1, and the per-class recall table.
- **Uncertainty:** the paired difference in mean log loss, LR minus the best baseline. Its 95% CI comes from a group bootstrap over episode groups (2,000 draws, seed 20261109).
- **Decision.** **H8 supported** if the LR's log loss is lower than every baseline's and the CI of the difference with the best baseline excludes 0. **Not supported** otherwise. Markov winning is a valid negative result: it would mean simple statistics suffice.

## 5. RQ2 exploratory (archive development split only)

- **B5 semantic channel ranking:** candidates whose latest planting is `spoofed_out` rank first, with recency (T0) breaking ties. It is compared with T0 by tie-averaged top-1 on development episodes, with a group bootstrap CI. It is reported as exploratory. **The test split is not used.**
- **H3a** is checked numerically: a median/MAD-normalized recency must produce T0's ranking exactly.

## 6. Wallet-centric work (T1, T2, T5)

**Candidate feature schema `poisoning-candidate-features/1`.** Every value is paired with a status: `observed`, `zero_observed`, `unknown` or `not_applicable`. Its families:
- address: affixes, matched references, earlier payment to the reference, blocks since that payment;
- semantics: kind, zero value, signer role, emitter reviewed, receipt status;
- temporal: first and last seen, events, events in the last day, median interarrival;
- graph: in-window signer reuse;
- completeness: the coverage per category.

The schema uses only observations strictly before the cutoff. Metamorphic tests check that future events, payoffs and signer links change nothing, and that reordering changes nothing.

**Shadow ranking `poisoning-candidate-ranking/1`** (offline, disabled by default):
- **Input:** C2 candidates.
- **Default order:** B4 (recency of the latest evidence), the only signal with large-sample support. That support is source-conditional, from Phase 12.1.
- **Reported alongside:** B3 (similarity), B5 (semantic channel) and B6 (familiarity) ranks, with feature availability, completeness and evidence references.
- **Never:** a probability, a severity change or a suppression.

**Robustness (P1, P3):**
- shortened window;
- native observations removed;
- signer unknown;
- no reference history;
- receipts unknown.

The measures are candidate-set stability, abstention and unsupported rate.

**Cost (P1):** floods of 10,000 zero-value native transfers and 1,000 lookalikes. The measures are runtime, peak traced memory, and C2 candidates, bounded by distinct lookalikes.

## 7. Feasibility audits (no forced models)

- **Self-supervised learning on wallet histories:** blocked if the eligible wallet-centric sequences hold fewer than 1,000 events. At freezing there are about 8 windows with roughly 100 events.
- **PU learning:**
  - **Positives:** the paid candidates. Exactly one per episode, chosen by the source's payoff-confirmation rule.
  - **Unlabelled:** the rival candidates, all of them plantings.
  - **The class prior is fixed by design (1/k)**, and SCAR is violated, so no PU risk is estimated. The ranking formulation (12.1's conditional logit) stays the appropriate one.
- **Graph:** not re-run (§2).

## 8. Integrity rules

- **Cohorts and fixtures:** the hashes of Cohort A and B sheets and of the frozen fixtures are checked before and after the phase.
- **Labels and metrics:** no label is invented, and nothing unknown is treated as benign. No false-positive rate, precision or recall is reported.
- **Production:** the detector, its findings and C0 are unchanged, and ML stays out of production.
- **Resources:** one heavy process at a time, under 1 GiB RSS, with no live RPC. The archive episodes are cached once in the git-ignored `data/ml/research/phase12.5/`, and never committed.
- **Gate labels:** PASS, PASS WITH LIMITATIONS, FAIL, BLOCKED BY DATA, NOT EVALUATED.
